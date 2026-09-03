use crate::core_generation_contracts::MAX_GENERATION_BYTES;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const CACHE_STATE_LIMIT: usize = 16 * 1024;
const CACHE_STATE_SCHEMA: u32 = 2;
const CACHE_STATE_KIND: &str = "opemos-core-host-generation-state";
const CACHE_STATE_REQUIRED_MARKER: &str = "state-required";
static STATE_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static CACHE_TRANSACTION_LOCK: Mutex<()> = Mutex::new(());
const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_LOCK_RETRY: Duration = Duration::from_millis(20);
const CANDIDATE_LEASE_LIMIT: u64 = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreGenerationIdentity {
    pub(crate) sequence: u64,
    pub(crate) generation_id: String,
    pub(crate) manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreGenerationCacheState {
    schema_version: u32,
    kind: String,
    pub(crate) revision: u64,
    pub(crate) high_water_sequence: u64,
    pub(crate) active: Option<CoreGenerationIdentity>,
    pub(crate) pending: Option<CoreGenerationIdentity>,
    pub(crate) pending_operation_id: Option<String>,
    pub(crate) last_known_good: Option<CoreGenerationIdentity>,
}

impl Default for CoreGenerationCacheState {
    fn default() -> Self {
        Self {
            schema_version: CACHE_STATE_SCHEMA,
            kind: CACHE_STATE_KIND.into(),
            revision: 0,
            high_water_sequence: 0,
            active: None,
            pending: None,
            pending_operation_id: None,
            last_known_good: None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum GenerationCommit {
    Installed,
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FilesystemIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct CoreGenerationCache {
    root: PathBuf,
}

struct CoreGenerationCacheLock {
    file: File,
}

#[derive(Debug)]
pub(crate) struct CandidateLease {
    candidate: PathBuf,
    candidate_identity: FilesystemIdentity,
    lease_path: PathBuf,
    lease_identity: FilesystemIdentity,
    lease_file: File,
    expected_bytes: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateLeaseDocument<'a> {
    candidate_basename: &'a str,
    device: u64,
    inode: u64,
    reservation_bytes: u64,
}

impl Drop for CoreGenerationCacheLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl Drop for CandidateLease {
    fn drop(&mut self) {
        // Lease residue is intentional after process death or an abandoned
        // handle. Reconciliation owns deletion; Drop only releases the lock.
        let _ = self.lease_file.unlock();
    }
}

impl CandidateLease {
    pub(crate) fn path(&self) -> &Path {
        &self.candidate
    }
}

impl std::ops::Deref for CandidateLease {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

impl AsRef<Path> for CandidateLease {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl CoreGenerationIdentity {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.sequence == 0
            || !lowercase_hex(&self.manifest_sha256, 64)
            || self.generation_id != self.manifest_sha256
        {
            return Err("Core generation cache identity is invalid.".into());
        }
        Ok(())
    }
}

impl CoreGenerationCacheState {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != CACHE_STATE_SCHEMA || self.kind != CACHE_STATE_KIND {
            return Err("Core generation cache state has an unsupported identity.".into());
        }
        if self.last_known_good.is_some() && self.active.is_none() {
            return Err(
                "Core generation cache state has no active generation for its fallback.".into(),
            );
        }
        if (self.high_water_sequence == 0) != self.active.is_none() {
            return Err("Core generation cache activation state is invalid.".into());
        }
        if self
            .active
            .as_ref()
            .is_some_and(|identity| identity.sequence > self.high_water_sequence)
            || self
                .last_known_good
                .as_ref()
                .is_some_and(|identity| identity.sequence > self.high_water_sequence)
        {
            return Err("Core generation cache high-water state is invalid.".into());
        }
        if let (Some(active), Some(last_known_good)) =
            (self.active.as_ref(), self.last_known_good.as_ref())
        {
            if last_known_good.sequence > active.sequence
                || (last_known_good.sequence == active.sequence && last_known_good != active)
            {
                return Err("Core generation cache fallback relationship is invalid.".into());
            }
        }
        match (&self.pending, &self.pending_operation_id) {
            (Some(_), Some(operation)) if safe_operation_id(operation) => {}
            (None, None) => {}
            _ => {
                return Err("Core generation cache pending state is incomplete or invalid.".into());
            }
        }
        for identity in [
            self.active.as_ref(),
            self.pending.as_ref(),
            self.last_known_good.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            identity.validate()?;
        }
        if self.pending.is_some()
            && (self.pending == self.active || self.pending == self.last_known_good)
        {
            return Err("Core generation cache pending identity is already active.".into());
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|identity| identity.sequence <= self.high_water_sequence)
        {
            return Err("Core generation cache pending identity is replayed.".into());
        }
        Ok(())
    }
}

impl CoreGenerationCache {
    pub(crate) fn open(root: &Path) -> Result<Self, String> {
        match fs::symlink_metadata(root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err("Core generation cache root must be a real directory.".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "Could not inspect the Core generation cache: {error}"
                ));
            }
        }
        fs::create_dir_all(root)
            .map_err(|error| format!("Could not create the Core generation cache: {error}"))?;
        let created = fs::symlink_metadata(root)
            .map_err(|error| format!("Could not revalidate the Core generation cache: {error}"))?;
        if created.file_type().is_symlink() || !created.is_dir() {
            return Err("Core generation cache root changed while it was being created.".into());
        }
        let mut root_options = OpenOptions::new();
        root_options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let root_handle = root_options
            .open(root)
            .map_err(|error| format!("Could not safely open the Core generation cache: {error}"))?;
        let opened = root_handle
            .metadata()
            .map_err(|error| format!("Could not identify the Core generation cache: {error}"))?;
        use std::os::unix::fs::MetadataExt as _;
        if created.dev() != opened.dev() || created.ino() != opened.ino() {
            return Err("Core generation cache root identity changed while opening it.".into());
        }
        let root = fs::canonicalize(root)
            .map_err(|error| format!("Could not resolve the Core generation cache: {error}"))?;
        let current = fs::symlink_metadata(&root)
            .map_err(|error| format!("Could not recheck the Core generation cache: {error}"))?;
        if current.file_type().is_symlink()
            || !current.is_dir()
            || current.dev() != opened.dev()
            || current.ino() != opened.ino()
        {
            return Err("Core generation cache root changed while resolving it.".into());
        }
        require_directory(&root, "Core generation cache")?;
        set_private_directory_permissions(&root)?;
        for child in ["candidates", "generations", "commits", "leases"] {
            let path = root.join(child);
            fs::create_dir(&path)
                .or_else(|error| {
                    if error.kind() == ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(|error| format!("Could not prepare the Core generation cache: {error}"))?;
            require_directory(&path, "Core generation cache directory")?;
            set_private_directory_permissions(&path)?;
        }
        sync_directory(&root)?;
        Ok(Self { root })
    }

    fn acquire_lock(&self) -> Result<CoreGenerationCacheLock, String> {
        let path = self.root.join("cache.lock");
        let before = fs::symlink_metadata(&path).ok();
        if before
            .as_ref()
            .is_some_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
        {
            return Err("Core generation cache lock is not a safe regular file.".into());
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .map_err(|error| format!("Could not open the Core generation cache lock: {error}"))?;
        let metadata = file.metadata().map_err(|error| {
            format!("Could not inspect the Core generation cache lock: {error}")
        })?;
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.is_file()
            || before.as_ref().is_some_and(|before| {
                before.dev() != metadata.dev() || before.ino() != metadata.ino()
            })
        {
            return Err("Core generation cache lock identity changed.".into());
        }
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    format!("Could not secure the Core generation cache lock: {error}")
                })?;
        }
        let deadline = Instant::now()
            .checked_add(CACHE_LOCK_TIMEOUT)
            .ok_or("Core generation cache lock deadline overflowed.")?;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(CoreGenerationCacheLock { file }),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(CACHE_LOCK_RETRY);
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err("Timed out waiting for the Core generation cache lock.".into());
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(format!("Could not lock the Core generation cache: {error}"));
                }
            }
        }
    }

    pub(crate) fn create_candidate(
        &self,
        operation_id: &str,
        reservation_bytes: u64,
    ) -> Result<CandidateLease, String> {
        self.create_candidate_with_prepare(
            operation_id,
            reservation_bytes,
            prepare_candidate_directory,
            |_lease_path| Ok(()),
        )
    }

    fn create_candidate_with_prepare(
        &self,
        operation_id: &str,
        reservation_bytes: u64,
        prepare: impl FnOnce(&Path, &Path) -> Result<(), String>,
        after_lease_open: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<CandidateLease, String> {
        if !safe_operation_id(operation_id) {
            return Err("Core generation cache operation identity is invalid.".into());
        }
        if !(1..=MAX_GENERATION_BYTES).contains(&reservation_bytes) {
            return Err("Core generation candidate reservation is invalid.".into());
        }
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        let candidates_root = self.root.join("candidates");
        let leases_root = self.root.join("leases");
        let mut created = None;
        for _ in 0..8 {
            let token = random_candidate_token()?;
            let path = candidates_root.join(format!("candidate-{operation_id}-{token}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    created = Some(path);
                    break;
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "Could not create a private Core generation candidate: {error}"
                    ));
                }
            }
        }
        let path = created.ok_or(
            "Could not allocate a unique private Core generation candidate after 8 attempts.",
        )?;
        let mut created_lease_identity = None;
        let prepared = prepare(&path, &candidates_root).and_then(|()| {
            let candidate_identity = candidate_directory_identity(&path)?.ok_or_else(|| {
                "New Core generation candidate disappeared during creation.".to_string()
            })?;
            let basename = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("New Core generation candidate name is invalid.")?;
            let lease_path = leases_root.join(basename);
            let expected_bytes =
                candidate_lease_bytes(basename, candidate_identity, reservation_bytes)?;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let mut lease_file = options.open(&lease_path).map_err(|error| {
                format!("Could not create the Core generation candidate lease: {error}")
            })?;
            let lease_metadata = lease_file.metadata().map_err(|error| {
                format!("Could not identify the Core generation candidate lease: {error}")
            })?;
            use std::os::unix::fs::MetadataExt as _;
            let lease_identity = FilesystemIdentity {
                device: lease_metadata.dev(),
                inode: lease_metadata.ino(),
            };
            created_lease_identity = Some(lease_identity);
            after_lease_open(&lease_path)?;
            lease_file
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    format!("Could not secure the Core generation candidate lease: {error}")
                })?;
            match lease_file.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(
                        "New Core generation candidate lease unexpectedly contended.".into(),
                    );
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(format!(
                        "Could not lock the Core generation candidate lease: {error}"
                    ));
                }
            }
            lease_file.write_all(&expected_bytes).map_err(|error| {
                format!("Could not write the Core generation candidate lease: {error}")
            })?;
            lease_file.sync_all().map_err(|error| {
                format!("Could not sync the Core generation candidate lease: {error}")
            })?;
            sync_directory(&candidates_root)?;
            sync_directory(&leases_root)?;
            let lease = CandidateLease {
                candidate: path.clone(),
                candidate_identity,
                lease_path,
                lease_identity,
                lease_file,
                expected_bytes,
            };
            self.require_valid_candidate_lease(&lease)?;
            Ok(lease)
        });
        match prepared {
            Ok(lease) => Ok(lease),
            Err(error) => {
                let lease_path = path.file_name().map(|basename| leases_root.join(basename));
                let lease_cleanup = lease_path
                    .as_deref()
                    .zip(created_lease_identity)
                    .map_or(Ok(()), |(lease, expected)| {
                        remove_new_lease_if_same(lease, &leases_root, expected)
                    });
                let cleanup = cleanup_candidate_tree(&path, &candidates_root);
                match (lease_cleanup, cleanup) {
                    (Ok(()), Ok(())) => Err(error),
                    (lease_cleanup, candidate_cleanup) => Err(format!(
                        "{error} Candidate creation cleanup also failed: lease={}; candidate={}",
                        lease_cleanup.err().unwrap_or_else(|| "ok".into()),
                        candidate_cleanup.err().unwrap_or_else(|| "ok".into())
                    )),
                }
            }
        }
    }

    pub(crate) fn stage_candidate(
        &self,
        operation_id: &str,
        reservation_bytes: u64,
        identity: &CoreGenerationIdentity,
        populate: impl FnOnce(&Path) -> Result<(), String>,
        verify: impl Fn(&Path) -> Result<(), String>,
    ) -> Result<GenerationCommit, String> {
        let lease = self.create_candidate_with_prepare(
            operation_id,
            reservation_bytes,
            prepare_candidate_directory,
            |_lease_path| Ok(()),
        )?;
        if let Err(error) = populate(lease.path()) {
            return match self.abort_candidate(&lease) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!("{error} Candidate cleanup also failed: {cleanup}")),
            };
        }
        self.commit_candidate(&lease, identity, verify)
    }

    pub(crate) fn abort_candidate(&self, lease: &CandidateLease) -> Result<(), String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        self.require_valid_candidate_lease(lease)?;
        cleanup_candidate_tree(&lease.candidate, &self.root.join("candidates"))?;
        self.remove_candidate_lease(lease)
    }

    pub(crate) fn commit_candidate(
        &self,
        lease: &CandidateLease,
        identity: &CoreGenerationIdentity,
        verify: impl Fn(&Path) -> Result<(), String>,
    ) -> Result<GenerationCommit, String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        self.require_valid_candidate_lease(lease)?;
        let candidate = lease.path();
        let result = identity
            .validate()
            .and_then(|()| self.commit_candidate_locked(candidate, identity, verify));
        match result {
            Ok(outcome) => {
                self.remove_candidate_lease(lease)?;
                Ok(outcome)
            }
            Err(error) => {
                let candidate_cleanup = match candidate_directory_identity(candidate) {
                    Ok(Some(_)) => self.require_valid_candidate_lease(lease).and_then(|()| {
                        cleanup_candidate_tree(candidate, &self.root.join("candidates"))
                    }),
                    Ok(None) => self.require_valid_lease_sidecar(lease),
                    Err(cleanup) => Err(cleanup),
                };
                let lease_cleanup = self.remove_candidate_lease(lease);
                match (candidate_cleanup, lease_cleanup) {
                    (Ok(()), Ok(())) => Err(error),
                    (candidate_cleanup, lease_cleanup) => Err(format!(
                        "{error} Candidate cleanup also failed: candidate={}; lease={}",
                        candidate_cleanup.err().unwrap_or_else(|| "ok".into()),
                        lease_cleanup.err().unwrap_or_else(|| "ok".into())
                    )),
                }
            }
        }
    }

    fn commit_candidate_locked(
        &self,
        candidate: &Path,
        identity: &CoreGenerationIdentity,
        verify: impl Fn(&Path) -> Result<(), String>,
    ) -> Result<GenerationCommit, String> {
        verify(candidate)?;
        sync_closed_tree(candidate)?;

        let destination = self.generation_path(identity)?;
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                require_directory(&destination, "cached Core generation")?;
                seal_closed_tree(&destination)?;
                verify(&destination)?;
                self.ensure_generation_commit_marker(identity)?;
                remove_owned_candidate(candidate, &self.root.join("candidates"))?;
                return Ok(GenerationCommit::AlreadyPresent);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "Could not inspect the Core generation cache: {error}"
                ));
            }
        }

        // A marker without its generation can survive a prior interrupted
        // cleanup. Invalidate and durably forget it before exposing a fresh
        // directory at the same identity.
        self.invalidate_generation_commit_marker(identity)?;

        seal_closed_tree(candidate)?;
        verify(candidate)?;
        // macOS requires the moved directory itself to remain owner-writable
        // during rename. Its contents stay sealed, and the destination root is
        // resealed and reverified before this method returns.
        fs::set_permissions(candidate, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Could not prepare sealed Core generation commit: {error}"))?;
        fs::rename(candidate, &destination)
            .map_err(|error| format!("Could not commit the Core generation atomically: {error}"))?;
        let publication = (|| {
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o500))
                .map_err(|error| format!("Could not reseal committed Core generation: {error}"))?;
            sync_directory(&self.root.join("generations"))?;
            sync_directory(&self.root.join("candidates"))?;
            sync_closed_tree(&destination)?;
            verify(&destination)?;
            self.ensure_generation_commit_marker(identity)
        })();
        if let Err(error) = publication {
            let cleanup = cleanup_failed_publication(
                &destination,
                &self.root.join("generations"),
                &self.root.join("candidates"),
                &self.generation_commit_marker_path(identity)?,
                &self.root.join("commits"),
            );
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!(
                    "{error} Failed committed-generation cleanup also failed: {cleanup}"
                )),
            };
        }
        Ok(GenerationCommit::Installed)
    }

    fn require_valid_candidate_lease(&self, lease: &CandidateLease) -> Result<(), String> {
        self.require_owned_candidate(&lease.candidate)?;
        let current = candidate_directory_identity(&lease.candidate)?
            .ok_or("Core generation candidate disappeared while leased.")?;
        if current != lease.candidate_identity {
            return Err("Core generation candidate identity changed while leased.".into());
        }
        self.require_valid_lease_sidecar(lease)
    }

    fn require_valid_lease_sidecar(&self, lease: &CandidateLease) -> Result<(), String> {
        let leases_root = self.root.join("leases");
        if lease.lease_path.parent() != Some(leases_root.as_path())
            || lease.lease_path.file_name() != lease.candidate.file_name()
        {
            return Err("Core generation candidate lease path is invalid.".into());
        }
        let path_metadata = fs::symlink_metadata(&lease.lease_path).map_err(|error| {
            format!("Could not inspect the Core generation candidate lease: {error}")
        })?;
        let file_metadata = lease.lease_file.metadata().map_err(|error| {
            format!("Could not identify the Core generation candidate lease: {error}")
        })?;
        use std::os::unix::fs::{FileExt as _, MetadataExt as _};
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.nlink() != 1
            || path_metadata.permissions().mode() & 0o7777 != 0o600
            || path_metadata.dev() != lease.lease_identity.device
            || path_metadata.ino() != lease.lease_identity.inode
            || !file_metadata.is_file()
            || file_metadata.dev() != lease.lease_identity.device
            || file_metadata.ino() != lease.lease_identity.inode
            || file_metadata.nlink() != 1
            || file_metadata.permissions().mode() & 0o7777 != 0o600
            || file_metadata.len() > CANDIDATE_LEASE_LIMIT
            || file_metadata.len() != lease.expected_bytes.len() as u64
        {
            return Err("Core generation candidate lease is unsafe or invalid.".into());
        }
        let mut actual = vec![0_u8; lease.expected_bytes.len()];
        lease
            .lease_file
            .read_exact_at(&mut actual, 0)
            .map_err(|error| {
                format!("Could not read the Core generation candidate lease: {error}")
            })?;
        if actual != lease.expected_bytes {
            return Err("Core generation candidate lease binding changed.".into());
        }
        let rechecked = fs::symlink_metadata(&lease.lease_path).map_err(|error| {
            format!("Could not recheck the Core generation candidate lease: {error}")
        })?;
        if rechecked.file_type().is_symlink()
            || !rechecked.is_file()
            || rechecked.dev() != lease.lease_identity.device
            || rechecked.ino() != lease.lease_identity.inode
            || rechecked.nlink() != 1
            || rechecked.len() != lease.expected_bytes.len() as u64
            || rechecked.permissions().mode() & 0o7777 != 0o600
        {
            return Err("Core generation candidate lease changed while being checked.".into());
        }
        Ok(())
    }

    fn remove_candidate_lease(&self, lease: &CandidateLease) -> Result<(), String> {
        self.require_valid_lease_sidecar(lease)?;
        fs::remove_file(&lease.lease_path).map_err(|error| {
            format!("Could not remove the Core generation candidate lease: {error}")
        })?;
        sync_directory(&self.root.join("leases"))
    }

    pub(crate) fn begin_activation(
        &self,
        identity: &CoreGenerationIdentity,
        operation_id: &str,
        expected_revision: u64,
        verify: impl Fn(&Path) -> Result<(), String>,
    ) -> Result<CoreGenerationCacheState, String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        if !safe_operation_id(operation_id) {
            return Err("Core generation activation operation identity is invalid.".into());
        }
        let generation = self.generation_path(identity)?;
        require_directory(&generation, "cached Core generation")?;
        self.require_generation_committed(identity)?;
        verify(&generation)?;
        let mut state = self.load_state_unlocked()?;
        if let Some(pending) = state.pending.as_ref() {
            if pending == identity && state.pending_operation_id.as_deref() == Some(operation_id) {
                return Ok(state);
            }
            return Err("Another Core generation is already pending health validation.".into());
        }
        require_expected_revision(&state, expected_revision)?;
        if state.active.as_ref() == Some(identity) {
            return Ok(state);
        }
        if identity.sequence <= state.high_water_sequence {
            return Err("Core generation is a replay or downgrade.".into());
        }
        state.pending = Some(identity.clone());
        state.pending_operation_id = Some(operation_id.into());
        self.save_next_state(state)
    }

    pub(crate) fn acknowledge_healthy(
        &self,
        identity: &CoreGenerationIdentity,
        operation_id: &str,
        expected_revision: u64,
        verify: impl Fn(&Path) -> Result<(), String>,
    ) -> Result<CoreGenerationCacheState, String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        let generation = self.generation_path(identity)?;
        require_directory(&generation, "cached Core generation")?;
        self.require_generation_committed(identity)?;
        verify(&generation)?;
        let mut state = self.load_state_unlocked()?;
        require_expected_revision(&state, expected_revision)?;
        if state.pending.as_ref() != Some(identity)
            || state.pending_operation_id.as_deref() != Some(operation_id)
        {
            return Err(
                "Core generation health acknowledgement does not match pending state.".into(),
            );
        }
        let previous = state.active.take();
        state.active = Some(identity.clone());
        state.high_water_sequence = state.high_water_sequence.max(identity.sequence);
        state.pending = None;
        state.pending_operation_id = None;
        state.last_known_good = previous.filter(|prior| prior != identity);
        self.save_next_state(state)
    }

    pub(crate) fn reject_pending(
        &self,
        identity: &CoreGenerationIdentity,
        operation_id: &str,
        expected_revision: u64,
    ) -> Result<CoreGenerationCacheState, String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        identity.validate()?;
        let mut state = self.load_state_unlocked()?;
        require_expected_revision(&state, expected_revision)?;
        if state.pending.as_ref() != Some(identity)
            || state.pending_operation_id.as_deref() != Some(operation_id)
        {
            return Err("Rejected Core generation does not match pending state.".into());
        }
        state.pending = None;
        state.pending_operation_id = None;
        self.save_next_state(state)
    }

    pub(crate) fn rollback_to_last_known_good(
        &self,
        expected_active: &CoreGenerationIdentity,
        expected_revision: u64,
        verify: impl Fn(&Path) -> Result<(), String>,
    ) -> Result<CoreGenerationCacheState, String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        let mut state = self.load_state_unlocked()?;
        require_expected_revision(&state, expected_revision)?;
        if state.pending.is_some() {
            return Err("A pending Core generation must be rejected before rollback.".into());
        }
        if state.active.as_ref() != Some(expected_active) {
            return Err("Core generation rollback no longer matches the active generation.".into());
        }
        let target = state
            .last_known_good
            .clone()
            .ok_or("No last-known-good Core generation is available.")?;
        let generation = self.generation_path(&target)?;
        require_directory(&generation, "last-known-good Core generation")?;
        self.require_generation_committed(&target)?;
        verify(&generation)?;
        if state.active.as_ref() == Some(&target) {
            return Ok(state);
        }
        state.active = Some(target.clone());
        state.last_known_good = Some(target);
        self.save_next_state(state)
    }

    pub(crate) fn load_state(&self) -> Result<CoreGenerationCacheState, String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        self.load_state_unlocked()
    }

    fn load_state_unlocked(&self) -> Result<CoreGenerationCacheState, String> {
        let path = self.root.join("state.json");
        let before = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if safe_regular_file(&self.root.join(CACHE_STATE_REQUIRED_MARKER))? {
                    return Err(
                        "Core generation cache state is missing after prior activation.".into(),
                    );
                }
                return Ok(CoreGenerationCacheState::default());
            }
            Err(error) => {
                return Err(format!(
                    "Could not read Core generation cache state: {error}"
                ));
            }
        };
        use std::os::unix::fs::MetadataExt as _;
        if before.file_type().is_symlink()
            || !before.is_file()
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > CACHE_STATE_LIMIT as u64
        {
            return Err("Core generation cache state is not a bounded regular file.".into());
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(&path)
            .map_err(|error| format!("Could not open Core generation cache state: {error}"))?;
        let opened = file
            .metadata()
            .map_err(|error| format!("Could not inspect opened Core cache state: {error}"))?;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || before.len() != opened.len()
            || opened.nlink() != 1
        {
            return Err("Core generation cache state changed while opening it.".into());
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        Read::by_ref(&mut file)
            .take(CACHE_STATE_LIMIT.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("Could not read Core generation cache state: {error}"))?;
        let after = file
            .metadata()
            .map_err(|error| format!("Could not recheck opened Core cache state: {error}"))?;
        if opened.dev() != after.dev()
            || opened.ino() != after.ino()
            || opened.len() != after.len()
            || opened.mtime() != after.mtime()
            || opened.mtime_nsec() != after.mtime_nsec()
            || after.nlink() != 1
            || bytes.len() as u64 != opened.len()
        {
            return Err("Core generation cache state changed while it was read.".into());
        }
        if bytes.is_empty() || bytes.len() > CACHE_STATE_LIMIT {
            return Err("Core generation cache state is empty or excessive.".into());
        }
        let state: CoreGenerationCacheState = serde_json::from_slice(&bytes)
            .map_err(|error| format!("Core generation cache state is invalid: {error}"))?;
        state.validate()?;
        if canonical_state_bytes(&state)? != bytes {
            return Err("Core generation cache state is not canonical.".into());
        }
        Ok(state)
    }

    fn save_next_state(
        &self,
        mut state: CoreGenerationCacheState,
    ) -> Result<CoreGenerationCacheState, String> {
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or("Core generation cache revision overflowed.")?;
        state.validate()?;
        let bytes = canonical_state_bytes(&state)?;
        let sequence = STATE_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self.root.join(format!(
            ".state.json.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let path = self.root.join("state.json");
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options
                .open(&temporary)
                .map_err(|error| format!("Could not stage Core generation state: {error}"))?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("Could not sync Core generation state: {error}"))?;
            ensure_state_required_marker(&self.root)?;
            fs::rename(&temporary, &path)
                .map_err(|error| format!("Could not activate Core generation state: {error}"))?;
            sync_directory(&self.root)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map(|_| state)
    }

    fn generation_path(&self, identity: &CoreGenerationIdentity) -> Result<PathBuf, String> {
        identity.validate()?;
        Ok(self.root.join("generations").join(&identity.generation_id))
    }

    fn generation_commit_marker_path(
        &self,
        identity: &CoreGenerationIdentity,
    ) -> Result<PathBuf, String> {
        identity.validate()?;
        Ok(self.root.join("commits").join(&identity.generation_id))
    }

    fn ensure_generation_commit_marker(
        &self,
        identity: &CoreGenerationIdentity,
    ) -> Result<(), String> {
        let path = self.generation_commit_marker_path(identity)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => return self.require_generation_committed(identity),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "Could not inspect Core generation commit evidence: {error}"
                ));
            }
        }
        let bytes = generation_commit_marker_bytes(identity);
        let commits = self.root.join("commits");
        let temporary = commits.join(format!(
            ".commit-{}-{}.tmp",
            identity.sequence,
            random_candidate_token()?
        ));
        let result = (|| {
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let mut file = options
                .open(&temporary)
                .map_err(|error| format!("Could not stage Core commit evidence: {error}"))?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("Could not sync Core commit evidence: {error}"))?;
            file.set_permissions(fs::Permissions::from_mode(0o400))
                .map_err(|error| format!("Could not seal Core commit evidence: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("Could not sync sealed Core commit evidence: {error}"))?;
            fs::rename(&temporary, &path)
                .map_err(|error| format!("Could not publish Core commit evidence: {error}"))?;
            sync_directory(&commits)?;
            self.require_generation_committed(identity)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn invalidate_generation_commit_marker(
        &self,
        identity: &CoreGenerationIdentity,
    ) -> Result<(), String> {
        let path = self.generation_commit_marker_path(identity)?;
        invalidate_commit_marker_path(&path, &self.root.join("commits"))
    }

    fn require_generation_committed(
        &self,
        identity: &CoreGenerationIdentity,
    ) -> Result<(), String> {
        let path = self.generation_commit_marker_path(identity)?;
        let expected = generation_commit_marker_bytes(identity);
        let before = fs::symlink_metadata(&path)
            .map_err(|error| format!("Core generation is not durably committed: {error}"))?;
        use std::os::unix::fs::MetadataExt as _;
        if before.file_type().is_symlink()
            || !before.is_file()
            || before.nlink() != 1
            || before.len() != expected.len() as u64
            || before.permissions().mode() & 0o7777 != 0o400
        {
            return Err("Core generation commit evidence is unsafe or invalid.".into());
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let mut file = options
            .open(&path)
            .map_err(|error| format!("Could not open Core generation commit evidence: {error}"))?;
        let opened = file.metadata().map_err(|error| {
            format!("Could not inspect Core generation commit evidence: {error}")
        })?;
        let mut actual = Vec::with_capacity(expected.len());
        Read::by_ref(&mut file)
            .take(expected.len().saturating_add(1) as u64)
            .read_to_end(&mut actual)
            .map_err(|error| format!("Could not read Core generation commit evidence: {error}"))?;
        let after = file.metadata().map_err(|error| {
            format!("Could not recheck Core generation commit evidence: {error}")
        })?;
        let current = fs::symlink_metadata(&path).map_err(|error| {
            format!("Could not recheck published Core generation commit evidence: {error}")
        })?;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || !opened.is_file()
            || opened.nlink() != 1
            || opened.len() != expected.len() as u64
            || opened.permissions().mode() & 0o7777 != 0o400
            || opened.dev() != after.dev()
            || opened.ino() != after.ino()
            || opened.len() != after.len()
            || opened.mtime() != after.mtime()
            || opened.mtime_nsec() != after.mtime_nsec()
            || after.nlink() != 1
            || after.permissions().mode() & 0o7777 != 0o400
            || current.file_type().is_symlink()
            || !current.is_file()
            || current.nlink() != 1
            || current.len() != expected.len() as u64
            || current.permissions().mode() & 0o7777 != 0o400
            || current.dev() != opened.dev()
            || current.ino() != opened.ino()
            || actual != expected
        {
            return Err("Core generation commit evidence changed or does not match.".into());
        }
        Ok(())
    }

    fn require_owned_candidate(&self, candidate: &Path) -> Result<(), String> {
        if !candidate.is_absolute() {
            return Err("Core generation candidate path is not absolute.".into());
        }
        let resolved = fs::canonicalize(candidate)
            .map_err(|error| format!("Could not resolve the Core generation candidate: {error}"))?;
        if resolved != candidate {
            return Err("Core generation candidate path is aliased or linked.".into());
        }
        let parent = resolved
            .parent()
            .ok_or("Core generation candidate has no parent directory.")?;
        if parent != self.root.join("candidates") {
            return Err("Core generation candidate is outside its private cache directory.".into());
        }
        let name = resolved
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("Core generation candidate name is invalid.")?;
        let valid_name = name.strip_prefix("candidate-").and_then(|suffix| {
            let (operation, token) = suffix.rsplit_once('-')?;
            Some(safe_operation_id(operation) && lowercase_hex(token, 64))
        });
        if valid_name != Some(true) {
            return Err("Core generation candidate name is invalid.".into());
        }
        require_directory(&resolved, "Core generation candidate")
    }
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn random_candidate_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .map_err(|error| format!("Could not create a Core candidate identity: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn candidate_lease_bytes(
    candidate_basename: &str,
    identity: FilesystemIdentity,
    reservation_bytes: u64,
) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(&CandidateLeaseDocument {
        candidate_basename,
        device: identity.device,
        inode: identity.inode,
        reservation_bytes,
    })
    .map_err(|error| format!("Could not encode the Core generation candidate lease: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > CANDIDATE_LEASE_LIMIT {
        return Err("Core generation candidate lease exceeds its size limit.".into());
    }
    Ok(bytes)
}

fn generation_commit_marker_bytes(identity: &CoreGenerationIdentity) -> Vec<u8> {
    format!("{}:{}\n", identity.sequence, identity.manifest_sha256).into_bytes()
}

fn require_expected_revision(
    state: &CoreGenerationCacheState,
    expected_revision: u64,
) -> Result<(), String> {
    if state.revision != expected_revision {
        return Err("Core generation cache state changed after this operation began.".into());
    }
    Ok(())
}

fn require_directory(path: &Path, description: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect {description}: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{description} is not a safe directory."));
    }
    Ok(())
}

fn candidate_directory_identity(path: &Path) -> Result<Option<FilesystemIdentity>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "Could not inspect the Core generation candidate identity: {error}"
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Core generation candidate identity is not a safe directory.".into());
    }
    use std::os::unix::fs::MetadataExt as _;
    Ok(Some(FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

fn safe_regular_file(path: &Path) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("Could not inspect Core cache marker: {error}")),
    };
    use std::os::unix::fs::MetadataExt as _;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err("Core generation cache marker is unsafe.".into());
    }
    Ok(true)
}

fn ensure_state_required_marker(root: &Path) -> Result<(), String> {
    let path = root.join(CACHE_STATE_REQUIRED_MARKER);
    if safe_regular_file(&path)? {
        return Ok(());
    }
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(&path)
        .map_err(|error| format!("Could not create Core cache state marker: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("Could not sync Core cache state marker: {error}"))?;
    sync_directory(root)
}

fn set_private_directory_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!("Could not restrict Core generation cache permissions: {error}")
    })?;
    Ok(())
}

fn prepare_candidate_directory(path: &Path, candidates_root: &Path) -> Result<(), String> {
    set_private_directory_permissions(path)?;
    sync_directory(candidates_root)
}

fn remove_new_lease_if_same(
    lease_path: &Path,
    leases_root: &Path,
    expected: FilesystemIdentity,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(lease_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return sync_directory(leases_root),
        Err(error) => {
            return Err(format!(
                "Could not inspect the failed Core generation candidate lease: {error}"
            ));
        }
    };
    use std::os::unix::fs::MetadataExt as _;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
    {
        return Err("Refusing to remove a replacement Core generation candidate lease.".into());
    }
    if lease_path.parent() != Some(leases_root) {
        return Err(
            "Refusing to remove a Core generation candidate lease outside the cache.".into(),
        );
    }
    fs::remove_file(lease_path).map_err(|error| {
        format!("Could not remove failed Core generation candidate lease: {error}")
    })?;
    sync_directory(leases_root)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("Could not sync Core generation cache metadata: {error}"))
}

fn sync_closed_tree(root: &Path) -> Result<(), String> {
    require_directory(root, "Core generation candidate")?;
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        index += 1;
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("Could not inspect Core generation candidate: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("Could not inspect Core generation candidate: {error}"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("Could not inspect Core generation entry: {error}"))?;
            if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                directories.push(entry.path());
            } else if metadata.file_type().is_file() {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    return Err("Core generation candidate contains a multiply linked file.".into());
                }
                let mut options = OpenOptions::new();
                options
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
                let file = options.open(entry.path()).map_err(|error| {
                    format!("Could not safely open Core generation entry: {error}")
                })?;
                let opened = file.metadata().map_err(|error| {
                    format!("Could not identify opened Core generation entry: {error}")
                })?;
                if !opened.is_file()
                    || opened.nlink() != 1
                    || opened.dev() != metadata.dev()
                    || opened.ino() != metadata.ino()
                    || opened.len() != metadata.len()
                {
                    return Err("Core generation entry changed while it was opened.".into());
                }
                file.sync_all()
                    .map_err(|error| format!("Could not sync Core generation entry: {error}"))?;
            } else {
                return Err("Core generation candidate contains a linked or special entry.".into());
            }
        }
    }
    for directory in directories.iter().rev() {
        sync_directory(directory)?;
    }
    Ok(())
}

fn seal_closed_tree(root: &Path) -> Result<(), String> {
    sync_closed_tree(root)?;
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        index += 1;
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("Could not seal Core generation directory: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("Could not seal Core generation entry: {error}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("Could not inspect Core generation entry: {error}"))?;
            if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                directories.push(path);
            } else if metadata.is_file() && !metadata.file_type().is_symlink() {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    return Err("Core generation contains a multiply linked file.".into());
                }
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
                    .map_err(|error| format!("Could not seal Core generation file: {error}"))?;
                File::open(&path)
                    .and_then(|file| file.sync_all())
                    .map_err(|error| format!("Could not sync sealed Core generation: {error}"))?;
            } else {
                return Err("Core generation contains a linked or special entry.".into());
            }
        }
    }
    for directory in directories.iter().rev() {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500))
            .map_err(|error| format!("Could not seal Core generation directory: {error}"))?;
        sync_directory(directory)?;
    }
    Ok(())
}

fn make_tree_removable(root: &Path) -> Result<(), String> {
    require_directory(root, "Core generation candidate")?;
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        index += 1;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Could not unlock Core candidate cleanup: {error}"))?;
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("Could not inspect failed Core candidate: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("Could not inspect failed Core candidate: {error}"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("Could not inspect failed Core candidate: {error}"))?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                directories.push(entry.path());
            } else if metadata.is_file() && !metadata.file_type().is_symlink() {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))
                    .map_err(|error| format!("Could not unlock Core candidate file: {error}"))?;
            }
        }
    }
    Ok(())
}

fn cleanup_candidate_tree(candidate: &Path, candidates_root: &Path) -> Result<(), String> {
    let mut failures = Vec::new();
    if let Err(error) = make_tree_removable(candidate) {
        failures.push(error);
    }
    if let Err(error) = remove_owned_candidate(candidate, candidates_root) {
        failures.push(error);
    }
    if let Err(error) = sync_directory(candidates_root) {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join(" "))
    }
}

fn cleanup_failed_publication(
    destination: &Path,
    generations_root: &Path,
    candidates_root: &Path,
    commit_marker: &Path,
    commits_root: &Path,
) -> Result<(), String> {
    let mut failures = Vec::new();
    // Revoke trust first. A crash after this point can leave an unmarked
    // generation residue, but never evidence that authorizes that residue.
    if let Err(error) = invalidate_commit_marker_path(commit_marker, commits_root) {
        failures.push(error);
    }
    if let Err(error) = make_tree_removable(destination) {
        failures.push(error);
    }
    if let Err(error) = remove_owned_candidate(destination, generations_root) {
        failures.push(error);
    }
    for directory in [generations_root, candidates_root] {
        if let Err(error) = sync_directory(directory) {
            failures.push(error);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join(" "))
    }
}

fn invalidate_commit_marker_path(commit_marker: &Path, commits_root: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(commit_marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return sync_directory(commits_root),
        Err(error) => {
            return Err(format!(
                "Could not inspect stale Core commit evidence: {error}"
            ));
        }
    };
    use std::os::unix::fs::MetadataExt as _;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err("Stale Core commit evidence is unsafe to remove.".into());
    }
    let resolved = fs::canonicalize(commit_marker)
        .map_err(|error| format!("Could not resolve stale Core commit evidence: {error}"))?;
    if resolved != commit_marker || resolved.parent() != Some(commits_root) {
        return Err("Refusing to remove Core commit evidence outside the cache.".into());
    }
    fs::remove_file(commit_marker)
        .map_err(|error| format!("Could not remove stale Core commit evidence: {error}"))?;
    sync_directory(commits_root)
}

fn remove_owned_candidate(candidate: &Path, candidates_root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(candidate)
        .map_err(|error| format!("Could not inspect redundant Core candidate: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Redundant Core candidate is not a safe directory.".into());
    }
    let resolved = fs::canonicalize(candidate)
        .map_err(|error| format!("Could not resolve redundant Core candidate: {error}"))?;
    if resolved != candidate || resolved.parent() != Some(candidates_root) {
        return Err("Refusing to remove a Core candidate outside the cache.".into());
    }
    fs::remove_dir_all(candidate)
        .map_err(|error| format!("Could not remove redundant Core candidate: {error}"))?;
    sync_directory(candidates_root)
}

fn canonical_state_bytes(state: &CoreGenerationCacheState) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(state)
        .map_err(|error| format!("Could not serialize Core generation cache state: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() > CACHE_STATE_LIMIT {
        return Err("Core generation cache state exceeds its size limit.".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_cache(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "opemos-core-generation-cache-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn identity(sequence: u64, byte: char) -> CoreGenerationIdentity {
        let manifest_sha256 = byte.to_string().repeat(64);
        CoreGenerationIdentity {
            sequence,
            generation_id: manifest_sha256.clone(),
            manifest_sha256,
        }
    }

    fn populate(candidate: &Path, value: &str) {
        fs::create_dir(candidate.join("contracts")).unwrap();
        fs::write(candidate.join("contracts/manifest.json"), value).unwrap();
    }

    fn verify_value(expected: &'static str) -> impl Fn(&Path) -> Result<(), String> {
        move |root| {
            let value = fs::read_to_string(root.join("contracts/manifest.json"))
                .map_err(|error| error.to_string())?;
            if value != expected {
                return Err("candidate content mismatch".into());
            }
            Ok(())
        }
    }

    fn cleanup(root: &Path) {
        fn make_writable(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                for entry in fs::read_dir(path).unwrap().flatten() {
                    make_writable(&entry.path());
                }
            } else if metadata.is_file() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        make_writable(root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generation_cache_commits_create_only_and_reuses_only_verified_content() {
        let root = temporary_cache("commit");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = cache.create_candidate("operation-1", 1).unwrap();
        populate(&first, "verified");
        let generation = identity(1, '1');
        assert_eq!(
            cache
                .commit_candidate(&first, &generation, verify_value("verified"))
                .unwrap(),
            GenerationCommit::Installed
        );

        let duplicate = cache.create_candidate("operation-2", 1).unwrap();
        populate(&duplicate, "verified");
        assert_eq!(
            cache
                .commit_candidate(&duplicate, &generation, verify_value("verified"))
                .unwrap(),
            GenerationCommit::AlreadyPresent
        );
        assert!(!duplicate.exists());

        let conflicting = cache.create_candidate("operation-3", 1).unwrap();
        populate(&conflicting, "different");
        assert!(cache
            .commit_candidate(&conflicting, &generation, verify_value("different"))
            .is_err());
        assert!(!conflicting.exists());
        assert_eq!(
            fs::read_to_string(
                root.join("generations")
                    .join(&generation.generation_id)
                    .join("contracts/manifest.json")
            )
            .unwrap(),
            "verified"
        );
        cleanup(&root);
    }

    #[test]
    fn activation_rejects_unmarked_publication_and_verified_retry_recovers_it() {
        let root = temporary_cache("interrupted-publication");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generation = identity(1, 'd');
        let interrupted = cache.create_candidate("interrupted", 1).unwrap();
        populate(&interrupted, "verified");
        let destination = cache.generation_path(&generation).unwrap();
        fs::rename(&interrupted, &destination).unwrap();
        assert!(cache
            .begin_activation(&generation, "unsafe", 0, verify_value("verified"))
            .is_err());

        let retry = cache.create_candidate("retry", 1).unwrap();
        populate(&retry, "verified");
        assert_eq!(
            cache
                .commit_candidate(&retry, &generation, verify_value("verified"))
                .unwrap(),
            GenerationCommit::AlreadyPresent
        );
        cache
            .begin_activation(&generation, "recovered", 0, verify_value("verified"))
            .unwrap();

        let marker = cache.generation_commit_marker_path(&generation).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(cache
            .acknowledge_healthy(&generation, "recovered", 1, verify_value("verified"))
            .is_err());
        cleanup(&root);
    }

    #[test]
    fn stale_marker_is_revoked_before_a_fresh_publication_is_exposed() {
        let root = temporary_cache("stale-marker");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generation = identity(2, 'e');
        let original = cache.create_candidate("original", 1).unwrap();
        populate(&original, "verified");
        cache
            .commit_candidate(&original, &generation, verify_value("verified"))
            .unwrap();
        let destination = cache.generation_path(&generation).unwrap();
        let marker = cache.generation_commit_marker_path(&generation).unwrap();
        assert!(marker.is_file());

        make_tree_removable(&destination).unwrap();
        remove_owned_candidate(&destination, &cache.root.join("generations")).unwrap();
        assert!(marker.is_file());
        let interrupted = cache.create_candidate("fresh", 1).unwrap();
        populate(&interrupted, "verified");
        cache
            .invalidate_generation_commit_marker(&generation)
            .unwrap();
        assert!(!marker.exists());
        fs::rename(&interrupted, &destination).unwrap();
        assert!(cache
            .begin_activation(&generation, "unsafe", 0, verify_value("verified"))
            .is_err());
        cleanup(&root);
    }

    #[test]
    fn failed_candidate_staging_cleans_partial_data_without_changing_state() {
        let root = temporary_cache("staging-failure");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generation = identity(1, 'c');
        for (operation, reason) in [
            ("cancelled", "generation download cancelled"),
            ("no-space", "generation staging ran out of space"),
        ] {
            let error = cache
                .stage_candidate(
                    operation,
                    1,
                    &generation,
                    |candidate| {
                        populate(candidate, "partial");
                        Err(reason.into())
                    },
                    verify_value("complete"),
                )
                .unwrap_err();
            assert!(error.contains(reason));
            assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
            assert_eq!(
                cache.load_state().unwrap(),
                CoreGenerationCacheState::default()
            );
        }

        let verify_calls = AtomicU64::new(0);
        let error = cache
            .stage_candidate(
                "late-verification",
                1,
                &generation,
                |candidate| {
                    populate(candidate, "complete");
                    Ok(())
                },
                |candidate| {
                    verify_value("complete")(candidate)?;
                    if verify_calls.fetch_add(1, Ordering::Relaxed) < 2 {
                        Ok(())
                    } else {
                        Err("late verification failed".into())
                    }
                },
            )
            .unwrap_err();
        assert!(error.contains("late verification failed"));
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.join("generations")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.join("commits")).unwrap().count(), 0);

        assert_eq!(
            cache
                .stage_candidate(
                    "complete",
                    1,
                    &generation,
                    |candidate| {
                        populate(candidate, "complete");
                        Ok(())
                    },
                    verify_value("complete"),
                )
                .unwrap(),
            GenerationCommit::Installed
        );
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(
            cache.load_state().unwrap(),
            CoreGenerationCacheState::default()
        );
        cleanup(&root);
    }

    #[test]
    fn candidate_creation_failure_after_mkdir_is_transactional_and_retryable() {
        let root = temporary_cache("create-failure");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let error = cache
            .create_candidate_with_prepare(
                "retryable",
                1,
                |_candidate, _parent| Err("synthetic post-mkdir metadata failure".into()),
                |_lease_path| Ok(()),
            )
            .unwrap_err();
        assert!(error.contains("synthetic post-mkdir metadata failure"));
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);

        let retry = cache.create_candidate("retryable", 1).unwrap();
        assert!(retry.is_dir());
        cleanup(&root);
    }

    #[test]
    fn candidate_creation_failure_after_lease_open_removes_both_resources() {
        let root = temporary_cache("lease-open-failure");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let error = cache
            .create_candidate_with_prepare(
                "retryable",
                1,
                prepare_candidate_directory,
                |_lease_path| Err("synthetic post-open lease failure".into()),
            )
            .unwrap_err();
        assert!(error.contains("synthetic post-open lease failure"));
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.join("leases")).unwrap().count(), 0);

        let retry = cache.create_candidate("retryable", 1).unwrap();
        cache.abort_candidate(&retry).unwrap();
        cleanup(&root);
    }

    #[test]
    fn candidate_lease_is_private_locked_and_binds_exact_reservation_and_identity() {
        let root = temporary_cache("lease-binding");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let reservation = 123_456;
        let lease = cache.create_candidate("bound", reservation).unwrap();
        let basename = lease.path().file_name().unwrap().to_str().unwrap();
        let expected =
            candidate_lease_bytes(basename, lease.candidate_identity, reservation).unwrap();
        assert_eq!(fs::read(&lease.lease_path).unwrap(), expected);
        let metadata = fs::symlink_metadata(&lease.lease_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(metadata.nlink(), 1);
        let competing = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lease.lease_path)
            .unwrap();
        assert!(matches!(
            competing.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        cache.abort_candidate(&lease).unwrap();
        assert!(!lease.lease_path.exists());
        cleanup(&root);
    }

    #[test]
    fn candidate_lease_mode_and_content_tampering_fail_closed() {
        let root = temporary_cache("lease-tamper");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("tamper", 7).unwrap();
        fs::set_permissions(&lease.lease_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(cache.abort_candidate(&lease).is_err());
        assert!(lease.path().exists());
        fs::set_permissions(&lease.lease_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&lease.lease_path, b"{}\n").unwrap();
        assert!(cache.abort_candidate(&lease).is_err());
        assert!(lease.path().exists());
        fs::write(&lease.lease_path, &lease.expected_bytes).unwrap();
        cache.abort_candidate(&lease).unwrap();
        cleanup(&root);
    }

    #[test]
    fn hard_linked_candidate_lease_is_rejected_without_deleting_it() {
        let root = temporary_cache("lease-hard-link");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("hard-link", 9).unwrap();
        let external = root.parent().unwrap().join(format!(
            "opemos-core-lease-hard-link-{}",
            std::process::id()
        ));
        fs::hard_link(&lease.lease_path, &external).unwrap();
        assert!(cache.abort_candidate(&lease).is_err());
        assert!(lease.path().exists());
        assert!(lease.lease_path.exists());
        fs::remove_file(&external).unwrap();
        cache.abort_candidate(&lease).unwrap();
        cleanup(&root);
    }

    #[test]
    fn candidate_identity_replacement_is_not_removed_by_its_old_lease() {
        let root = temporary_cache("lease-candidate-replacement");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("replacement", 11).unwrap();
        fs::remove_dir(lease.path()).unwrap();
        fs::create_dir(lease.path()).unwrap();
        fs::set_permissions(lease.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(cache.abort_candidate(&lease).is_err());
        assert!(lease.path().exists());
        assert!(lease.lease_path.exists());
        fs::remove_dir(lease.path()).unwrap();
        fs::remove_file(&lease.lease_path).unwrap();
        cleanup(&root);
    }

    #[test]
    fn dropping_candidate_lease_only_unlocks_and_preserves_residue() {
        let root = temporary_cache("lease-drop");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("abandoned", 13).unwrap();
        let candidate = lease.path().to_path_buf();
        let sidecar = lease.lease_path.clone();
        drop(lease);
        assert!(candidate.is_dir());
        assert!(sidecar.is_file());
        cleanup(&root);
    }

    #[test]
    fn same_operation_retries_use_distinct_lease_targets() {
        let root = temporary_cache("stale-cleanup");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let original = cache.create_candidate("shared-operation", 1).unwrap();
        let original_path = original.path().to_path_buf();
        let original_lease_path = original.lease_path.clone();
        cache.abort_candidate(&original).unwrap();

        let replacement = cache.create_candidate("shared-operation", 1).unwrap();
        let replacement_identity = candidate_directory_identity(&replacement).unwrap().unwrap();
        assert_ne!(original_path, replacement.path());
        assert_ne!(original_lease_path, replacement.lease_path);
        assert_eq!(
            candidate_directory_identity(&replacement).unwrap(),
            Some(replacement_identity)
        );
        cache.abort_candidate(&replacement).unwrap();
        cleanup(&root);
    }

    #[test]
    fn concurrent_generation_commits_preserve_one_verified_identity() {
        use std::sync::{Arc, Barrier};

        let root = temporary_cache("concurrent-commit");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = cache.create_candidate("concurrent-1", 1).unwrap();
        let second = cache.create_candidate("concurrent-2", 1).unwrap();
        populate(&first, "shared");
        populate(&second, "shared");
        let generation = identity(5, '5');
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for candidate in [first, second] {
            let cache = cache.clone();
            let generation = generation.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                cache.commit_candidate(&candidate, &generation, verify_value("shared"))
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == GenerationCommit::Installed)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == GenerationCommit::AlreadyPresent)
                .count(),
            1
        );
        cleanup(&root);
    }

    #[test]
    fn health_acknowledgement_is_atomic_and_preserves_last_known_good() {
        let root = temporary_cache("activation");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = identity(1, '2');
        let second = identity(2, '4');
        for (operation, generation, value) in
            [("first", &first, "first"), ("second", &second, "second")]
        {
            let candidate = cache.create_candidate(operation, 1).unwrap();
            populate(&candidate, value);
            cache
                .commit_candidate(&candidate, generation, verify_value(value))
                .unwrap();
        }

        cache
            .begin_activation(&first, "activate-first", 0, verify_value("first"))
            .unwrap();
        let state = cache
            .acknowledge_healthy(&first, "activate-first", 1, verify_value("first"))
            .unwrap();
        assert_eq!(state.active.as_ref(), Some(&first));
        assert_eq!(state.high_water_sequence, 1);
        assert!(state.last_known_good.is_none());

        let pending = cache
            .begin_activation(&second, "activate-second", 2, verify_value("second"))
            .unwrap();
        assert_eq!(pending.active.as_ref(), Some(&first));
        assert_eq!(pending.pending.as_ref(), Some(&second));
        let rejected = cache.reject_pending(&second, "activate-second", 3).unwrap();
        assert_eq!(rejected.active.as_ref(), Some(&first));
        assert!(rejected.pending.is_none());

        cache
            .begin_activation(&second, "retry-second", 4, verify_value("second"))
            .unwrap();
        let active = cache
            .acknowledge_healthy(&second, "retry-second", 5, verify_value("second"))
            .unwrap();
        assert_eq!(active.active.as_ref(), Some(&second));
        assert_eq!(active.high_water_sequence, 2);
        assert_eq!(active.last_known_good.as_ref(), Some(&first));
        let rolled_back = cache
            .rollback_to_last_known_good(&second, 6, verify_value("first"))
            .unwrap();
        assert_eq!(rolled_back.active.as_ref(), Some(&first));
        assert_eq!(rolled_back.last_known_good.as_ref(), Some(&first));
        assert_eq!(rolled_back.high_water_sequence, 2);
        assert!(cache
            .begin_activation(
                &second,
                "replay-second",
                rolled_back.revision,
                verify_value("second")
            )
            .is_err());

        let third = identity(3, '6');
        let candidate = cache.create_candidate("third", 1).unwrap();
        populate(&candidate, "third");
        cache
            .commit_candidate(&candidate, &third, verify_value("third"))
            .unwrap();
        cache
            .begin_activation(
                &third,
                "activate-third",
                rolled_back.revision,
                verify_value("third"),
            )
            .unwrap();
        let later = cache
            .acknowledge_healthy(
                &third,
                "activate-third",
                rolled_back.revision + 1,
                verify_value("third"),
            )
            .unwrap();
        assert_eq!(later.active.as_ref(), Some(&third));
        assert_eq!(later.last_known_good.as_ref(), Some(&first));
        assert_eq!(later.high_water_sequence, 3);
        cleanup(&root);
    }

    #[test]
    fn invalid_state_and_unsafe_candidates_fail_without_changing_active_state() {
        let root = temporary_cache("failure");
        let cache = CoreGenerationCache::open(&root).unwrap();
        assert!(cache.create_candidate("../escape", 1).is_err());
        assert!(cache.create_candidate("invalid-reservation", 0).is_err());
        assert!(cache
            .create_candidate("invalid-reservation", MAX_GENERATION_BYTES + 1)
            .is_err());

        fs::write(root.join("state.json"), b"{\"schemaVersion\":1}\n").unwrap();
        assert!(cache.load_state().is_err());
        fs::remove_file(root.join("state.json")).unwrap();
        let state = cache.load_state().unwrap();
        assert!(state.active.is_none());
        cleanup(&root);
    }

    #[test]
    fn stale_activation_operations_cannot_replace_pending_user_intent() {
        let root = temporary_cache("stale-operation");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = identity(1, '1');
        let second = identity(2, '3');
        for (operation, generation, value) in
            [("first", &first, "first"), ("second", &second, "second")]
        {
            let candidate = cache.create_candidate(operation, 1).unwrap();
            populate(&candidate, value);
            cache
                .commit_candidate(&candidate, generation, verify_value(value))
                .unwrap();
        }
        cache
            .begin_activation(&first, "activate-first", 0, verify_value("first"))
            .unwrap();
        assert!(cache
            .begin_activation(&second, "activate-second", 1, verify_value("second"))
            .is_err());
        assert!(cache
            .acknowledge_healthy(&first, "stale-worker", 1, verify_value("first"))
            .is_err());
        assert!(cache.reject_pending(&first, "stale-worker", 1).is_err());
        let state = cache.load_state().unwrap();
        assert_eq!(state.pending.as_ref(), Some(&first));
        assert_eq!(
            state.pending_operation_id.as_deref(),
            Some("activate-first")
        );
        cache
            .reject_pending(&first, "activate-first", state.revision)
            .unwrap();
        cache
            .begin_activation(&second, "activate-second", 2, verify_value("second"))
            .unwrap();
        cache
            .acknowledge_healthy(&second, "activate-second", 3, verify_value("second"))
            .unwrap();
        assert!(cache
            .begin_activation(&first, "activate-first", 0, verify_value("first"))
            .is_err());
        assert!(cache
            .rollback_to_last_known_good(&first, 1, verify_value("first"))
            .is_err());
        assert_eq!(cache.load_state().unwrap().active.as_ref(), Some(&second));
        cleanup(&root);
    }

    #[test]
    fn malformed_relational_state_is_rejected() {
        let root = temporary_cache("relational-state");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let state = CoreGenerationCacheState {
            schema_version: CACHE_STATE_SCHEMA,
            kind: CACHE_STATE_KIND.into(),
            revision: 1,
            high_water_sequence: 0,
            active: None,
            pending: None,
            pending_operation_id: None,
            last_known_good: Some(identity(1, '2')),
        };
        fs::write(
            root.join("state.json"),
            canonical_state_bytes(&state).unwrap(),
        )
        .unwrap();
        assert!(cache.load_state().is_err());
        cleanup(&root);
    }

    #[test]
    fn durable_identity_and_high_water_invariants_fail_closed() {
        let root = temporary_cache("durable-invariants");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let mut mismatched = identity(1, '2');
        mismatched.generation_id = "3".repeat(64);
        assert!(mismatched.validate().is_err());

        let active = identity(2, '4');
        let replay = identity(2, '5');
        let state = CoreGenerationCacheState {
            schema_version: CACHE_STATE_SCHEMA,
            kind: CACHE_STATE_KIND.into(),
            revision: 1,
            high_water_sequence: 2,
            active: Some(active),
            pending: Some(replay),
            pending_operation_id: Some("replay".into()),
            last_known_good: None,
        };
        fs::write(
            root.join("state.json"),
            canonical_state_bytes(&state).unwrap(),
        )
        .unwrap();
        assert!(cache.load_state().is_err());

        let impossible_fallback = CoreGenerationCacheState {
            schema_version: CACHE_STATE_SCHEMA,
            kind: CACHE_STATE_KIND.into(),
            revision: 2,
            high_water_sequence: 3,
            active: Some(identity(2, '4')),
            pending: None,
            pending_operation_id: None,
            last_known_good: Some(identity(3, '6')),
        };
        fs::write(
            root.join("state.json"),
            canonical_state_bytes(&impossible_fallback).unwrap(),
        )
        .unwrap();
        assert!(cache.load_state().is_err());
        cleanup(&root);
    }

    #[test]
    fn activated_cache_rejects_deleted_state_and_committed_files_are_sealed() {
        let root = temporary_cache("state-loss");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let identity = identity(1, 'a');
        let candidate = cache.create_candidate("activate", 1).unwrap();
        populate(&candidate, "sealed");
        cache
            .commit_candidate(&candidate, &identity, verify_value("sealed"))
            .unwrap();
        let committed = root
            .join("generations")
            .join(&identity.generation_id)
            .join("contracts/manifest.json");
        assert_eq!(
            fs::metadata(&committed).unwrap().permissions().mode() & 0o777,
            0o400
        );
        cache
            .begin_activation(&identity, "activate", 0, verify_value("sealed"))
            .unwrap();
        cache
            .acknowledge_healthy(&identity, "activate", 1, verify_value("sealed"))
            .unwrap();
        fs::remove_file(root.join("state.json")).unwrap();
        assert!(cache.load_state().is_err());
        cleanup(&root);
    }

    #[cfg(unix)]
    #[test]
    fn linked_cache_root_and_state_are_rejected() {
        use std::os::unix::fs::symlink;

        let actual = temporary_cache("actual-root");
        fs::create_dir(&actual).unwrap();
        let alias = temporary_cache("root-alias");
        symlink(&actual, &alias).unwrap();
        assert!(CoreGenerationCache::open(&alias).is_err());
        fs::remove_file(&alias).unwrap();

        let cache = CoreGenerationCache::open(&actual).unwrap();
        let external = actual
            .parent()
            .unwrap()
            .join(format!("opemos-core-state-external-{}", std::process::id()));
        fs::write(&external, vec![b'x'; CACHE_STATE_LIMIT + 1]).unwrap();
        symlink(&external, actual.join("state.json")).unwrap();
        assert!(cache.load_state().is_err());
        fs::remove_file(actual.join("state.json")).unwrap();
        fs::remove_file(external).unwrap();

        let state_path = actual.join("state.json");
        fs::write(
            &state_path,
            canonical_state_bytes(&CoreGenerationCacheState::default()).unwrap(),
        )
        .unwrap();
        let alias = actual.parent().unwrap().join(format!(
            "opemos-core-state-hard-link-{}",
            std::process::id()
        ));
        fs::hard_link(&state_path, &alias).unwrap();
        assert!(cache.load_state().is_err());
        fs::remove_file(alias).unwrap();
        cleanup(&actual);
    }

    #[cfg(unix)]
    #[test]
    fn linked_generation_content_is_rejected_before_commit() {
        use std::os::unix::fs::symlink;

        let root = temporary_cache("symlink");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let candidate = cache.create_candidate("linked", 1).unwrap();
        symlink("/tmp", candidate.join("escape")).unwrap();
        assert!(cache
            .commit_candidate(&candidate, &identity(8, '8'), |_| Ok(()))
            .is_err());
        assert!(!candidate.exists());
        cleanup(&root);
    }

    #[test]
    fn hard_linked_generation_content_is_rejected_before_commit() {
        let root = temporary_cache("hard-link");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let candidate = cache.create_candidate("hard-linked", 1).unwrap();
        let external = root.parent().unwrap().join(format!(
            "opemos-core-hard-link-external-{}",
            std::process::id()
        ));
        fs::write(&external, "mutable-outside-cache").unwrap();
        fs::hard_link(&external, candidate.join("linked-file")).unwrap();
        assert!(cache
            .commit_candidate(&candidate, &identity(7, '7'), |_| Ok(()))
            .is_err());
        assert_eq!(
            fs::read_to_string(&external).unwrap(),
            "mutable-outside-cache"
        );
        fs::remove_file(external).unwrap();
        cleanup(&root);
    }
}
