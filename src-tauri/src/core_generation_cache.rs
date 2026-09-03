use crate::core_generation_contracts::{
    MAX_FILES, MAX_GENERATION_STORAGE_BYTES, MAX_LINEAGE_GENERATIONS,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
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
static STATE_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static CACHE_TRANSACTION_LOCK: Mutex<()> = Mutex::new(());
const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_LOCK_RETRY: Duration = Duration::from_millis(20);
const CANDIDATE_LEASE_LIMIT: u64 = 1024;
const CACHE_DIRECTORY_ENTRY_LIMIT: usize = MAX_FILES + MAX_LINEAGE_GENERATIONS + 256;
const MAX_TREE_DEPTH: usize = 64;
const MAX_TREE_NODES: usize = MAX_FILES * 2 + 1;
const MAX_GENERATION_STORAGE_FILES: usize = MAX_FILES + 5;
const MAX_RETAINED_GENERATIONS: usize = 4;
const MAX_TOTAL_GENERATION_BYTES: u64 =
    MAX_GENERATION_STORAGE_BYTES * MAX_RETAINED_GENERATIONS as u64;
const TOMBSTONE_BATCH_OPERATIONS: usize = 256;

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
    root_file: Arc<File>,
    root_identity: FilesystemIdentity,
    lock_identity: FilesystemIdentity,
    trash_identity: FilesystemIdentity,
}

struct CoreGenerationCacheLock {
    file: File,
}

#[derive(Debug)]
pub(crate) struct CandidateLease {
    candidate: PathBuf,
    candidate_identity: FilesystemIdentity,
    candidate_file: File,
    lease_path: PathBuf,
    lease_identity: FilesystemIdentity,
    lease_file: File,
    expected_bytes: Vec<u8>,
    reservation_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateLeaseDocument<'a> {
    candidate_basename: &'a str,
    device: u64,
    inode: u64,
    reservation_bytes: u64,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedCandidateLeaseDocument {
    candidate_basename: String,
    device: u64,
    inode: u64,
    reservation_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CacheReconciliationReport {
    pub(crate) removed_candidates: usize,
    pub(crate) removed_leases: usize,
    pub(crate) removed_state_temporaries: usize,
    pub(crate) removed_commit_temporaries: usize,
    pub(crate) removed_generations: usize,
    pub(crate) removed_commit_markers: usize,
    pub(crate) live_candidates: usize,
    pub(crate) retained_generations: usize,
    pub(crate) protected_over_budget: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TreeUsage {
    nodes: usize,
    files: usize,
    logical_bytes: u64,
}

struct CommitInventory {
    markers: BTreeMap<String, PathBuf>,
    temporaries: Vec<(PathBuf, FilesystemIdentity)>,
}

struct ReconciliationLease {
    path: PathBuf,
    identity: FilesystemIdentity,
    file: File,
    document: OwnedCandidateLeaseDocument,
}

enum ReconciliationLeaseState {
    Live {
        document: OwnedCandidateLeaseDocument,
    },
    Acquired(ReconciliationLease),
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

    pub(crate) fn create_file(&self, name: &str) -> std::io::Result<File> {
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || name.as_bytes().contains(&b'/')
            || name.as_bytes().contains(&0)
        {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Core generation staged filename is unsafe.",
            ));
        }
        self.require_bound_candidate_file()
            .map_err(std::io::Error::other)?;
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                "Core generation staged filename is unsafe.",
            )
        })?;
        let descriptor = unsafe {
            libc::openat(
                self.candidate_file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        self.require_bound_candidate_file()
            .map_err(std::io::Error::other)?;
        Ok(file)
    }

    fn require_bound_candidate_file(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;
        let opened = self.candidate_file.metadata().map_err(|error| {
            format!("Could not identify leased Core generation candidate: {error}")
        })?;
        let path = candidate_directory_identity(&self.candidate)?
            .ok_or("Leased Core generation candidate disappeared.")?;
        if !opened.is_dir()
            || opened.dev() != self.candidate_identity.device
            || opened.ino() != self.candidate_identity.inode
            || path != self.candidate_identity
        {
            return Err("Leased Core generation candidate identity changed.".into());
        }
        Ok(())
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
        for child in ["candidates", "generations", "commits", "leases", "trash"] {
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
        root_handle
            .sync_all()
            .map_err(|error| format!("Could not sync the Core generation cache: {error}"))?;
        let trash_identity = candidate_directory_identity(&root.join("trash"))?
            .ok_or("Core generation trash directory disappeared during creation.")?;
        let root_identity = FilesystemIdentity {
            device: opened.dev(),
            inode: opened.ino(),
        };
        require_bound_root(&root, &root_handle, root_identity)?;
        let (initial_lock, lock_identity) = acquire_bound_cache_lock(
            &root_handle,
            &root.join("cache.lock"),
            None,
            |_| Ok(()),
            |_| Ok(()),
        )?;
        root_handle
            .sync_all()
            .map_err(|error| format!("Could not sync the Core generation cache lock: {error}"))?;
        drop(initial_lock);
        Ok(Self {
            root,
            root_file: Arc::new(root_handle),
            root_identity,
            lock_identity,
            trash_identity,
        })
    }

    fn acquire_lock(&self) -> Result<CoreGenerationCacheLock, String> {
        self.acquire_lock_with_hooks(|_| Ok(()), |_| Ok(()))
    }

    fn acquire_lock_with_hooks(
        &self,
        before_lock: impl FnOnce(&Path) -> Result<(), String>,
        after_lock: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<CoreGenerationCacheLock, String> {
        require_bound_root(&self.root, &self.root_file, self.root_identity)?;
        let (guard, identity) = acquire_bound_cache_lock(
            &self.root_file,
            &self.root.join("cache.lock"),
            Some(self.lock_identity),
            before_lock,
            after_lock,
        )?;
        if identity != self.lock_identity {
            return Err("Core generation cache lock identity changed.".into());
        }
        require_bound_root(&self.root, &self.root_file, self.root_identity)?;
        Ok(guard)
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
        if !(1..=MAX_GENERATION_STORAGE_BYTES).contains(&reservation_bytes) {
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
            let mut candidate_options = OpenOptions::new();
            candidate_options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let candidate_file = candidate_options.open(&path).map_err(|error| {
                format!("Could not pin the Core generation candidate directory: {error}")
            })?;
            let opened_candidate = candidate_file.metadata().map_err(|error| {
                format!("Could not identify the opened Core generation candidate: {error}")
            })?;
            use std::os::unix::fs::MetadataExt as _;
            if opened_candidate.dev() != candidate_identity.device
                || opened_candidate.ino() != candidate_identity.inode
            {
                return Err("Core generation candidate changed while opening.".into());
            }
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
                candidate_file,
                lease_path,
                lease_identity,
                lease_file,
                expected_bytes,
                reservation_bytes,
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
        let candidates_root = self.root.join("candidates");
        match scan_bounded_tree(&lease.candidate, "aborted Core generation candidate") {
            Err(error) if bounded_scan_limit(&error) => quarantine_directory(
                &lease.candidate,
                &candidates_root,
                &self.root.join("trash"),
                lease.candidate_identity,
                self.trash_identity,
            )?,
            _ => cleanup_candidate_tree(&lease.candidate, &candidates_root)?,
        }
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
        let result = identity.validate().and_then(|()| {
            self.commit_candidate_locked(candidate, lease.reservation_bytes, identity, verify)
        });
        match result {
            Ok(outcome) => {
                self.remove_candidate_lease(lease)?;
                Ok(outcome)
            }
            Err(error) => {
                let candidate_cleanup = match candidate_directory_identity(candidate) {
                    Ok(Some(_)) => self.require_valid_candidate_lease(lease).and_then(|()| {
                        if bounded_scan_limit(&error) {
                            quarantine_directory(
                                candidate,
                                &self.root.join("candidates"),
                                &self.root.join("trash"),
                                lease.candidate_identity,
                                self.trash_identity,
                            )
                        } else {
                            cleanup_candidate_tree(candidate, &self.root.join("candidates"))
                        }
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
        reservation_bytes: u64,
        identity: &CoreGenerationIdentity,
        verify: impl Fn(&Path) -> Result<(), String>,
    ) -> Result<GenerationCommit, String> {
        let usage = scan_bounded_tree(candidate, "Core generation candidate")?;
        if usage.logical_bytes > reservation_bytes {
            return Err("Core generation candidate exceeds its reserved size.".into());
        }
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

    pub(crate) fn reconcile(&self) -> Result<CacheReconciliationReport, String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;

        // State is the authority for retention. It must be loaded before any
        // residue is inspected or removed.
        let state = self.load_state_unlocked()?;
        let mut protected = BTreeMap::<String, CoreGenerationIdentity>::new();
        for identity in [
            state.active.as_ref(),
            state.pending.as_ref(),
            state.last_known_good.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(existing) =
                protected.insert(identity.generation_id.clone(), identity.clone())
            {
                if existing != *identity {
                    return Err(
                        "Core generation cache state reuses an identity inconsistently.".into(),
                    );
                }
            }
        }

        let root_temporaries = validate_cache_root_inventory(&self.root)?;
        let candidates_root = self.root.join("candidates");
        let leases_root = self.root.join("leases");
        let generations_root = self.root.join("generations");
        let commits_root = self.root.join("commits");
        let trash_root = self.root.join("trash");
        let candidates = inventory_candidate_directories(&candidates_root)?;
        let leases = inventory_lease_files(&leases_root)?;
        let generations = inventory_generation_directories(&generations_root)?;
        let CommitInventory {
            markers,
            temporaries: commit_temporaries,
        } = inventory_commit_files(&commits_root)?;
        let tombstones = inventory_tombstones(&trash_root)?;

        for (name, identity) in &protected {
            if !generations.contains_key(name) {
                return Err(format!(
                    "Protected Core generation {} is missing from the cache.",
                    identity.generation_id
                ));
            }
            if !markers.contains_key(name) {
                return Err(format!(
                    "Protected Core generation {} has no durable commit evidence.",
                    identity.generation_id
                ));
            }
            self.require_generation_committed(identity)
                .map_err(|error| {
                    format!("Protected Core generation commit evidence is invalid: {error}")
                })?;
        }
        clean_tombstones_bounded(&tombstones, &trash_root, self.trash_identity)?;

        let mut generation_usage = BTreeMap::new();
        let mut generation_tombstones = BTreeSet::new();
        let mut protected_bytes = 0_u64;
        for (name, (path, _identity)) in &generations {
            let usage = match scan_bounded_tree(path, "cached Core generation") {
                Ok(usage) => usage,
                Err(error) if !protected.contains_key(name) && bounded_scan_limit(&error) => {
                    generation_tombstones.insert(name.clone());
                    continue;
                }
                Err(error) => return Err(error),
            };
            if protected.contains_key(name) {
                if usage.logical_bytes > MAX_GENERATION_STORAGE_BYTES {
                    return Err("Protected Core generation exceeds its size bound.".into());
                }
                protected_bytes = protected_bytes
                    .checked_add(usage.logical_bytes)
                    .ok_or("Protected Core generation byte count overflowed.")?;
            }
            generation_usage.insert(name.clone(), usage);
        }

        // Acquire abandoned leases without ever waiting. A contended lease is
        // live and its candidate is deliberately not traversed.
        let mut live = BTreeSet::new();
        let mut acquired = BTreeMap::new();
        let mut live_reservation_bytes = 0_u64;
        let mut removable_candidate_bytes = 0_u64;
        for (name, path) in &leases {
            match inspect_reconciliation_lease(path, name)? {
                ReconciliationLeaseState::Live { document } => {
                    let Some((_candidate, identity)) = candidates.get(name) else {
                        return Err("A live Core generation lease has no candidate.".into());
                    };
                    if document.device != identity.device || document.inode != identity.inode {
                        return Err(
                            "A live Core generation lease does not bind its candidate.".into()
                        );
                    }
                    live_reservation_bytes = live_reservation_bytes
                        .checked_add(document.reservation_bytes)
                        .ok_or("Core generation candidate reservation count overflowed.")?;
                    live.insert(name.clone());
                }
                ReconciliationLeaseState::Acquired(lease) => {
                    acquired.insert(name.clone(), lease);
                }
            }
        }

        let mut abandoned_candidates = Vec::new();
        let mut candidate_tombstones = BTreeSet::new();
        for (name, (path, identity)) in &candidates {
            if live.contains(name) {
                continue;
            }
            if let Some(lease) = acquired.get(name) {
                if lease.document.candidate_basename != *name
                    || lease.document.device != identity.device
                    || lease.document.inode != identity.inode
                {
                    return Err(
                        "Core generation candidate lease does not match its candidate.".into(),
                    );
                }
            }
            match scan_bounded_tree(path, "abandoned Core generation candidate") {
                Ok(usage) => {
                    removable_candidate_bytes = removable_candidate_bytes
                        .checked_add(usage.logical_bytes)
                        .ok_or("Core generation candidate byte count overflowed.")?;
                }
                Err(error) if bounded_scan_limit(&error) => {
                    candidate_tombstones.insert(name.clone());
                }
                Err(error) => return Err(error),
            }
            abandoned_candidates.push(name.clone());
        }
        let _observed_candidate_bytes = live_reservation_bytes
            .checked_add(removable_candidate_bytes)
            .ok_or("Core generation candidate total accounting overflowed.")?;

        let mut report = CacheReconciliationReport {
            live_candidates: live.len(),
            protected_over_budget: protected.len() > MAX_RETAINED_GENERATIONS
                || protected_bytes > MAX_TOTAL_GENERATION_BYTES,
            ..CacheReconciliationReport::default()
        };

        for name in abandoned_candidates {
            let (candidate, expected_identity) = &candidates[&name];
            require_current_directory_identity(
                candidate,
                *expected_identity,
                "abandoned Core generation candidate",
            )?;
            if candidate_tombstones.contains(&name) {
                quarantine_directory(
                    candidate,
                    &candidates_root,
                    &trash_root,
                    *expected_identity,
                    self.trash_identity,
                )?;
            } else {
                cleanup_candidate_tree(candidate, &candidates_root)?;
            }
            report.removed_candidates += 1;
            if let Some(lease) = acquired.remove(&name) {
                remove_acquired_lease(lease, &leases_root)?;
                report.removed_leases += 1;
            }
        }
        for (_, lease) in acquired {
            // Exact canonical sidecars with no candidate are unlocked orphans.
            remove_acquired_lease(lease, &leases_root)?;
            report.removed_leases += 1;
        }

        for (temporary, identity) in root_temporaries {
            remove_safe_regular_file(
                &temporary,
                &self.root,
                identity,
                "stale Core state temporary",
            )?;
            report.removed_state_temporaries += 1;
        }
        if report.removed_state_temporaries != 0 {
            sync_directory(&self.root)?;
        }
        for (temporary, identity) in commit_temporaries {
            remove_safe_regular_file(
                &temporary,
                &commits_root,
                identity,
                "stale Core commit temporary",
            )?;
            report.removed_commit_temporaries += 1;
        }
        if report.removed_commit_temporaries != 0 {
            sync_directory(&commits_root)?;
        }

        for (name, marker) in &markers {
            if !generations.contains_key(name) {
                invalidate_commit_marker_path(marker, &commits_root)?;
                report.removed_commit_markers += 1;
            }
        }
        let mut valid_pairs = BTreeMap::<String, CoreGenerationIdentity>::new();
        for (name, (generation, expected_identity)) in &generations {
            if generation_tombstones.contains(name) {
                if let Some(marker) = markers.get(name) {
                    invalidate_commit_marker_path(marker, &commits_root)?;
                    report.removed_commit_markers += 1;
                }
                quarantine_directory(
                    generation,
                    &generations_root,
                    &trash_root,
                    *expected_identity,
                    self.trash_identity,
                )?;
                report.removed_generations += 1;
                continue;
            }
            if generation_usage[name].logical_bytes > MAX_GENERATION_STORAGE_BYTES {
                if protected.contains_key(name) {
                    return Err("A protected Core generation exceeds its size bound.".into());
                }
                if let Some(marker) = markers.get(name) {
                    invalidate_commit_marker_path(marker, &commits_root)?;
                    report.removed_commit_markers += 1;
                }
                require_current_directory_identity(
                    generation,
                    *expected_identity,
                    "oversized Core generation residue",
                )?;
                cleanup_candidate_tree(generation, &generations_root)?;
                report.removed_generations += 1;
                continue;
            }
            let Some(marker) = markers.get(name) else {
                if protected.contains_key(name) {
                    return Err("A protected Core generation lost its commit evidence.".into());
                }
                require_current_directory_identity(
                    generation,
                    *expected_identity,
                    "unmarked Core generation",
                )?;
                cleanup_candidate_tree(generation, &generations_root)?;
                report.removed_generations += 1;
                continue;
            };
            let valid = read_commit_marker_identity(marker, name).and_then(|identity| {
                self.require_generation_committed(&identity)?;
                Ok(identity)
            });
            if let Ok(identity) = valid {
                valid_pairs.insert(name.clone(), identity);
            } else {
                if protected.contains_key(name) {
                    return Err("A protected Core generation has invalid commit evidence.".into());
                }
                invalidate_commit_marker_path(marker, &commits_root)?;
                report.removed_commit_markers += 1;
                require_current_directory_identity(
                    generation,
                    *expected_identity,
                    "invalid Core generation",
                )?;
                cleanup_candidate_tree(generation, &generations_root)?;
                report.removed_generations += 1;
            }
        }

        let mut sequences = BTreeMap::<u64, String>::new();
        for (name, identity) in &valid_pairs {
            if let Some(existing) = sequences.insert(identity.sequence, name.clone()) {
                if existing != *name {
                    return Err(
                        "Distinct committed Core generations reuse the same sequence.".into(),
                    );
                }
            }
        }

        let protected_and_live_bytes = protected_bytes
            .checked_add(live_reservation_bytes)
            .ok_or("Protected Core generation footprint overflowed.")?;
        if protected_and_live_bytes > MAX_TOTAL_GENERATION_BYTES {
            return Err("Protected and live Core cache footprint exceeds its bound.".into());
        }

        let mut retained_bytes = valid_pairs.keys().try_fold(0_u64, |total, name| {
            total
                .checked_add(generation_usage[name].logical_bytes)
                .ok_or("Retained Core generation byte count overflowed.")
        })?;
        let available_unprotected_slots = MAX_RETAINED_GENERATIONS.saturating_sub(protected.len());
        let mut unprotected = valid_pairs
            .iter()
            .filter(|(name, _identity)| !protected.contains_key(*name))
            .map(|(name, identity)| (identity.sequence, name.clone()))
            .collect::<Vec<_>>();
        unprotected.sort();
        let mut remaining_unprotected = unprotected.len();
        for (_sequence, name) in unprotected {
            let footprint = retained_bytes
                .checked_add(live_reservation_bytes)
                .ok_or("Core generation cache unavoidable byte count overflowed.")?;
            let must_prune_for_count = remaining_unprotected > available_unprotected_slots;
            let must_prune_for_bytes = footprint > MAX_TOTAL_GENERATION_BYTES;
            if !must_prune_for_count && !must_prune_for_bytes {
                break;
            }
            let marker = &markers[&name];
            let (generation, expected_identity) = &generations[&name];
            require_current_directory_identity(
                generation,
                *expected_identity,
                "expired Core generation",
            )?;
            invalidate_commit_marker_path(marker, &commits_root)?;
            report.removed_commit_markers += 1;
            require_current_directory_identity(
                generation,
                *expected_identity,
                "expired Core generation",
            )?;
            cleanup_candidate_tree(generation, &generations_root)?;
            report.removed_generations += 1;
            valid_pairs.remove(&name);
            retained_bytes = retained_bytes
                .checked_sub(generation_usage[&name].logical_bytes)
                .ok_or("Retained Core generation byte count underflowed.")?;
            remaining_unprotected -= 1;
        }

        report.retained_generations = valid_pairs.len();
        let unavoidable_bytes = retained_bytes
            .checked_add(live_reservation_bytes)
            .ok_or("Core generation cache unavoidable byte count overflowed.")?;
        if unavoidable_bytes > MAX_TOTAL_GENERATION_BYTES {
            return Err("Core generation cache unavoidable footprint exceeds its bound.".into());
        }
        Ok(report)
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

fn bounded_directory_entries(path: &Path, description: &str) -> Result<Vec<fs::DirEntry>, String> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(path).map_err(|error| format!("Could not inspect {description}: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Could not inspect {description}: {error}"))?;
        if entries.len() >= CACHE_DIRECTORY_ENTRY_LIMIT {
            return Err(format!("{description} contains too many entries."));
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn entry_name(entry: &fs::DirEntry, description: &str) -> Result<String, String> {
    entry
        .file_name()
        .into_string()
        .map_err(|_| format!("{description} contains a non-UTF-8 name."))
}

fn valid_candidate_basename(name: &str) -> bool {
    name.strip_prefix("candidate-")
        .and_then(|suffix| suffix.rsplit_once('-'))
        .is_some_and(|(operation, token)| safe_operation_id(operation) && lowercase_hex(token, 64))
}

fn valid_state_temporary_name(name: &str) -> bool {
    let Some(body) = name
        .strip_prefix(".state.json.")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((process, sequence)) = body.split_once('.') else {
        return false;
    };
    let Ok(process) = process.parse::<u32>() else {
        return false;
    };
    let Ok(sequence) = sequence.parse::<u64>() else {
        return false;
    };
    process > 0 && sequence > 0 && format!(".state.json.{process}.{sequence}.tmp") == name
}

fn valid_commit_temporary_name(name: &str) -> bool {
    let Some(body) = name
        .strip_prefix(".commit-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((sequence, token)) = body.split_once('-') else {
        return false;
    };
    let Ok(sequence) = sequence.parse::<u64>() else {
        return false;
    };
    sequence > 0 && lowercase_hex(token, 64) && format!(".commit-{sequence}-{token}.tmp") == name
}

fn validate_cache_root_inventory(
    root: &Path,
) -> Result<Vec<(PathBuf, FilesystemIdentity)>, String> {
    let mut temporaries = Vec::new();
    for entry in bounded_directory_entries(root, "Core generation cache root")? {
        let name = entry_name(&entry, "Core generation cache root")?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            format!("Could not inspect Core generation cache root entry: {error}")
        })?;
        let known_directory = matches!(
            name.as_str(),
            "candidates" | "generations" | "commits" | "leases" | "trash"
        );
        let known_file = matches!(
            name.as_str(),
            "cache.lock" | "state.json" | CACHE_STATE_REQUIRED_MARKER
        );
        use std::os::unix::fs::MetadataExt as _;
        if known_directory {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(
                    "Core generation cache root contains an unsafe directory entry.".into(),
                );
            }
        } else if known_file {
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
                return Err("Core generation cache root contains an unsafe file entry.".into());
            }
        } else if valid_state_temporary_name(&name) {
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
                return Err("Core generation cache contains an unsafe state temporary.".into());
            }
            temporaries.push((
                entry.path(),
                FilesystemIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            ));
        } else {
            return Err(format!(
                "Core generation cache contains unknown root entry {name}."
            ));
        }
    }
    Ok(temporaries)
}

fn bounded_scan_limit(error: &str) -> bool {
    error.ends_with("contains too many entries.")
        || error.ends_with("contains too many nodes.")
        || error.ends_with("contains too many files.")
        || error.ends_with("is too deeply nested.")
}

fn inventory_tombstones(root: &Path) -> Result<Vec<(PathBuf, FilesystemIdentity)>, String> {
    let mut tombstones = Vec::new();
    for entry in bounded_directory_entries(root, "Core generation tombstone directory")? {
        let name = entry_name(&entry, "Core generation tombstone directory")?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Could not inspect Core generation tombstone: {error}"))?;
        if !name
            .strip_prefix("tombstone-")
            .is_some_and(|token| lowercase_hex(token, 64))
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
        {
            return Err("Core generation tombstone directory contains an unsafe entry.".into());
        }
        use std::os::unix::fs::MetadataExt as _;
        tombstones.push((
            entry.path(),
            FilesystemIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        ));
    }
    Ok(tombstones)
}

fn quarantine_directory(
    path: &Path,
    source_root: &Path,
    trash_root: &Path,
    expected: FilesystemIdentity,
    expected_trash: FilesystemIdentity,
) -> Result<(), String> {
    if path.parent() != Some(source_root) {
        return Err("Refusing to quarantine Core generation residue outside its store.".into());
    }
    let source = open_bound_directory(source_root, None, "Core generation source directory")?;
    let trash = open_bound_directory(
        trash_root,
        Some(expected_trash),
        "Core generation trash directory",
    )?;
    let source_name = path_component_cstring(path, "Core generation cleanup residue")?;
    let source_stat = statat_nofollow(source.as_raw_fd(), &source_name)?;
    if !stat_is_directory(&source_stat)
        || source_stat.st_dev as u64 != expected.device
        || source_stat.st_ino != expected.inode
    {
        return Err("Core generation cleanup residue changed before quarantine.".into());
    }
    for _ in 0..8 {
        let destination = CString::new(format!("tombstone-{}", random_candidate_token()?))
            .map_err(|_| "Core generation tombstone name is invalid.".to_string())?;
        if unsafe {
            libc::renameat(
                source.as_raw_fd(),
                source_name.as_ptr(),
                trash.as_raw_fd(),
                destination.as_ptr(),
            )
        } == 0
        {
            source.sync_all().map_err(|error| {
                format!("Could not sync Core generation source directory: {error}")
            })?;
            return trash.sync_all().map_err(|error| {
                format!("Could not sync Core generation trash directory: {error}")
            });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::AlreadyExists {
            return Err(format!(
                "Could not quarantine bounded Core generation residue: {error}"
            ));
        }
    }
    Err("Could not allocate a unique Core generation tombstone.".into())
}

fn clean_tombstones_bounded(
    tombstones: &[(PathBuf, FilesystemIdentity)],
    trash_root: &Path,
    expected_trash: FilesystemIdentity,
) -> Result<(), String> {
    let trash = open_bound_directory(
        trash_root,
        Some(expected_trash),
        "Core generation trash directory",
    )?;
    use std::os::unix::fs::MetadataExt as _;
    let trash_device = trash
        .metadata()
        .map_err(|error| format!("Could not identify Core generation trash directory: {error}"))?
        .dev();
    let mut budget = TOMBSTONE_BATCH_OPERATIONS;
    for (path, identity) in tombstones {
        if budget == 0 {
            break;
        }
        let name = path_component_cstring(path, "Core generation tombstone")?;
        let tombstone = openat_bound_directory(trash.as_raw_fd(), &name, *identity)?;
        clean_tombstone_directory(&tombstone, trash_device, &mut budget)?;
        if budget != 0 && directory_names_bounded(&tombstone, 1)?.is_empty() {
            budget -= 1;
            unlinkat_checked(trash.as_raw_fd(), &name, libc::AT_REMOVEDIR, true)?;
        }
    }
    trash
        .sync_all()
        .map_err(|error| format!("Could not sync Core generation trash directory: {error}"))
}

fn clean_tombstone_directory(
    directory: &File,
    trash_device: u64,
    budget: &mut usize,
) -> Result<(), String> {
    if *budget == 0 {
        return Ok(());
    }
    require_opened_directory_device(directory, trash_device)?;
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(format!(
            "Could not unlock Core generation tombstone directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    while *budget != 0 {
        let Some(name) = directory_names_bounded(directory, 1)?.into_iter().next() else {
            break;
        };
        *budget -= 1;
        let stat = statat_nofollow(directory.as_raw_fd(), &name)?;
        if stat_is_directory(&stat) {
            let identity = FilesystemIdentity {
                device: stat.st_dev as u64,
                inode: stat.st_ino,
            };
            let child = openat_bound_directory(directory.as_raw_fd(), &name, identity)?;
            clean_tombstone_directory(&child, trash_device, budget)?;
            if *budget != 0 && directory_names_bounded(&child, 1)?.is_empty() {
                *budget -= 1;
                unlinkat_checked(directory.as_raw_fd(), &name, libc::AT_REMOVEDIR, true)?;
            }
        } else {
            unlinkat_checked(directory.as_raw_fd(), &name, 0, false)?;
        }
    }
    Ok(())
}

fn require_opened_directory_device(directory: &File, expected_device: u64) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("Could not identify opened Core tombstone directory: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_dir() || metadata.dev() != expected_device {
        return Err("Core generation tombstone crosses a filesystem boundary.".into());
    }
    Ok(())
}

fn open_bound_directory(
    path: &Path,
    expected: Option<FilesystemIdentity>,
    description: &str,
) -> Result<File, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect {description}: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    if before.file_type().is_symlink() || !before.is_dir() {
        return Err(format!("{description} is unsafe."));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|error| format!("Could not safely open {description}: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("Could not identify {description}: {error}"))?;
    let identity = FilesystemIdentity {
        device: opened.dev(),
        inode: opened.ino(),
    };
    if !opened.is_dir()
        || before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || expected.is_some_and(|expected| expected != identity)
    {
        return Err(format!("{description} identity changed."));
    }
    Ok(file)
}

fn openat_bound_directory(
    parent_fd: libc::c_int,
    name: &CStr,
    expected: FilesystemIdentity,
) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not safely open Core generation tombstone: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|error| format!("Could not identify Core generation tombstone: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_dir() || metadata.dev() != expected.device || metadata.ino() != expected.inode {
        return Err("Core generation tombstone identity changed while opening it.".into());
    }
    Ok(file)
}

fn require_bound_root(
    path: &Path,
    root_file: &File,
    expected: FilesystemIdentity,
) -> Result<(), String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not revalidate the Core generation cache root: {error}"))?;
    let opened = root_file
        .metadata()
        .map_err(|error| format!("Could not identify the pinned Core generation cache: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || !opened.is_dir()
        || path_metadata.dev() != expected.device
        || path_metadata.ino() != expected.inode
        || opened.dev() != expected.device
        || opened.ino() != expected.inode
    {
        return Err("Core generation cache root identity changed after opening.".into());
    }
    Ok(())
}

fn acquire_bound_cache_lock(
    root_file: &File,
    lock_path: &Path,
    expected: Option<FilesystemIdentity>,
    before_lock: impl FnOnce(&Path) -> Result<(), String>,
    after_lock: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(CoreGenerationCacheLock, FilesystemIdentity), String> {
    let name = CString::new("cache.lock")
        .map_err(|_| "Core generation cache lock name is invalid.".to_string())?;
    let (fd, created) = if expected.is_some() {
        let fd = unsafe {
            libc::openat(
                root_file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        (fd, false)
    } else {
        let fd = unsafe {
            libc::openat(
                root_file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            (fd, true)
        } else if std::io::Error::last_os_error().kind() == ErrorKind::AlreadyExists {
            let existing = unsafe {
                libc::openat(
                    root_file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            (existing, false)
        } else {
            (fd, false)
        }
    };
    if fd < 0 {
        return Err(format!(
            "Could not open the bound Core generation cache lock: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let initial = file.metadata().map_err(|error| {
        format!("Could not inspect the bound Core generation cache lock: {error}")
    })?;
    use std::os::unix::fs::MetadataExt as _;
    if !initial.is_file() || initial.uid() != unsafe { libc::geteuid() } || initial.nlink() != 1 {
        return Err("Core generation cache lock is unsafe or foreign.".into());
    }
    if created {
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(format!(
                "Could not secure the new Core generation cache lock: {}",
                std::io::Error::last_os_error()
            ));
        }
        file.sync_all().map_err(|error| {
            format!("Could not sync the new Core generation cache lock: {error}")
        })?;
    }
    let opened = file.metadata().map_err(|error| {
        format!("Could not recheck the bound Core generation cache lock: {error}")
    })?;
    let identity = FilesystemIdentity {
        device: opened.dev(),
        inode: opened.ino(),
    };
    if !opened.is_file()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.nlink() != 1
        || opened.permissions().mode() & 0o7777 != 0o600
        || expected.is_some_and(|expected| expected != identity)
    {
        return Err("Core generation cache lock has invalid identity or permissions.".into());
    }
    require_lock_path_identity(root_file, &name, identity)?;
    before_lock(lock_path)?;
    let deadline = Instant::now()
        .checked_add(CACHE_LOCK_TIMEOUT)
        .ok_or("Core generation cache lock deadline overflowed.")?;
    loop {
        match file.try_lock() {
            Ok(()) => break,
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
    after_lock(lock_path)?;
    let locked = file.metadata().map_err(|error| {
        format!("Could not identify the locked Core generation cache lock: {error}")
    })?;
    if !locked.is_file()
        || locked.dev() != identity.device
        || locked.ino() != identity.inode
        || locked.uid() != unsafe { libc::geteuid() }
        || locked.nlink() != 1
        || locked.permissions().mode() & 0o7777 != 0o600
    {
        return Err("Core generation cache lock changed while acquiring it.".into());
    }
    require_lock_path_identity(root_file, &name, identity)?;
    Ok((CoreGenerationCacheLock { file }, identity))
}

fn require_lock_path_identity(
    root_file: &File,
    name: &CStr,
    expected: FilesystemIdentity,
) -> Result<(), String> {
    let stat = statat_nofollow(root_file.as_raw_fd(), name)?;
    if !stat_is_regular(&stat)
        || stat.st_dev as u64 != expected.device
        || stat.st_ino != expected.inode
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err("Core generation cache lock pathname changed or is unsafe.".into());
    }
    Ok(())
}

fn path_component_cstring(path: &Path, description: &str) -> Result<CString, String> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("{description} has no basename."))?;
    CString::new(name.as_bytes()).map_err(|_| format!("{description} basename is invalid."))
}

fn statat_nofollow(parent_fd: libc::c_int, name: &CStr) -> Result<libc::stat, String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(format!(
            "Could not inspect descriptor-relative Core cache entry: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { stat.assume_init() })
}

fn stat_is_directory(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn stat_is_regular(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn directory_names_bounded(directory: &File, limit: usize) -> Result<Vec<CString>, String> {
    let independent = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if independent < 0 {
        return Err(format!(
            "Could not open an independent Core tombstone directory descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stream = unsafe { libc::fdopendir(independent) };
    if stream.is_null() {
        unsafe { libc::close(independent) };
        return Err(format!(
            "Could not enumerate Core tombstone directory descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    while names.len() < limit {
        set_errno(0);
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = get_errno();
            if errno != 0 {
                return Err(format!(
                    "Could not read Core tombstone directory descriptor: {}",
                    std::io::Error::from_raw_os_error(errno)
                ));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        names.push(
            CString::new(name.to_bytes()).map_err(|_| {
                "Core generation tombstone contains an invalid basename.".to_string()
            })?,
        );
    }
    Ok(names)
}

#[cfg(target_os = "macos")]
fn set_errno(value: libc::c_int) {
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
fn get_errno() -> libc::c_int {
    unsafe { *libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_errno(value: libc::c_int) {
    unsafe { *libc::__errno_location() = value };
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_errno() -> libc::c_int {
    unsafe { *libc::__errno_location() }
}

fn unlinkat_checked(
    parent_fd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
    allow_not_empty: bool,
) -> Result<(), String> {
    if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), flags) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if allow_not_empty && error.raw_os_error() == Some(libc::ENOTEMPTY) {
        return Ok(());
    }
    Err(format!(
        "Could not remove descriptor-relative Core tombstone entry: {error}"
    ))
}

fn inventory_candidate_directories(
    root: &Path,
) -> Result<BTreeMap<String, (PathBuf, FilesystemIdentity)>, String> {
    let mut result = BTreeMap::new();
    for entry in bounded_directory_entries(root, "Core generation candidates directory")? {
        let name = entry_name(&entry, "Core generation candidates directory")?;
        if !valid_candidate_basename(&name) {
            return Err("Core generation candidates directory contains an unknown name.".into());
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Could not inspect Core generation candidate: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Core generation candidates directory contains an unsafe entry.".into());
        }
        use std::os::unix::fs::MetadataExt as _;
        result.insert(
            name,
            (
                entry.path(),
                FilesystemIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            ),
        );
    }
    Ok(result)
}

fn inventory_lease_files(root: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut result = BTreeMap::new();
    for entry in bounded_directory_entries(root, "Core generation leases directory")? {
        let name = entry_name(&entry, "Core generation leases directory")?;
        if !valid_candidate_basename(&name) {
            return Err("Core generation leases directory contains an unknown name.".into());
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Could not inspect Core generation lease: {error}"))?;
        use std::os::unix::fs::MetadataExt as _;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > CANDIDATE_LEASE_LIMIT
        {
            return Err("Core generation leases directory contains an unsafe entry.".into());
        }
        result.insert(name, entry.path());
    }
    Ok(result)
}

fn inventory_generation_directories(
    root: &Path,
) -> Result<BTreeMap<String, (PathBuf, FilesystemIdentity)>, String> {
    let mut result = BTreeMap::new();
    for entry in bounded_directory_entries(root, "Core generations directory")? {
        let name = entry_name(&entry, "Core generations directory")?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Could not inspect cached Core generation: {error}"))?;
        if !lowercase_hex(&name, 64) || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Core generations directory contains an unsafe or unknown entry.".into());
        }
        use std::os::unix::fs::MetadataExt as _;
        result.insert(
            name,
            (
                entry.path(),
                FilesystemIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            ),
        );
    }
    Ok(result)
}

fn inventory_commit_files(root: &Path) -> Result<CommitInventory, String> {
    let mut markers = BTreeMap::new();
    let mut temporaries = Vec::new();
    for entry in bounded_directory_entries(root, "Core generation commits directory")? {
        let name = entry_name(&entry, "Core generation commits directory")?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Could not inspect Core generation commit entry: {error}"))?;
        use std::os::unix::fs::MetadataExt as _;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
            return Err("Core generation commits directory contains an unsafe entry.".into());
        }
        if lowercase_hex(&name, 64) {
            markers.insert(name, entry.path());
        } else if valid_commit_temporary_name(&name) {
            temporaries.push((
                entry.path(),
                FilesystemIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            ));
        } else {
            return Err("Core generation commits directory contains an unknown entry.".into());
        }
    }
    Ok(CommitInventory {
        markers,
        temporaries,
    })
}

fn inspect_reconciliation_lease(
    path: &Path,
    name: &str,
) -> Result<ReconciliationLeaseState, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect Core generation lease: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|error| format!("Could not safely open Core generation lease: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("Could not identify opened Core generation lease: {error}"))?;
    if before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || !opened.is_file()
        || opened.nlink() != 1
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.permissions().mode() & 0o7777 != 0o600
        || opened.len() == 0
        || opened.len() > CANDIDATE_LEASE_LIMIT
    {
        return Err("Core generation lease changed while opening it.".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::by_ref(&mut file)
        .take(CANDIDATE_LEASE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read Core generation lease: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("Could not recheck Core generation lease: {error}"))?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || opened.mtime() != after.mtime()
        || opened.mtime_nsec() != after.mtime_nsec()
        || after.nlink() != 1
        || after.uid() != unsafe { libc::geteuid() }
        || bytes.len() as u64 != opened.len()
    {
        return Err("Core generation lease changed while it was read.".into());
    }
    let document: OwnedCandidateLeaseDocument = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Core generation lease is invalid: {error}"))?;
    let identity = FilesystemIdentity {
        device: document.device,
        inode: document.inode,
    };
    if document.candidate_basename != name
        || !(1..=MAX_GENERATION_STORAGE_BYTES).contains(&document.reservation_bytes)
        || candidate_lease_bytes(name, identity, document.reservation_bytes)? != bytes
    {
        return Err("Core generation lease is not canonical.".into());
    }
    match file.try_lock() {
        Ok(()) => Ok(ReconciliationLeaseState::Acquired(ReconciliationLease {
            path: path.to_path_buf(),
            identity: FilesystemIdentity {
                device: opened.dev(),
                inode: opened.ino(),
            },
            file,
            document,
        })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(ReconciliationLeaseState::Live { document }),
        Err(std::fs::TryLockError::Error(error)) => Err(format!(
            "Could not test Core generation lease ownership: {error}"
        )),
    }
}

fn remove_acquired_lease(lease: ReconciliationLease, leases_root: &Path) -> Result<(), String> {
    let current = fs::symlink_metadata(&lease.path)
        .map_err(|error| format!("Could not recheck abandoned Core generation lease: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    if lease.path.parent() != Some(leases_root)
        || current.file_type().is_symlink()
        || !current.is_file()
        || current.nlink() != 1
        || current.dev() != lease.identity.device
        || current.ino() != lease.identity.inode
    {
        return Err("Refusing to remove a replacement Core generation lease.".into());
    }
    fs::remove_file(&lease.path)
        .map_err(|error| format!("Could not remove abandoned Core generation lease: {error}"))?;
    sync_directory(leases_root)?;
    lease
        .file
        .unlock()
        .map_err(|error| format!("Could not unlock removed Core generation lease: {error}"))
}

fn remove_safe_regular_file(
    path: &Path,
    parent: &Path,
    expected: FilesystemIdentity,
    description: &str,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect {description}: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    if path.parent() != Some(parent)
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
    {
        return Err(format!("Refusing to remove unsafe {description}."));
    }
    fs::remove_file(path).map_err(|error| format!("Could not remove {description}: {error}"))
}

fn require_current_directory_identity(
    path: &Path,
    expected: FilesystemIdentity,
    description: &str,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not recheck {description}: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
    {
        return Err(format!("{description} changed before cleanup."));
    }
    Ok(())
}

fn read_commit_marker_identity(
    path: &Path,
    generation_id: &str,
) -> Result<CoreGenerationIdentity, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect Core commit evidence: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > 128
    {
        return Err("Core generation commit evidence is malformed.".into());
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|error| format!("Could not safely open Core commit evidence: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("Could not identify Core commit evidence: {error}"))?;
    if before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || opened.nlink() != 1
        || opened.len() != before.len()
    {
        return Err("Core generation commit evidence changed while opening it.".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::by_ref(&mut file)
        .take(129)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read Core commit evidence: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("Could not recheck Core commit evidence: {error}"))?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || opened.mtime() != after.mtime()
        || opened.mtime_nsec() != after.mtime_nsec()
        || after.nlink() != 1
        || bytes.len() as u64 != opened.len()
        || !bytes.ends_with(b"\n")
    {
        return Err("Core generation commit evidence changed or is malformed.".into());
    }
    let text = std::str::from_utf8(&bytes[..bytes.len() - 1])
        .map_err(|_| "Core generation commit evidence is not UTF-8.".to_string())?;
    let (sequence, hash) = text
        .split_once(':')
        .ok_or("Core generation commit evidence is malformed.")?;
    if hash != generation_id
        || sequence.is_empty()
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("Core generation commit evidence identity is invalid.".into());
    }
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| "Core generation commit sequence is invalid.".to_string())?;
    let identity = CoreGenerationIdentity {
        sequence,
        generation_id: generation_id.into(),
        manifest_sha256: generation_id.into(),
    };
    identity.validate()?;
    if generation_commit_marker_bytes(&identity) != bytes {
        return Err("Core generation commit evidence is not canonical.".into());
    }
    Ok(identity)
}

fn scan_bounded_tree(root: &Path, description: &str) -> Result<TreeUsage, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("Could not inspect {description}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{description} is not a safe directory."));
    }
    let mut usage = TreeUsage {
        nodes: 1,
        ..TreeUsage::default()
    };
    let mut directories = vec![(root.to_path_buf(), 0_usize)];
    let mut index = 0;
    while index < directories.len() {
        let (directory, depth) = directories[index].clone();
        index += 1;
        for entry in bounded_directory_entries(&directory, description)? {
            usage.nodes = usage
                .nodes
                .checked_add(1)
                .ok_or_else(|| format!("{description} node count overflowed."))?;
            if usage.nodes > MAX_TREE_NODES {
                return Err(format!("{description} contains too many nodes."));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("Could not inspect {description} entry: {error}"))?;
            use std::os::unix::fs::MetadataExt as _;
            if metadata.file_type().is_symlink() {
                return Err(format!("{description} contains a link."));
            } else if metadata.is_dir() {
                let child_depth = depth
                    .checked_add(1)
                    .ok_or_else(|| format!("{description} depth overflowed."))?;
                if child_depth > MAX_TREE_DEPTH {
                    return Err(format!("{description} is too deeply nested."));
                }
                directories.push((entry.path(), child_depth));
            } else if metadata.is_file() {
                if metadata.nlink() != 1 {
                    return Err(format!("{description} contains a multiply linked file."));
                }
                usage.files = usage
                    .files
                    .checked_add(1)
                    .ok_or_else(|| format!("{description} file count overflowed."))?;
                if usage.files > MAX_GENERATION_STORAGE_FILES {
                    return Err(format!("{description} contains too many files."));
                }
                usage.logical_bytes = usage
                    .logical_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| format!("{description} byte count overflowed."))?;
            } else {
                return Err(format!("{description} contains a special entry."));
            }
        }
    }
    Ok(usage)
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

    const TEST_RESERVATION: u64 = 1024;

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

    fn create_private_file(path: &Path) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options.open(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn generation_cache_commits_create_only_and_reuses_only_verified_content() {
        let root = temporary_cache("commit");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = cache
            .create_candidate("operation-1", TEST_RESERVATION)
            .unwrap();
        populate(&first, "verified");
        let generation = identity(1, '1');
        assert_eq!(
            cache
                .commit_candidate(&first, &generation, verify_value("verified"))
                .unwrap(),
            GenerationCommit::Installed
        );

        let duplicate = cache
            .create_candidate("operation-2", TEST_RESERVATION)
            .unwrap();
        populate(&duplicate, "verified");
        assert_eq!(
            cache
                .commit_candidate(&duplicate, &generation, verify_value("verified"))
                .unwrap(),
            GenerationCommit::AlreadyPresent
        );
        assert!(!duplicate.exists());

        let conflicting = cache
            .create_candidate("operation-3", TEST_RESERVATION)
            .unwrap();
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
        let interrupted = cache
            .create_candidate("interrupted", TEST_RESERVATION)
            .unwrap();
        populate(&interrupted, "verified");
        let destination = cache.generation_path(&generation).unwrap();
        fs::rename(&interrupted, &destination).unwrap();
        assert!(cache
            .begin_activation(&generation, "unsafe", 0, verify_value("verified"))
            .is_err());

        let retry = cache.create_candidate("retry", TEST_RESERVATION).unwrap();
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
        let original = cache
            .create_candidate("original", TEST_RESERVATION)
            .unwrap();
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
        let interrupted = cache.create_candidate("fresh", TEST_RESERVATION).unwrap();
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
                    TEST_RESERVATION,
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
                TEST_RESERVATION,
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
                    TEST_RESERVATION,
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
    fn descriptor_relative_staging_rejects_candidate_path_replacement() {
        let root = temporary_cache("lease-staging-replacement");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("stage-replacement", 11).unwrap();
        let moved = root.join("candidates/moved-candidate");
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::rename(lease.path(), &moved).unwrap();
        std::os::unix::fs::symlink(&outside, lease.path()).unwrap();

        assert!(lease.create_file("must-not-escape").is_err());
        assert!(!outside.join("must-not-escape").exists());

        fs::remove_file(lease.path()).unwrap();
        fs::rename(&moved, lease.path()).unwrap();
        cache.abort_candidate(&lease).unwrap();
        cleanup(&root);
    }

    #[test]
    fn cache_accepts_manifest_maximum_plus_control_file_envelope() {
        let root = temporary_cache("storage-file-envelope");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("max-files", 1).unwrap();
        for index in 0..MAX_GENERATION_STORAGE_FILES {
            lease
                .create_file(&format!("entry-{index:04}"))
                .unwrap()
                .sync_all()
                .unwrap();
        }
        let generation = identity(1, 'c');
        assert_eq!(
            cache
                .commit_candidate(&lease, &generation, |_| Ok(()))
                .unwrap(),
            GenerationCommit::Installed
        );
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
    fn reconciliation_preserves_live_lease_then_removes_dropped_candidate() {
        let root = temporary_cache("reconcile-live-lease");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("live", 64).unwrap();
        populate(&lease, "partially-staged");
        let candidate = lease.path().to_path_buf();
        let sidecar = lease.lease_path.clone();

        let live = cache.reconcile().unwrap();
        assert_eq!(live.live_candidates, 1);
        assert_eq!(live.removed_candidates, 0);
        assert_eq!(live.removed_leases, 0);
        assert!(candidate.is_dir());
        assert!(sidecar.is_file());

        drop(lease);
        let abandoned = cache.reconcile().unwrap();
        assert_eq!(abandoned.live_candidates, 0);
        assert_eq!(abandoned.removed_candidates, 1);
        assert_eq!(abandoned.removed_leases, 1);
        assert!(!candidate.exists());
        assert!(!sidecar.exists());
        cleanup(&root);
    }

    #[test]
    fn reconciliation_rejects_live_lease_bound_to_another_candidate_identity() {
        let root = temporary_cache("reconcile-live-binding");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("live-binding", 64).unwrap();
        let basename = lease.path().file_name().unwrap().to_str().unwrap();
        let wrong = FilesystemIdentity {
            device: lease.candidate_identity.device,
            inode: lease.candidate_identity.inode.wrapping_add(1),
        };
        fs::write(
            &lease.lease_path,
            candidate_lease_bytes(basename, wrong, 64).unwrap(),
        )
        .unwrap();

        assert!(cache.reconcile().is_err());
        assert!(lease.path().exists());
        assert!(lease.lease_path.exists());
        fs::write(&lease.lease_path, &lease.expected_bytes).unwrap();
        cache.abort_candidate(&lease).unwrap();
        cleanup(&root);
    }

    #[test]
    fn reconciliation_removes_unleased_candidate_and_unlocked_orphan_sidecar() {
        let root = temporary_cache("reconcile-orphans");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let unleased = root
            .join("candidates")
            .join(format!("candidate-unleased-{}", "a".repeat(64)));
        fs::create_dir(&unleased).unwrap();
        fs::set_permissions(&unleased, fs::Permissions::from_mode(0o700)).unwrap();
        populate(&unleased, "residue");

        let orphan = cache.create_candidate("orphan", 41).unwrap();
        let orphan_candidate = orphan.path().to_path_buf();
        let orphan_sidecar = orphan.lease_path.clone();
        drop(orphan);
        fs::remove_dir(&orphan_candidate).unwrap();

        let report = cache.reconcile().unwrap();
        assert_eq!(report.removed_candidates, 1);
        assert_eq!(report.removed_leases, 1);
        assert!(!unleased.exists());
        assert!(!orphan_sidecar.exists());
        cleanup(&root);
    }

    #[test]
    fn reconciliation_removes_abandoned_candidate_larger_than_its_reservation() {
        let root = temporary_cache("reconcile-reservation-overrun");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let lease = cache.create_candidate("oversized", 1).unwrap();
        populate(&lease, "larger-than-one-byte");
        let candidate = lease.path().to_path_buf();
        let sidecar = lease.lease_path.clone();
        drop(lease);

        let report = cache.reconcile().unwrap();
        assert_eq!(report.removed_candidates, 1);
        assert_eq!(report.removed_leases, 1);
        assert!(!candidate.exists());
        assert!(!sidecar.exists());
        cleanup(&root);
    }

    #[test]
    fn commit_rejects_candidate_larger_than_its_reservation_before_publication() {
        let root = temporary_cache("commit-reservation-overrun");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generation = identity(1, 'e');
        let candidate = cache.create_candidate("oversized-commit", 1).unwrap();
        populate(&candidate, "larger-than-one-byte");

        assert!(cache
            .commit_candidate(&candidate, &generation, |_| Ok(()))
            .is_err());
        assert!(!candidate.exists());
        assert!(!cache.generation_path(&generation).unwrap().exists());
        assert!(!cache
            .generation_commit_marker_path(&generation)
            .unwrap()
            .exists());
        cleanup(&root);
    }

    #[test]
    fn reconciliation_removes_structurally_safe_oversized_unmarked_generation() {
        let root = temporary_cache("reconcile-oversized-unmarked");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generation = identity(1, 'f');
        let path = cache.generation_path(&generation).unwrap();
        fs::create_dir(&path).unwrap();
        let file = File::create(path.join("sparse-residue")).unwrap();
        file.set_len(MAX_GENERATION_STORAGE_BYTES + 1).unwrap();

        let report = cache.reconcile().unwrap();
        assert_eq!(report.removed_generations, 1);
        assert!(!path.exists());
        cleanup(&root);
    }

    #[test]
    fn reconciliation_quarantines_depth_explosion_and_cleans_it_in_bounded_batch() {
        let root = temporary_cache("reconcile-deep-unmarked");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generation = identity(2, 'f');
        let generation_path = cache.generation_path(&generation).unwrap();
        fs::create_dir(&generation_path).unwrap();
        let mut deepest = generation_path.clone();
        for _ in 0..=MAX_TREE_DEPTH {
            deepest = deepest.join("nested");
            fs::create_dir(&deepest).unwrap();
        }

        let report = cache.reconcile().unwrap();
        assert_eq!(report.removed_generations, 1);
        assert!(!generation_path.exists());
        assert_eq!(fs::read_dir(root.join("trash")).unwrap().count(), 1);

        cache.reconcile().unwrap();
        assert_eq!(fs::read_dir(root.join("trash")).unwrap().count(), 0);
        cleanup(&root);
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_cleanup_rejects_replacement_symlink_without_touching_external_tree() {
        use std::os::unix::fs::symlink;

        let root = temporary_cache("tombstone-replacement-symlink");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let tombstone = root
            .join("trash")
            .join(format!("tombstone-{}", "a".repeat(64)));
        fs::create_dir(&tombstone).unwrap();
        fs::write(tombstone.join("residue"), "cache").unwrap();
        let inventory = inventory_tombstones(&root.join("trash")).unwrap();

        let held = root.parent().unwrap().join(format!(
            "opemos-held-tombstone-{}",
            random_candidate_token().unwrap()
        ));
        let external = root.parent().unwrap().join(format!(
            "opemos-external-tombstone-{}",
            random_candidate_token().unwrap()
        ));
        fs::rename(&tombstone, &held).unwrap();
        fs::create_dir(&external).unwrap();
        fs::write(external.join("sentinel"), "untouched").unwrap();
        symlink(&external, &tombstone).unwrap();

        assert!(
            clean_tombstones_bounded(&inventory, &root.join("trash"), cache.trash_identity)
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(external.join("sentinel")).unwrap(),
            "untouched"
        );

        fs::remove_file(tombstone).unwrap();
        cleanup(&root);
        cleanup(&held);
        cleanup(&external);
    }

    #[test]
    fn reconciliation_rejects_replaced_trash_root_identity() {
        let root = temporary_cache("trash-root-replacement");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let original = root.parent().unwrap().join(format!(
            "opemos-original-trash-{}",
            random_candidate_token().unwrap()
        ));
        fs::rename(root.join("trash"), &original).unwrap();
        fs::create_dir(root.join("trash")).unwrap();
        fs::set_permissions(root.join("trash"), fs::Permissions::from_mode(0o700)).unwrap();

        assert!(cache.reconcile().is_err());
        cleanup(&root);
        cleanup(&original);
    }

    #[test]
    fn descriptor_cleanup_removes_sealed_directories_and_files() {
        let root = temporary_cache("sealed-tombstone");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let tombstone = root
            .join("trash")
            .join(format!("tombstone-{}", "b".repeat(64)));
        let nested = tombstone.join("sealed");
        fs::create_dir(&tombstone).unwrap();
        fs::create_dir(&nested).unwrap();
        let file = nested.join("content");
        fs::write(&file, "sealed").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&tombstone, fs::Permissions::from_mode(0o500)).unwrap();

        let inventory = inventory_tombstones(&root.join("trash")).unwrap();
        clean_tombstones_bounded(&inventory, &root.join("trash"), cache.trash_identity).unwrap();
        assert!(!tombstone.exists());
        cleanup(&root);
    }

    #[test]
    fn descriptor_cleanup_removes_a_full_many_sibling_batch() {
        let root = temporary_cache("many-sibling-tombstone");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let tombstone = root
            .join("trash")
            .join(format!("tombstone-{}", "c".repeat(64)));
        fs::create_dir(&tombstone).unwrap();
        for index in 0..300 {
            fs::write(tombstone.join(format!("entry-{index:03}")), "x").unwrap();
        }

        cache.reconcile().unwrap();
        assert_eq!(fs::read_dir(&tombstone).unwrap().count(), 44);
        cache.reconcile().unwrap();
        assert!(!tombstone.exists());
        cleanup(&root);
    }

    #[test]
    fn tombstone_device_check_precedes_permission_changes() {
        let root = temporary_cache("wrong-device-tombstone");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let tombstone = root
            .join("trash")
            .join(format!("tombstone-{}", "d".repeat(64)));
        fs::create_dir(&tombstone).unwrap();
        fs::set_permissions(&tombstone, fs::Permissions::from_mode(0o500)).unwrap();
        let opened = open_bound_directory(&tombstone, None, "test tombstone").unwrap();

        assert!(require_opened_directory_device(
            &opened,
            cache.trash_identity.device.wrapping_add(1)
        )
        .is_err());
        assert_eq!(
            fs::symlink_metadata(&tombstone)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o500
        );
        cleanup(&root);
    }

    #[test]
    fn reconciliation_removes_only_exact_stale_temporary_patterns() {
        let root = temporary_cache("reconcile-temporaries");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let state_temp = root.join(".state.json.123.456.tmp");
        let commit_temp = root
            .join("commits")
            .join(format!(".commit-7-{}.tmp", "b".repeat(64)));
        fs::write(&state_temp, "state-residue").unwrap();
        fs::write(&commit_temp, "commit-residue").unwrap();

        let report = cache.reconcile().unwrap();
        assert_eq!(report.removed_state_temporaries, 1);
        assert_eq!(report.removed_commit_temporaries, 1);
        assert!(!state_temp.exists());
        assert!(!commit_temp.exists());

        fs::write(root.join(".state.json.not-a-pid.1.tmp"), "unknown").unwrap();
        assert!(cache.reconcile().is_err());
        fs::remove_file(root.join(".state.json.not-a-pid.1.tmp")).unwrap();
        fs::write(root.join(".state.json.0123.1.tmp"), "noncanonical").unwrap();
        assert!(cache.reconcile().is_err());
        fs::remove_file(root.join(".state.json.0123.1.tmp")).unwrap();
        let noncanonical_commit = root
            .join("commits")
            .join(format!(".commit-07-{}.tmp", "c".repeat(64)));
        fs::write(&noncanonical_commit, "noncanonical").unwrap();
        assert!(cache.reconcile().is_err());
        fs::remove_file(noncanonical_commit).unwrap();

        let replaceable = root.join(".state.json.123.789.tmp");
        fs::write(&replaceable, "original").unwrap();
        let (_, original_identity) = validate_cache_root_inventory(&root)
            .unwrap()
            .into_iter()
            .find(|(path, _identity)| path == &replaceable)
            .unwrap();
        let held = root.join("held-original-temp");
        fs::rename(&replaceable, &held).unwrap();
        fs::write(&replaceable, "replacement").unwrap();
        assert!(remove_safe_regular_file(
            &replaceable,
            &root,
            original_identity,
            "test state temporary"
        )
        .is_err());
        assert_eq!(fs::read_to_string(&replaceable).unwrap(), "replacement");
        fs::remove_file(held).unwrap();
        cleanup(&root);
    }

    #[test]
    fn reconciliation_prunes_oldest_unprotected_pairs_and_preserves_active() {
        let root = temporary_cache("reconcile-retention");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generations = (1_u64..=5)
            .map(|sequence| {
                let generation = identity(sequence, char::from_digit(sequence as u32, 16).unwrap());
                let candidate = cache
                    .create_candidate(&format!("retention-{sequence}"), 1)
                    .unwrap();
                cache
                    .commit_candidate(&candidate, &generation, |_| Ok(()))
                    .unwrap();
                generation
            })
            .collect::<Vec<_>>();
        cache
            .begin_activation(&generations[0], "retain-active", 0, |_| Ok(()))
            .unwrap();
        cache
            .acknowledge_healthy(&generations[0], "retain-active", 1, |_| Ok(()))
            .unwrap();

        let report = cache.reconcile().unwrap();
        assert_eq!(report.retained_generations, MAX_RETAINED_GENERATIONS);
        assert_eq!(report.removed_generations, 1);
        assert_eq!(report.removed_commit_markers, 1);
        assert!(cache.generation_path(&generations[0]).unwrap().exists());
        assert!(!cache.generation_path(&generations[1]).unwrap().exists());
        for generation in &generations[2..] {
            assert!(cache.generation_path(generation).unwrap().exists());
        }
        assert_eq!(
            cache.load_state().unwrap().active.as_ref(),
            Some(&generations[0])
        );
        cleanup(&root);
    }

    #[test]
    fn reconciliation_prunes_unprotected_pairs_to_fit_live_reservations() {
        let root = temporary_cache("reconcile-byte-retention");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generation = identity(1, 'd');
        let candidate = cache.create_candidate("retained-byte", 1).unwrap();
        populate(&candidate, "x");
        cache
            .commit_candidate(&candidate, &generation, verify_value("x"))
            .unwrap();

        let leases = (0..MAX_RETAINED_GENERATIONS)
            .map(|index| {
                cache
                    .create_candidate(
                        &format!("live-budget-{index}"),
                        MAX_GENERATION_STORAGE_BYTES,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let report = cache.reconcile().unwrap();
        assert_eq!(report.live_candidates, MAX_RETAINED_GENERATIONS);
        assert_eq!(report.retained_generations, 0);
        assert_eq!(report.removed_generations, 1);
        assert_eq!(report.removed_commit_markers, 1);
        assert!(!cache.generation_path(&generation).unwrap().exists());

        drop(leases);
        let abandoned = cache.reconcile().unwrap();
        assert_eq!(abandoned.removed_candidates, MAX_RETAINED_GENERATIONS);
        assert_eq!(abandoned.removed_leases, MAX_RETAINED_GENERATIONS);
        cleanup(&root);
    }

    #[test]
    fn reconciliation_rejects_distinct_valid_generations_with_duplicate_sequences() {
        let root = temporary_cache("reconcile-duplicate-sequence");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = identity(7, 'a');
        let second = identity(7, 'b');
        for (operation, generation) in [("duplicate-a", &first), ("duplicate-b", &second)] {
            let candidate = cache.create_candidate(operation, 1).unwrap();
            cache
                .commit_candidate(&candidate, generation, |_| Ok(()))
                .unwrap();
        }

        assert!(cache.reconcile().is_err());
        for generation in [&first, &second] {
            assert!(cache.generation_path(generation).unwrap().exists());
            assert!(cache
                .generation_commit_marker_path(generation)
                .unwrap()
                .exists());
        }
        cleanup(&root);
    }

    #[test]
    fn reconciliation_revokes_orphan_markers_and_removes_unmarked_generations() {
        let root = temporary_cache("reconcile-generation-residue");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let orphan = identity(7, '7');
        let orphan_marker = cache.generation_commit_marker_path(&orphan).unwrap();
        fs::write(&orphan_marker, generation_commit_marker_bytes(&orphan)).unwrap();
        fs::set_permissions(&orphan_marker, fs::Permissions::from_mode(0o400)).unwrap();

        let unmarked = identity(8, '8');
        let unmarked_path = cache.generation_path(&unmarked).unwrap();
        fs::create_dir(&unmarked_path).unwrap();
        fs::set_permissions(&unmarked_path, fs::Permissions::from_mode(0o500)).unwrap();

        let report = cache.reconcile().unwrap();
        assert_eq!(report.removed_commit_markers, 1);
        assert_eq!(report.removed_generations, 1);
        assert!(!orphan_marker.exists());
        assert!(!unmarked_path.exists());
        cleanup(&root);
    }

    #[test]
    fn reconciliation_retains_valid_pairs_and_fails_closed_for_protected_damage() {
        let root = temporary_cache("reconcile-protected");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let generation = identity(1, '9');
        let candidate = cache
            .create_candidate("protected", TEST_RESERVATION)
            .unwrap();
        populate(&candidate, "protected");
        cache
            .commit_candidate(&candidate, &generation, verify_value("protected"))
            .unwrap();
        cache
            .begin_activation(&generation, "activate", 0, verify_value("protected"))
            .unwrap();
        cache
            .acknowledge_healthy(&generation, "activate", 1, verify_value("protected"))
            .unwrap();

        let retained = cache.reconcile().unwrap();
        assert_eq!(retained.retained_generations, 1);
        assert_eq!(retained.removed_generations, 0);
        let marker = cache.generation_commit_marker_path(&generation).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(cache.reconcile().is_err());
        assert!(cache.generation_path(&generation).unwrap().exists());
        assert!(marker.exists());
        cleanup(&root);
    }

    #[cfg(unix)]
    #[test]
    fn reconciliation_rejects_linked_and_special_residue_without_removal() {
        use std::os::unix::fs::symlink;

        let root = temporary_cache("reconcile-unsafe");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let candidate = root
            .join("candidates")
            .join(format!("candidate-unsafe-{}", "c".repeat(64)));
        fs::create_dir(&candidate).unwrap();
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
        symlink("/tmp", candidate.join("escape")).unwrap();

        assert!(cache.reconcile().is_err());
        assert!(candidate.exists());
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
        let first = cache
            .create_candidate("concurrent-1", TEST_RESERVATION)
            .unwrap();
        let second = cache
            .create_candidate("concurrent-2", TEST_RESERVATION)
            .unwrap();
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
            let candidate = cache.create_candidate(operation, TEST_RESERVATION).unwrap();
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
        let candidate = cache.create_candidate("third", TEST_RESERVATION).unwrap();
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
            .create_candidate("invalid-reservation", MAX_GENERATION_STORAGE_BYTES + 1)
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
            let candidate = cache.create_candidate(operation, TEST_RESERVATION).unwrap();
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
        let candidate = cache
            .create_candidate("activate", TEST_RESERVATION)
            .unwrap();
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

    #[test]
    fn preexisting_hard_linked_or_misconfigured_lock_is_rejected_without_repair() {
        let hard_link_root = temporary_cache("hard-linked-lock-open");
        fs::create_dir(&hard_link_root).unwrap();
        fs::set_permissions(&hard_link_root, fs::Permissions::from_mode(0o700)).unwrap();
        let external = hard_link_root
            .parent()
            .unwrap()
            .join(format!("opemos-core-external-lock-{}", std::process::id()));
        create_private_file(&external);
        fs::hard_link(&external, hard_link_root.join("cache.lock")).unwrap();
        assert!(CoreGenerationCache::open(&hard_link_root).is_err());
        assert_eq!(
            fs::metadata(&external).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        cleanup(&hard_link_root);
        fs::remove_file(&external).unwrap();

        let mode_root = temporary_cache("unsafe-lock-mode-open");
        fs::create_dir(&mode_root).unwrap();
        fs::set_permissions(&mode_root, fs::Permissions::from_mode(0o700)).unwrap();
        create_private_file(&mode_root.join("cache.lock"));
        fs::set_permissions(
            mode_root.join("cache.lock"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(CoreGenerationCache::open(&mode_root).is_err());
        assert_eq!(
            fs::metadata(mode_root.join("cache.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o640
        );
        cleanup(&mode_root);
    }

    #[test]
    fn lock_path_replacement_before_and_after_locking_is_rejected() {
        for replace_after_lock in [false, true] {
            let root = temporary_cache(if replace_after_lock {
                "lock-replaced-after"
            } else {
                "lock-replaced-before"
            });
            let cache = CoreGenerationCache::open(&root).unwrap();
            let displaced = root.join("displaced.lock");
            let replace = |path: &Path| {
                fs::rename(path, &displaced).map_err(|error| error.to_string())?;
                create_private_file(path);
                Ok(())
            };
            let result = if replace_after_lock {
                cache.acquire_lock_with_hooks(|_| Ok(()), replace)
            } else {
                cache.acquire_lock_with_hooks(replace, |_| Ok(()))
            };
            assert!(result.is_err());
            assert!(root.join("cache.lock").is_file());
            assert!(displaced.is_file());
            cleanup(&root);
        }
    }

    #[test]
    fn pinned_root_rejects_rename_and_path_replacement() {
        let root = temporary_cache("pinned-root");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let displaced = root.with_extension("displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(cache.load_state().is_err());
        cleanup(&root);
        cleanup(&displaced);
    }

    #[test]
    fn pinned_lock_refuses_a_second_lock_namespace() {
        let root = temporary_cache("split-lock");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = cache.acquire_lock().unwrap();
        let displaced = root.join("original.lock");
        fs::rename(root.join("cache.lock"), &displaced).unwrap();
        create_private_file(&root.join("cache.lock"));
        let replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("cache.lock"))
            .unwrap();
        replacement.try_lock().unwrap();
        assert!(cache.acquire_lock().is_err());
        replacement.unlock().unwrap();
        drop(first);
        cleanup(&root);
    }

    #[cfg(unix)]
    #[test]
    fn foreign_owned_lock_is_rejected_when_test_can_change_ownership() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = temporary_cache("foreign-lock-owner");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = root.join("cache.lock");
        create_private_file(&lock);
        let path = CString::new(lock.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(path.as_ptr(), 1, u32::MAX) }, 0);
        assert!(CoreGenerationCache::open(&root).is_err());
        cleanup(&root);
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
