use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
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
const CACHE_STATE_SCHEMA: u32 = 1;
const CACHE_STATE_KIND: &str = "opemos-core-host-generation-state";
static STATE_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static CACHE_TRANSACTION_LOCK: Mutex<()> = Mutex::new(());
const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_LOCK_RETRY: Duration = Duration::from_millis(20);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreGenerationIdentity {
    pub(crate) generation_id: String,
    pub(crate) manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreGenerationCacheState {
    schema_version: u32,
    kind: String,
    pub(crate) revision: u64,
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

#[derive(Clone, Debug)]
pub(crate) struct CoreGenerationCache {
    root: PathBuf,
}

struct CoreGenerationCacheLock {
    file: File,
}

impl Drop for CoreGenerationCacheLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl CoreGenerationIdentity {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !lowercase_hex(&self.generation_id, 64) || !lowercase_hex(&self.manifest_sha256, 64) {
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
        let mut identities = HashSet::new();
        for identity in [
            self.active.as_ref(),
            self.pending.as_ref(),
            self.last_known_good.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !identities.insert(identity.generation_id.as_str()) {
                return Err("Core generation cache state repeats a generation role.".into());
            }
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
        for child in ["candidates", "generations"] {
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

    pub(crate) fn create_candidate(&self, operation_id: &str) -> Result<PathBuf, String> {
        if !safe_operation_id(operation_id) {
            return Err("Core generation cache operation identity is invalid.".into());
        }
        let path = self
            .root
            .join("candidates")
            .join(format!("candidate-{operation_id}"));
        fs::create_dir(&path).map_err(|error| {
            format!("Could not create a private Core generation candidate: {error}")
        })?;
        set_private_directory_permissions(&path)?;
        sync_directory(&self.root.join("candidates"))?;
        Ok(path)
    }

    pub(crate) fn commit_candidate(
        &self,
        candidate: &Path,
        identity: &CoreGenerationIdentity,
        verify: impl Fn(&Path) -> Result<(), String>,
    ) -> Result<GenerationCommit, String> {
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _file_guard = self.acquire_lock()?;
        identity.validate()?;
        self.require_owned_candidate(candidate)?;
        verify(candidate)?;
        sync_closed_tree(candidate)?;

        let destination = self.generation_path(identity)?;
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                require_directory(&destination, "cached Core generation")?;
                verify(&destination)?;
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

        fs::rename(candidate, &destination)
            .map_err(|error| format!("Could not commit the Core generation atomically: {error}"))?;
        sync_directory(&self.root.join("generations"))?;
        sync_directory(&self.root.join("candidates"))?;
        Ok(GenerationCommit::Installed)
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
        verify(&generation)?;
        let previous = state.active.replace(target);
        state.last_known_good = previous;
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
                return Ok(CoreGenerationCacheState::default());
            }
            Err(error) => {
                return Err(format!(
                    "Could not read Core generation cache state: {error}"
                ));
            }
        };
        if before.file_type().is_symlink()
            || !before.is_file()
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
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || before.len() != opened.len()
        {
            return Err("Core generation cache state changed while opening it.".into());
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        Read::by_ref(&mut file)
            .take(CACHE_STATE_LIMIT.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("Could not read Core generation cache state: {error}"))?;
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
        if !name
            .strip_prefix("candidate-")
            .is_some_and(safe_operation_id)
        {
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

fn set_private_directory_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!("Could not restrict Core generation cache permissions: {error}")
    })?;
    Ok(())
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

    fn identity(byte: char) -> CoreGenerationIdentity {
        CoreGenerationIdentity {
            generation_id: byte.to_string().repeat(64),
            manifest_sha256: char::from_u32(byte as u32 + 1)
                .unwrap()
                .to_string()
                .repeat(64),
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

    #[test]
    fn generation_cache_commits_create_only_and_reuses_only_verified_content() {
        let root = temporary_cache("commit");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = cache.create_candidate("operation-1").unwrap();
        populate(&first, "verified");
        let generation = identity('1');
        assert_eq!(
            cache
                .commit_candidate(&first, &generation, verify_value("verified"))
                .unwrap(),
            GenerationCommit::Installed
        );

        let duplicate = cache.create_candidate("operation-2").unwrap();
        populate(&duplicate, "verified");
        assert_eq!(
            cache
                .commit_candidate(&duplicate, &generation, verify_value("verified"))
                .unwrap(),
            GenerationCommit::AlreadyPresent
        );
        assert!(!duplicate.exists());

        let conflicting = cache.create_candidate("operation-3").unwrap();
        populate(&conflicting, "different");
        assert!(cache
            .commit_candidate(&conflicting, &generation, verify_value("different"))
            .is_err());
        assert!(conflicting.exists());
        assert_eq!(
            fs::read_to_string(
                root.join("generations")
                    .join(&generation.generation_id)
                    .join("contracts/manifest.json")
            )
            .unwrap(),
            "verified"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_generation_commits_preserve_one_verified_identity() {
        use std::sync::{Arc, Barrier};

        let root = temporary_cache("concurrent-commit");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = cache.create_candidate("concurrent-1").unwrap();
        let second = cache.create_candidate("concurrent-2").unwrap();
        populate(&first, "shared");
        populate(&second, "shared");
        let generation = identity('5');
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
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn health_acknowledgement_is_atomic_and_preserves_last_known_good() {
        let root = temporary_cache("activation");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = identity('2');
        let second = identity('4');
        for (operation, generation, value) in
            [("first", &first, "first"), ("second", &second, "second")]
        {
            let candidate = cache.create_candidate(operation).unwrap();
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
        assert_eq!(active.last_known_good.as_ref(), Some(&first));
        let rolled_back = cache
            .rollback_to_last_known_good(&second, 6, verify_value("first"))
            .unwrap();
        assert_eq!(rolled_back.active.as_ref(), Some(&first));
        assert_eq!(rolled_back.last_known_good.as_ref(), Some(&second));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_state_and_unsafe_candidates_fail_without_changing_active_state() {
        let root = temporary_cache("failure");
        let cache = CoreGenerationCache::open(&root).unwrap();
        assert!(cache.create_candidate("../escape").is_err());
        assert!(cache
            .commit_candidate(Path::new("/tmp"), &identity('6'), |_| Ok(()))
            .is_err());

        fs::write(root.join("state.json"), b"{\"schemaVersion\":1}\n").unwrap();
        assert!(cache.load_state().is_err());
        fs::remove_file(root.join("state.json")).unwrap();
        let state = cache.load_state().unwrap();
        assert!(state.active.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_activation_operations_cannot_replace_pending_user_intent() {
        let root = temporary_cache("stale-operation");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let first = identity('1');
        let second = identity('3');
        for (operation, generation, value) in
            [("first", &first, "first"), ("second", &second, "second")]
        {
            let candidate = cache.create_candidate(operation).unwrap();
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
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_relational_state_is_rejected() {
        let root = temporary_cache("relational-state");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let state = CoreGenerationCacheState {
            schema_version: CACHE_STATE_SCHEMA,
            kind: CACHE_STATE_KIND.into(),
            revision: 1,
            active: None,
            pending: None,
            pending_operation_id: None,
            last_known_good: Some(identity('2')),
        };
        fs::write(
            root.join("state.json"),
            canonical_state_bytes(&state).unwrap(),
        )
        .unwrap();
        assert!(cache.load_state().is_err());
        fs::remove_dir_all(root).unwrap();
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
        fs::remove_dir_all(actual).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn linked_generation_content_is_rejected_before_commit() {
        use std::os::unix::fs::symlink;

        let root = temporary_cache("symlink");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let candidate = cache.create_candidate("linked").unwrap();
        symlink("/tmp", candidate.join("escape")).unwrap();
        assert!(cache
            .commit_candidate(&candidate, &identity('8'), |_| Ok(()))
            .is_err());
        assert!(candidate.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hard_linked_generation_content_is_rejected_before_commit() {
        let root = temporary_cache("hard-link");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let candidate = cache.create_candidate("hard-linked").unwrap();
        let external = root.parent().unwrap().join(format!(
            "opemos-core-hard-link-external-{}",
            std::process::id()
        ));
        fs::write(&external, "mutable-outside-cache").unwrap();
        fs::hard_link(&external, candidate.join("linked-file")).unwrap();
        assert!(cache
            .commit_candidate(&candidate, &identity('7'), |_| Ok(()))
            .is_err());
        assert_eq!(
            fs::read_to_string(&external).unwrap(),
            "mutable-outside-cache"
        );
        fs::remove_file(external).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
