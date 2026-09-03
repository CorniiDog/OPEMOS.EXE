//! Inactive, test-only adapter for EXE-owned installed Core trust snapshots.
//!
//! The physical host directory and its permissions belong to OPEMOS.EXE. Core
//! owns the documents' semantics and the logical keyring basename. This module
//! deliberately contains no production path, endpoint, updater, command, or UI
//! wiring; production activation remains blocked on a reviewed host trust
//! installation channel and explicit macOS ACL validation. Unix owner/mode
//! checks here are not a claim that ACL-bearing production paths are private.

use super::{
    authenticate_installed_bootstrap_checkpoint, AuthenticatedBootstrapCheckpoint,
    MAX_CHECKPOINT_BYTES, MAX_KEYRING_BYTES, MAX_POLICY_BYTES,
};
use crate::core_generation_contracts::MAX_LINEAGE_GENERATIONS;
use crate::core_generation_verifier::{
    authenticate_discovery_snapshot, authenticate_manifest_snapshot, AuthenticatedGeneration,
    DetachedVerifierOutput, ManifestRequestIdentity, PendingAuthenticatedDiscovery,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd as _},
        unix::{
            ffi::OsStrExt as _,
            fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        },
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
};

pub(crate) const POLICY_FILENAME: &str = "userspace-lock-generation-policy.json";
pub(crate) const KEYRING_FILENAME: &str = "opemos-userspace-lock-generations.gpg";
pub(crate) const CHECKPOINT_FILENAME: &str = "userspace-lock-bootstrap-checkpoint.json";

const TRUST_DIRECTORY_MODE: u32 = 0o700;
const TRUST_FILE_MODE: u32 = 0o400;
const MAX_DIRECTORY_ENTRIES: usize = 4;

/// Opaque independently installed identity for the local trust set. There is
/// intentionally no deserializer or caller-facing string constructor. A
/// future production install/config channel must create this capability from
/// binary/config-pinned constants, never from files beside the trust payload.
pub(crate) struct InstalledTrustPins {
    policy_sha256: String,
    keyring_sha256: String,
    checkpoint_sha256: String,
    _seal: InstalledTrustPinsSeal,
}

struct InstalledTrustPinsSeal;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileIdentity {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            nlink: metadata.nlink(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

struct PinnedTrustFile {
    file: File,
    identity: FileIdentity,
}

/// Descriptor-bound proof that the three EXE-installed trust inputs still
/// denote the exact stable snapshot that produced verifier capabilities.
pub(crate) struct InstalledTrustGuard {
    parent_path: PathBuf,
    root_path: PathBuf,
    root_name: CString,
    parent: File,
    parent_identity: (u64, u64),
    root: File,
    root_identity: FileIdentity,
    files: BTreeMap<&'static str, PinnedTrustFile>,
    trust_hashes: [String; 3],
}

impl InstalledTrustGuard {
    fn same_snapshot_identity(&self, other: &Self) -> bool {
        self.root_identity == other.root_identity
            && self.trust_hashes == other.trust_hashes
            && self.files.len() == other.files.len()
            && self.files.iter().all(|(name, file)| {
                other
                    .files
                    .get(name)
                    .is_some_and(|other_file| file.identity == other_file.identity)
            })
    }

    pub(crate) fn revalidate<C>(&self, cancelled: &C) -> Result<(), String>
    where
        C: Fn() -> bool + ?Sized,
    {
        poll_cancelled(cancelled)?;
        require_directory_identity(&self.parent, self.parent_identity)?;
        let reopened_parent = open_directory(&self.parent_path)?;
        require_directory_identity(&reopened_parent, self.parent_identity)?;
        let reopened_root_path = open_directory(&self.root_path)?;
        require_identity(
            &reopened_root_path,
            self.root_identity,
            true,
            Some(TRUST_DIRECTORY_MODE),
        )?;
        let reopened_root = open_directory_at(&self.parent, &self.root_name)?;
        require_identity(
            &reopened_root,
            self.root_identity,
            true,
            Some(TRUST_DIRECTORY_MODE),
        )?;
        require_identity(
            &self.root,
            self.root_identity,
            true,
            Some(TRUST_DIRECTORY_MODE),
        )?;
        require_exact_inventory(&self.root, cancelled)?;
        for (name, pinned) in &self.files {
            poll_cancelled(cancelled)?;
            require_identity(&pinned.file, pinned.identity, false, Some(TRUST_FILE_MODE))?;
            let reopened = open_file_at(&self.root, name)?;
            require_identity(&reopened, pinned.identity, false, Some(TRUST_FILE_MODE))?;
        }
        require_identity(
            &self.root,
            self.root_identity,
            true,
            Some(TRUST_DIRECTORY_MODE),
        )?;
        poll_cancelled(cancelled)
    }
}

/// First phase: pin the complete local trust root, then authenticate discovery
/// before allowing its manifest identity to escape.
pub(crate) fn authenticate_installed_discovery<F, C>(
    trust_root: &Path,
    installed_pins: &InstalledTrustPins,
    discovery_payload: &[u8],
    discovery_signature: &[u8],
    cancelled: &C,
    verify_detached: F,
) -> Result<InstalledPendingDiscovery, String>
where
    F: FnMut(
        &[u8],
        &[u8],
        &[u8],
        &str,
        &dyn Fn() -> bool,
    ) -> Result<DetachedVerifierOutput, String>,
    C: Fn() -> bool,
{
    let snapshot = InstalledTrustSnapshot::open(trust_root, installed_pins, cancelled)?;
    let guard = Arc::new(snapshot.guard);
    let pending = authenticate_discovery_snapshot(
        &snapshot.policy,
        &snapshot.keyring,
        discovery_payload,
        discovery_signature,
        cancelled,
        verify_detached,
    )?;
    guard.revalidate(cancelled)?;
    Ok(InstalledPendingDiscovery {
        pending,
        checkpoint: snapshot.checkpoint,
        checkpoint_sha256: installed_pins.checkpoint_sha256.clone(),
        guard,
        _seal: InstalledPendingSeal,
    })
}

/// Second phase: authenticate only the exact manifest named by discovery and
/// seal the checkpoint from the same descriptor-bound trust snapshot.
pub(crate) fn authenticate_installed_manifest<F, C>(
    pending: InstalledPendingDiscovery,
    manifest_payload: &[u8],
    manifest_signature: &[u8],
    cancelled: &C,
    verify_detached: F,
) -> Result<
    (
        InstalledAuthenticatedGeneration,
        InstalledAuthenticatedCheckpoint,
    ),
    String,
>
where
    F: FnMut(
        &[u8],
        &[u8],
        &[u8],
        &str,
        &dyn Fn() -> bool,
    ) -> Result<DetachedVerifierOutput, String>,
    C: Fn() -> bool,
{
    pending.guard.revalidate(cancelled)?;
    let checkpoint_payload = pending.checkpoint;
    let checkpoint_sha256 = pending.checkpoint_sha256;
    let guard = pending.guard;
    let generation = authenticate_manifest_snapshot(
        pending.pending,
        manifest_payload,
        manifest_signature,
        cancelled,
        verify_detached,
    )?;
    guard.revalidate(cancelled)?;
    let checkpoint = authenticate_installed_bootstrap_checkpoint(
        &checkpoint_payload,
        &checkpoint_sha256,
        &generation,
    )?;
    guard.revalidate(cancelled)?;
    Ok((
        InstalledAuthenticatedGeneration {
            generation,
            guard: guard.clone(),
            _seal: InstalledGenerationSeal,
        },
        InstalledAuthenticatedCheckpoint {
            checkpoint,
            guard,
            _seal: InstalledCheckpointSeal,
        },
    ))
}

pub(crate) struct InstalledPendingDiscovery {
    pending: PendingAuthenticatedDiscovery,
    checkpoint: Vec<u8>,
    checkpoint_sha256: String,
    guard: Arc<InstalledTrustGuard>,
    _seal: InstalledPendingSeal,
}

struct InstalledPendingSeal;

impl InstalledPendingDiscovery {
    pub(crate) fn manifest_request(&self) -> ManifestRequestIdentity {
        self.pending.manifest_request()
    }
}

pub(crate) struct InstalledAuthenticatedGeneration {
    generation: AuthenticatedGeneration,
    guard: Arc<InstalledTrustGuard>,
    _seal: InstalledGenerationSeal,
}

struct InstalledGenerationSeal;

impl InstalledAuthenticatedGeneration {
    pub(crate) fn generation(&self) -> &AuthenticatedGeneration {
        &self.generation
    }
}

pub(crate) struct InstalledAuthenticatedCheckpoint {
    checkpoint: AuthenticatedBootstrapCheckpoint,
    guard: Arc<InstalledTrustGuard>,
    _seal: InstalledCheckpointSeal,
}

struct InstalledCheckpointSeal;

impl InstalledAuthenticatedCheckpoint {
    pub(crate) fn checkpoint(&self) -> &AuthenticatedBootstrapCheckpoint {
        &self.checkpoint
    }
}

pub(crate) fn revalidate_installed_capabilities<C>(
    generation: &InstalledAuthenticatedGeneration,
    checkpoint: &InstalledAuthenticatedCheckpoint,
    lineage: &[&InstalledAuthenticatedGeneration],
    cancelled: &C,
) -> Result<(), String>
where
    C: Fn() -> bool + ?Sized,
{
    if lineage.len() > MAX_LINEAGE_GENERATIONS {
        return Err("Authenticated lineage exceeds its generation limit.".into());
    }
    if !Arc::ptr_eq(&generation.guard, &checkpoint.guard) {
        return Err("Core generation and checkpoint do not share installed trust.".into());
    }
    for predecessor in lineage {
        if !generation.guard.same_snapshot_identity(&predecessor.guard) {
            return Err("Authenticated lineage does not share installed trust.".into());
        }
        predecessor.guard.revalidate(cancelled)?;
    }
    generation.guard.revalidate(cancelled)
}

struct InstalledTrustSnapshot {
    policy: Vec<u8>,
    keyring: Vec<u8>,
    checkpoint: Vec<u8>,
    guard: InstalledTrustGuard,
}

impl InstalledTrustSnapshot {
    fn open<C>(
        root_path: &Path,
        installed_pins: &InstalledTrustPins,
        cancelled: &C,
    ) -> Result<Self, String>
    where
        C: Fn() -> bool + ?Sized,
    {
        poll_cancelled(cancelled)?;
        if !root_path.is_absolute() {
            return Err("Installed Core trust root must be absolute.".into());
        }
        let root_name = single_component_name(root_path)?;
        let parent_path = root_path
            .parent()
            .ok_or("Installed Core trust root has no parent directory.")?
            .to_path_buf();
        let parent = open_directory(&parent_path)?;
        let parent_metadata = parent
            .metadata()
            .map_err(|_| "Installed Core trust parent could not be inspected.")?;
        let parent_identity = (parent_metadata.dev(), parent_metadata.ino());
        let root = open_directory_at(&parent, &root_name)?;
        let root_metadata = root
            .metadata()
            .map_err(|_| "Installed Core trust root could not be inspected.")?;
        if !root_metadata.is_dir()
            || root_metadata.uid() != unsafe { libc::geteuid() }
            || root_metadata.permissions().mode() & 0o7777 != TRUST_DIRECTORY_MODE
        {
            return Err("Installed Core trust root ownership or mode is unsafe.".into());
        }
        let root_identity = FileIdentity::from(&root_metadata);
        require_exact_inventory(&root, cancelled)?;

        let mut files = BTreeMap::new();
        let policy = read_pinned_file(
            &root,
            POLICY_FILENAME,
            MAX_POLICY_BYTES,
            cancelled,
            &mut files,
        )?;
        let keyring = read_pinned_file(
            &root,
            KEYRING_FILENAME,
            MAX_KEYRING_BYTES,
            cancelled,
            &mut files,
        )?;
        let checkpoint = read_pinned_file(
            &root,
            CHECKPOINT_FILENAME,
            MAX_CHECKPOINT_BYTES,
            cancelled,
            &mut files,
        )?;
        if sha256(&policy) != installed_pins.policy_sha256
            || sha256(&keyring) != installed_pins.keyring_sha256
            || sha256(&checkpoint) != installed_pins.checkpoint_sha256
        {
            return Err("Installed Core trust differs from independently pinned identity.".into());
        }
        require_identity(&root, root_identity, true, Some(TRUST_DIRECTORY_MODE))?;
        require_exact_inventory(&root, cancelled)?;
        let reopened_root = open_directory_at(&parent, &root_name)?;
        require_identity(
            &reopened_root,
            root_identity,
            true,
            Some(TRUST_DIRECTORY_MODE),
        )?;

        Ok(Self {
            policy,
            keyring,
            checkpoint,
            guard: InstalledTrustGuard {
                parent_path,
                root_path: root_path.to_path_buf(),
                root_name,
                parent,
                parent_identity,
                root,
                root_identity,
                files,
                trust_hashes: [
                    installed_pins.policy_sha256.clone(),
                    installed_pins.keyring_sha256.clone(),
                    installed_pins.checkpoint_sha256.clone(),
                ],
            },
        })
    }
}

fn read_pinned_file<C>(
    root: &File,
    name: &'static str,
    maximum: usize,
    cancelled: &C,
    files: &mut BTreeMap<&'static str, PinnedTrustFile>,
) -> Result<Vec<u8>, String>
where
    C: Fn() -> bool + ?Sized,
{
    poll_cancelled(cancelled)?;
    let mut file = open_file_at(root, name)?;
    let before = file
        .metadata()
        .map_err(|_| "Installed Core trust file could not be inspected.")?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != TRUST_FILE_MODE
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err(format!("Installed Core trust file {name} is unsafe."));
    }
    let identity = FileIdentity::from(&before);
    let mut payload = Vec::with_capacity(before.len() as usize);
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        poll_cancelled(cancelled)?;
        let count = file
            .read(&mut buffer)
            .map_err(|_| format!("Installed Core trust file {name} could not be read."))?;
        if count == 0 {
            break;
        }
        if payload.len().saturating_add(count) > maximum {
            return Err(format!("Installed Core trust file {name} is excessive."));
        }
        payload.extend_from_slice(&buffer[..count]);
    }
    if payload.len() as u64 != identity.size {
        return Err(format!(
            "Installed Core trust file {name} changed while reading."
        ));
    }
    require_identity(&file, identity, false, Some(TRUST_FILE_MODE))?;
    let reopened = open_file_at(root, name)?;
    require_identity(&reopened, identity, false, Some(TRUST_FILE_MODE))?;
    if files
        .insert(name, PinnedTrustFile { file, identity })
        .is_some()
    {
        return Err("Installed Core trust inventory contains a duplicate.".into());
    }
    Ok(payload)
}

fn require_identity(
    file: &File,
    expected: FileIdentity,
    directory: bool,
    exact_mode: Option<u32>,
) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|_| "Installed Core trust identity could not be inspected.")?;
    if FileIdentity::from(&metadata) != expected
        || metadata.uid() != unsafe { libc::geteuid() }
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || (!directory && metadata.nlink() != 1)
        || exact_mode.is_some_and(|mode| metadata.permissions().mode() & 0o7777 != mode)
    {
        return Err("Installed Core trust identity changed or is unsafe.".into());
    }
    Ok(())
}

fn require_directory_identity(file: &File, expected: (u64, u64)) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|_| "Installed Core trust identity could not be inspected.")?;
    if (metadata.dev(), metadata.ino()) != expected || !metadata.is_dir() {
        return Err("Installed Core trust identity changed or is unsafe.".into());
    }
    Ok(())
}

fn require_exact_inventory<C>(root: &File, cancelled: &C) -> Result<(), String>
where
    C: Fn() -> bool + ?Sized,
{
    let names = directory_names(root, cancelled)?;
    let expected = BTreeSet::from([
        POLICY_FILENAME.to_owned(),
        KEYRING_FILENAME.to_owned(),
        CHECKPOINT_FILENAME.to_owned(),
    ]);
    let mut folded = BTreeSet::new();
    for name in &names {
        let lower = name.to_ascii_lowercase();
        if !folded.insert(lower) {
            return Err("Installed Core trust inventory has a case collision.".into());
        }
    }
    if names != expected {
        return Err("Installed Core trust inventory is not exact.".into());
    }
    Ok(())
}

fn directory_names<C>(root: &File, cancelled: &C) -> Result<BTreeSet<String>, String>
where
    C: Fn() -> bool + ?Sized,
{
    // A fresh open file description avoids sharing the directory cursor with
    // the pinned root (dup/fdopendir would share it and make repeat checks
    // observe false EOF).
    let independent = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if independent < 0 {
        return Err("Installed Core trust directory could not be enumerated.".into());
    }
    let stream = unsafe { libc::fdopendir(independent) };
    if stream.is_null() {
        unsafe { libc::close(independent) };
        return Err("Installed Core trust directory could not be enumerated.".into());
    }
    let mut names = BTreeSet::new();
    let result = (|| {
        loop {
            poll_cancelled(cancelled)?;
            clear_errno();
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                if current_errno() != 0 {
                    return Err("Installed Core trust directory enumeration failed.".into());
                }
                break;
            }
            let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            if names.len() >= MAX_DIRECTORY_ENTRIES {
                return Err("Installed Core trust inventory is excessive.".into());
            }
            let name = std::str::from_utf8(raw)
                .map_err(|_| "Installed Core trust filename is not UTF-8.".to_string())?
                .to_owned();
            if !names.insert(name) {
                return Err("Installed Core trust inventory contains a duplicate.".into());
            }
        }
        Ok(names)
    })();
    unsafe { libc::closedir(stream) };
    result
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

fn clear_errno() {
    unsafe { *errno_location() = 0 };
}

fn current_errno() -> libc::c_int {
    unsafe { *errno_location() }
}

fn open_directory(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|_| "Installed Core trust directory could not be opened safely.".into())
}

fn open_directory_at(parent: &File, name: &CString) -> Result<File, String> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err("Installed Core trust root could not be opened safely.".into());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_file_at(root: &File, name: &str) -> Result<File, String> {
    let name =
        CString::new(name).map_err(|_| "Installed Core trust filename is invalid.".to_string())?;
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err("Installed Core trust file could not be opened safely.".into());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn single_component_name(path: &Path) -> Result<CString, String> {
    let name = path
        .file_name()
        .ok_or("Installed Core trust root name is invalid.")?;
    if name.is_empty()
        || Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err("Installed Core trust root name is invalid.".into());
    }
    CString::new(name.as_bytes())
        .map_err(|_| "Installed Core trust root name is invalid.".to_string())
}

fn poll_cancelled<C>(cancelled: &C) -> Result<(), String>
where
    C: Fn() -> bool + ?Sized,
{
    if cancelled() {
        Err("Installed Core trust snapshot was cancelled.".into())
    } else {
        Ok(())
    }
}

fn sha256(payload: &[u8]) -> String {
    format!("{:x}", Sha256::digest(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core_generation_bootstrap::{
            expected_generation_authority, BootstrapAuthority, BootstrapChannel,
            BootstrapCheckpoint, BootstrapCompatibility, BootstrapPolicy, BootstrapReplayPolicy,
        },
        core_generation_cache::{
            activation::{
                begin_installed_authenticated_activation,
                begin_installed_authenticated_activation_with_hook,
            },
            CoreGenerationCache, CoreGenerationCacheState, CoreGenerationIdentity,
        },
        core_generation_contracts::{
            DiscoveryGeneration, GenerationCompatibility, GenerationDiscovery, GenerationFile,
            GenerationLock, GenerationManifest, GenerationTarget, GenerationTargetLock,
            DISCOVERY_FILENAME, DISCOVERY_SIGNATURE_FILENAME, DISCOVERY_SIGNATURE_SCHEME,
            MAX_LINEAGE_GENERATIONS, OPENPGP_HASH_ALGORITHM_IDS,
        },
    };
    use serde::Serialize;
    use std::{
        fs,
        io::Write as _,
        os::unix::fs::symlink,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        policy: Vec<u8>,
        keyring: Vec<u8>,
        checkpoint: Vec<u8>,
        pins: InstalledTrustPins,
        discovery: Vec<u8>,
        discovery_signature: Vec<u8>,
        manifest: Vec<u8>,
        manifest_signature: Vec<u8>,
        payload: Vec<u8>,
        fingerprint: String,
    }

    impl Fixture {
        fn create(name: &str) -> Self {
            let root = temporary_root(name);
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(TRUST_DIRECTORY_MODE)).unwrap();
            let keyring = b"fixture-installed-core-keyring".to_vec();
            let fingerprint = "A".repeat(40);
            let policy = BootstrapPolicy {
                schema_version: 1,
                kind: "opemos-userspace-lock-bootstrap-policy".into(),
                status: "active".into(),
                policy_id: "opemos-userspace-lock-generations".into(),
                policy_schema_version: 1,
                authority: BootstrapAuthority {
                    keyring_filename: KEYRING_FILENAME.into(),
                    keyring_sha256: sha256(&keyring),
                    primary_signing_fingerprint: fingerprint.clone(),
                    signature_scheme: DISCOVERY_SIGNATURE_SCHEME.into(),
                    allowed_hash_algorithm_ids: OPENPGP_HASH_ALGORITHM_IDS.to_vec(),
                },
                channel: BootstrapChannel {
                    origin: "https://updates.opemos.invalid".into(),
                    discovery_path:
                        "/userspace-locks/reviewed/opemos-userspace-lock-discovery-v1.json".into(),
                    discovery_filename: DISCOVERY_FILENAME.into(),
                    discovery_signature_filename: DISCOVERY_SIGNATURE_FILENAME.into(),
                    immutable_release_path_prefix: "/userspace-locks/releases/".into(),
                    release_tag_prefix: "opemos-userspace-lock-generation-v1-s".into(),
                    allow_redirects: false,
                },
                compatibility: BootstrapCompatibility {
                    discovery_schema_versions: vec![1],
                    generation_manifest_schema_versions: vec![1],
                    userspace_lock_schema_versions: vec![1],
                    installer_result_schema_versions: vec![1],
                },
                replay_policy: BootstrapReplayPolicy {
                    require_monotonic_high_water: true,
                    require_immediate_predecessor: true,
                    allow_authenticated_lineage_catchup: true,
                    maximum_lineage_generations: MAX_LINEAGE_GENERATIONS,
                },
            };
            let policy = canonical(&policy);
            let authority = expected_generation_authority(
                &super::super::parse_bootstrap_policy(&policy).unwrap(),
                &policy,
            )
            .unwrap();
            let target = GenerationTarget {
                steamos_version: "3.8.14".into(),
                kernel_version: "6.11.11-valve1-1-neptune-611".into(),
                nvidia_version: "575.64.05".into(),
                architecture: "x86_64".into(),
            };
            let payload = b"{\"schemaVersion\":1}\n".to_vec();
            let lock = GenerationLock {
                filename: "userspace-lock.json".into(),
                schema_version: 1,
                sha256: sha256(&payload),
                size: payload.len() as u64,
            };
            let target_lock = GenerationTargetLock {
                target,
                lock: lock.clone(),
            };
            let manifest_document = GenerationManifest {
                schema_version: 1,
                kind: "opemos-userspace-lock-generation".into(),
                channel: "reviewed".into(),
                sequence: 1,
                published_at: "2026-09-03T00:00:00Z".into(),
                authority: authority.clone(),
                previous_manifest_sha256: None,
                target_locks: vec![target_lock.clone()],
                files: vec![GenerationFile {
                    role: "userspace-lock".into(),
                    filename: lock.filename.clone(),
                    size: payload.len() as u64,
                    sha256: sha256(&payload),
                }],
            };
            let manifest = canonical(&manifest_document);
            let manifest_signature = b"manifest-signature".to_vec();
            let manifest_hash = sha256(&manifest);
            let release_tag = "opemos-userspace-lock-generation-v1-s1";
            let discovery = canonical(&GenerationDiscovery {
                schema_version: 1,
                kind: "opemos-userspace-lock-discovery".into(),
                channel: "reviewed".into(),
                sequence: 1,
                published_at: "2026-09-03T00:00:00Z".into(),
                authority,
                compatibility: GenerationCompatibility {
                    discovery_schema_version: 1,
                    generation_manifest_schema_version: 1,
                    userspace_lock_schema_version: 1,
                    minimum_installer_result_schema_version: 1,
                },
                generation: DiscoveryGeneration {
                    release_tag: release_tag.into(),
                    manifest_filename: format!("{release_tag}.manifest.json"),
                    manifest_sha256: manifest_hash.clone(),
                    manifest_size: manifest.len() as u64,
                    signature_filename: format!("{release_tag}.manifest.json.sig"),
                    signature_sha256: sha256(&manifest_signature),
                    signature_size: manifest_signature.len() as u64,
                    previous_manifest_sha256: None,
                },
                targets: vec![target_lock],
            });
            let checkpoint = canonical(&BootstrapCheckpoint {
                schema_version: 1,
                kind: "opemos-userspace-lock-bootstrap-checkpoint".into(),
                policy_sha256: sha256(&policy),
                minimum_sequence: 1,
                minimum_manifest_sha256: manifest_hash,
            });
            let pins = InstalledTrustPins {
                policy_sha256: sha256(&policy),
                keyring_sha256: sha256(&keyring),
                checkpoint_sha256: sha256(&checkpoint),
                _seal: InstalledTrustPinsSeal,
            };
            write_private(&root.join(POLICY_FILENAME), &policy);
            write_private(&root.join(KEYRING_FILENAME), &keyring);
            write_private(&root.join(CHECKPOINT_FILENAME), &checkpoint);
            Self {
                root,
                policy,
                keyring,
                checkpoint,
                pins,
                discovery,
                discovery_signature: b"discovery-signature".to_vec(),
                manifest,
                manifest_signature,
                payload,
                fingerprint,
            }
        }

        fn authenticate(
            &self,
        ) -> Result<
            (
                InstalledAuthenticatedGeneration,
                InstalledAuthenticatedCheckpoint,
            ),
            String,
        > {
            let fingerprint = self.fingerprint.clone();
            let pending = authenticate_installed_discovery(
                &self.root,
                &self.pins,
                &self.discovery,
                &self.discovery_signature,
                &|| false,
                move |_, _, _, _, _| Ok(valid_output(&fingerprint)),
            )?;
            assert_eq!(
                pending.manifest_request().size(),
                self.manifest.len() as u64
            );
            let fingerprint = self.fingerprint.clone();
            authenticate_installed_manifest(
                pending,
                &self.manifest,
                &self.manifest_signature,
                &|| false,
                move |_, _, _, _, _| Ok(valid_output(&fingerprint)),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            make_writable(&self.root);
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn valid_output(fingerprint: &str) -> DetachedVerifierOutput {
        DetachedVerifierOutput {
            exit_status: 0,
            status: format!(
                "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG {0} 2026-09-03 1788436800 0 4 0 1 8 00 {0}\n",
                fingerprint
            )
            .into_bytes(),
        }
    }

    fn canonical(value: &impl Serialize) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&serde_json::to_value(value).unwrap()).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "opemos-installed-trust-{name}-{}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            nonce
        ))
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(TRUST_FILE_MODE)).unwrap();
    }

    fn make_writable(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    make_writable(&entry.path());
                }
            }
        } else if metadata.is_file() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }

    fn stage_generation(
        cache: &CoreGenerationCache,
        installed_generation: &InstalledAuthenticatedGeneration,
        fixture: &Fixture,
    ) -> CoreGenerationIdentity {
        let generation = installed_generation.generation();
        let identity = CoreGenerationIdentity {
            sequence: generation.discovery().sequence,
            generation_id: sha256(&fixture.manifest),
            manifest_sha256: sha256(&fixture.manifest),
        };
        let evidence = generation.canonical_evidence_bytes().unwrap();
        let files = BTreeMap::from([
            (DISCOVERY_FILENAME.to_owned(), fixture.discovery.clone()),
            (
                DISCOVERY_SIGNATURE_FILENAME.to_owned(),
                fixture.discovery_signature.clone(),
            ),
            (
                generation.discovery().generation.manifest_filename.clone(),
                fixture.manifest.clone(),
            ),
            (
                generation.discovery().generation.signature_filename.clone(),
                fixture.manifest_signature.clone(),
            ),
            ("acquisition-trust-v1.json".to_owned(), evidence),
            ("userspace-lock.json".to_owned(), fixture.payload.clone()),
        ]);
        let reservation = files.values().map(|bytes| bytes.len() as u64).sum();
        cache
            .stage_candidate(
                "stage-installed-trust",
                reservation,
                &identity,
                |root| {
                    for (name, bytes) in &files {
                        let mut options = OpenOptions::new();
                        let mut file = options
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(root.join(name))
                            .map_err(|error| error.to_string())?;
                        file.write_all(bytes).map_err(|error| error.to_string())?;
                        file.sync_all().map_err(|error| error.to_string())?;
                    }
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap();
        identity
    }

    fn mutate_cached_payload(cache_root: &Path, identity: &CoreGenerationIdentity) {
        let payload = cache_root
            .join("generations")
            .join(&identity.generation_id)
            .join("userspace-lock.json");
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&payload, b"cache-mutated-by-final-cancellation-poll").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o400)).unwrap();
    }

    #[test]
    fn exact_private_snapshot_produces_one_shared_sealed_guard() {
        let fixture = Fixture::create("valid");
        let (generation, checkpoint) = fixture.authenticate().unwrap();
        revalidate_installed_capabilities(&generation, &checkpoint, &[], &|| false).unwrap();
    }

    #[test]
    fn guarded_lineage_accepts_same_root_and_rejects_different_root() {
        let first = Fixture::create("lineage-first");
        let second = Fixture::create("lineage-second");
        let (first_generation, first_checkpoint) = first.authenticate().unwrap();
        let (same_root_generation, _) = first.authenticate().unwrap();
        let (second_generation, _) = second.authenticate().unwrap();
        revalidate_installed_capabilities(
            &first_generation,
            &first_checkpoint,
            &[&same_root_generation],
            &|| false,
        )
        .unwrap();
        assert!(revalidate_installed_capabilities(
            &first_generation,
            &first_checkpoint,
            &[&second_generation],
            &|| false,
        )
        .is_err());
    }

    #[test]
    fn descriptor_relative_inventory_revalidation_is_concurrent_and_repeatable() {
        let fixture = Fixture::create("concurrent-revalidation");
        let (generation, _) = fixture.authenticate().unwrap();
        let guard = generation.guard.clone();
        let workers = (0..4)
            .map(|_| {
                let guard = guard.clone();
                std::thread::spawn(move || {
                    for _ in 0..64 {
                        guard.revalidate(&|| false).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn root_and_file_modes_inventory_and_bounds_fail_closed() {
        let root_mode = Fixture::create("root-mode");
        fs::set_permissions(&root_mode.root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(root_mode.authenticate().is_err());

        let file_mode = Fixture::create("file-mode");
        fs::set_permissions(
            file_mode.root.join(POLICY_FILENAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(file_mode.authenticate().is_err());

        let extra = Fixture::create("extra");
        write_private(&extra.root.join("unexpected"), b"unexpected");
        assert!(extra.authenticate().is_err());

        #[cfg(target_os = "linux")]
        {
            let collision = Fixture::create("collision");
            write_private(
                &collision.root.join("OPEMOS-USERSPACE-LOCK-GENERATIONS.GPG"),
                b"collision",
            );
            assert!(collision.authenticate().is_err());
        }

        let empty = Fixture::create("empty");
        fs::set_permissions(
            empty.root.join(KEYRING_FILENAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(empty.root.join(KEYRING_FILENAME), b"").unwrap();
        fs::set_permissions(
            empty.root.join(KEYRING_FILENAME),
            fs::Permissions::from_mode(TRUST_FILE_MODE),
        )
        .unwrap();
        assert!(empty.authenticate().is_err());

        let excessive = Fixture::create("excessive");
        fs::set_permissions(
            excessive.root.join(CHECKPOINT_FILENAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        File::create(excessive.root.join(CHECKPOINT_FILENAME))
            .unwrap()
            .set_len(MAX_CHECKPOINT_BYTES as u64 + 1)
            .unwrap();
        fs::set_permissions(
            excessive.root.join(CHECKPOINT_FILENAME),
            fs::Permissions::from_mode(TRUST_FILE_MODE),
        )
        .unwrap();
        assert!(excessive.authenticate().is_err());
    }

    #[test]
    fn symlinks_hardlinks_and_special_files_fail_closed() {
        let symlinked = Fixture::create("symlink");
        let policy = symlinked.root.join(POLICY_FILENAME);
        let policy_real = symlinked.root.with_extension("policy-real");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&policy, &policy_real).unwrap();
        symlink(&policy_real, &policy).unwrap();
        assert!(symlinked.authenticate().is_err());
        fs::remove_file(&policy_real).unwrap();

        let hardlinked = Fixture::create("hardlink");
        let hardlink_copy = hardlinked.root.with_extension("keyring-copy");
        fs::hard_link(hardlinked.root.join(KEYRING_FILENAME), &hardlink_copy).unwrap();
        assert!(hardlinked.authenticate().is_err());
        fs::remove_file(&hardlink_copy).unwrap();

        let fifo = Fixture::create("fifo");
        let checkpoint = fifo.root.join(CHECKPOINT_FILENAME);
        fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&checkpoint).unwrap();
        let path = CString::new(checkpoint.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(path.as_ptr(), TRUST_FILE_MODE as libc::mode_t) },
            0
        );
        assert!(fifo.authenticate().is_err());
    }

    #[test]
    fn root_file_replacement_and_stale_capability_fail_closed() {
        let fixture = Fixture::create("replace");
        let (generation, checkpoint) = fixture.authenticate().unwrap();
        let original = fixture.root.with_extension("original");
        fs::rename(&fixture.root, &original).unwrap();
        let replacement = Fixture::create("replacement-source");
        fs::rename(&replacement.root, &fixture.root).unwrap();
        assert!(
            revalidate_installed_capabilities(&generation, &checkpoint, &[], &|| false).is_err()
        );
        make_writable(&fixture.root);
        fs::remove_dir_all(&fixture.root).unwrap();
        fs::rename(&original, &fixture.root).unwrap();

        let file = fixture.root.join(KEYRING_FILENAME);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&file).unwrap();
        write_private(&file, &fixture.keyring);
        assert!(
            revalidate_installed_capabilities(&generation, &checkpoint, &[], &|| false).is_err()
        );
    }

    #[test]
    fn mixed_snapshot_mutation_and_cancellation_are_rejected() {
        let fixture = Fixture::create("mixed");
        let mutated = AtomicBool::new(false);
        let fingerprint = fixture.fingerprint.clone();
        let result = authenticate_installed_discovery(
            &fixture.root,
            &fixture.pins,
            &fixture.discovery,
            &fixture.discovery_signature,
            &|| false,
            |_, _, _, _, _| {
                let path = fixture.root.join(KEYRING_FILENAME);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&path, b"rotated-keyring").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(TRUST_FILE_MODE)).unwrap();
                mutated.store(true, Ordering::SeqCst);
                Ok(valid_output(&fingerprint))
            },
        );
        assert!(mutated.load(Ordering::SeqCst));
        assert!(result.is_err());

        let manifest_race = Fixture::create("manifest-race");
        let fingerprint = manifest_race.fingerprint.clone();
        let pending = authenticate_installed_discovery(
            &manifest_race.root,
            &manifest_race.pins,
            &manifest_race.discovery,
            &manifest_race.discovery_signature,
            &|| false,
            move |_, _, _, _, _| Ok(valid_output(&fingerprint)),
        )
        .unwrap();
        let fingerprint = manifest_race.fingerprint.clone();
        assert!(authenticate_installed_manifest(
            pending,
            &manifest_race.manifest,
            &manifest_race.manifest_signature,
            &|| false,
            |_, _, _, _, _| {
                let path = manifest_race.root.join(POLICY_FILENAME);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&path, b"policy-replaced-during-manifest-verification").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(TRUST_FILE_MODE)).unwrap();
                Ok(valid_output(&fingerprint))
            },
        )
        .is_err());

        let cancelled = Fixture::create("cancelled");
        let polls = AtomicU64::new(0);
        assert!(authenticate_installed_discovery(
            &cancelled.root,
            &cancelled.pins,
            &cancelled.discovery,
            &cancelled.discovery_signature,
            &|| polls.fetch_add(1, Ordering::SeqCst) >= 1,
            |_, _, _, _, _| unreachable!(),
        )
        .is_err());
    }

    #[test]
    fn self_consistent_replacement_cannot_authorize_its_own_hashes() {
        let trusted = Fixture::create("trusted-pins");
        let replacement = Fixture::create("replacement-pins");
        let checkpoint_path = replacement.root.join(CHECKPOINT_FILENAME);
        fs::set_permissions(&checkpoint_path, fs::Permissions::from_mode(0o600)).unwrap();
        let replacement_policy = fs::read(replacement.root.join(POLICY_FILENAME)).unwrap();
        let self_consistent = canonical(&BootstrapCheckpoint {
            schema_version: 1,
            kind: "opemos-userspace-lock-bootstrap-checkpoint".into(),
            policy_sha256: sha256(&replacement_policy),
            minimum_sequence: 2,
            minimum_manifest_sha256: "b".repeat(64),
        });
        fs::write(&checkpoint_path, &self_consistent).unwrap();
        fs::set_permissions(
            &checkpoint_path,
            fs::Permissions::from_mode(TRUST_FILE_MODE),
        )
        .unwrap();
        assert!(authenticate_installed_discovery(
            &replacement.root,
            &trusted.pins,
            &replacement.discovery,
            &replacement.discovery_signature,
            &|| false,
            |_, _, _, _, _| Ok(valid_output(&replacement.fingerprint)),
        )
        .is_err());
    }

    #[test]
    fn trust_rotation_before_pending_save_is_rejected_under_cache_lock() {
        let fixture = Fixture::create("activation-rotation");
        let (generation, checkpoint) = fixture.authenticate().unwrap();
        let cache_root = temporary_root("activation-cache");
        let cache = CoreGenerationCache::open(&cache_root).unwrap();
        let identity = stage_generation(&cache, &generation, &fixture);
        let target = generation.generation().manifest().target_locks[0]
            .target
            .clone();
        let final_hook_seen = AtomicBool::new(false);
        let trust_rotated = AtomicBool::new(false);
        let result = begin_installed_authenticated_activation_with_hook(
            &cache,
            &generation,
            &checkpoint,
            &target,
            &[],
            "activate-installed-trust",
            || {
                if final_hook_seen.load(Ordering::SeqCst)
                    && !trust_rotated.swap(true, Ordering::SeqCst)
                {
                    let path = fixture.root.join(KEYRING_FILENAME);
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&path, b"rotated-by-final-cancellation-poll").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(TRUST_FILE_MODE))
                        .unwrap();
                }
                false
            },
            |phase| {
                if phase == "final-cancellation-boundary" {
                    final_hook_seen.store(true, Ordering::SeqCst);
                }
            },
        );
        assert!(trust_rotated.load(Ordering::SeqCst));
        assert!(result.is_err());
        assert_eq!(
            cache.load_state().unwrap(),
            CoreGenerationCacheState::default()
        );
        assert!(cache_root
            .join("generations")
            .join(identity.generation_id)
            .is_dir());
        make_writable(&cache_root);
        fs::remove_dir_all(&cache_root).unwrap();
    }

    #[test]
    fn final_callback_cache_mutation_cannot_publish_or_confirm_pending_state() {
        let fixture = Fixture::create("activation-cache-race");
        let (generation, checkpoint) = fixture.authenticate().unwrap();
        let target = generation.generation().manifest().target_locks[0]
            .target
            .clone();

        let first_root = temporary_root("activation-cache-first-race");
        let first_cache = CoreGenerationCache::open(&first_root).unwrap();
        let first_identity = stage_generation(&first_cache, &generation, &fixture);
        let final_seen = AtomicBool::new(false);
        let mutated = AtomicBool::new(false);
        let result = begin_installed_authenticated_activation_with_hook(
            &first_cache,
            &generation,
            &checkpoint,
            &target,
            &[],
            "activate-cache-race",
            || {
                if final_seen.load(Ordering::SeqCst) && !mutated.swap(true, Ordering::SeqCst) {
                    mutate_cached_payload(&first_root, &first_identity);
                }
                false
            },
            |phase| {
                if phase == "final-cancellation-boundary" {
                    final_seen.store(true, Ordering::SeqCst);
                }
            },
        );
        assert!(mutated.load(Ordering::SeqCst));
        assert!(result.is_err());
        assert_eq!(
            first_cache.load_state().unwrap(),
            CoreGenerationCacheState::default()
        );
        make_writable(&first_root);
        fs::remove_dir_all(&first_root).unwrap();

        let repeat_root = temporary_root("activation-cache-repeat-race");
        let repeat_cache = CoreGenerationCache::open(&repeat_root).unwrap();
        let repeat_identity = stage_generation(&repeat_cache, &generation, &fixture);
        let pending = begin_installed_authenticated_activation(
            &repeat_cache,
            &generation,
            &checkpoint,
            &target,
            &[],
            "activate-repeat-race",
            || false,
        )
        .unwrap();
        let repeat_seen = AtomicBool::new(false);
        let repeat_mutated = AtomicBool::new(false);
        let repeated = begin_installed_authenticated_activation_with_hook(
            &repeat_cache,
            &generation,
            &checkpoint,
            &target,
            &[],
            "activate-repeat-race",
            || {
                if repeat_seen.load(Ordering::SeqCst)
                    && !repeat_mutated.swap(true, Ordering::SeqCst)
                {
                    mutate_cached_payload(&repeat_root, &repeat_identity);
                }
                false
            },
            |phase| {
                if phase == "before-idempotent-return" {
                    repeat_seen.store(true, Ordering::SeqCst);
                }
            },
        );
        assert!(repeat_mutated.load(Ordering::SeqCst));
        assert!(repeated.is_err());
        assert_eq!(repeat_cache.load_state().unwrap(), pending);
        make_writable(&repeat_root);
        fs::remove_dir_all(&repeat_root).unwrap();
    }

    #[test]
    fn fixture_keeps_expected_trust_bytes() {
        let fixture = Fixture::create("bytes");
        assert_eq!(
            fs::read(fixture.root.join(POLICY_FILENAME)).unwrap(),
            fixture.policy
        );
        assert_eq!(
            fs::read(fixture.root.join(KEYRING_FILENAME)).unwrap(),
            fixture.keyring
        );
        assert_eq!(
            fs::read(fixture.root.join(CHECKPOINT_FILENAME)).unwrap(),
            fixture.checkpoint
        );
    }
}
