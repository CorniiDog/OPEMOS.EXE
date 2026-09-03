//! Inactive, test-only host-cache to appliance handoff staging.
//!
//! This bridge owns only EXE host lifecycle: it snapshots an already
//! authenticated, pending host-cache generation into a private destination and
//! atomically exposes a descriptor-bound handoff. It contains no guest
//! installer contract, production QEMU/Tauri wiring, network path, or legacy
//! bundle fallback.

use super::{
    activation::{expected_authenticated_inventory, verify_authenticated_inventory},
    physical_reservation_bytes, pin_generation_directory, probe_statvfs_capacity,
    require_pinned_generation_directory, require_storage_admission, safe_operation_id,
    CoreGenerationCache, CoreGenerationCacheState, CoreGenerationIdentity, CACHE_TRANSACTION_LOCK,
};
use crate::{
    core_generation_bootstrap::{
        installed_trust::{
            revalidate_installed_capabilities, InstalledAuthenticatedCheckpoint,
            InstalledAuthenticatedGeneration,
        },
        validate_authenticated_bootstrap_activation,
    },
    core_generation_contracts::{
        DurableGenerationIdentity, GenerationActivationState, GenerationTarget,
        MAX_GENERATION_STORAGE_BYTES, MAX_LINEAGE_GENERATIONS,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString, OsStr},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        io::{AsRawFd, FromRawFd as _},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const HANDOFF_SCHEMA: u32 = 1;
const HANDOFF_KIND: &str = "opemos-core-appliance-generation-handoff";
const HANDOFF_FILENAME: &str = "opemos-core-generation-handoff-v1.json";
const DESTINATION_DIRECTORY_MODE: u32 = 0o700;
const HANDOFF_DIRECTORY_MODE: u32 = 0o500;
const HANDOFF_FILE_MODE: u32 = 0o400;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const HANDOFF_RECORD_MAX_BYTES: usize = 256 * 1024;
const DESTINATION_LOCK_FILENAME: &str = "handoff.lock";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct DestinationLock {
    file: File,
    identity: (u64, u64, u32, u32, u64, u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandoffFileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl HandoffFileIdentity {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            nlink: metadata.nlink(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

struct PinnedHandoffFile {
    name: CString,
    file: File,
    identity: HandoffFileIdentity,
}

impl PinnedHandoffFile {
    fn revalidate(&self, parent: &File) -> Result<(), String> {
        if handoff_file_identity(&self.file)? != self.identity {
            return Err("Appliance handoff file changed during verification.".into());
        }
        let reopened = open_handoff_file(parent, &self.name)?;
        if handoff_file_identity(&reopened)? != self.identity {
            return Err("Appliance handoff file identity changed during verification.".into());
        }
        Ok(())
    }
}

impl DestinationLock {
    fn revalidate(&self, destination: &File) -> Result<(), String> {
        let current = lock_file_identity(&self.file)?;
        if current != self.identity {
            return Err("Appliance handoff lock descriptor changed.".into());
        }
        let name = CString::new(DESTINATION_LOCK_FILENAME).unwrap();
        let reopened = open_lock_file(destination, &name)?;
        if lock_file_identity(&reopened)? != self.identity {
            return Err("Appliance handoff lock identity changed.".into());
        }
        Ok(())
    }
}

impl DirectoryIdentity {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplianceHandoffRecord {
    schema_version: u32,
    kind: String,
    operation_id: String,
    identity: CoreGenerationIdentity,
    target: GenerationTarget,
    lineage_manifest_sha256: Vec<String>,
    files: Vec<ApplianceHandoffFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplianceHandoffFile {
    filename: String,
    size: u64,
    sha256: String,
}

/// Descriptor-backed proof of one exact, atomically exposed handoff. There is
/// deliberately no raw destination path accessor or deserializer.
pub(crate) struct StagedApplianceGeneration<'a> {
    cache: &'a CoreGenerationCache,
    generation: &'a InstalledAuthenticatedGeneration,
    checkpoint: &'a InstalledAuthenticatedCheckpoint,
    lineage: Vec<&'a InstalledAuthenticatedGeneration>,
    expected_state: CoreGenerationCacheState,
    identity: CoreGenerationIdentity,
    operation_id: String,
    root: File,
    root_path: PathBuf,
    root_identity: DirectoryIdentity,
    directory: File,
    directory_name: CString,
    directory_identity: DirectoryIdentity,
    record: ApplianceHandoffRecord,
    inventory: BTreeMap<String, (u64, String)>,
    retired: bool,
    _seal: StagedApplianceGenerationSeal,
}

struct StagedApplianceGenerationSeal;

impl StagedApplianceGeneration<'_> {
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        if self.retired {
            return Err("Appliance handoff has already been retired.".into());
        }
        let _process_guard = CACHE_TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _cache_guard = self.cache.acquire_lock()?;
        require_exact_pending_state(
            self.cache,
            &self.expected_state,
            &self.identity,
            &self.operation_id,
        )?;
        revalidate_installed_capabilities(
            self.generation,
            self.checkpoint,
            &self.lineage,
            &|| false,
        )?;
        require_destination_root(&self.root_path, &self.root, self.root_identity)?;
        let destination_guard = acquire_destination_lock(&self.root, &|| false)?;
        destination_guard.revalidate(&self.root)?;
        let reopened = open_directory_at(&self.root, &self.directory_name)?;
        require_directory_metadata(
            &reopened,
            self.directory_identity,
            HANDOFF_DIRECTORY_MODE,
            "staged appliance handoff",
        )?;
        require_directory_metadata(
            &self.directory,
            self.directory_identity,
            HANDOFF_DIRECTORY_MODE,
            "staged appliance handoff",
        )?;
        verify_published_handoff(&self.directory, &self.record, &self.inventory, &|| false)?;
        require_exact_pending_state(
            self.cache,
            &self.expected_state,
            &self.identity,
            &self.operation_id,
        )?;
        revalidate_installed_capabilities(
            self.generation,
            self.checkpoint,
            &self.lineage,
            &|| false,
        )?;
        require_destination_root(&self.root_path, &self.root, self.root_identity)?;
        destination_guard.revalidate(&self.root)
    }

    /// Explicitly retires the descriptor-bound handoff after the owning guest
    /// lifecycle has completed. Production guest wiring must call this on
    /// success, failure, and cancellation; crash reconciliation remains a
    /// separate prerequisite.
    pub(crate) fn retire(&mut self) -> Result<(), String> {
        if self.retired {
            return Ok(());
        }
        require_destination_root(&self.root_path, &self.root, self.root_identity)?;
        let destination_guard = acquire_destination_lock(&self.root, &|| false)?;
        destination_guard.revalidate(&self.root)?;
        if directory_missing_at(&self.root, &self.directory_name)? {
            let metadata = self.directory.metadata().map_err(|error| {
                format!("Could not inspect unlinked appliance handoff: {error}")
            })?;
            if metadata.nlink() != 0 {
                return Err("Appliance handoff path changed before retirement.".into());
            }
            self.root
                .sync_all()
                .map_err(|error| format!("Could not sync retired appliance handoff: {error}"))?;
            self.retired = true;
            return Ok(());
        }
        remove_owned_directory_at(
            &self.root,
            &self.directory_name,
            self.directory_identity,
            self.inventory.len().saturating_add(2),
        )?;
        self.retired = true;
        Ok(())
    }
}

/// Stages one exact pending generation without changing host-cache state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn stage_pending_generation_for_appliance<'a, C>(
    cache: &'a CoreGenerationCache,
    generation: &'a InstalledAuthenticatedGeneration,
    checkpoint: &'a InstalledAuthenticatedCheckpoint,
    expected_target: &GenerationTarget,
    lineage: &[&'a InstalledAuthenticatedGeneration],
    operation_id: &str,
    destination_root: &Path,
    cancelled: C,
) -> Result<StagedApplianceGeneration<'a>, String>
where
    C: Fn() -> bool,
{
    stage_pending_generation_for_appliance_with_hook(
        cache,
        generation,
        checkpoint,
        expected_target,
        lineage,
        operation_id,
        destination_root,
        cancelled,
        |_| {},
    )
}

#[allow(clippy::too_many_arguments)]
fn stage_pending_generation_for_appliance_with_hook<'a, C, H>(
    cache: &'a CoreGenerationCache,
    generation: &'a InstalledAuthenticatedGeneration,
    checkpoint: &'a InstalledAuthenticatedCheckpoint,
    expected_target: &GenerationTarget,
    lineage: &[&'a InstalledAuthenticatedGeneration],
    operation_id: &str,
    destination_root: &Path,
    cancelled: C,
    mut hook: H,
) -> Result<StagedApplianceGeneration<'a>, String>
where
    C: Fn() -> bool,
    H: FnMut(&'static str),
{
    poll_cancelled(&cancelled)?;
    if !safe_operation_id(operation_id) {
        return Err("Core appliance handoff operation identity is invalid.".into());
    }
    if lineage.len() > MAX_LINEAGE_GENERATIONS {
        return Err("Authenticated lineage exceeds its generation limit.".into());
    }
    let inventory = expected_authenticated_inventory(generation.generation())?;
    let total_bytes = inventory.values().try_fold(0_u64, |total, (size, _)| {
        total
            .checked_add(*size)
            .ok_or("Core appliance handoff size overflowed.")
    })?;
    if total_bytes == 0 || total_bytes > MAX_GENERATION_STORAGE_BYTES {
        return Err("Core appliance handoff size is invalid.".into());
    }

    let raw_lineage = lineage
        .iter()
        .map(|item| item.generation())
        .collect::<Vec<_>>();
    let _process_guard = CACHE_TRANSACTION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _cache_guard = cache.acquire_lock()?;
    hook("after-cache-lock");
    poll_cancelled(&cancelled)?;
    revalidate_installed_capabilities(generation, checkpoint, lineage, &cancelled)?;

    let state = cache.load_state_unlocked()?;
    let authorized = validate_authenticated_bootstrap_activation(
        generation.generation(),
        checkpoint.checkpoint(),
        expected_target,
        &GenerationActivationState {
            high_water_sequence: state.high_water_sequence,
            active: state
                .active
                .as_ref()
                .map(|identity| DurableGenerationIdentity {
                    sequence: identity.sequence,
                    manifest_sha256: identity.manifest_sha256.clone(),
                }),
        },
        &raw_lineage,
    )?;
    let identity = CoreGenerationIdentity {
        sequence: authorized.sequence,
        generation_id: authorized.manifest_sha256.clone(),
        manifest_sha256: authorized.manifest_sha256,
    };
    require_exact_pending(&state, &identity, operation_id)?;

    let source_path = cache.generation_path(&identity)?;
    let source = pin_generation_directory(&source_path, "appliance handoff source generation")?;
    cache.require_generation_committed(&identity)?;
    cache.require_unique_committed_sequence(&identity)?;
    verify_authenticated_inventory(&source, &inventory, &cancelled)?;
    require_pinned_generation_directory(
        &source_path,
        &source,
        "appliance handoff source generation",
    )?;
    hook("after-source-verification");

    let (destination, destination_identity) = open_destination_root(destination_root)?;
    let destination_guard = acquire_destination_lock(&destination, &cancelled)?;
    destination_guard.revalidate(&destination)?;
    require_destination_root(destination_root, &destination, destination_identity)?;
    let directory_basename = format!("handoff-{}-{}", operation_id, identity.manifest_sha256);
    let directory_name = CString::new(directory_basename)
        .map_err(|_| "Core appliance handoff destination name is unsafe.".to_string())?;
    let record = build_handoff_record(
        operation_id,
        identity.clone(),
        expected_target.clone(),
        lineage,
        &inventory,
    );
    let record_bytes = canonical_record(&record)?;

    if let Ok(existing) = open_directory_at(&destination, &directory_name) {
        let existing_identity = private_directory_identity(
            &existing,
            HANDOFF_DIRECTORY_MODE,
            "existing appliance handoff",
        )?;
        verify_published_handoff(&existing, &record, &inventory, &cancelled)?;
        require_destination_root(destination_root, &destination, destination_identity)?;
        destination_guard.revalidate(&destination)?;
        require_exact_pending_state(cache, &state, &identity, operation_id)?;
        revalidate_installed_capabilities(generation, checkpoint, lineage, &|| false)?;
        require_destination_root(destination_root, &destination, destination_identity)?;
        destination_guard.revalidate(&destination)?;
        return Ok(StagedApplianceGeneration {
            cache,
            generation,
            checkpoint,
            lineage: lineage.to_vec(),
            expected_state: state,
            identity,
            operation_id: operation_id.into(),
            root: destination,
            root_path: destination_root.to_path_buf(),
            root_identity: destination_identity,
            directory: existing,
            directory_name,
            directory_identity: existing_identity,
            record,
            inventory,
            retired: false,
            _seal: StagedApplianceGenerationSeal,
        });
    }

    let logical_bytes = total_bytes
        .checked_add(record_bytes.len() as u64)
        .ok_or("Core appliance handoff size overflowed.")?;
    let file_nodes = u64::try_from(inventory.len())
        .ok()
        .and_then(|count| count.checked_add(2))
        .ok_or("Core appliance handoff file count overflowed.")?;
    let capacity = probe_statvfs_capacity(&destination)
        .map_err(|error| storage_error("Could not inspect appliance handoff capacity", error))?;
    let physical_bytes =
        physical_reservation_bytes(logical_bytes, file_nodes, capacity.allocation_unit_bytes)?;
    require_storage_admission(capacity, physical_bytes, file_nodes, 0, 0)
        .map_err(|error| error.replace("Core generation cache", "Core appliance handoff"))?;

    let stage_name = CString::new(format!(".handoff-{}-{}.tmp", operation_id, random_token()?))
        .map_err(|_| "Core appliance staging name is unsafe.".to_string())?;
    let (stage, stage_identity) = create_staging_directory_at(&destination, &stage_name)?;
    let published = Cell::new(false);
    let result = (|| {
        for (name, (size, hash)) in &inventory {
            poll_cancelled(&cancelled)?;
            copy_inventory_file(&source.file, &stage, name, *size, hash, &cancelled)?;
        }
        hook("after-copy");
        poll_cancelled(&cancelled)?;
        create_exact_file(&stage, HANDOFF_FILENAME, &record_bytes)?;
        stage
            .sync_all()
            .map_err(|error| format!("Could not sync staged appliance handoff: {error}"))?;
        require_destination_root(destination_root, &destination, destination_identity)?;
        destination_guard.revalidate(&destination)?;
        require_staging_directory(&destination, &stage_name, &stage, stage_identity)?;
        destination_guard.revalidate(&destination)?;
        verify_published_handoff(&stage, &record, &inventory, &cancelled)?;
        verify_authenticated_inventory(&source, &inventory, &cancelled)?;
        require_pinned_generation_directory(
            &source_path,
            &source,
            "appliance handoff source generation",
        )?;
        cache.require_generation_committed(&identity)?;
        cache.require_unique_committed_sequence(&identity)?;
        require_exact_pending_state(cache, &state, &identity, operation_id)?;
        revalidate_installed_capabilities(generation, checkpoint, lineage, &cancelled)?;
        hook("before-publish");
        hook("final-cancellation-boundary");
        poll_cancelled(&cancelled)?;

        // No caller-controlled work occurs after this point. Recheck every
        // authority and identity non-cancellably, then publish atomically.
        verify_authenticated_inventory(&source, &inventory, &|| false)?;
        require_pinned_generation_directory(
            &source_path,
            &source,
            "appliance handoff source generation",
        )?;
        cache.require_generation_committed(&identity)?;
        cache.require_unique_committed_sequence(&identity)?;
        require_exact_pending_state(cache, &state, &identity, operation_id)?;
        revalidate_installed_capabilities(generation, checkpoint, lineage, &|| false)?;
        require_destination_root(destination_root, &destination, destination_identity)?;
        require_staging_directory(&destination, &stage_name, &stage, stage_identity)?;
        set_directory_mode(&stage, HANDOFF_DIRECTORY_MODE)?;
        let sealed_identity =
            private_directory_identity(&stage, HANDOFF_DIRECTORY_MODE, "sealed appliance handoff")?;
        destination_guard.revalidate(&destination)?;
        rename_directory_at(&destination, &stage_name, &directory_name)?;
        published.set(true);
        destination
            .sync_all()
            .map_err(|error| format!("Could not sync appliance handoff destination: {error}"))?;
        destination_guard.revalidate(&destination)?;
        require_destination_root(destination_root, &destination, destination_identity)?;
        let published = open_directory_at(&destination, &directory_name)?;
        let published_identity = private_directory_identity(
            &published,
            HANDOFF_DIRECTORY_MODE,
            "published appliance handoff",
        )?;
        if published_identity.device != sealed_identity.device
            || published_identity.inode != sealed_identity.inode
            || published_identity.uid != sealed_identity.uid
            || published_identity.mode != sealed_identity.mode
        {
            return Err("Published appliance handoff identity changed.".into());
        }
        verify_published_handoff(&published, &record, &inventory, &|| false)?;
        verify_authenticated_inventory(&source, &inventory, &|| false)?;
        require_pinned_generation_directory(
            &source_path,
            &source,
            "appliance handoff source generation",
        )?;
        require_exact_pending_state(cache, &state, &identity, operation_id)?;
        revalidate_installed_capabilities(generation, checkpoint, lineage, &|| false)?;
        require_destination_root(destination_root, &destination, destination_identity)?;
        destination_guard.revalidate(&destination)?;
        Ok((published, published_identity))
    })();

    match result {
        Ok((directory, directory_identity)) => Ok(StagedApplianceGeneration {
            cache,
            generation,
            checkpoint,
            lineage: lineage.to_vec(),
            expected_state: state,
            identity,
            operation_id: operation_id.into(),
            root: destination,
            root_path: destination_root.to_path_buf(),
            root_identity: destination_identity,
            directory,
            directory_name,
            directory_identity,
            record,
            inventory,
            retired: false,
            _seal: StagedApplianceGenerationSeal,
        }),
        Err(primary) => {
            let cleanup_name = if published.get() {
                &directory_name
            } else {
                &stage_name
            };
            let cleanup = remove_owned_directory_at(
                &destination,
                cleanup_name,
                stage_identity,
                inventory.len().saturating_add(2),
            );
            match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(format!("{primary} Cleanup failed: {cleanup}")),
            }
        }
    }
}

fn require_exact_pending(
    state: &CoreGenerationCacheState,
    identity: &CoreGenerationIdentity,
    operation_id: &str,
) -> Result<(), String> {
    if state.pending.as_ref() != Some(identity)
        || state.pending_operation_id.as_deref() != Some(operation_id)
    {
        return Err("Core appliance handoff does not match the pending cache operation.".into());
    }
    Ok(())
}

fn require_exact_pending_state(
    cache: &CoreGenerationCache,
    expected_state: &CoreGenerationCacheState,
    identity: &CoreGenerationIdentity,
    operation_id: &str,
) -> Result<(), String> {
    let current = cache.load_state_unlocked()?;
    require_exact_pending(&current, identity, operation_id)?;
    if &current != expected_state {
        return Err("Core generation cache state changed during appliance staging.".into());
    }
    Ok(())
}

fn build_handoff_record(
    operation_id: &str,
    identity: CoreGenerationIdentity,
    target: GenerationTarget,
    lineage: &[&InstalledAuthenticatedGeneration],
    inventory: &BTreeMap<String, (u64, String)>,
) -> ApplianceHandoffRecord {
    ApplianceHandoffRecord {
        schema_version: HANDOFF_SCHEMA,
        kind: HANDOFF_KIND.into(),
        operation_id: operation_id.into(),
        identity,
        target,
        lineage_manifest_sha256: lineage
            .iter()
            .map(|item| {
                item.generation()
                    .discovery()
                    .generation
                    .manifest_sha256
                    .clone()
            })
            .collect(),
        files: inventory
            .iter()
            .map(|(filename, (size, sha256))| ApplianceHandoffFile {
                filename: filename.clone(),
                size: *size,
                sha256: sha256.clone(),
            })
            .collect(),
    }
}

fn canonical_record(record: &ApplianceHandoffRecord) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(record)
        .map_err(|error| format!("Could not encode appliance handoff record: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() > HANDOFF_RECORD_MAX_BYTES {
        return Err("Core appliance handoff record exceeds its size limit.".into());
    }
    Ok(bytes)
}

fn open_destination_root(path: &Path) -> Result<(File, DirectoryIdentity), String> {
    if !path.is_absolute() {
        return Err("Core appliance handoff destination must be absolute.".into());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect appliance handoff destination: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Core appliance handoff destination must be a real directory.".into());
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let directory = options
        .open(path)
        .map_err(|error| format!("Could not open appliance handoff destination: {error}"))?;
    let identity = private_directory_identity(
        &directory,
        DESTINATION_DIRECTORY_MODE,
        "appliance handoff destination",
    )?;
    if metadata.dev() != identity.device || metadata.ino() != identity.inode {
        return Err("Core appliance handoff destination changed while opening.".into());
    }
    Ok((directory, identity))
}

fn require_destination_root(
    path: &Path,
    directory: &File,
    expected: DirectoryIdentity,
) -> Result<(), String> {
    let observed = private_directory_identity(
        directory,
        DESTINATION_DIRECTORY_MODE,
        "appliance handoff destination",
    )?;
    if observed.device != expected.device
        || observed.inode != expected.inode
        || observed.uid != expected.uid
        || observed.mode != expected.mode
    {
        return Err("Core appliance handoff destination identity changed.".into());
    }
    let current = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not recheck appliance handoff destination: {error}"))?;
    if current.file_type().is_symlink()
        || !current.is_dir()
        || current.dev() != expected.device
        || current.ino() != expected.inode
    {
        return Err("Core appliance handoff destination identity changed.".into());
    }
    Ok(())
}

fn private_directory_identity(
    directory: &File,
    mode: u32,
    description: &str,
) -> Result<DirectoryIdentity, String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("Could not identify {description}: {error}"))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(format!("{description} ownership or mode is unsafe."));
    }
    Ok(DirectoryIdentity::from(&metadata))
}

fn require_directory_metadata(
    directory: &File,
    expected: DirectoryIdentity,
    mode: u32,
    description: &str,
) -> Result<(), String> {
    let observed = private_directory_identity(directory, mode, description)?;
    if observed != expected {
        return Err(format!("{description} identity changed."));
    }
    Ok(())
}

fn require_staging_directory(
    parent: &File,
    name: &CStr,
    directory: &File,
    expected: DirectoryIdentity,
) -> Result<(), String> {
    let opened = open_directory_at(parent, name)?;
    for candidate in [directory, &opened] {
        let observed = private_directory_identity(
            candidate,
            DESTINATION_DIRECTORY_MODE,
            "staged appliance handoff",
        )?;
        if observed.device != expected.device
            || observed.inode != expected.inode
            || observed.uid != expected.uid
            || observed.mode != expected.mode
        {
            return Err("Staged appliance handoff identity changed.".into());
        }
    }
    Ok(())
}

fn open_directory_at(parent: &File, name: &CStr) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not open appliance handoff directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn directory_missing_at(parent: &File, name: &CStr) -> Result<bool, String> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(true)
    } else {
        Err(format!(
            "Could not inspect retired appliance handoff: {error}"
        ))
    }
}

fn create_staging_directory_at(
    parent: &File,
    name: &CStr,
) -> Result<(File, DirectoryIdentity), String> {
    if unsafe {
        libc::mkdirat(
            parent.as_raw_fd(),
            name.as_ptr(),
            DESTINATION_DIRECTORY_MODE as libc::mode_t,
        )
    } != 0
    {
        return Err(format!(
            "Could not create appliance handoff directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut opened_identity = None;
    let result = (|| {
        let directory = open_directory_at(parent, name)?;
        let created_metadata = directory
            .metadata()
            .map_err(|error| format!("Could not identify staged appliance handoff: {error}"))?;
        let created_identity = DirectoryIdentity::from(&created_metadata);
        opened_identity = Some(created_identity);
        directory
            .set_permissions(fs::Permissions::from_mode(DESTINATION_DIRECTORY_MODE))
            .map_err(|error| format!("Could not secure staged appliance handoff: {error}"))?;
        let identity = private_directory_identity(
            &directory,
            DESTINATION_DIRECTORY_MODE,
            "staged appliance handoff",
        )?;
        opened_identity = Some(identity);
        parent
            .sync_all()
            .map_err(|error| format!("Could not sync appliance handoff destination: {error}"))?;
        require_staging_directory(parent, name, &directory, identity)?;
        Ok((directory, identity))
    })();
    match result {
        Ok(created) => Ok(created),
        Err(primary) => {
            let cleanup = if let Some(identity) = opened_identity {
                remove_owned_directory_at(parent, name, identity, 1)
            } else if unsafe {
                libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
            } == 0
            {
                parent.sync_all().map_err(|error| {
                    format!("Could not sync appliance handoff setup cleanup: {error}")
                })
            } else {
                Err(format!(
                    "Could not remove unowned appliance handoff setup: {}",
                    std::io::Error::last_os_error()
                ))
            };
            match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(format!("{primary} Cleanup failed: {cleanup}")),
            }
        }
    }
}

fn set_directory_mode(directory: &File, mode: u32) -> Result<(), String> {
    directory
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| format!("Could not seal appliance handoff directory: {error}"))?;
    directory
        .sync_all()
        .map_err(|error| format!("Could not sync sealed appliance handoff directory: {error}"))
}

fn rename_directory_at(parent: &File, source: &CStr, destination: &CStr) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result = -1;
    if result != 0 {
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err("Atomic create-only appliance handoff publication is unsupported.".into());
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        return Err(format!(
            "Could not publish appliance handoff: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn copy_inventory_file<C>(
    source: &File,
    destination: &File,
    name: &str,
    expected_size: u64,
    expected_hash: &str,
    cancelled: &C,
) -> Result<(), String>
where
    C: Fn() -> bool,
{
    let name_c = CString::new(name)
        .map_err(|_| "Authenticated generation filename is unsafe.".to_string())?;
    let source_fd = unsafe {
        libc::openat(
            source.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if source_fd < 0 {
        return Err(format!(
            "Could not open appliance handoff source file: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut source_file = unsafe { File::from_raw_fd(source_fd) };
    let before = source_file
        .metadata()
        .map_err(|error| format!("Could not inspect appliance handoff source file: {error}"))?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != HANDOFF_FILE_MODE
        || before.len() != expected_size
    {
        return Err("Appliance handoff source file metadata is invalid.".into());
    }

    let destination_fd = unsafe {
        libc::openat(
            destination.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if destination_fd < 0 {
        return Err(format!(
            "Could not create appliance handoff file: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut destination_file = unsafe { File::from_raw_fd(destination_fd) };
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        poll_cancelled(cancelled)?;
        let read = source_file
            .read(&mut buffer)
            .map_err(|error| format!("Could not read appliance handoff source file: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or("Appliance handoff file size overflowed.")?;
        if total > expected_size {
            return Err("Appliance handoff source file exceeds its declared size.".into());
        }
        destination_file
            .write_all(&buffer[..read])
            .map_err(|error| storage_error("Could not write appliance handoff file", error))?;
        digest.update(&buffer[..read]);
    }
    if total != expected_size || format!("{:x}", digest.finalize()) != expected_hash {
        return Err("Appliance handoff source file does not match authenticated inventory.".into());
    }
    destination_file
        .sync_all()
        .map_err(|error| storage_error("Could not sync appliance handoff file", error))?;
    destination_file
        .set_permissions(fs::Permissions::from_mode(HANDOFF_FILE_MODE))
        .map_err(|error| format!("Could not seal appliance handoff file: {error}"))?;
    destination_file
        .sync_all()
        .map_err(|error| storage_error("Could not sync sealed appliance handoff file", error))?;
    let after = source_file
        .metadata()
        .map_err(|error| format!("Could not recheck appliance handoff source file: {error}"))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.nlink() != after.nlink()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("Appliance handoff source file changed while copying.".into());
    }
    verify_exact_file(destination, name, expected_size, expected_hash, cancelled).map(|_| ())
}

fn create_exact_file(parent: &File, name: &str, bytes: &[u8]) -> Result<(), String> {
    let name =
        CString::new(name).map_err(|_| "Appliance handoff filename is unsafe.".to_string())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not create appliance handoff record: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .map_err(|error| storage_error("Could not write appliance handoff record", error))?;
    file.sync_all()
        .map_err(|error| storage_error("Could not sync appliance handoff record", error))?;
    file.set_permissions(fs::Permissions::from_mode(HANDOFF_FILE_MODE))
        .map_err(|error| format!("Could not seal appliance handoff record: {error}"))?;
    file.sync_all()
        .map_err(|error| storage_error("Could not sync sealed appliance handoff record", error))
}

fn verify_published_handoff(
    directory: &File,
    expected_record: &ApplianceHandoffRecord,
    inventory: &BTreeMap<String, (u64, String)>,
    cancelled: &impl Fn() -> bool,
) -> Result<(), String> {
    let before = handoff_directory_snapshot(directory)?;
    let mut pinned_files = Vec::with_capacity(inventory.len().saturating_add(1));
    let expected_record_bytes = canonical_record(expected_record)?;
    let expected_count = inventory.len().saturating_add(1);
    let names = directory_names(directory, expected_count.saturating_add(1))?;
    if names.len() != expected_count {
        return Err("Appliance handoff inventory is not exact.".into());
    }
    let mut folded = BTreeSet::new();
    for name in &names {
        let name = name
            .to_str()
            .ok_or("Appliance handoff filename is not UTF-8.")?;
        if !folded.insert(name.to_ascii_lowercase()) {
            return Err("Appliance handoff inventory contains a filename collision.".into());
        }
    }
    for (name, (size, hash)) in inventory {
        if !names.iter().any(|actual| actual == OsStr::new(name)) {
            return Err("Appliance handoff inventory is incomplete.".into());
        }
        pinned_files.push(verify_exact_file(directory, name, *size, hash, cancelled)?);
    }
    if !names
        .iter()
        .any(|actual| actual == OsStr::new(HANDOFF_FILENAME))
    {
        return Err("Appliance handoff record is missing.".into());
    }
    pinned_files.push(verify_exact_file(
        directory,
        HANDOFF_FILENAME,
        expected_record_bytes.len() as u64,
        &sha256(&expected_record_bytes),
        cancelled,
    )?);
    let actual = read_exact_file(directory, HANDOFF_FILENAME, HANDOFF_RECORD_MAX_BYTES)?;
    if actual != expected_record_bytes {
        return Err("Appliance handoff record is not canonical or exact.".into());
    }
    let parsed: ApplianceHandoffRecord = serde_json::from_slice(&actual)
        .map_err(|_| "Appliance handoff record is malformed.".to_string())?;
    if parsed != *expected_record {
        return Err("Appliance handoff record identity does not match.".into());
    }
    for pinned in &pinned_files {
        pinned.revalidate(directory)?;
    }
    let after = handoff_directory_snapshot(directory)?;
    if before != after {
        return Err("Appliance handoff directory changed during verification.".into());
    }
    Ok(())
}

fn handoff_directory_snapshot(directory: &File) -> Result<DirectoryIdentity, String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("Could not inspect appliance handoff directory: {error}"))?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || (mode != DESTINATION_DIRECTORY_MODE && mode != HANDOFF_DIRECTORY_MODE)
    {
        return Err("Appliance handoff directory ownership or mode is unsafe.".into());
    }
    Ok(DirectoryIdentity::from(&metadata))
}

fn acquire_destination_lock<C>(destination: &File, cancelled: &C) -> Result<DestinationLock, String>
where
    C: Fn() -> bool,
{
    let name = CString::new(DESTINATION_LOCK_FILENAME).unwrap();
    let create = unsafe {
        libc::openat(
            destination.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    let (file, created) = if create >= 0 {
        (unsafe { File::from_raw_fd(create) }, true)
    } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
        let opened = unsafe {
            libc::openat(
                destination.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if opened < 0 {
            return Err(format!(
                "Could not open appliance handoff lock: {}",
                std::io::Error::last_os_error()
            ));
        }
        (unsafe { File::from_raw_fd(opened) }, false)
    } else {
        return Err(format!(
            "Could not create appliance handoff lock: {}",
            std::io::Error::last_os_error()
        ));
    };
    if created {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Could not secure appliance handoff lock: {error}"))?;
        file.sync_all()
            .map_err(|error| storage_error("Could not sync appliance handoff lock", error))?;
        destination
            .sync_all()
            .map_err(|error| storage_error("Could not sync appliance handoff lock entry", error))?;
    }
    let identity = lock_file_identity(&file)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        poll_cancelled(cancelled)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Err(format!(
                "Could not lock appliance handoff destination: {error}"
            ));
        }
        if Instant::now() >= deadline {
            return Err("Timed out locking the appliance handoff destination.".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let guard = DestinationLock { file, identity };
    guard.revalidate(destination)?;
    Ok(guard)
}

fn open_lock_file(destination: &File, name: &CStr) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            destination.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not open appliance handoff lock: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn lock_file_identity(file: &File) -> Result<(u64, u64, u32, u32, u64, u64), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("Could not inspect appliance handoff lock: {error}"))?;
    let identity = (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.permissions().mode() & 0o7777,
        metadata.nlink(),
        metadata.len(),
    );
    if !metadata.is_file()
        || identity.2 != unsafe { libc::geteuid() }
        || identity.3 != 0o600
        || identity.4 != 1
        || identity.5 != 0
    {
        return Err("Appliance handoff lock metadata is unsafe.".into());
    }
    Ok(identity)
}

fn verify_exact_file(
    parent: &File,
    name: &str,
    expected_size: u64,
    expected_hash: &str,
    cancelled: &impl Fn() -> bool,
) -> Result<PinnedHandoffFile, String> {
    let name =
        CString::new(name).map_err(|_| "Appliance handoff filename is unsafe.".to_string())?;
    let mut file = open_handoff_file(parent, &name)?;
    let before = file
        .metadata()
        .map_err(|error| format!("Could not inspect appliance handoff file: {error}"))?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != HANDOFF_FILE_MODE
        || before.len() != expected_size
    {
        return Err("Appliance handoff file metadata is invalid.".into());
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        poll_cancelled(cancelled)?;
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("Could not read appliance handoff file: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or("Appliance handoff file size overflowed.")?;
        if total > expected_size {
            return Err("Appliance handoff file exceeds its declared size.".into());
        }
        digest.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(|error| format!("Could not recheck appliance handoff file: {error}"))?;
    if total != expected_size
        || format!("{:x}", digest.finalize()) != expected_hash
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.nlink() != after.nlink()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("Appliance handoff file does not match authenticated inventory.".into());
    }
    Ok(PinnedHandoffFile {
        name,
        file,
        identity: HandoffFileIdentity::from(&after),
    })
}

fn open_handoff_file(parent: &File, name: &CStr) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not open appliance handoff file: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn handoff_file_identity(file: &File) -> Result<HandoffFileIdentity, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("Could not identify appliance handoff file: {error}"))?;
    let identity = HandoffFileIdentity::from(&metadata);
    if !metadata.is_file()
        || identity.uid != unsafe { libc::geteuid() }
        || identity.nlink != 1
        || identity.mode != HANDOFF_FILE_MODE
    {
        return Err("Appliance handoff file metadata is invalid.".into());
    }
    Ok(identity)
}

fn read_exact_file(parent: &File, name: &str, limit: usize) -> Result<Vec<u8>, String> {
    let name =
        CString::new(name).map_err(|_| "Appliance handoff filename is unsafe.".to_string())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not open appliance handoff file: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let before = file
        .metadata()
        .map_err(|error| format!("Could not inspect appliance handoff file: {error}"))?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != HANDOFF_FILE_MODE
        || before.len() > limit as u64
    {
        return Err("Appliance handoff file metadata is invalid.".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read appliance handoff file: {error}"))?;
    if bytes.len() > limit {
        return Err("Appliance handoff file exceeds its size limit.".into());
    }
    let after = file
        .metadata()
        .map_err(|error| format!("Could not recheck appliance handoff file: {error}"))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.nlink() != after.nlink()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("Appliance handoff file changed while reading.".into());
    }
    Ok(bytes)
}

fn directory_names(directory: &File, limit: usize) -> Result<Vec<std::ffi::OsString>, String> {
    let dot = c".";
    let independent = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if independent < 0 {
        return Err(format!(
            "Could not independently open appliance handoff directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stream = unsafe { libc::fdopendir(independent) };
    if stream.is_null() {
        unsafe { libc::close(independent) };
        return Err(format!(
            "Could not enumerate appliance handoff directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut names = Vec::new();
    loop {
        set_errno(0);
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::closedir(stream) };
            if error.raw_os_error().unwrap_or(0) != 0 {
                return Err(format!(
                    "Could not enumerate appliance handoff directory: {error}"
                ));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        names.push(OsStr::from_bytes(name.to_bytes()).to_os_string());
        if names.len() > limit {
            unsafe { libc::closedir(stream) };
            return Err("Appliance handoff directory exceeds its entry limit.".into());
        }
    }
    Ok(names)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn set_errno(value: libc::c_int) {
    unsafe { *libc::__error() = value };
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn set_errno(value: libc::c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn remove_owned_directory_at(
    parent: &File,
    name: &CStr,
    expected: DirectoryIdentity,
    maximum_entries: usize,
) -> Result<(), String> {
    let directory = open_directory_at(parent, name)?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("Could not identify failed appliance handoff: {error}"))?;
    let observed = DirectoryIdentity::from(&metadata);
    if observed.device != expected.device || observed.inode != expected.inode {
        return Err("Failed appliance handoff identity changed before cleanup.".into());
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("Failed appliance handoff ownership or mode is unsafe.".into());
    }
    if mode != DESTINATION_DIRECTORY_MODE {
        directory
            .set_permissions(fs::Permissions::from_mode(DESTINATION_DIRECTORY_MODE))
            .map_err(|error| format!("Could not reopen failed appliance handoff: {error}"))?;
    }
    for child in directory_names(&directory, maximum_entries)? {
        let child = CString::new(child.as_bytes())
            .map_err(|_| "Failed appliance handoff filename is unsafe.".to_string())?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), child.as_ptr(), 0) } != 0 {
            return Err(format!(
                "Could not remove failed appliance handoff file: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    directory
        .sync_all()
        .map_err(|error| format!("Could not sync failed appliance handoff cleanup: {error}"))?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(format!(
            "Could not remove failed appliance handoff directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    parent
        .sync_all()
        .map_err(|error| format!("Could not sync appliance handoff cleanup: {error}"))
}

fn poll_cancelled(cancelled: &impl Fn() -> bool) -> Result<(), String> {
    if cancelled() {
        Err("Core appliance handoff was cancelled.".into())
    } else {
        Ok(())
    }
}

fn storage_error(context: &str, error: std::io::Error) -> String {
    if error.raw_os_error() == Some(libc::ENOSPC) || error.kind() == std::io::ErrorKind::StorageFull
    {
        format!("{context}: storage-admission-no-space: {error}")
    } else {
        format!("{context}: {error}")
    }
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .map_err(|error| format!("Could not create appliance handoff identity: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core_generation_bootstrap::{
            expected_generation_authority,
            installed_trust::{
                authenticate_installed_discovery, authenticate_installed_manifest,
                InstalledTrustPins, CHECKPOINT_FILENAME, KEYRING_FILENAME, POLICY_FILENAME,
            },
            BootstrapAuthority, BootstrapChannel, BootstrapCheckpoint, BootstrapCompatibility,
            BootstrapPolicy, BootstrapReplayPolicy,
        },
        core_generation_cache::activation::begin_installed_authenticated_activation,
        core_generation_contracts::{
            DiscoveryGeneration, GenerationCompatibility, GenerationDiscovery, GenerationFile,
            GenerationLock, GenerationManifest, GenerationTargetLock, DISCOVERY_FILENAME,
            DISCOVERY_SIGNATURE_FILENAME, DISCOVERY_SIGNATURE_SCHEME, OPENPGP_HASH_ALGORITHM_IDS,
        },
        core_generation_verifier::DetachedVerifierOutput,
    };
    use std::{
        os::unix::fs::symlink,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct PreparedFixture {
        base: PathBuf,
        cache: CoreGenerationCache,
        destination: PathBuf,
        generation: InstalledAuthenticatedGeneration,
        checkpoint: InstalledAuthenticatedCheckpoint,
        target: GenerationTarget,
        identity: CoreGenerationIdentity,
        operation: String,
    }

    impl PreparedFixture {
        fn create(name: &str) -> Self {
            let base = temporary_root(name);
            let trust = base.join("trust");
            let cache_root = base.join("cache");
            let destination = base.join("appliance");
            fs::create_dir_all(&trust).unwrap();
            fs::create_dir(&destination).unwrap();
            fs::set_permissions(&trust, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();

            let keyring = b"fixture-generation-keyring".to_vec();
            let fingerprint = "A".repeat(40);
            let policy_document = BootstrapPolicy {
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
            let policy = canonical(&policy_document);
            let authority = expected_generation_authority(&policy_document, &policy).unwrap();
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
                target: target.clone(),
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
            let discovery_document = GenerationDiscovery {
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
            };
            let discovery = canonical(&discovery_document);
            let discovery_signature = b"discovery-signature".to_vec();
            let checkpoint_document = BootstrapCheckpoint {
                schema_version: 1,
                kind: "opemos-userspace-lock-bootstrap-checkpoint".into(),
                policy_sha256: sha256(&policy),
                minimum_sequence: 1,
                minimum_manifest_sha256: manifest_hash.clone(),
            };
            let checkpoint_bytes = canonical(&checkpoint_document);
            let pins = InstalledTrustPins::fixture(&policy, &keyring, &checkpoint_bytes);
            write_private(&trust.join(POLICY_FILENAME), &policy);
            write_private(&trust.join(KEYRING_FILENAME), &keyring);
            write_private(&trust.join(CHECKPOINT_FILENAME), &checkpoint_bytes);

            let verifier_fingerprint = fingerprint.clone();
            let pending = authenticate_installed_discovery(
                &trust,
                &pins,
                &discovery,
                &discovery_signature,
                &|| false,
                move |_, _, _, _, _| Ok(valid_output(&verifier_fingerprint)),
            )
            .unwrap();
            let verifier_fingerprint = fingerprint;
            let (generation, checkpoint) = authenticate_installed_manifest(
                pending,
                &manifest,
                &manifest_signature,
                &|| false,
                move |_, _, _, _, _| Ok(valid_output(&verifier_fingerprint)),
            )
            .unwrap();

            let identity = CoreGenerationIdentity {
                sequence: 1,
                generation_id: manifest_hash.clone(),
                manifest_sha256: manifest_hash,
            };
            let evidence = generation.generation().canonical_evidence_bytes().unwrap();
            let files = BTreeMap::from([
                (DISCOVERY_FILENAME.to_owned(), discovery),
                (DISCOVERY_SIGNATURE_FILENAME.to_owned(), discovery_signature),
                (
                    generation
                        .generation()
                        .discovery()
                        .generation
                        .manifest_filename
                        .clone(),
                    manifest,
                ),
                (
                    generation
                        .generation()
                        .discovery()
                        .generation
                        .signature_filename
                        .clone(),
                    manifest_signature,
                ),
                ("acquisition-trust-v1.json".to_owned(), evidence),
                ("userspace-lock.json".to_owned(), payload),
            ]);
            let cache = CoreGenerationCache::open(&cache_root).unwrap();
            let reservation = files.values().map(|bytes| bytes.len() as u64).sum();
            cache
                .stage_candidate(
                    "fixture-cache-stage",
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
            let operation = "fixture-appliance-stage".to_owned();
            begin_installed_authenticated_activation(
                &cache,
                &generation,
                &checkpoint,
                &target,
                &[],
                &operation,
                || false,
            )
            .unwrap();
            Self {
                base,
                cache,
                destination,
                generation,
                checkpoint,
                target,
                identity,
                operation,
            }
        }

        fn stage(&self) -> Result<StagedApplianceGeneration<'_>, String> {
            stage_pending_generation_for_appliance(
                &self.cache,
                &self.generation,
                &self.checkpoint,
                &self.target,
                &[],
                &self.operation,
                &self.destination,
                || false,
            )
        }
    }

    impl Drop for PreparedFixture {
        fn drop(&mut self) {
            make_writable(&self.base);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn canonical(value: &impl Serialize) -> Vec<u8> {
        let value = serde_json::to_value(value).unwrap();
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        bytes
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

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "opemos-appliance-staging-{name}-{}-{}-{nonce}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
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

    fn destination_entries(path: &Path) -> Vec<PathBuf> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|entry| entry.file_name() != Some(OsStr::new(DESTINATION_LOCK_FILENAME)))
            .collect()
    }

    #[test]
    fn exact_pending_generation_is_staged_and_reused_without_state_change() {
        let fixture = PreparedFixture::create("success-reuse");
        let before = fixture.cache.load_state().unwrap();
        let first = fixture.stage().unwrap();
        first.revalidate().unwrap();
        assert!(first.directory.metadata().unwrap().is_dir());
        let first_identity = first.directory_identity;
        let second = fixture.stage().unwrap();
        second.revalidate().unwrap();
        assert_eq!(second.directory_identity, first_identity);
        assert_eq!(destination_entries(&fixture.destination).len(), 1);
        assert_eq!(fixture.cache.load_state().unwrap(), before);
    }

    #[test]
    fn stale_operation_and_cancellation_leave_no_handoff_residue() {
        let fixture = PreparedFixture::create("stale-cancel");
        let before = fixture.cache.load_state().unwrap();
        assert!(stage_pending_generation_for_appliance(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[],
            "stale-operation",
            &fixture.destination,
            || false,
        )
        .is_err());
        assert!(stage_pending_generation_for_appliance(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[],
            &fixture.operation,
            &fixture.destination,
            || true,
        )
        .is_err());
        assert!(destination_entries(&fixture.destination).is_empty());
        assert_eq!(fixture.cache.load_state().unwrap(), before);
    }

    #[test]
    fn capability_fails_after_pending_state_changes_and_can_be_retired() {
        let fixture = PreparedFixture::create("stale-capability");
        let mut staged = fixture.stage().unwrap();
        let pending = fixture.cache.load_state().unwrap();
        fixture
            .cache
            .reject_pending(&fixture.identity, &fixture.operation, pending.revision)
            .unwrap();
        assert!(staged.revalidate().is_err());
        staged.retire().unwrap();
        staged.retire().unwrap();
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn retirement_rejects_a_renamed_handoff_without_losing_retry_identity() {
        let fixture = PreparedFixture::create("retire-rename");
        let mut staged = fixture.stage().unwrap();
        let original = fixture.destination.join(format!(
            "handoff-{}-{}",
            fixture.operation, fixture.identity.manifest_sha256
        ));
        let renamed = fixture.destination.join("renamed-handoff");
        fs::rename(&original, &renamed).unwrap();
        assert!(staged.retire().is_err());
        assert!(renamed.exists());
        fs::rename(&renamed, &original).unwrap();
        staged.retire().unwrap();
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn cancellation_after_copy_removes_private_stage() {
        let fixture = PreparedFixture::create("cancel-after-copy");
        let cancelled = AtomicBool::new(false);
        let result = stage_pending_generation_for_appliance_with_hook(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[],
            &fixture.operation,
            &fixture.destination,
            || cancelled.load(Ordering::SeqCst),
            |phase| {
                if phase == "after-copy" {
                    cancelled.store(true, Ordering::SeqCst);
                }
            },
        );
        assert!(result.is_err());
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn destination_replacement_fails_and_cleans_the_pinned_root() {
        let fixture = PreparedFixture::create("destination-replacement");
        let original = fixture.base.join("appliance-original");
        let replacement = fixture.base.join("appliance-replacement");
        fs::create_dir(&replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        let result = stage_pending_generation_for_appliance_with_hook(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[],
            &fixture.operation,
            &fixture.destination,
            || false,
            |phase| {
                if phase == "after-copy" {
                    fs::rename(&fixture.destination, &original).unwrap();
                    fs::rename(&replacement, &fixture.destination).unwrap();
                }
            },
        );
        assert!(result.is_err());
        assert!(destination_entries(&original).is_empty());
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn source_path_replacement_fails_and_leaves_no_handoff() {
        let fixture = PreparedFixture::create("source-replacement");
        let source = fixture.cache.generation_path(&fixture.identity).unwrap();
        let generations = source.parent().unwrap().to_path_buf();
        let original = generations.join("source-original");
        let result = stage_pending_generation_for_appliance_with_hook(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[],
            &fixture.operation,
            &fixture.destination,
            || false,
            |phase| {
                if phase == "after-source-verification" {
                    fs::set_permissions(&generations, fs::Permissions::from_mode(0o700)).unwrap();
                    fs::rename(&source, &original).unwrap();
                    fs::create_dir(&source).unwrap();
                    fs::set_permissions(&source, fs::Permissions::from_mode(0o500)).unwrap();
                    fs::set_permissions(&generations, fs::Permissions::from_mode(0o500)).unwrap();
                }
            },
        );
        assert!(result.is_err());
        assert!(destination_entries(&fixture.destination).is_empty());
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(&source).unwrap();
        fs::rename(&original, &source).unwrap();
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o500)).unwrap();
    }

    #[test]
    fn prepopulated_links_and_special_entries_fail_closed() {
        let symlinked = PreparedFixture::create("symlink-prepopulation");
        let final_name = format!(
            "handoff-{}-{}",
            symlinked.operation, symlinked.identity.manifest_sha256
        );
        symlink(&symlinked.base, symlinked.destination.join(&final_name)).unwrap();
        assert!(symlinked.stage().is_err());
        assert_eq!(destination_entries(&symlinked.destination).len(), 1);

        let fifo = PreparedFixture::create("fifo-prepopulation");
        let final_name = format!(
            "handoff-{}-{}",
            fifo.operation, fifo.identity.manifest_sha256
        );
        let fifo_path = fifo.destination.join(&final_name);
        let fifo_c = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(fifo.stage().is_err());
        assert_eq!(destination_entries(&fifo.destination).len(), 1);
    }

    #[test]
    fn publication_race_never_replaces_foreign_destination() {
        let fixture = PreparedFixture::create("publish-race");
        let final_path = fixture.destination.join(format!(
            "handoff-{}-{}",
            fixture.operation, fixture.identity.manifest_sha256
        ));
        let result = stage_pending_generation_for_appliance_with_hook(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[],
            &fixture.operation,
            &fixture.destination,
            || false,
            |phase| {
                if phase == "before-publish" {
                    fs::create_dir(&final_path).unwrap();
                    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o700)).unwrap();
                    fs::write(final_path.join("foreign"), b"do-not-replace").unwrap();
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(final_path.join("foreign")).unwrap(),
            b"do-not-replace"
        );
        assert_eq!(destination_entries(&fixture.destination).len(), 1);
    }

    #[test]
    fn destination_lock_replacement_fails_before_publication() {
        let fixture = PreparedFixture::create("lock-replacement");
        let lock = fixture.destination.join(DESTINATION_LOCK_FILENAME);
        let result = stage_pending_generation_for_appliance_with_hook(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[],
            &fixture.operation,
            &fixture.destination,
            || false,
            |phase| {
                if phase == "after-copy" {
                    fs::remove_file(&lock).unwrap();
                    fs::write(&lock, b"").unwrap();
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
                }
            },
        );
        assert!(result.is_err());
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn concurrent_repeat_staging_converges_on_one_exact_handoff() {
        let fixture = Arc::new(PreparedFixture::create("concurrency"));
        let workers = (0..4)
            .map(|_| {
                let fixture = fixture.clone();
                std::thread::spawn(move || {
                    let staged = fixture.stage().unwrap();
                    staged.revalidate().unwrap();
                    staged.directory_identity
                })
            })
            .collect::<Vec<_>>();
        let identities = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert!(identities.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(destination_entries(&fixture.destination).len(), 1);
    }
}
