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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
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
const HANDOFF_RECORD_MAX_BYTES: usize = 2 * 1024 * 1024;
const DESTINATION_LOCK_FILENAME: &str = "handoff.lock";
const LEASE_DIRECTORY_PREFIX: &str = ".handoff-lease-";
const LEASE_INTENT_FILENAME: &str = "intent.json";
const LEASE_STAGE_FILENAME: &str = "stage.json";
const LEASE_PUBLISHED_FILENAME: &str = "published.json";
const LEASE_RETIRING_FILENAME: &str = "retiring.json";
const LEASE_FILES_FILENAME: &str = "files.json";
const LEASE_SCHEMA: u32 = 1;
const LEASE_KIND: &str = "opemos-core-appliance-handoff-lease";
const LEASE_STAGE_KIND: &str = "opemos-core-appliance-handoff-stage";
const LEASE_PUBLISHED_KIND: &str = "opemos-core-appliance-handoff-published";
const LEASE_RETIRING_KIND: &str = "opemos-core-appliance-handoff-retiring";
const LEASE_FILES_KIND: &str = "opemos-core-appliance-handoff-files";
const LEASE_RECORD_MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_LEASE_DIRECTORIES: usize = 32;
const MAX_HANDOFF_DIRECTORY_ENTRIES: usize = crate::core_generation_contracts::MAX_FILES + 6;
const LEASE_INTENT_TEMP_FILENAME: &str = ".intent.tmp";
const LEASE_STAGE_TEMP_FILENAME: &str = ".stage.tmp";
const LEASE_PUBLISHED_TEMP_FILENAME: &str = ".published.tmp";
const LEASE_RETIRING_TEMP_FILENAME: &str = ".retiring.tmp";
const LEASE_FILES_TEMP_FILENAME: &str = ".files.tmp";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

fn canonical_lease_record<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| format!("Could not encode appliance handoff lease: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() > LEASE_RECORD_MAX_BYTES {
        return Err("Appliance handoff lease exceeds its size limit.".into());
    }
    Ok(bytes)
}

fn read_canonical_lease_record<T>(directory: &File, name: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = read_exact_file(directory, name, LEASE_RECORD_MAX_BYTES)?;
    let parsed: T = serde_json::from_slice(&bytes)
        .map_err(|_| "Appliance handoff lease is malformed.".to_string())?;
    if canonical_lease_record(&parsed)? != bytes {
        return Err("Appliance handoff lease is not canonical.".into());
    }
    Ok(parsed)
}

fn validate_lease_intent(intent: &HandoffLeaseIntent, directory_name: &CStr) -> Result<(), String> {
    if intent.schema_version != LEASE_SCHEMA
        || intent.kind != LEASE_KIND
        || !safe_operation_id(&intent.operation_id)
        || intent.lease_token.len() != 32
        || !intent
            .lease_token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || intent.identity.sequence == 0
        || intent.identity.generation_id != intent.identity.manifest_sha256
        || intent.identity.manifest_sha256.len() != 64
        || !intent
            .identity
            .manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || intent.stage_name != format!(".handoff-stage-{}", intent.lease_token)
        || intent.maximum_entries == 0
        || intent.maximum_entries > MAX_HANDOFF_DIRECTORY_ENTRIES as u64
        || intent.expected_files.len() as u64 != intent.maximum_entries
        || intent.handoff_record_sha256.len() != 64
        || !intent
            .handoff_record_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("Appliance handoff lease identity is invalid.".into());
    }
    let mut total = 0_u64;
    for (name, file) in &intent.expected_files {
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || name.ends_with('.')
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'~' | b'-')
            })
            || file.size == 0
            || file.size > MAX_GENERATION_STORAGE_BYTES
            || file.sha256.len() != 64
            || !file
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Appliance handoff lease file inventory is invalid.".into());
        }
        total = total
            .checked_add(file.size)
            .ok_or("Appliance handoff lease file inventory overflowed.")?;
    }
    if total > MAX_GENERATION_STORAGE_BYTES + HANDOFF_RECORD_MAX_BYTES as u64 {
        return Err("Appliance handoff lease file inventory is too large.".into());
    }
    let canonical_handoff = canonical_record(&intent.handoff_record)?;
    if sha256(&canonical_handoff) != intent.handoff_record_sha256
        || intent.handoff_record.schema_version != HANDOFF_SCHEMA
        || intent.handoff_record.kind != HANDOFF_KIND
        || intent.handoff_record.operation_id != intent.operation_id
        || intent.handoff_record.identity != intent.identity
    {
        return Err("Appliance handoff lease record binding is invalid.".into());
    }
    let expected_record_file = intent
        .expected_files
        .get(HANDOFF_FILENAME)
        .ok_or("Appliance handoff lease omits its handoff record.")?;
    if expected_record_file.size != canonical_handoff.len() as u64
        || expected_record_file.sha256 != intent.handoff_record_sha256
    {
        return Err("Appliance handoff lease record inventory is invalid.".into());
    }
    let record_files = intent
        .handoff_record
        .files
        .iter()
        .map(|file| {
            (
                file.filename.clone(),
                HandoffExpectedFile {
                    size: file.size,
                    sha256: file.sha256.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut expected_payload = intent.expected_files.clone();
    expected_payload.remove(HANDOFF_FILENAME);
    if record_files.len() != intent.handoff_record.files.len() || record_files != expected_payload {
        return Err("Appliance handoff lease payload inventory is invalid.".into());
    }
    let expected_lease_name = format!("{LEASE_DIRECTORY_PREFIX}{}", intent.lease_token);
    let expected_published_name = format!(
        "handoff-{}-{}",
        intent.operation_id, intent.identity.manifest_sha256
    );
    if directory_name.to_bytes() != expected_lease_name.as_bytes()
        || intent.published_name != expected_published_name
    {
        return Err("Appliance handoff lease path identity is invalid.".into());
    }
    Ok(())
}

fn validate_lease_phase(
    phase: &HandoffLeasePhase,
    kind: &str,
    intent: &HandoffLeaseIntent,
) -> Result<(), String> {
    if phase.schema_version != LEASE_SCHEMA
        || phase.kind != kind
        || phase.lease_token != intent.lease_token
        || phase.directory.device != intent.destination.device
        || phase.directory.uid != intent.destination.uid
    {
        return Err("Appliance handoff lease phase identity is invalid.".into());
    }
    Ok(())
}

fn lease_directory_name(token: &str) -> Result<CString, String> {
    CString::new(format!("{LEASE_DIRECTORY_PREFIX}{token}"))
        .map_err(|_| "Appliance handoff lease name is unsafe.".to_string())
}

#[allow(clippy::too_many_arguments)]
fn create_handoff_lease<H>(
    destination: &File,
    operation_id: &str,
    identity: &CoreGenerationIdentity,
    source_identity: DirectoryIdentity,
    destination_identity: DirectoryIdentity,
    published_name: &CStr,
    handoff_record: &ApplianceHandoffRecord,
    expected_files: &BTreeMap<String, HandoffExpectedFile>,
    hook: &mut H,
) -> Result<(File, CString, HandoffLeaseIntent), String>
where
    H: FnMut(&'static str) -> Result<(), String>,
{
    let lease_token = random_token()?;
    let directory_name = lease_directory_name(&lease_token)?;
    let (directory, _) = create_staging_directory_at(destination, &directory_name)?;
    let result = (|| {
        hook("after-lease-mkdir")?;
        let intent = HandoffLeaseIntent {
            schema_version: LEASE_SCHEMA,
            kind: LEASE_KIND.into(),
            lease_token: lease_token.clone(),
            operation_id: operation_id.into(),
            identity: identity.clone(),
            source_cache: source_identity,
            destination: destination_identity.into(),
            stage_name: format!(".handoff-stage-{lease_token}"),
            published_name: published_name
                .to_str()
                .map_err(|_| "Appliance handoff destination name is not UTF-8.")?
                .into(),
            handoff_record_sha256: sha256(&canonical_record(handoff_record)?),
            handoff_record: handoff_record.clone(),
            maximum_entries: u64::try_from(expected_files.len())
                .map_err(|_| "Appliance handoff entry count overflowed.")?,
            expected_files: expected_files.clone(),
        };
        validate_lease_intent(&intent, &directory_name)?;
        create_lease_intent_file(&directory, &canonical_lease_record(&intent)?, hook)?;
        hook("after-intent-publish")?;
        directory
            .sync_all()
            .map_err(|error| storage_error("Could not sync appliance handoff lease", error))?;
        hook("after-intent-directory-sync")?;
        destination.sync_all().map_err(|error| {
            storage_error("Could not sync appliance handoff lease publication", error)
        })?;
        hook("after-lease-parent-sync")?;
        Ok(intent)
    })();
    match result {
        Ok(intent) => Ok((directory, directory_name, intent)),
        Err(primary) => {
            let cleanup = cleanup_lease_directory(destination, &directory, &directory_name);
            match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(format!("{primary} Cleanup failed: {cleanup}")),
            }
        }
    }
}

fn create_lease_intent_file<H>(directory: &File, bytes: &[u8], hook: &mut H) -> Result<(), String>
where
    H: FnMut(&'static str) -> Result<(), String>,
{
    let temporary = CString::new(LEASE_INTENT_TEMP_FILENAME).unwrap();
    let published = CString::new(LEASE_INTENT_FILENAME).unwrap();
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not create appliance handoff lease intent: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    hook("after-intent-create")?;
    file.write_all(bytes)
        .map_err(|error| storage_error("Could not write appliance handoff lease intent", error))?;
    hook("after-intent-write")?;
    file.sync_all()
        .map_err(|error| storage_error("Could not sync appliance handoff lease intent", error))?;
    file.set_permissions(fs::Permissions::from_mode(HANDOFF_FILE_MODE))
        .map_err(|error| format!("Could not seal appliance handoff lease intent: {error}"))?;
    file.sync_all().map_err(|error| {
        storage_error(
            "Could not sync sealed appliance handoff lease intent",
            error,
        )
    })?;
    hook("after-intent-sync")?;
    rename_directory_at(directory, &temporary, &published)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct PhaseHooks {
    created: &'static str,
    written: &'static str,
    synced: &'static str,
    published: &'static str,
    directory_synced: &'static str,
}

#[derive(Clone, Copy)]
struct LeasePhaseDefinition {
    filename: &'static str,
    temporary_filename: &'static str,
    kind: &'static str,
    hooks: PhaseHooks,
}

const STAGE_PHASE_HOOKS: PhaseHooks = PhaseHooks {
    created: "after-stage-marker-create",
    written: "after-stage-marker-write",
    synced: "after-stage-marker-sync",
    published: "after-stage-marker-publish",
    directory_synced: "after-stage-marker-directory-sync",
};
const PUBLISHED_PHASE_HOOKS: PhaseHooks = PhaseHooks {
    created: "after-published-marker-create",
    written: "after-published-marker-write",
    synced: "after-published-marker-sync",
    published: "after-published-marker-publish",
    directory_synced: "after-published-marker-directory-sync",
};
const RETIRING_PHASE_HOOKS: PhaseHooks = PhaseHooks {
    created: "after-retiring-marker-create",
    written: "after-retiring-marker-write",
    synced: "after-retiring-marker-sync",
    published: "after-retiring-marker-publish",
    directory_synced: "after-retiring-marker-directory-sync",
};
const FILES_PHASE_HOOKS: PhaseHooks = PhaseHooks {
    created: "after-files-receipt-create",
    written: "after-files-receipt-write",
    synced: "after-files-receipt-sync",
    published: "after-files-receipt-publish",
    directory_synced: "after-files-receipt-directory-sync",
};
const STAGE_PHASE: LeasePhaseDefinition = LeasePhaseDefinition {
    filename: LEASE_STAGE_FILENAME,
    temporary_filename: LEASE_STAGE_TEMP_FILENAME,
    kind: LEASE_STAGE_KIND,
    hooks: STAGE_PHASE_HOOKS,
};
const PUBLISHED_PHASE: LeasePhaseDefinition = LeasePhaseDefinition {
    filename: LEASE_PUBLISHED_FILENAME,
    temporary_filename: LEASE_PUBLISHED_TEMP_FILENAME,
    kind: LEASE_PUBLISHED_KIND,
    hooks: PUBLISHED_PHASE_HOOKS,
};
const RETIRING_PHASE: LeasePhaseDefinition = LeasePhaseDefinition {
    filename: LEASE_RETIRING_FILENAME,
    temporary_filename: LEASE_RETIRING_TEMP_FILENAME,
    kind: LEASE_RETIRING_KIND,
    hooks: RETIRING_PHASE_HOOKS,
};

fn create_lease_phase<H>(
    lease_directory: &File,
    definition: LeasePhaseDefinition,
    intent: &HandoffLeaseIntent,
    directory: DirectoryIdentity,
    hook: &mut H,
) -> Result<HandoffLeasePhase, String>
where
    H: FnMut(&'static str) -> Result<(), String>,
{
    let phase = HandoffLeasePhase {
        schema_version: LEASE_SCHEMA,
        kind: definition.kind.into(),
        lease_token: intent.lease_token.clone(),
        directory: directory.into(),
    };
    validate_lease_phase(&phase, definition.kind, intent)?;
    create_atomic_lease_record(
        lease_directory,
        definition.filename,
        definition.temporary_filename,
        &canonical_lease_record(&phase)?,
        hook,
        definition.hooks,
    )?;
    Ok(phase)
}

fn create_atomic_lease_record<H>(
    directory: &File,
    filename: &str,
    temporary_filename: &str,
    bytes: &[u8],
    hook: &mut H,
    hooks: PhaseHooks,
) -> Result<(), String>
where
    H: FnMut(&'static str) -> Result<(), String>,
{
    let temporary = CString::new(temporary_filename)
        .map_err(|_| "Appliance handoff lease temporary name is unsafe.".to_string())?;
    let published = CString::new(filename)
        .map_err(|_| "Appliance handoff lease record name is unsafe.".to_string())?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not create appliance handoff lease phase: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    hook(hooks.created)?;
    file.write_all(bytes)
        .map_err(|error| storage_error("Could not write appliance handoff lease phase", error))?;
    hook(hooks.written)?;
    file.sync_all()
        .map_err(|error| storage_error("Could not sync appliance handoff lease phase", error))?;
    file.set_permissions(fs::Permissions::from_mode(HANDOFF_FILE_MODE))
        .map_err(|error| format!("Could not seal appliance handoff lease phase: {error}"))?;
    file.sync_all().map_err(|error| {
        storage_error("Could not sync sealed appliance handoff lease phase", error)
    })?;
    hook(hooks.synced)?;
    rename_directory_at(directory, &temporary, &published)?;
    hook(hooks.published)?;
    directory
        .sync_all()
        .map_err(|error| storage_error("Could not sync appliance handoff lease phase", error))?;
    hook(hooks.directory_synced)
}

fn capture_handoff_file_receipt(
    directory: &File,
    intent: &HandoffLeaseIntent,
) -> Result<HandoffLeaseFiles, String> {
    let mut files = BTreeMap::new();
    let names = directory_names(directory, intent.expected_files.len().saturating_add(1))?;
    if names.len() != intent.expected_files.len() {
        return Err("Appliance handoff receipt inventory is not exact.".into());
    }
    for (name, expected) in &intent.expected_files {
        if !names.iter().any(|observed| observed == OsStr::new(name)) {
            return Err("Appliance handoff receipt inventory is incomplete.".into());
        }
        let pinned =
            verify_exact_file(directory, name, expected.size, &expected.sha256, &|| false)?;
        files.insert(
            name.clone(),
            HandoffFileReceipt {
                identity: pinned.identity,
            },
        );
    }
    Ok(HandoffLeaseFiles {
        schema_version: LEASE_SCHEMA,
        kind: LEASE_FILES_KIND.into(),
        lease_token: intent.lease_token.clone(),
        directory: LeaseDirectoryIdentity::from(handoff_directory_snapshot(directory)?),
        files,
    })
}

fn validate_handoff_file_receipt(
    receipt: &HandoffLeaseFiles,
    intent: &HandoffLeaseIntent,
) -> Result<(), String> {
    if receipt.schema_version != LEASE_SCHEMA
        || receipt.kind != LEASE_FILES_KIND
        || receipt.lease_token != intent.lease_token
        || receipt.directory.device != intent.destination.device
        || receipt.directory.uid != intent.destination.uid
        || receipt.files.len() != intent.expected_files.len()
    {
        return Err("Appliance handoff file receipt identity is invalid.".into());
    }
    for (name, expected) in &intent.expected_files {
        let observed = receipt
            .files
            .get(name)
            .ok_or("Appliance handoff file receipt inventory is incomplete.")?
            .identity;
        if observed.uid != intent.destination.uid
            || observed.nlink != 1
            || observed.mode != HANDOFF_FILE_MODE
            || observed.len != expected.size
        {
            return Err("Appliance handoff file receipt metadata is invalid.".into());
        }
    }
    Ok(())
}

fn revalidate_published_lease(destination: &File, lease: &HandoffLease) -> Result<(), String> {
    let reopened = open_directory_at(destination, &lease.directory_name)?;
    require_directory_metadata(
        &reopened,
        lease.directory_identity,
        DESTINATION_DIRECTORY_MODE,
        "appliance handoff lease",
    )?;
    require_directory_metadata(
        &lease.directory,
        lease.directory_identity,
        DESTINATION_DIRECTORY_MODE,
        "appliance handoff lease",
    )?;
    let names = directory_names(&reopened, 5)?;
    let expected = BTreeSet::from([
        OsStr::new(LEASE_INTENT_FILENAME).to_os_string(),
        OsStr::new(LEASE_STAGE_FILENAME).to_os_string(),
        OsStr::new(LEASE_FILES_FILENAME).to_os_string(),
        OsStr::new(LEASE_PUBLISHED_FILENAME).to_os_string(),
    ]);
    if names.into_iter().collect::<BTreeSet<_>>() != expected {
        return Err("Published appliance handoff lease inventory is not exact.".into());
    }
    let intent: HandoffLeaseIntent = read_canonical_lease_record(&reopened, LEASE_INTENT_FILENAME)?;
    let published: HandoffLeasePhase =
        read_canonical_lease_record(&reopened, LEASE_PUBLISHED_FILENAME)?;
    let files: HandoffLeaseFiles = read_canonical_lease_record(&reopened, LEASE_FILES_FILENAME)?;
    validate_lease_intent(&intent, &lease.directory_name)?;
    validate_lease_phase(&published, LEASE_PUBLISHED_KIND, &intent)?;
    validate_handoff_file_receipt(&files, &intent)?;
    if intent != lease.intent || published != lease.published {
        return Err("Published appliance handoff lease changed.".into());
    }
    Ok(())
}

fn revalidate_staging_lease(
    destination: &File,
    lease_directory: &File,
    lease_name: &CStr,
    lease_identity: StableDirectoryIdentity,
    intent: &HandoffLeaseIntent,
    stage: &HandoffLeasePhase,
) -> Result<(), String> {
    let reopened = open_directory_at(destination, lease_name)?;
    for directory in [&reopened, lease_directory] {
        let observed = private_directory_identity(
            directory,
            DESTINATION_DIRECTORY_MODE,
            "staging appliance handoff lease",
        )?;
        if StableDirectoryIdentity::from(observed) != lease_identity {
            return Err("Staging appliance handoff lease identity changed.".into());
        }
    }
    let names = directory_names(&reopened, 4)?;
    let expected = BTreeSet::from([
        OsStr::new(LEASE_INTENT_FILENAME).to_os_string(),
        OsStr::new(LEASE_STAGE_FILENAME).to_os_string(),
        OsStr::new(LEASE_FILES_FILENAME).to_os_string(),
    ]);
    if names.into_iter().collect::<BTreeSet<_>>() != expected {
        return Err("Staging appliance handoff lease inventory is not exact.".into());
    }
    let observed_intent: HandoffLeaseIntent =
        read_canonical_lease_record(&reopened, LEASE_INTENT_FILENAME)?;
    let observed_stage: HandoffLeasePhase =
        read_canonical_lease_record(&reopened, LEASE_STAGE_FILENAME)?;
    validate_lease_intent(&observed_intent, lease_name)?;
    validate_lease_phase(&observed_stage, LEASE_STAGE_KIND, &observed_intent)?;
    if &observed_intent != intent || &observed_stage != stage {
        return Err("Staging appliance handoff lease changed.".into());
    }
    Ok(())
}

fn remove_retiring_lease(destination: &File, lease: &HandoffLease) -> Result<(), String> {
    revalidate_retiring_lease(destination, lease)?;
    let current = private_directory_identity(
        &lease.directory,
        DESTINATION_DIRECTORY_MODE,
        "retiring appliance handoff lease",
    )?;
    remove_confined_directory_at(
        destination,
        &lease.directory_name,
        current,
        &lease_cleanup_spec(),
    )
}

fn revalidate_retiring_lease(destination: &File, lease: &HandoffLease) -> Result<(), String> {
    let reopened = open_directory_at(destination, &lease.directory_name)?;
    let observed = private_directory_identity(
        &reopened,
        DESTINATION_DIRECTORY_MODE,
        "retiring appliance handoff lease",
    )?;
    if StableDirectoryIdentity::from(observed)
        != StableDirectoryIdentity::from(lease.directory_identity)
    {
        return Err("Retiring appliance handoff lease identity changed.".into());
    }
    let intent: HandoffLeaseIntent = read_canonical_lease_record(&reopened, LEASE_INTENT_FILENAME)?;
    let published: HandoffLeasePhase =
        read_canonical_lease_record(&reopened, LEASE_PUBLISHED_FILENAME)?;
    let retiring: HandoffLeasePhase =
        read_canonical_lease_record(&reopened, LEASE_RETIRING_FILENAME)?;
    let files: HandoffLeaseFiles = read_canonical_lease_record(&reopened, LEASE_FILES_FILENAME)?;
    validate_lease_intent(&intent, &lease.directory_name)?;
    validate_lease_phase(&published, LEASE_PUBLISHED_KIND, &intent)?;
    validate_lease_phase(&retiring, LEASE_RETIRING_KIND, &intent)?;
    validate_handoff_file_receipt(&files, &intent)?;
    if intent != lease.intent
        || published != lease.published
        || retiring.directory != lease.published.directory
    {
        return Err("Appliance handoff retirement identity changed.".into());
    }
    let names = directory_names(&reopened, 6)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        OsStr::new(LEASE_INTENT_FILENAME).to_os_string(),
        OsStr::new(LEASE_STAGE_FILENAME).to_os_string(),
        OsStr::new(LEASE_FILES_FILENAME).to_os_string(),
        OsStr::new(LEASE_PUBLISHED_FILENAME).to_os_string(),
        OsStr::new(LEASE_RETIRING_FILENAME).to_os_string(),
    ]);
    if names != expected {
        return Err("Retiring appliance handoff lease inventory is not exact.".into());
    }
    Ok(())
}

fn open_optional_directory_at(parent: &File, name: &CStr) -> Result<Option<File>, String> {
    match open_directory_at(parent, name) {
        Ok(directory) => Ok(Some(directory)),
        Err(_error) if directory_missing_at(parent, name)? => Ok(None),
        Err(_) => Err("Appliance handoff lease entry is not a confined directory.".into()),
    }
}

fn file_exists_at(parent: &File, name: &str) -> Result<bool, String> {
    let name = CString::new(name).map_err(|_| "Appliance handoff lease filename is unsafe.")?;
    Ok(!directory_missing_at(parent, &name)?)
}

fn remove_partial_lease_record(directory: &File, name: &str) -> Result<(), String> {
    let name = CString::new(name)
        .map_err(|_| "Partial appliance handoff lease filename is unsafe.".to_string())?;
    let file = open_handoff_file(directory, &name)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Could not inspect partial appliance handoff lease: {error}"))?;
    let identity = HandoffFileIdentity::from(&metadata);
    if !metadata.is_file()
        || identity.uid != unsafe { libc::geteuid() }
        || identity.nlink != 1
        || (identity.mode != 0o600 && identity.mode != HANDOFF_FILE_MODE)
        || identity.len > LEASE_RECORD_MAX_BYTES as u64
    {
        return Err("Partial appliance handoff lease is unsafe.".into());
    }
    let reopened = open_handoff_file(directory, &name)?;
    let reopened_metadata = reopened
        .metadata()
        .map_err(|error| format!("Could not recheck partial appliance handoff lease: {error}"))?;
    if HandoffFileIdentity::from(&reopened_metadata) != identity {
        return Err("Partial appliance handoff lease changed before cleanup.".into());
    }
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(format!(
            "Could not remove partial appliance handoff lease: {}",
            std::io::Error::last_os_error()
        ));
    }
    let after = file
        .metadata()
        .map_err(|error| format!("Could not confirm partial lease removal: {error}"))?;
    if after.nlink() != 0 {
        return Err("Partial appliance handoff lease path changed during cleanup.".into());
    }
    directory
        .sync_all()
        .map_err(|error| format!("Could not sync partial appliance handoff cleanup: {error}"))
}

fn reconcile_partial_lease_records(directory: &File) -> Result<(), String> {
    for (temporary, final_name) in [
        (LEASE_STAGE_TEMP_FILENAME, LEASE_STAGE_FILENAME),
        (LEASE_FILES_TEMP_FILENAME, LEASE_FILES_FILENAME),
        (LEASE_PUBLISHED_TEMP_FILENAME, LEASE_PUBLISHED_FILENAME),
        (LEASE_RETIRING_TEMP_FILENAME, LEASE_RETIRING_FILENAME),
    ] {
        if file_exists_at(directory, temporary)? {
            if file_exists_at(directory, final_name)? {
                return Err("Appliance handoff lease contains ambiguous phase records.".into());
            }
            remove_partial_lease_record(directory, temporary)?;
        }
    }
    Ok(())
}

fn lease_cleanup_spec() -> BTreeMap<String, u64> {
    [
        LEASE_INTENT_FILENAME,
        LEASE_INTENT_TEMP_FILENAME,
        LEASE_STAGE_FILENAME,
        LEASE_STAGE_TEMP_FILENAME,
        LEASE_FILES_FILENAME,
        LEASE_FILES_TEMP_FILENAME,
        LEASE_PUBLISHED_FILENAME,
        LEASE_PUBLISHED_TEMP_FILENAME,
        LEASE_RETIRING_FILENAME,
        LEASE_RETIRING_TEMP_FILENAME,
    ]
    .into_iter()
    .map(|name| (name.to_owned(), LEASE_RECORD_MAX_BYTES as u64))
    .collect()
}

fn cleanup_lease_directory(
    destination: &File,
    lease_directory: &File,
    lease_name: &CStr,
) -> Result<(), String> {
    let identity = DirectoryIdentity::from(
        &lease_directory
            .metadata()
            .map_err(|error| format!("Could not identify failed lease: {error}"))?,
    );
    remove_confined_directory_at(destination, lease_name, identity, &lease_cleanup_spec())
}

fn remove_confined_directory_at(
    parent: &File,
    name: &CStr,
    expected: DirectoryIdentity,
    allowed: &BTreeMap<String, u64>,
) -> Result<(), String> {
    remove_confined_directory_at_with_receipts(parent, name, expected, allowed, None)
}

fn remove_receipted_handoff_at(
    parent: &File,
    name: &CStr,
    expected: DirectoryIdentity,
    intent: &HandoffLeaseIntent,
    receipt: &HandoffLeaseFiles,
) -> Result<(), String> {
    validate_handoff_file_receipt(receipt, intent)?;
    let directory = open_directory_at(parent, name)?;
    for (filename, expected_file) in &intent.expected_files {
        verify_exact_file(
            &directory,
            filename,
            expected_file.size,
            &expected_file.sha256,
            &|| false,
        )?;
    }
    let allowed = intent
        .expected_files
        .iter()
        .map(|(name, file)| (name.clone(), file.size))
        .collect::<BTreeMap<_, _>>();
    remove_confined_directory_at_with_receipts(
        parent,
        name,
        expected,
        &allowed,
        Some(&receipt.files),
    )
}

fn remove_confined_directory_at_with_receipts(
    parent: &File,
    name: &CStr,
    expected: DirectoryIdentity,
    allowed: &BTreeMap<String, u64>,
    receipts: Option<&BTreeMap<String, HandoffFileReceipt>>,
) -> Result<(), String> {
    let directory = open_directory_at(parent, name)?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("Could not identify failed appliance handoff: {error}"))?;
    let observed = DirectoryIdentity::from(&metadata);
    if !metadata.is_dir()
        || observed.uid != unsafe { libc::geteuid() }
        || observed.device != expected.device
        || observed.inode != expected.inode
        || (observed.mode != DESTINATION_DIRECTORY_MODE && observed.mode != HANDOFF_DIRECTORY_MODE)
    {
        return Err("Failed appliance handoff identity is unsafe.".into());
    }
    let names = directory_names(&directory, allowed.len().saturating_add(1))?;
    let mut pinned = Vec::with_capacity(names.len());
    for raw_name in names {
        let child_name = raw_name
            .to_str()
            .ok_or("Failed appliance handoff filename is not UTF-8.")?;
        let maximum_size = allowed
            .get(child_name)
            .ok_or("Failed appliance handoff contains an unexpected entry.")?;
        let child = CString::new(raw_name.as_bytes())
            .map_err(|_| "Failed appliance handoff filename is unsafe.".to_string())?;
        let file = open_handoff_file(&directory, &child)?;
        let child_metadata = file
            .metadata()
            .map_err(|error| format!("Could not inspect failed handoff child: {error}"))?;
        let child_identity = HandoffFileIdentity::from(&child_metadata);
        if !child_metadata.is_file()
            || child_identity.uid != unsafe { libc::geteuid() }
            || child_identity.nlink != 1
            || (child_identity.mode != 0o600 && child_identity.mode != HANDOFF_FILE_MODE)
            || child_identity.len > *maximum_size
        {
            return Err("Failed appliance handoff child metadata is unsafe.".into());
        }
        if receipts.is_some_and(|receipts| {
            receipts
                .get(child_name)
                .is_none_or(|receipt| receipt.identity != child_identity)
        }) {
            return Err(
                "Failed appliance handoff child does not match its durable receipt.".into(),
            );
        }
        let reopened = open_handoff_file(&directory, &child)?;
        if HandoffFileIdentity::from(
            &reopened
                .metadata()
                .map_err(|error| format!("Could not recheck failed handoff child: {error}"))?,
        ) != child_identity
        {
            return Err("Failed appliance handoff child changed before cleanup.".into());
        }
        pinned.push((child, file, child_identity));
    }
    if receipts.is_some_and(|receipts| receipts.len() != pinned.len()) {
        return Err("Failed appliance handoff receipt inventory is not exact.".into());
    }
    if observed.mode != DESTINATION_DIRECTORY_MODE {
        directory
            .set_permissions(fs::Permissions::from_mode(DESTINATION_DIRECTORY_MODE))
            .map_err(|error| format!("Could not reopen failed appliance handoff: {error}"))?;
    }
    for (child, file, identity) in pinned {
        let reopened = open_handoff_file(&directory, &child)?;
        if HandoffFileIdentity::from(
            &reopened
                .metadata()
                .map_err(|error| format!("Could not bind failed handoff child: {error}"))?,
        ) != identity
        {
            return Err("Failed appliance handoff child changed before unlink.".into());
        }
        if unsafe { libc::unlinkat(directory.as_raw_fd(), child.as_ptr(), 0) } != 0 {
            return Err(format!(
                "Could not remove failed appliance handoff file: {}",
                std::io::Error::last_os_error()
            ));
        }
        if file
            .metadata()
            .map_err(|error| format!("Could not confirm handoff child removal: {error}"))?
            .nlink()
            != 0
        {
            return Err("Failed appliance handoff child path changed during unlink.".into());
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

#[allow(clippy::too_many_arguments)]
fn reconcile_handoff_leases(
    destination: &File,
    destination_identity: DirectoryIdentity,
    operation_id: &str,
    identity: &CoreGenerationIdentity,
    source_identity: DirectoryIdentity,
    expected_record: &ApplianceHandoffRecord,
    inventory: &BTreeMap<String, (u64, String)>,
    cancelled: &impl Fn() -> bool,
) -> Result<Option<RecoveredHandoff>, String> {
    let record_hash = sha256(&canonical_record(expected_record)?);
    let authenticated_payload = inventory
        .iter()
        .map(|(name, (size, sha256))| {
            (
                name.clone(),
                HandoffExpectedFile {
                    size: *size,
                    sha256: sha256.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut expected_files = authenticated_payload.clone();
    expected_files.insert(
        HANDOFF_FILENAME.into(),
        HandoffExpectedFile {
            size: canonical_record(expected_record)?.len() as u64,
            sha256: record_hash.clone(),
        },
    );
    let names = directory_names(
        destination,
        MAX_LEASE_DIRECTORIES
            .saturating_add(inventory.len())
            .saturating_add(64),
    )?;
    let mut recovered = None;
    let mut lease_count = 0_usize;
    for raw_name in names {
        let Some(name) = raw_name.to_str() else {
            continue;
        };
        if !name.starts_with(LEASE_DIRECTORY_PREFIX) {
            continue;
        }
        lease_count = lease_count.saturating_add(1);
        if lease_count > MAX_LEASE_DIRECTORIES {
            return Err("Appliance handoff lease count exceeds its limit.".into());
        }
        poll_cancelled(cancelled)?;
        let name_c = CString::new(name)
            .map_err(|_| "Appliance handoff lease directory name is unsafe.".to_string())?;
        let lease_directory = open_directory_at(destination, &name_c)
            .map_err(|_| "Appliance handoff lease path is not a confined directory.".to_string())?;
        let lease_identity = private_directory_identity(
            &lease_directory,
            DESTINATION_DIRECTORY_MODE,
            "appliance handoff lease",
        )?;
        if !file_exists_at(&lease_directory, LEASE_INTENT_FILENAME)? {
            let abandoned = directory_names(&lease_directory, 2)?;
            if abandoned.is_empty() {
                remove_confined_directory_at(
                    destination,
                    &name_c,
                    lease_identity,
                    &lease_cleanup_spec(),
                )?;
                continue;
            }
            if abandoned.len() == 1 && abandoned[0] == OsStr::new(LEASE_INTENT_TEMP_FILENAME) {
                remove_partial_lease_record(&lease_directory, LEASE_INTENT_TEMP_FILENAME)?;
                let refreshed =
                    DirectoryIdentity::from(&lease_directory.metadata().map_err(|error| {
                        format!("Could not identify partial lease cleanup: {error}")
                    })?);
                remove_confined_directory_at(
                    destination,
                    &name_c,
                    refreshed,
                    &lease_cleanup_spec(),
                )?;
                continue;
            }
            return Err("Uninitialized appliance handoff lease inventory is ambiguous.".into());
        }
        let intent: HandoffLeaseIntent =
            read_canonical_lease_record(&lease_directory, LEASE_INTENT_FILENAME)?;
        validate_lease_intent(&intent, &name_c)?;
        if intent.destination != StableDirectoryIdentity::from(destination_identity) {
            return Err("Appliance handoff lease belongs to another destination.".into());
        }
        let stage_name = CString::new(intent.stage_name.as_str()).unwrap();
        let published_name = CString::new(intent.published_name.as_str())
            .map_err(|_| "Appliance handoff published name is unsafe.".to_string())?;
        reconcile_partial_lease_records(&lease_directory)?;
        let stage = open_optional_directory_at(destination, &stage_name)?;
        let published = open_optional_directory_at(destination, &published_name)?;
        let stage_marker_exists = file_exists_at(&lease_directory, LEASE_STAGE_FILENAME)?;
        let files_receipt_exists = file_exists_at(&lease_directory, LEASE_FILES_FILENAME)?;
        let published_marker_exists = file_exists_at(&lease_directory, LEASE_PUBLISHED_FILENAME)?;
        let retiring_marker_exists = file_exists_at(&lease_directory, LEASE_RETIRING_FILENAME)?;
        let stage_marker = if stage_marker_exists {
            let marker: HandoffLeasePhase =
                read_canonical_lease_record(&lease_directory, LEASE_STAGE_FILENAME)?;
            validate_lease_phase(&marker, LEASE_STAGE_KIND, &intent)?;
            Some(marker)
        } else {
            None
        };
        let files_receipt = if files_receipt_exists {
            let receipt: HandoffLeaseFiles =
                read_canonical_lease_record(&lease_directory, LEASE_FILES_FILENAME)?;
            validate_handoff_file_receipt(&receipt, &intent)?;
            Some(receipt)
        } else {
            None
        };
        let published_marker = if published_marker_exists {
            let marker: HandoffLeasePhase =
                read_canonical_lease_record(&lease_directory, LEASE_PUBLISHED_FILENAME)?;
            validate_lease_phase(&marker, LEASE_PUBLISHED_KIND, &intent)?;
            Some(marker)
        } else {
            None
        };
        let retiring_marker = if retiring_marker_exists {
            let marker: HandoffLeasePhase =
                read_canonical_lease_record(&lease_directory, LEASE_RETIRING_FILENAME)?;
            validate_lease_phase(&marker, LEASE_RETIRING_KIND, &intent)?;
            Some(marker)
        } else {
            None
        };
        if retiring_marker.is_some() && published_marker.is_none() {
            return Err("Appliance handoff retirement lacks publication identity.".into());
        }
        if files_receipt.is_some() && stage_marker.is_none() {
            return Err("Appliance handoff file receipt lacks its staged identity.".into());
        }
        let intent_payload = intent
            .expected_files
            .iter()
            .filter(|(name, _)| name.as_str() != HANDOFF_FILENAME)
            .map(|(name, file)| (name.clone(), file.clone()))
            .collect::<BTreeMap<_, _>>();
        let is_authenticated_generation = intent.identity == *identity
            && intent.source_cache == source_identity
            && intent_payload == authenticated_payload
            && intent.handoff_record.identity == expected_record.identity
            && intent.handoff_record.target == expected_record.target
            && intent.handoff_record.lineage_manifest_sha256
                == expected_record.lineage_manifest_sha256
            && intent.handoff_record.files == expected_record.files
            && intent.maximum_entries == expected_files.len() as u64;
        let is_expected = intent.operation_id == operation_id
            && is_authenticated_generation
            && intent.handoff_record_sha256 == record_hash
            && intent.handoff_record == *expected_record
            && intent.expected_files == expected_files;

        match (stage, published) {
            (Some(stage), None) => {
                if published_marker.is_some() {
                    return Err("Appliance handoff lease phase is inconsistent.".into());
                }
                if retiring_marker.is_some() {
                    return Err("Appliance handoff lease phase is inconsistent.".into());
                }
                if !is_authenticated_generation {
                    return Err(
                        "appliance-handoff-recovery-required: a stale handoff cannot be reauthenticated from the current generation; preserving it."
                            .into(),
                    );
                }
                if files_receipt.is_none()
                    && !directory_names(
                        &stage,
                        usize::try_from(intent.maximum_entries)
                            .unwrap_or(MAX_HANDOFF_DIRECTORY_ENTRIES)
                            .saturating_add(1),
                    )?
                    .is_empty()
                {
                    return Err(
                        "appliance-handoff-recovery-required: an interrupted stage has no durable file receipt; preserving it."
                            .into(),
                    );
                }
                let observed_stage = if let Some(marker) = stage_marker {
                    require_recoverable_stage_identity(&stage, marker.directory)?
                } else {
                    let observed = private_directory_identity(
                        &stage,
                        DESTINATION_DIRECTORY_MODE,
                        "unmarked appliance handoff stage",
                    )?;
                    if !directory_names(&stage, 1)?.is_empty() {
                        return Err(
                            "Unmarked appliance handoff stage is not empty; preserving it.".into(),
                        );
                    }
                    observed
                };
                if let Some(receipt) = files_receipt.as_ref() {
                    remove_receipted_handoff_at(
                        destination,
                        &stage_name,
                        observed_stage,
                        &intent,
                        receipt,
                    )?;
                } else {
                    remove_confined_directory_at(
                        destination,
                        &stage_name,
                        observed_stage,
                        &BTreeMap::new(),
                    )?;
                }
                let refreshed_identity =
                    DirectoryIdentity::from(&lease_directory.metadata().map_err(|error| {
                        format!("Could not inspect recovered appliance handoff lease: {error}")
                    })?);
                remove_confined_directory_at(
                    destination,
                    &name_c,
                    refreshed_identity,
                    &lease_cleanup_spec(),
                )?;
            }
            (None, Some(published)) => {
                if !is_authenticated_generation {
                    return Err(
                        "appliance-handoff-recovery-required: a published stale handoff cannot be reauthenticated from the current generation; preserving it."
                            .into(),
                    );
                }
                let Some(stage_marker) = stage_marker else {
                    return Err("Published appliance handoff lacks its staged identity.".into());
                };
                let Some(files_receipt) = files_receipt.as_ref() else {
                    return Err("Published appliance handoff lacks its file receipt.".into());
                };
                let published_identity = require_lease_directory_identity(
                    &published,
                    stage_marker.directory,
                    HANDOFF_DIRECTORY_MODE,
                    "recovered appliance handoff",
                )?;
                let marker = if let Some(marker) = published_marker {
                    if marker.directory != stage_marker.directory {
                        return Err(
                            "Published appliance handoff lease identity is inconsistent.".into(),
                        );
                    }
                    marker
                } else {
                    let mut no_hook = |_| Ok(());
                    create_lease_phase(
                        &lease_directory,
                        PUBLISHED_PHASE,
                        &intent,
                        published_identity,
                        &mut no_hook,
                    )?
                };
                if let Some(retiring) = retiring_marker {
                    if retiring.directory != marker.directory {
                        return Err("Appliance handoff retirement identity is inconsistent.".into());
                    }
                    remove_receipted_handoff_at(
                        destination,
                        &published_name,
                        published_identity,
                        &intent,
                        files_receipt,
                    )?;
                    let refreshed =
                        DirectoryIdentity::from(&lease_directory.metadata().map_err(|error| {
                            format!("Could not inspect retiring handoff lease: {error}")
                        })?);
                    remove_confined_directory_at(
                        destination,
                        &name_c,
                        refreshed,
                        &lease_cleanup_spec(),
                    )?;
                    continue;
                }
                destination.sync_all().map_err(|error| {
                    storage_error("Could not sync recovered appliance handoff", error)
                })?;
                let final_lease_identity = private_directory_identity(
                    &lease_directory,
                    DESTINATION_DIRECTORY_MODE,
                    "published appliance handoff lease",
                )?;
                let lease = HandoffLease {
                    directory: lease_directory,
                    directory_name: name_c,
                    directory_identity: final_lease_identity,
                    intent: intent.clone(),
                    published: marker,
                };
                revalidate_published_lease(destination, &lease)?;
                if is_expected {
                    if recovered.is_some() {
                        return Err(
                            "Multiple appliance handoff leases match this operation.".into()
                        );
                    }
                    verify_published_handoff(&published, expected_record, inventory, cancelled)?;
                    recovered = Some(RecoveredHandoff {
                        directory: published,
                        directory_name: published_name,
                        directory_identity: published_identity,
                        lease,
                    });
                } else {
                    remove_receipted_handoff_at(
                        destination,
                        &published_name,
                        published_identity,
                        &intent,
                        files_receipt,
                    )?;
                    let refreshed =
                        DirectoryIdentity::from(&lease.directory.metadata().map_err(|error| {
                            format!("Could not inspect superseded handoff lease: {error}")
                        })?);
                    remove_confined_directory_at(
                        destination,
                        &lease.directory_name,
                        refreshed,
                        &lease_cleanup_spec(),
                    )?;
                }
            }
            (None, None) => {
                if !is_authenticated_generation {
                    return Err(
                        "appliance-handoff-recovery-required: a stale handoff lease cannot be reauthenticated from the current generation; preserving it."
                            .into(),
                    );
                }
                if let (Some(published), Some(retiring)) =
                    (published_marker.as_ref(), retiring_marker.as_ref())
                {
                    if published.directory != retiring.directory {
                        return Err("Appliance handoff retirement identity is inconsistent.".into());
                    }
                    let refreshed =
                        DirectoryIdentity::from(&lease_directory.metadata().map_err(|error| {
                            format!("Could not inspect retired handoff lease: {error}")
                        })?);
                    remove_confined_directory_at(
                        destination,
                        &name_c,
                        refreshed,
                        &lease_cleanup_spec(),
                    )?;
                    continue;
                }
                if published_marker.is_some() || retiring_marker.is_some() {
                    return Err(
                        "Completed appliance handoff disappeared before reconciliation.".into(),
                    );
                }
                let expected_names = if stage_marker.is_some() {
                    let mut names = BTreeSet::from([
                        OsStr::new(LEASE_INTENT_FILENAME).to_os_string(),
                        OsStr::new(LEASE_STAGE_FILENAME).to_os_string(),
                    ]);
                    if files_receipt.is_some() {
                        names.insert(OsStr::new(LEASE_FILES_FILENAME).to_os_string());
                    }
                    names
                } else {
                    BTreeSet::from([OsStr::new(LEASE_INTENT_FILENAME).to_os_string()])
                };
                let actual = directory_names(&lease_directory, 3)?
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                if actual != expected_names {
                    return Err("Abandoned appliance handoff lease inventory is not exact.".into());
                }
                remove_confined_directory_at(
                    destination,
                    &name_c,
                    lease_identity,
                    &lease_cleanup_spec(),
                )?;
            }
            (Some(_), Some(_)) => {
                return Err(
                    "Appliance handoff lease has both staged and published directories.".into(),
                );
            }
        }
    }
    Ok(recovered)
}

#[allow(clippy::too_many_arguments)]
fn cleanup_inflight_lease(
    destination: &File,
    lease_directory: &File,
    lease_name: &CStr,
    stage_name: &CStr,
    published_name: &CStr,
    stage_identity: DirectoryIdentity,
    published: bool,
    intent: &HandoffLeaseIntent,
    receipt: Option<&HandoffLeaseFiles>,
) -> Result<(), String> {
    let child_parent = destination;
    let child_name = if published {
        published_name
    } else {
        stage_name
    };
    if !directory_missing_at(child_parent, child_name)? {
        let child = open_directory_at(child_parent, child_name)?;
        let observed = require_recoverable_stage_identity(
            &child,
            LeaseDirectoryIdentity::from(stage_identity),
        )?;
        if let Some(receipt) = receipt {
            remove_receipted_handoff_at(child_parent, child_name, observed, intent, receipt)?;
        } else {
            remove_confined_directory_at(child_parent, child_name, observed, &BTreeMap::new())?;
        }
    }
    let lease_identity =
        DirectoryIdentity::from(&lease_directory.metadata().map_err(|error| {
            format!("Could not inspect failed appliance handoff lease: {error}")
        })?);
    remove_confined_directory_at(
        destination,
        lease_name,
        lease_identity,
        &lease_cleanup_spec(),
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StableDirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LeaseDirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

impl From<DirectoryIdentity> for LeaseDirectoryIdentity {
    fn from(value: DirectoryIdentity) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
            uid: value.uid,
        }
    }
}

impl From<DirectoryIdentity> for StableDirectoryIdentity {
    fn from(value: DirectoryIdentity) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
            uid: value.uid,
            mode: value.mode,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HandoffLeaseIntent {
    schema_version: u32,
    kind: String,
    lease_token: String,
    operation_id: String,
    identity: CoreGenerationIdentity,
    source_cache: DirectoryIdentity,
    destination: StableDirectoryIdentity,
    stage_name: String,
    published_name: String,
    handoff_record_sha256: String,
    handoff_record: ApplianceHandoffRecord,
    maximum_entries: u64,
    expected_files: BTreeMap<String, HandoffExpectedFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HandoffExpectedFile {
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HandoffLeaseFiles {
    schema_version: u32,
    kind: String,
    lease_token: String,
    directory: LeaseDirectoryIdentity,
    files: BTreeMap<String, HandoffFileReceipt>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HandoffFileReceipt {
    identity: HandoffFileIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HandoffLeasePhase {
    schema_version: u32,
    kind: String,
    lease_token: String,
    directory: LeaseDirectoryIdentity,
}

struct HandoffLease {
    directory: File,
    directory_name: CString,
    directory_identity: DirectoryIdentity,
    intent: HandoffLeaseIntent,
    published: HandoffLeasePhase,
}

struct RecoveredHandoff {
    directory: File,
    directory_name: CString,
    directory_identity: DirectoryIdentity,
    lease: HandoffLease,
}

struct DestinationLock {
    file: File,
    identity: (u64, u64, u32, u32, u64, u64),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    lease: HandoffLease,
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
        revalidate_published_lease(&self.root, &self.lease)?;
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
        revalidate_published_lease(&self.root, &self.lease)?;
        destination_guard.revalidate(&self.root)
    }

    /// Explicitly retires the descriptor-bound handoff after the owning guest
    /// lifecycle has completed. The durable retiring marker lets a later
    /// staging call finish restart reconciliation. Production guest wiring
    /// remains separately gated by the complete lifecycle and storage matrix.
    pub(crate) fn retire(&mut self) -> Result<(), String> {
        self.retire_with_hook(|_| Ok(()))
    }

    fn retire_with_hook<H>(&mut self, mut hook: H) -> Result<(), String>
    where
        H: FnMut(&'static str) -> Result<(), String>,
    {
        if self.retired {
            return Ok(());
        }
        require_destination_root(&self.root_path, &self.root, self.root_identity)?;
        let destination_guard = acquire_destination_lock(&self.root, &|| false)?;
        destination_guard.revalidate(&self.root)?;
        reconcile_partial_lease_records(&self.lease.directory)?;
        if file_exists_at(&self.lease.directory, LEASE_RETIRING_FILENAME)? {
            revalidate_retiring_lease(&self.root, &self.lease)?;
        } else {
            revalidate_published_lease(&self.root, &self.lease)?;
            create_lease_phase(
                &self.lease.directory,
                RETIRING_PHASE,
                &self.lease.intent,
                self.directory_identity,
                &mut hook,
            )?;
            self.root.sync_all().map_err(|error| {
                storage_error("Could not sync appliance handoff retirement intent", error)
            })?;
        }
        hook("after-retiring-marker")?;
        if directory_missing_at(&self.root, &self.directory_name)? {
            let metadata = self
                .directory
                .metadata()
                .map_err(|error| format!("Could not inspect retired appliance handoff: {error}"))?;
            if metadata.nlink() != 0 {
                return Err("Appliance handoff path changed before retirement.".into());
            }
        } else {
            let receipt: HandoffLeaseFiles =
                read_canonical_lease_record(&self.lease.directory, LEASE_FILES_FILENAME)?;
            remove_receipted_handoff_at(
                &self.root,
                &self.directory_name,
                self.directory_identity,
                &self.lease.intent,
                &receipt,
            )?;
        }
        hook("after-retired-handoff")?;
        remove_retiring_lease(&self.root, &self.lease)?;
        hook("after-retired-lease")?;
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
        |_| Ok(()),
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
    H: FnMut(&'static str) -> Result<(), String>,
{
    poll_cancelled(&cancelled)?;
    if !safe_operation_id(operation_id) {
        return Err("Core appliance handoff operation identity is invalid.".into());
    }
    if lineage.len() > MAX_LINEAGE_GENERATIONS {
        return Err("Authenticated lineage exceeds its generation limit.".into());
    }
    let inventory = expected_authenticated_inventory(generation.generation())?;
    let lineage_inventory = expected_lineage_inventory(lineage)?;
    let (total_bytes, transfer_file_count) =
        transfer_inventory_totals(&inventory, &lineage_inventory)?;
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
    hook("after-cache-lock")?;
    poll_cancelled(&cancelled)?;
    revalidate_installed_capabilities(generation, checkpoint, lineage, &cancelled)?;
    validate_transfer_inventory_names(&inventory, &lineage_inventory)?;

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
    let _lineage_sources = pin_lineage_sources(cache, lineage, &cancelled)?;
    require_pinned_generation_directory(
        &source_path,
        &source,
        "appliance handoff source generation",
    )?;
    let source_identity = DirectoryIdentity::from(
        &source
            .file
            .metadata()
            .map_err(|error| format!("Could not identify appliance handoff source: {error}"))?,
    );
    hook("after-source-verification")?;

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
    let mut expected_files = inventory
        .iter()
        .map(|(name, (size, sha256))| {
            (
                name.clone(),
                HandoffExpectedFile {
                    size: *size,
                    sha256: sha256.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    expected_files.insert(
        HANDOFF_FILENAME.into(),
        HandoffExpectedFile {
            size: record_bytes.len() as u64,
            sha256: sha256(&record_bytes),
        },
    );

    if let Some(recovered) = reconcile_handoff_leases(
        &destination,
        destination_identity,
        operation_id,
        &identity,
        source_identity,
        &record,
        &inventory,
        &cancelled,
    )? {
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
            directory: recovered.directory,
            directory_name: recovered.directory_name,
            directory_identity: recovered.directory_identity,
            lease: recovered.lease,
            record,
            inventory,
            retired: false,
            _seal: StagedApplianceGenerationSeal,
        });
    }
    if !directory_missing_at(&destination, &directory_name)? {
        return Err("Existing appliance handoff has no valid durable lease.".into());
    }

    let logical_bytes = total_bytes
        .checked_add(record_bytes.len() as u64)
        .and_then(|bytes| bytes.checked_add((LEASE_RECORD_MAX_BYTES as u64) * 5))
        .ok_or("Core appliance handoff size overflowed.")?;
    let file_nodes = u64::try_from(transfer_file_count)
        .ok()
        .and_then(|count| count.checked_add(8))
        .ok_or("Core appliance handoff file count overflowed.")?;
    let capacity = probe_statvfs_capacity(&destination)
        .map_err(|error| storage_error("Could not inspect appliance handoff capacity", error))?;
    let physical_bytes =
        physical_reservation_bytes(logical_bytes, file_nodes, capacity.allocation_unit_bytes)?;
    require_storage_admission(capacity, physical_bytes, file_nodes, 0, 0)
        .map_err(|error| error.replace("Core generation cache", "Core appliance handoff"))?;

    let (lease_directory, lease_name, lease_intent) = create_handoff_lease(
        &destination,
        operation_id,
        &identity,
        source_identity,
        destination_identity,
        &directory_name,
        &record,
        &expected_files,
        &mut hook,
    )?;
    if let Err(primary) = hook("after-lease-created") {
        let cleanup = cleanup_lease_directory(&destination, &lease_directory, &lease_name);
        return match cleanup {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(format!("{primary} Cleanup failed: {cleanup}")),
        };
    }
    let stage_name = CString::new(lease_intent.stage_name.as_str()).unwrap();
    let (stage, stage_identity) = match create_staging_directory_at(&destination, &stage_name) {
        Ok(created) => created,
        Err(primary) => {
            let cleanup = cleanup_lease_directory(&destination, &lease_directory, &lease_name);
            return match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(format!("{primary} Cleanup failed: {cleanup}")),
            };
        }
    };
    if let Err(primary) = hook("after-stage-mkdir") {
        let cleanup = cleanup_inflight_lease(
            &destination,
            &lease_directory,
            &lease_name,
            &stage_name,
            &directory_name,
            stage_identity,
            false,
            &lease_intent,
            None,
        );
        return match cleanup {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(format!("{primary} Cleanup failed: {cleanup}")),
        };
    }
    let stage_phase = match create_lease_phase(
        &lease_directory,
        STAGE_PHASE,
        &lease_intent,
        stage_identity,
        &mut hook,
    ) {
        Ok(phase) => phase,
        Err(primary) => {
            let cleanup = cleanup_inflight_lease(
                &destination,
                &lease_directory,
                &lease_name,
                &stage_name,
                &directory_name,
                stage_identity,
                false,
                &lease_intent,
                None,
            );
            return match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(format!("{primary} Cleanup failed: {cleanup}")),
            };
        }
    };
    let staging_lease_identity = StableDirectoryIdentity::from(private_directory_identity(
        &lease_directory,
        DESTINATION_DIRECTORY_MODE,
        "staging appliance handoff lease",
    )?);
    let published = Cell::new(false);
    let completed_receipt = RefCell::new(None);
    let result = (|| {
        hook("after-stage-created")?;
        for (name, (size, hash)) in &inventory {
            poll_cancelled(&cancelled)?;
            copy_inventory_file(&source.file, &stage, name, *size, hash, &cancelled)?;
        }
        poll_cancelled(&cancelled)?;
        create_exact_file(&stage, HANDOFF_FILENAME, &record_bytes)?;
        stage
            .sync_all()
            .map_err(|error| format!("Could not sync staged appliance handoff: {error}"))?;
        let files_receipt = capture_handoff_file_receipt(&stage, &lease_intent)?;
        validate_handoff_file_receipt(&files_receipt, &lease_intent)?;
        create_atomic_lease_record(
            &lease_directory,
            LEASE_FILES_FILENAME,
            LEASE_FILES_TEMP_FILENAME,
            &canonical_lease_record(&files_receipt)?,
            &mut hook,
            FILES_PHASE_HOOKS,
        )?;
        *completed_receipt.borrow_mut() = Some(files_receipt);
        hook("after-record-sync")?;
        hook("after-copy")?;
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
        hook("before-publish")?;
        revalidate_staging_lease(
            &destination,
            &lease_directory,
            &lease_name,
            staging_lease_identity,
            &lease_intent,
            &stage_phase,
        )?;
        hook("final-cancellation-boundary")?;
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
        hook("after-seal")?;
        destination_guard.revalidate(&destination)?;
        revalidate_staging_lease(
            &destination,
            &lease_directory,
            &lease_name,
            staging_lease_identity,
            &lease_intent,
            &stage_phase,
        )?;
        rename_directory_at(&destination, &stage_name, &directory_name)?;
        published.set(true);
        hook("after-rename")?;
        destination
            .sync_all()
            .map_err(|error| format!("Could not sync appliance handoff destination: {error}"))?;
        hook("after-destination-sync")?;
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
        let published_phase = create_lease_phase(
            &lease_directory,
            PUBLISHED_PHASE,
            &lease_intent,
            published_identity,
            &mut hook,
        )?;
        destination.sync_all().map_err(|error| {
            storage_error("Could not sync completed appliance handoff lease", error)
        })?;
        hook("after-lease-complete")?;
        let lease_identity = private_directory_identity(
            &lease_directory,
            DESTINATION_DIRECTORY_MODE,
            "published appliance handoff lease",
        )?;
        let lease = HandoffLease {
            directory: lease_directory
                .try_clone()
                .map_err(|error| format!("Could not retain appliance handoff lease: {error}"))?,
            directory_name: lease_name.clone(),
            directory_identity: lease_identity,
            intent: lease_intent.clone(),
            published: published_phase,
        };
        revalidate_published_lease(&destination, &lease)?;
        Ok((published, published_identity, lease))
    })();

    match result {
        Ok((directory, directory_identity, lease)) => Ok(StagedApplianceGeneration {
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
            lease,
            record,
            inventory,
            retired: false,
            _seal: StagedApplianceGenerationSeal,
        }),
        Err(primary) => {
            let cleanup = cleanup_inflight_lease(
                &destination,
                &lease_directory,
                &lease_name,
                &stage_name,
                &directory_name,
                stage_identity,
                published.get(),
                &lease_intent,
                completed_receipt.borrow().as_ref(),
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

struct PinnedLineageSource {
    path: PathBuf,
    _directory: super::PinnedGenerationDirectory,
    inventory: BTreeMap<String, (u64, String)>,
}

fn pin_lineage_sources<C>(
    cache: &CoreGenerationCache,
    lineage: &[&InstalledAuthenticatedGeneration],
    cancelled: &C,
) -> Result<Vec<PinnedLineageSource>, String>
where
    C: Fn() -> bool,
{
    let mut sources = Vec::with_capacity(lineage.len());
    for predecessor in lineage {
        poll_cancelled(cancelled)?;
        let generation = predecessor.generation();
        let identity = CoreGenerationIdentity {
            sequence: generation.discovery().sequence,
            generation_id: generation.discovery().generation.manifest_sha256.clone(),
            manifest_sha256: generation.discovery().generation.manifest_sha256.clone(),
        };
        cache.require_generation_committed(&identity)?;
        cache.require_unique_committed_sequence(&identity)?;
        let path = cache.generation_path(&identity)?;
        let pinned = pin_generation_directory(&path, "appliance lineage source generation")?;
        let inventory = expected_authenticated_inventory(generation)?;
        verify_authenticated_inventory(&pinned, &inventory, cancelled)?;
        require_pinned_generation_directory(&path, &pinned, "appliance lineage source generation")?;
        sources.push(PinnedLineageSource {
            path,
            _directory: pinned,
            inventory,
        });
    }
    Ok(sources)
}

fn validate_transfer_inventory_names(
    inventory: &BTreeMap<String, (u64, String)>,
    lineage_inventory: &BTreeMap<String, (u64, String)>,
) -> Result<(), String> {
    let mut folded = BTreeSet::new();
    for name in inventory.keys().chain(lineage_inventory.keys()) {
        if !folded.insert(name.to_ascii_lowercase()) {
            return Err("Core appliance handoff transfer contains a filename collision.".into());
        }
    }
    Ok(())
}

fn transfer_inventory_totals(
    inventory: &BTreeMap<String, (u64, String)>,
    lineage_inventory: &BTreeMap<String, (u64, String)>,
) -> Result<(u64, usize), String> {
    let total_bytes = inventory
        .values()
        .chain(lineage_inventory.values())
        .try_fold(0_u64, |total, (size, _)| {
            total
                .checked_add(*size)
                .ok_or("Core appliance handoff size overflowed.")
        })?;
    let file_count = inventory
        .len()
        .checked_add(lineage_inventory.len())
        .ok_or("Core appliance handoff file count overflowed.")?;
    if file_count.saturating_add(1) > MAX_HANDOFF_DIRECTORY_ENTRIES {
        return Err("Core appliance handoff file count is invalid.".into());
    }
    Ok((total_bytes, file_count))
}

fn expected_lineage_inventory(
    lineage: &[&InstalledAuthenticatedGeneration],
) -> Result<BTreeMap<String, (u64, String)>, String> {
    let mut inventory = BTreeMap::new();
    let mut folded = BTreeSet::new();
    for predecessor in lineage {
        let generation = predecessor.generation();
        let discovery = generation.discovery();
        let inputs = generation.request_plan_inputs();
        for (name, bytes) in [
            (
                discovery.generation.manifest_filename.as_str(),
                inputs.manifest_payload,
            ),
            (
                discovery.generation.signature_filename.as_str(),
                inputs.manifest_signature,
            ),
        ] {
            if !folded.insert(name.to_ascii_lowercase())
                || inventory
                    .insert(name.to_owned(), (bytes.len() as u64, sha256(bytes)))
                    .is_some()
            {
                return Err("Authenticated lineage contains a filename collision.".into());
            }
        }
    }
    Ok(inventory)
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
    let value = serde_json::to_value(record)
        .map_err(|error| format!("Could not represent appliance handoff record: {error}"))?;
    let mut bytes = serde_json::to_vec(&value)
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

fn require_lease_directory_identity(
    directory: &File,
    expected: LeaseDirectoryIdentity,
    mode: u32,
    description: &str,
) -> Result<DirectoryIdentity, String> {
    let observed = private_directory_identity(directory, mode, description)?;
    if LeaseDirectoryIdentity::from(observed) != expected {
        return Err(format!("{description} identity changed."));
    }
    Ok(observed)
}

fn require_recoverable_stage_identity(
    directory: &File,
    expected: LeaseDirectoryIdentity,
) -> Result<DirectoryIdentity, String> {
    let metadata = directory.metadata().map_err(|error| {
        format!("Could not inspect recoverable appliance handoff stage: {error}")
    })?;
    let observed = DirectoryIdentity::from(&metadata);
    if !metadata.is_dir()
        || observed.uid != unsafe { libc::geteuid() }
        || LeaseDirectoryIdentity::from(observed) != expected
        || (observed.mode != DESTINATION_DIRECTORY_MODE && observed.mode != HANDOFF_DIRECTORY_MODE)
    {
        return Err("Recoverable appliance handoff stage identity is unsafe.".into());
    }
    Ok(observed)
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
                remove_confined_directory_at(parent, name, identity, &BTreeMap::new())
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
        core_generation_verifier::{DetachedVerifierOutput, VERIFIER_EVIDENCE_FILENAME},
    };
    use std::{
        os::unix::fs::symlink,
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    const STAGING_CRASH_PHASES: &[&str] = &[
        "after-lease-mkdir",
        "after-intent-create",
        "after-intent-write",
        "after-intent-sync",
        "after-intent-publish",
        "after-intent-directory-sync",
        "after-lease-parent-sync",
        "after-stage-mkdir",
        "after-stage-marker-create",
        "after-stage-marker-write",
        "after-stage-marker-sync",
        "after-stage-marker-publish",
        "after-stage-marker-directory-sync",
        "after-stage-created",
        "after-record-sync",
        "after-files-receipt-publish",
        "after-files-receipt-directory-sync",
        "after-copy",
        "after-seal",
        "after-rename",
        "after-destination-sync",
        "after-published-marker-create",
        "after-published-marker-write",
        "after-published-marker-sync",
        "after-published-marker-publish",
        "after-published-marker-directory-sync",
        "after-lease-complete",
    ];

    const PARTIAL_RECEIPT_CRASH_PHASES: &[&str] = &[
        "after-files-receipt-create",
        "after-files-receipt-write",
        "after-files-receipt-sync",
    ];

    const RETIREMENT_CRASH_PHASES: &[&str] = &[
        "after-retiring-marker",
        "after-retiring-marker-create",
        "after-retiring-marker-write",
        "after-retiring-marker-sync",
        "after-retiring-marker-publish",
        "after-retiring-marker-directory-sync",
        "after-retired-handoff",
        "after-retired-lease",
    ];

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct PreparedFixture {
        base: PathBuf,
        cleanup: bool,
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
            Self::load(base, true)
        }

        // Restart reauthenticates without rewriting trust files or cache state.
        fn load(base: PathBuf, initialize: bool) -> Self {
            let trust = base.join("trust");
            let cache_root = base.join("cache");
            let destination = base.join("appliance");
            if initialize {
                fs::create_dir_all(&trust).unwrap();
                fs::create_dir(&destination).unwrap();
                fs::set_permissions(&trust, fs::Permissions::from_mode(0o700)).unwrap();
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
            }

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
            if initialize {
                write_private(&trust.join(POLICY_FILENAME), &policy);
                write_private(&trust.join(KEYRING_FILENAME), &keyring);
                write_private(&trust.join(CHECKPOINT_FILENAME), &checkpoint_bytes);
            }

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
                (VERIFIER_EVIDENCE_FILENAME.to_owned(), evidence),
                ("userspace-lock.json".to_owned(), payload),
            ]);
            let cache = CoreGenerationCache::open(&cache_root).unwrap();
            let operation = "fixture-appliance-stage".to_owned();
            if initialize {
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
            }
            Self {
                base,
                cleanup: initialize,
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

        fn supersede_pending(&self, operation: &str) {
            let state = self.cache.load_state().unwrap();
            self.cache
                .reject_pending(&self.identity, &self.operation, state.revision)
                .unwrap();
            begin_installed_authenticated_activation(
                &self.cache,
                &self.generation,
                &self.checkpoint,
                &self.target,
                &[],
                operation,
                || false,
            )
            .unwrap();
        }

        fn stage_operation(
            &self,
            operation: &str,
        ) -> Result<StagedApplianceGeneration<'_>, String> {
            stage_pending_generation_for_appliance(
                &self.cache,
                &self.generation,
                &self.checkpoint,
                &self.target,
                &[],
                operation,
                &self.destination,
                || false,
            )
        }
    }

    impl Drop for PreparedFixture {
        fn drop(&mut self) {
            if self.cleanup {
                make_writable(&self.base);
                let _ = fs::remove_dir_all(&self.base);
            }
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
            .filter(|entry| {
                let name = entry.file_name().and_then(OsStr::to_str).unwrap_or("");
                name != DESTINATION_LOCK_FILENAME && !name.starts_with(LEASE_DIRECTORY_PREFIX)
            })
            .collect()
    }

    fn all_destination_entries(path: &Path) -> Vec<PathBuf> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
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
    fn handoff_uses_core_canonical_json_and_verifier_evidence_filename() {
        const CORE_EVIDENCE_FILENAME: &str = "opemos-userspace-lock-verifier-evidence-v1.json";
        let fixture = PreparedFixture::create("core-wire-identity");
        let mut staged = fixture.stage().unwrap();
        let handoff_root = fixture.destination.join(format!(
            "handoff-{}-{}",
            fixture.operation, fixture.identity.manifest_sha256
        ));
        let record_bytes = fs::read(handoff_root.join(HANDOFF_FILENAME)).unwrap();
        let record_value: serde_json::Value = serde_json::from_slice(&record_bytes).unwrap();
        let mut canonical = serde_json::to_vec(&record_value).unwrap();
        canonical.push(b'\n');
        assert_eq!(record_bytes, canonical);
        assert!(handoff_root.join(CORE_EVIDENCE_FILENAME).is_file());
        assert!(!handoff_root.join("acquisition-trust-v1.json").exists());
        assert!(record_value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["filename"] == CORE_EVIDENCE_FILENAME));
        staged.retire().unwrap();
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
    fn lineage_sources_require_exact_committed_cache_inventory() {
        let fixture = PreparedFixture::create("lineage-source-pin");
        let sources =
            pin_lineage_sources(&fixture.cache, &[&fixture.generation], &|| false).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(
            sources[0].path,
            fixture.cache.generation_path(&fixture.identity).unwrap()
        );
        assert!(sources[0].inventory.contains_key(
            &fixture
                .generation
                .generation()
                .discovery()
                .generation
                .manifest_filename
        ));
        drop(sources);
        fs::remove_file(
            fixture
                .cache
                .generation_commit_marker_path(&fixture.identity)
                .unwrap(),
        )
        .unwrap();
        assert!(pin_lineage_sources(&fixture.cache, &[&fixture.generation], &|| false).is_err());
    }

    #[test]
    fn current_and_lineage_inventory_names_cannot_collide() {
        let current = BTreeMap::from([("Current.Manifest.JSON".into(), (7, "a".repeat(64)))]);
        let distinct = BTreeMap::from([("predecessor.sig".into(), (11, "b".repeat(64)))]);
        validate_transfer_inventory_names(&current, &distinct).unwrap();
        let collision = BTreeMap::from([("current.manifest.json".into(), (13, "c".repeat(64)))]);
        assert_eq!(
            validate_transfer_inventory_names(&current, &collision).unwrap_err(),
            "Core appliance handoff transfer contains a filename collision."
        );
    }

    #[test]
    fn lineage_transfer_totals_are_checked_and_include_predecessors() {
        let current = BTreeMap::from([("current".into(), (7, "a".repeat(64)))]);
        let lineage = BTreeMap::from([
            ("predecessor.manifest.json".into(), (11, "b".repeat(64))),
            ("predecessor.manifest.json.sig".into(), (13, "c".repeat(64))),
        ]);
        assert_eq!(
            transfer_inventory_totals(&current, &lineage).unwrap(),
            (31, 3)
        );
        let overflow = BTreeMap::from([("overflow".into(), (u64::MAX, "d".repeat(64)))]);
        assert_eq!(
            transfer_inventory_totals(&overflow, &current).unwrap_err(),
            "Core appliance handoff size overflowed."
        );
    }

    #[test]
    fn lineage_inventory_contains_only_exact_manifest_signature_pairs() {
        let fixture = PreparedFixture::create("lineage-inventory");
        let generation = fixture.generation.generation();
        let discovery = generation.discovery();
        let inputs = generation.request_plan_inputs();
        let inventory = expected_lineage_inventory(&[&fixture.generation]).unwrap();
        assert_eq!(inventory.len(), 2);
        assert_eq!(
            inventory[&discovery.generation.manifest_filename],
            (
                inputs.manifest_payload.len() as u64,
                sha256(inputs.manifest_payload)
            )
        );
        assert_eq!(
            inventory[&discovery.generation.signature_filename],
            (
                inputs.manifest_signature.len() as u64,
                sha256(inputs.manifest_signature)
            )
        );
        assert_eq!(
            expected_lineage_inventory(&[&fixture.generation, &fixture.generation]).unwrap_err(),
            "Authenticated lineage contains a filename collision."
        );
    }

    #[test]
    fn self_lineage_is_rejected_before_handoff_publication() {
        let fixture = PreparedFixture::create("self-lineage");
        let before = fixture.cache.load_state().unwrap();
        let error = stage_pending_generation_for_appliance(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[&fixture.generation],
            &fixture.operation,
            &fixture.destination,
            || false,
        )
        .err()
        .expect("a pending generation cannot be its own predecessor");
        assert_eq!(
            error,
            "Core appliance handoff transfer contains a filename collision."
        );
        assert!(destination_entries(&fixture.destination).is_empty());
        assert_eq!(fixture.cache.load_state().unwrap(), before);
    }

    #[test]
    fn different_installed_trust_lineage_is_rejected_before_publication() {
        let fixture = PreparedFixture::create("mixed-lineage-primary");
        let other = PreparedFixture::create("mixed-lineage-other");
        let before = fixture.cache.load_state().unwrap();
        let error = stage_pending_generation_for_appliance(
            &fixture.cache,
            &fixture.generation,
            &fixture.checkpoint,
            &fixture.target,
            &[&other.generation],
            &fixture.operation,
            &fixture.destination,
            || false,
        )
        .err()
        .expect("lineage from another installed trust root must fail");
        assert_eq!(
            error,
            "Authenticated lineage does not share installed trust."
        );
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
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn injected_enospc_after_copy_removes_stage_and_lease() {
        let fixture = PreparedFixture::create("enospc-after-copy");
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
                    Err("storage-admission-no-space: injected staging failure".into())
                } else {
                    Ok(())
                }
            },
        );
        let error = match result {
            Ok(_) => panic!("injected ENOSPC unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error.contains("storage-admission-no-space: injected staging failure"));
        let entries = all_destination_entries(&fixture.destination);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].file_name(),
            Some(OsStr::new(DESTINATION_LOCK_FILENAME))
        );
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
                Ok(())
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
                Ok(())
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
                Ok(())
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
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn staging_lease_replacement_before_publication_is_preserved_fail_closed() {
        let fixture = PreparedFixture::create("staging-lease-replacement");
        let moved = fixture.destination.join("replaced-staging-lease");
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
                    let lease = fs::read_dir(&fixture.destination)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .find(|path| {
                            path.file_name()
                                .and_then(OsStr::to_str)
                                .is_some_and(|name| name.starts_with(LEASE_DIRECTORY_PREFIX))
                        })
                        .unwrap();
                    fs::rename(&lease, &moved).unwrap();
                    fs::create_dir(&lease).unwrap();
                    fs::set_permissions(&lease, fs::Permissions::from_mode(0o700)).unwrap();
                }
                Ok(())
            },
        );
        let error = match result {
            Ok(_) => panic!("replaced staging lease unexpectedly published"),
            Err(error) => error,
        };
        assert!(error.contains("Staging appliance handoff lease identity changed"));
        assert!(error.contains("Cleanup failed"));
        assert!(moved.exists());
        assert_eq!(destination_entries(&fixture.destination), vec![moved]);
    }

    #[test]
    fn staging_marker_replacement_before_publication_is_preserved_fail_closed() {
        let fixture = PreparedFixture::create("staging-marker-replacement");
        let mut lease_path = None;
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
                    let lease = fs::read_dir(&fixture.destination)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .find(|path| {
                            path.file_name()
                                .and_then(OsStr::to_str)
                                .is_some_and(|name| name.starts_with(LEASE_DIRECTORY_PREFIX))
                        })
                        .unwrap();
                    let marker = lease.join(LEASE_STAGE_FILENAME);
                    let saved = lease.join("saved-stage-marker");
                    fs::rename(&marker, &saved).unwrap();
                    symlink(&saved, &marker).unwrap();
                    lease_path = Some(lease);
                }
                Ok(())
            },
        );
        let error = match result {
            Ok(_) => panic!("replaced staging marker unexpectedly published"),
            Err(error) => error,
        };
        assert!(error.contains("Staging appliance handoff lease"));
        assert!(error.contains("Cleanup failed"));
        assert!(lease_path.unwrap().exists());
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn receipted_regular_file_replacement_is_never_removed_by_cleanup() {
        let fixture = PreparedFixture::create("receipted-file-replacement");
        let mut replaced = None;
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
                    let lease = fs::read_dir(&fixture.destination)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .find(|path| {
                            path.file_name()
                                .and_then(OsStr::to_str)
                                .is_some_and(|name| name.starts_with(LEASE_DIRECTORY_PREFIX))
                        })
                        .unwrap();
                    let intent: HandoffLeaseIntent = serde_json::from_slice(
                        &fs::read(lease.join(LEASE_INTENT_FILENAME)).unwrap(),
                    )
                    .unwrap();
                    let stage = fixture.destination.join(intent.stage_name);
                    let payload = stage.join("userspace-lock.json");
                    let saved = stage.join("saved-userspace-lock.json");
                    fs::rename(&payload, &saved).unwrap();
                    fs::write(&payload, b"replacement-not-owned-by-receipt").unwrap();
                    fs::set_permissions(&payload, fs::Permissions::from_mode(0o400)).unwrap();
                    replaced = Some((payload, saved));
                    return Err("injected failure after regular-file replacement".into());
                }
                Ok(())
            },
        );
        let error = match result {
            Ok(_) => panic!("regular-file replacement unexpectedly published"),
            Err(error) => error,
        };
        assert!(error.contains("injected failure after regular-file replacement"));
        assert!(error.contains("Cleanup failed"));
        let (payload, saved) = replaced.unwrap();
        assert_eq!(
            fs::read(payload).unwrap(),
            b"replacement-not-owned-by-receipt"
        );
        assert!(saved.exists());
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

    fn disk_snapshot(root: &Path) -> BTreeMap<PathBuf, (u64, u32, Vec<u8>)> {
        fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, (u64, u32, Vec<u8>)>) {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let bytes = if metadata.is_file() {
                fs::read(path).unwrap()
            } else {
                Vec::new()
            };
            entries.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                (metadata.ino(), metadata.mode(), bytes),
            );
            if metadata.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), entries);
                }
            }
        }
        let mut entries = BTreeMap::new();
        visit(root, root, &mut entries);
        entries
    }

    struct HandoffWorker(std::process::Child);

    impl Drop for HandoffWorker {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_handoff_worker(fixture: &PreparedFixture, mode: &str, phase: &str) -> HandoffWorker {
        use std::process::{Command, Stdio};
        HandoffWorker(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "core_generation_cache::appliance_staging::tests::handoff_sigkill_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("OPEMOS_HANDOFF_TEST_ROOT", &fixture.base)
                .env("OPEMOS_HANDOFF_TEST_MODE", mode)
                .env("OPEMOS_HANDOFF_TEST_PHASE", phase)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }

    fn wait_for_handoff_boundary(worker: &mut HandoffWorker, phase: &str) {
        use std::io::{BufRead, BufReader};
        let stdout = worker.0.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line.starts_with("HANDOFF_READY:") {
                    let _ = sender.send(line);
                    return;
                }
            }
        });
        let marker = receiver
            .recv_timeout(Duration::from_secs(20))
            .expect("handoff worker did not reach the requested boundary");
        reader.join().unwrap();
        assert_eq!(marker, format!("HANDOFF_READY:{phase}"));
        assert!(worker.0.try_wait().unwrap().is_none());
    }

    fn wait_for_handoff_exit(worker: &mut HandoffWorker) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = worker.0.try_wait().unwrap() {
                assert!(status.success(), "handoff restart failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "handoff restart timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn subprocess_sigkill_handoff_boundaries_preserve_pending_state_and_restart() {
        use std::os::unix::process::ExitStatusExt;
        for (mode, phases, recovery) in [
            ("stage", STAGING_CRASH_PHASES, "recover"),
            ("stage", PARTIAL_RECEIPT_CRASH_PHASES, "preserve"),
            ("retire", RETIREMENT_CRASH_PHASES, "recover"),
        ] {
            for &phase in phases {
                let fixture = PreparedFixture::create("sigkill");
                let before = fixture.cache.load_state().unwrap();
                let cache_before = disk_snapshot(&fixture.base.join("cache"));
                let trust_before = disk_snapshot(&fixture.base.join("trust"));
                let mut worker = spawn_handoff_worker(&fixture, mode, phase);
                wait_for_handoff_boundary(&mut worker, phase);
                worker.0.kill().unwrap();
                assert_eq!(worker.0.wait().unwrap().signal(), Some(libc::SIGKILL));
                assert_eq!(fixture.cache.load_state().unwrap(), before);

                // A fresh executable must reacquire released locks, reconstruct
                // authentication, and reconcile only the surviving disk evidence.
                let mut restarted = spawn_handoff_worker(&fixture, recovery, phase);
                wait_for_handoff_exit(&mut restarted);
                assert_eq!(disk_snapshot(&fixture.base.join("cache")), cache_before);
                assert_eq!(disk_snapshot(&fixture.base.join("trust")), trust_before);
                assert_eq!(fixture.cache.load_state().unwrap(), before);
                if recovery == "recover" {
                    assert!(destination_entries(&fixture.destination).is_empty());
                }
            }
        }
    }

    #[test]
    #[ignore = "subprocess helper for appliance handoff SIGKILL boundaries"]
    fn handoff_sigkill_worker() {
        let root = PathBuf::from(std::env::var_os("OPEMOS_HANDOFF_TEST_ROOT").unwrap());
        let root = root.canonicalize().unwrap();
        assert_eq!(
            root.parent().unwrap(),
            std::env::temp_dir().canonicalize().unwrap()
        );
        assert!(root
            .file_name()
            .unwrap()
            .as_bytes()
            .starts_with(b"opemos-appliance-staging-sigkill-"));
        let mode = std::env::var("OPEMOS_HANDOFF_TEST_MODE").unwrap();
        let phase = std::env::var("OPEMOS_HANDOFF_TEST_PHASE").unwrap();
        assert!(
            STAGING_CRASH_PHASES.contains(&phase.as_str())
                || PARTIAL_RECEIPT_CRASH_PHASES.contains(&phase.as_str())
                || RETIREMENT_CRASH_PHASES.contains(&phase.as_str())
        );
        // The parent retains stdin. If it dies, do not leave a parked worker.
        std::thread::spawn(|| {
            let mut byte = [0_u8; 1];
            let _ = std::io::stdin().read(&mut byte);
            std::process::exit(99);
        });
        let fixture = PreparedFixture::load(root, false);
        let before = fixture.cache.load_state().unwrap();
        let hook = |observed: &'static str| {
            if observed == phase {
                println!("\nHANDOFF_READY:{observed}");
                std::io::stdout().flush().unwrap();
                loop {
                    std::thread::park_timeout(Duration::from_secs(1));
                }
            }
            Ok(())
        };
        match mode.as_str() {
            "stage" => {
                stage_pending_generation_for_appliance_with_hook(
                    &fixture.cache,
                    &fixture.generation,
                    &fixture.checkpoint,
                    &fixture.target,
                    &[],
                    &fixture.operation,
                    &fixture.destination,
                    || false,
                    hook,
                )
                .unwrap();
                panic!("staging worker missed boundary {phase}");
            }
            "retire" => {
                fixture.stage().unwrap().retire_with_hook(hook).unwrap();
                panic!("retirement worker missed boundary {phase}");
            }
            "recover" => {
                let mut staged = fixture.stage().unwrap();
                staged.revalidate().unwrap();
                staged.retire().unwrap();
                assert!(destination_entries(&fixture.destination).is_empty());
            }
            "preserve" => {
                let mut preserved = disk_snapshot(&fixture.destination);
                // Recovery removes the exact unfinished lease-record temporary,
                // but must preserve every stage byte and durable lease entry.
                preserved.retain(|path, _| {
                    path.file_name() != Some(OsStr::new(LEASE_FILES_TEMP_FILENAME))
                });
                for _ in 0..2 {
                    let error = match fixture.stage() {
                        Ok(_) => panic!("partial receipt was accepted after SIGKILL"),
                        Err(error) => error,
                    };
                    assert!(error.starts_with("appliance-handoff-recovery-required:"));
                    let after = disk_snapshot(&fixture.destination);
                    for (path, expected) in &preserved {
                        assert!(after.get(path) == Some(expected), "preserved residue changed at {phase}: {path:?}; before inode/mode {:?}, after {:?}", (expected.0, expected.1), after.get(path).map(|entry| (entry.0, entry.1)));
                    }
                    assert_eq!(after.len(), preserved.len());
                }
            }
            _ => panic!("unknown handoff worker mode"),
        }
        assert_eq!(fixture.cache.load_state().unwrap(), before);
    }

    #[test]
    fn synthetic_crashes_reconcile_every_staging_publication_boundary() {
        let phases = STAGING_CRASH_PHASES;
        for &phase in phases {
            let fixture = PreparedFixture::create(&format!("crash-{}", phase.replace('-', "")));
            let before = fixture.cache.load_state().unwrap();
            let crashed = catch_unwind(AssertUnwindSafe(|| {
                let _ = stage_pending_generation_for_appliance_with_hook(
                    &fixture.cache,
                    &fixture.generation,
                    &fixture.checkpoint,
                    &fixture.target,
                    &[],
                    &fixture.operation,
                    &fixture.destination,
                    || false,
                    |observed| {
                        if observed == phase {
                            panic!("synthetic process death at {phase}");
                        }
                        Ok(())
                    },
                );
            }));
            assert!(crashed.is_err(), "phase {phase} did not crash");
            let mut recovered = fixture
                .stage()
                .unwrap_or_else(|error| panic!("phase {phase} did not reconcile: {error}"));
            recovered.revalidate().unwrap();
            assert_eq!(fixture.cache.load_state().unwrap(), before);
            assert_eq!(destination_entries(&fixture.destination).len(), 1);
            recovered.retire().unwrap();
            assert!(destination_entries(&fixture.destination).is_empty());
        }
    }

    #[test]
    fn partial_file_receipt_crashes_preserve_stage_and_require_maintenance() {
        for &phase in PARTIAL_RECEIPT_CRASH_PHASES {
            let fixture = PreparedFixture::create(&format!("partial-{}", phase.replace('-', "")));
            let crashed = catch_unwind(AssertUnwindSafe(|| {
                let _ = stage_pending_generation_for_appliance_with_hook(
                    &fixture.cache,
                    &fixture.generation,
                    &fixture.checkpoint,
                    &fixture.target,
                    &[],
                    &fixture.operation,
                    &fixture.destination,
                    || false,
                    |observed| {
                        if observed == phase {
                            panic!("synthetic partial receipt crash at {phase}");
                        }
                        Ok(())
                    },
                );
            }));
            assert!(crashed.is_err());
            let preserved = all_destination_entries(&fixture.destination)
                .into_iter()
                .filter(|path| path.is_dir())
                .collect::<Vec<_>>();
            let error = match fixture.stage() {
                Ok(_) => panic!("partial receipt stage was discarded at {phase}"),
                Err(error) => error,
            };
            assert!(error.starts_with("appliance-handoff-recovery-required:"));
            assert!(preserved.iter().all(|path| path.exists()));
        }
    }

    #[test]
    fn synthetic_retirement_crashes_finish_before_a_new_handoff_is_created() {
        for &phase in RETIREMENT_CRASH_PHASES {
            let fixture = PreparedFixture::create(&format!("retire-{}", phase.replace('-', "")));
            let mut staged = fixture.stage().unwrap();
            let crashed = catch_unwind(AssertUnwindSafe(|| {
                let _ = staged.retire_with_hook(|observed| {
                    if observed == phase {
                        panic!("synthetic process death at {phase}");
                    }
                    Ok(())
                });
            }));
            assert!(crashed.is_err());
            let mut replacement = fixture.stage().unwrap_or_else(|error| {
                panic!("retirement phase {phase} did not reconcile: {error}")
            });
            replacement.revalidate().unwrap();
            replacement.retire().unwrap();
            assert!(destination_entries(&fixture.destination).is_empty());
        }
    }

    #[test]
    fn superseded_operations_reconcile_receipted_stage_publication_and_retirement() {
        for phase in ["after-stage-created", "after-copy", "after-rename"] {
            let fixture = PreparedFixture::create(&format!("supersede-{}", phase.replace('-', "")));
            let crashed = catch_unwind(AssertUnwindSafe(|| {
                let _ = stage_pending_generation_for_appliance_with_hook(
                    &fixture.cache,
                    &fixture.generation,
                    &fixture.checkpoint,
                    &fixture.target,
                    &[],
                    &fixture.operation,
                    &fixture.destination,
                    || false,
                    |observed| {
                        if observed == phase {
                            panic!("synthetic superseded operation crash at {phase}");
                        }
                        Ok(())
                    },
                );
            }));
            assert!(crashed.is_err());
            let replacement_operation = format!("replacement-{phase}");
            fixture.supersede_pending(&replacement_operation);
            let mut replacement = fixture
                .stage_operation(&replacement_operation)
                .unwrap_or_else(|error| panic!("could not supersede {phase}: {error}"));
            replacement.revalidate().unwrap();
            assert_eq!(destination_entries(&fixture.destination).len(), 1);
            replacement.retire().unwrap();
            assert!(destination_entries(&fixture.destination).is_empty());
        }

        let fixture = PreparedFixture::create("supersede-retiring");
        let mut staged = fixture.stage().unwrap();
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let _ = staged.retire_with_hook(|phase| {
                if phase == "after-retiring-marker" {
                    panic!("synthetic superseded retirement crash");
                }
                Ok(())
            });
        }));
        assert!(crashed.is_err());
        let replacement_operation = "replacement-retiring";
        fixture.supersede_pending(replacement_operation);
        let mut replacement = fixture.stage_operation(replacement_operation).unwrap();
        replacement.revalidate().unwrap();
        assert_eq!(destination_entries(&fixture.destination).len(), 1);
        replacement.retire().unwrap();
        assert!(destination_entries(&fixture.destination).is_empty());
    }

    #[test]
    fn superseded_pre_receipt_stage_is_preserved_with_stable_recovery_reason() {
        let fixture = PreparedFixture::create("supersede-pre-receipt");
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let _ = stage_pending_generation_for_appliance_with_hook(
                &fixture.cache,
                &fixture.generation,
                &fixture.checkpoint,
                &fixture.target,
                &[],
                &fixture.operation,
                &fixture.destination,
                || false,
                |phase| {
                    if phase == "after-files-receipt-write" {
                        panic!("synthetic pre-receipt process death");
                    }
                    Ok(())
                },
            );
        }));
        assert!(crashed.is_err());
        let preserved = all_destination_entries(&fixture.destination)
            .into_iter()
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        fixture.supersede_pending("replacement-pre-receipt");
        let error = match fixture.stage_operation("replacement-pre-receipt") {
            Ok(_) => panic!("ambiguous pre-receipt stage was discarded"),
            Err(error) => error,
        };
        assert!(
            error.starts_with("appliance-handoff-recovery-required:"),
            "unexpected recovery error: {error}"
        );
        assert!(preserved.iter().all(|path| path.exists()));
    }

    #[test]
    fn self_consistent_receipt_and_stage_rewrite_cannot_authorize_restart_cleanup() {
        let fixture = PreparedFixture::create("self-consistent-receipt-rewrite");
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let _ = stage_pending_generation_for_appliance_with_hook(
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
                        panic!("synthetic death before publication");
                    }
                    Ok(())
                },
            );
        }));
        assert!(crashed.is_err());
        let lease = fs::read_dir(&fixture.destination)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(LEASE_DIRECTORY_PREFIX))
            })
            .unwrap();
        let intent_path = lease.join(LEASE_INTENT_FILENAME);
        let receipt_path = lease.join(LEASE_FILES_FILENAME);
        let mut intent: HandoffLeaseIntent =
            serde_json::from_slice(&fs::read(&intent_path).unwrap()).unwrap();
        let mut receipt: HandoffLeaseFiles =
            serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        let stage = fixture.destination.join(&intent.stage_name);
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
        let payload_name = "userspace-lock.json";
        let payload = b"attacker-selected-stage-content\n";
        let payload_path = stage.join(payload_name);
        fs::set_permissions(&payload_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&payload_path, payload).unwrap();
        fs::set_permissions(&payload_path, fs::Permissions::from_mode(0o400)).unwrap();
        let payload_expected = HandoffExpectedFile {
            size: payload.len() as u64,
            sha256: sha256(payload),
        };
        intent
            .expected_files
            .insert(payload_name.into(), payload_expected.clone());
        let record_file = intent
            .handoff_record
            .files
            .iter_mut()
            .find(|file| file.filename == payload_name)
            .unwrap();
        record_file.size = payload_expected.size;
        record_file.sha256 = payload_expected.sha256.clone();
        let handoff_bytes = canonical_record(&intent.handoff_record).unwrap();
        intent.handoff_record_sha256 = sha256(&handoff_bytes);
        intent.expected_files.insert(
            HANDOFF_FILENAME.into(),
            HandoffExpectedFile {
                size: handoff_bytes.len() as u64,
                sha256: intent.handoff_record_sha256.clone(),
            },
        );
        let handoff_path = stage.join(HANDOFF_FILENAME);
        fs::set_permissions(&handoff_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&handoff_path, &handoff_bytes).unwrap();
        fs::set_permissions(&handoff_path, fs::Permissions::from_mode(0o400)).unwrap();
        receipt.files.get_mut(payload_name).unwrap().identity =
            HandoffFileIdentity::from(&fs::metadata(&payload_path).unwrap());
        receipt.files.get_mut(HANDOFF_FILENAME).unwrap().identity =
            HandoffFileIdentity::from(&fs::metadata(&handoff_path).unwrap());
        fs::set_permissions(&intent_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&intent_path, canonical_lease_record(&intent).unwrap()).unwrap();
        fs::set_permissions(&intent_path, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&receipt_path, canonical_lease_record(&receipt).unwrap()).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o400)).unwrap();

        let error = match fixture.stage() {
            Ok(_) => panic!("self-consistent unauthenticated rewrite was accepted"),
            Err(error) => error,
        };
        assert!(error.starts_with("appliance-handoff-recovery-required:"));
        assert_eq!(fs::read(payload_path).unwrap(), payload);
        assert!(lease.exists());
    }

    #[test]
    fn malformed_noncanonical_duplicate_and_oversized_leases_fail_closed() {
        let variants = [
            b"not-json\n".to_vec(),
            b"{\"schemaVersion\":1,\"schemaVersion\":1}\n".to_vec(),
            b"{}".to_vec(),
            vec![b'x'; LEASE_RECORD_MAX_BYTES + 1],
        ];
        for (index, bytes) in variants.into_iter().enumerate() {
            let fixture = PreparedFixture::create(&format!("bad-lease-{index}"));
            let staged = fixture.stage().unwrap();
            let intent = fixture
                .destination
                .join(staged.lease.directory_name.to_str().unwrap())
                .join(LEASE_INTENT_FILENAME);
            fs::set_permissions(&intent, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&intent, bytes).unwrap();
            fs::set_permissions(&intent, fs::Permissions::from_mode(0o400)).unwrap();
            assert!(fixture.stage().is_err());
            assert_eq!(destination_entries(&fixture.destination).len(), 1);
        }
    }

    #[test]
    fn lease_links_special_files_and_replacement_are_preserved_fail_closed() {
        for kind in ["symlink", "hardlink", "fifo"] {
            let fixture = PreparedFixture::create(&format!("lease-{kind}"));
            let staged = fixture.stage().unwrap();
            let lease = fixture
                .destination
                .join(staged.lease.directory_name.to_str().unwrap());
            let intent = lease.join(LEASE_INTENT_FILENAME);
            let saved = lease.join("saved-intent");
            fs::rename(&intent, &saved).unwrap();
            match kind {
                "symlink" => symlink(&saved, &intent).unwrap(),
                "hardlink" => fs::hard_link(&saved, &intent).unwrap(),
                "fifo" => {
                    let path = CString::new(intent.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o400) }, 0);
                }
                _ => unreachable!(),
            }
            assert!(fixture.stage().is_err());
            assert_eq!(destination_entries(&fixture.destination).len(), 1);
        }

        let fixture = PreparedFixture::create("lease-replacement");
        let mut staged = fixture.stage().unwrap();
        let lease = fixture
            .destination
            .join(staged.lease.directory_name.to_str().unwrap());
        let moved = fixture.destination.join("moved-lease");
        fs::rename(&lease, &moved).unwrap();
        fs::create_dir(&lease).unwrap();
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(staged.revalidate().is_err());
        assert!(staged.retire().is_err());
        assert!(moved.exists());
        assert!(lease.exists());
        assert_eq!(destination_entries(&fixture.destination).len(), 2);
    }

    #[test]
    fn replaced_recovery_stage_is_never_removed() {
        let fixture = PreparedFixture::create("replaced-recovery-stage");
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let _ = stage_pending_generation_for_appliance_with_hook(
                &fixture.cache,
                &fixture.generation,
                &fixture.checkpoint,
                &fixture.target,
                &[],
                &fixture.operation,
                &fixture.destination,
                || false,
                |phase| {
                    if phase == "after-stage-created" {
                        panic!("synthetic process death");
                    }
                    Ok(())
                },
            );
        }));
        assert!(crashed.is_err());
        let lease_path = fs::read_dir(&fixture.destination)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(LEASE_DIRECTORY_PREFIX))
            })
            .unwrap();
        let intent: HandoffLeaseIntent =
            serde_json::from_slice(&fs::read(lease_path.join(LEASE_INTENT_FILENAME)).unwrap())
                .unwrap();
        let stage = fixture.destination.join(&intent.stage_name);
        let moved = fixture.destination.join("original-stage");
        fs::rename(&stage, &moved).unwrap();
        fs::create_dir(&stage).unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(fixture.stage().is_err());
        assert!(stage.exists());
        assert!(moved.exists());
    }

    #[test]
    fn lease_entry_bound_accepts_full_domain_and_rejects_one_more() {
        let fixture = PreparedFixture::create("lease-entry-bound");
        let staged = fixture.stage().unwrap();
        let mut intent = staged.lease.intent.clone();
        for index in intent.expected_files.len()..MAX_HANDOFF_DIRECTORY_ENTRIES {
            let filename = format!("bounded-{index}");
            intent.expected_files.insert(
                filename.clone(),
                HandoffExpectedFile {
                    size: 1,
                    sha256: "0".repeat(64),
                },
            );
            intent.handoff_record.files.push(ApplianceHandoffFile {
                filename,
                size: 1,
                sha256: "0".repeat(64),
            });
        }
        intent
            .handoff_record
            .files
            .sort_by(|left, right| left.filename.cmp(&right.filename));
        let handoff = canonical_record(&intent.handoff_record).unwrap();
        intent.handoff_record_sha256 = sha256(&handoff);
        intent.expected_files.insert(
            HANDOFF_FILENAME.into(),
            HandoffExpectedFile {
                size: handoff.len() as u64,
                sha256: intent.handoff_record_sha256.clone(),
            },
        );
        intent.maximum_entries = MAX_HANDOFF_DIRECTORY_ENTRIES as u64;
        validate_lease_intent(&intent, &staged.lease.directory_name)
            .unwrap_or_else(|error| panic!("maximum valid lease rejected: {error}"));
        intent.maximum_entries += 1;
        assert!(validate_lease_intent(&intent, &staged.lease.directory_name).is_err());
    }
}
