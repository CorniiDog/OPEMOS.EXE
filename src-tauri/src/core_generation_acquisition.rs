#![cfg(test)]

use crate::{
    core_generation_cache::{
        CandidateAdmissionError, CandidateLease, CoreGenerationCache, CoreGenerationIdentity,
        FilesystemCapacityProbe,
    },
    core_generation_contracts::{
        GenerationDiscovery, GenerationManifest, GenerationTarget, DISCOVERY_FILENAME,
        DISCOVERY_MAX_BYTES, DISCOVERY_SIGNATURE_FILENAME, MAX_GENERATION_STORAGE_BYTES,
        MAX_SIGNATURE_BYTES,
    },
    core_generation_request_plan::{authenticated_payload_requests, AuthenticatedPayloadRequest},
    core_generation_verifier::{
        authenticate_discovery_snapshot, authenticate_manifest_snapshot, DetachedVerifierOutput,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const TRUST_RECORD_FILENAME: &str = "acquisition-trust-v1.json";
const STREAM_BUFFER_BYTES: usize = 64 * 1024;

// Raw transport and verifier adapters are test-only acquisition internals. They
// must never become production authority or escape this module; future
// reachability must accept only a sealed verifier-owned capability.
trait GenerationTransport {
    // A production implementation must bound open/read time and own, cancel,
    // terminate, and reap any helper process. This inactive trait deliberately
    // has no network implementation yet.
    fn open(&mut self, canonical_filename: &str) -> Result<Box<dyn Read>, String>;

    fn open_authenticated_payload(
        &mut self,
        request: &AuthenticatedPayloadRequest,
    ) -> Result<Box<dyn Read>, String>;
}

#[derive(Debug, Eq, PartialEq)]
enum AcquisitionError {
    Cancelled,
    NoSpace(String),
    Contract(String),
    Authentication(String),
    Transport(String),
    Io(String),
    Cache(String),
    Cleanup {
        original: Box<AcquisitionError>,
        cleanup: String,
    },
}

struct StagedControls<'a> {
    discovery: &'a GenerationDiscovery,
    discovery_bytes: &'a [u8],
    discovery_signature: &'a [u8],
    manifest_bytes: &'a [u8],
    manifest_signature: &'a [u8],
    trust_record: &'a [u8],
    payload_requests: &'a [AuthenticatedPayloadRequest],
}

struct InactiveAcquisitionPolicy<'a> {
    policy_payload: &'a [u8],
    keyring_payload: &'a [u8],
    target: &'a GenerationTarget,
    capacity_probe: &'a dyn FilesystemCapacityProbe,
}

fn acquire_inactive_generation<T, F, C>(
    cache: &CoreGenerationCache,
    operation_id: &str,
    policy: &InactiveAcquisitionPolicy<'_>,
    transport: &mut T,
    verifier: &mut F,
    cancelled: C,
) -> Result<CoreGenerationIdentity, AcquisitionError>
where
    T: GenerationTransport,
    F: FnMut(
        &[u8],
        &[u8],
        &[u8],
        &str,
        &dyn Fn() -> bool,
    ) -> Result<DetachedVerifierOutput, String>,
    C: Fn() -> bool,
{
    poll_cancelled(&cancelled)?;
    let discovery_bytes = fetch_bounded(
        transport,
        DISCOVERY_FILENAME,
        DISCOVERY_MAX_BYTES as u64,
        &cancelled,
    )?;
    poll_cancelled(&cancelled)?;
    let discovery_signature = fetch_bounded(
        transport,
        DISCOVERY_SIGNATURE_FILENAME,
        MAX_SIGNATURE_BYTES,
        &cancelled,
    )?;
    let pending = authenticate_discovery_snapshot(
        policy.policy_payload,
        policy.keyring_payload,
        &discovery_bytes,
        &discovery_signature,
        &cancelled,
        &mut *verifier,
    )
    .map_err(|error| map_verifier_error(error, &cancelled))?;
    poll_cancelled(&cancelled)?;
    let manifest_request = pending.manifest_request();

    poll_cancelled(&cancelled)?;
    let manifest_bytes = fetch_exact(
        transport,
        manifest_request.filename(),
        manifest_request.size(),
        manifest_request.sha256(),
        &cancelled,
    )?;
    poll_cancelled(&cancelled)?;
    let manifest_signature = fetch_exact(
        transport,
        manifest_request.signature_filename(),
        manifest_request.signature_size(),
        manifest_request.signature_sha256(),
        &cancelled,
    )?;
    let authenticated = authenticate_manifest_snapshot(
        pending,
        &manifest_bytes,
        &manifest_signature,
        &cancelled,
        &mut *verifier,
    )
    .map_err(|error| map_verifier_error(error, &cancelled))?;
    poll_cancelled(&cancelled)?;
    require_exact_target(
        authenticated.discovery(),
        authenticated.manifest(),
        policy.target,
    )?;
    let payload_requests =
        authenticated_payload_requests(&authenticated).map_err(AcquisitionError::Contract)?;
    let trust_record = authenticated
        .canonical_evidence_bytes()
        .map_err(AcquisitionError::Authentication)?;
    let snapshots = authenticated.request_plan_inputs();
    let discovery = authenticated.discovery();
    let manifest = authenticated.manifest();
    let manifest_hash = hash(snapshots.manifest_payload);
    let inventory = expected_inventory(
        discovery,
        manifest,
        snapshots.discovery_payload,
        snapshots.discovery_signature,
        snapshots.manifest_payload,
        snapshots.manifest_signature,
        &trust_record,
    )?;

    let reservation = reservation_bytes(
        snapshots.discovery_payload,
        snapshots.discovery_signature,
        snapshots.manifest_payload,
        snapshots.manifest_signature,
        &trust_record,
        manifest,
    )?;
    let reservation_file_nodes = u64::try_from(inventory.len())
        .ok()
        // Candidate directory and its lease sidecar are also newly allocated.
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| {
            AcquisitionError::Contract("Generation file-node count overflowed.".into())
        })?;
    poll_cancelled(&cancelled)?;
    let lease = cache
        .create_candidate_admitted(
            operation_id,
            reservation,
            reservation_file_nodes,
            policy.capacity_probe,
        )
        .map_err(|error| match error {
            CandidateAdmissionError::NoSpace(detail) => AcquisitionError::NoSpace(detail),
            CandidateAdmissionError::Cache(detail) => AcquisitionError::Cache(detail),
        })?;
    let staged = stage_all(
        &lease,
        transport,
        &cancelled,
        &StagedControls {
            discovery,
            discovery_bytes: snapshots.discovery_payload,
            discovery_signature: snapshots.discovery_signature,
            manifest_bytes: snapshots.manifest_payload,
            manifest_signature: snapshots.manifest_signature,
            trust_record: &trust_record,
            payload_requests: &payload_requests,
        },
    );
    if let Err(original) = staged {
        return abort_with_context(cache, &lease, original);
    }
    if let Err(original) = poll_cancelled(&cancelled) {
        return abort_with_context(cache, &lease, original);
    }

    let identity = CoreGenerationIdentity {
        sequence: discovery.sequence,
        generation_id: manifest_hash.clone(),
        manifest_sha256: manifest_hash,
    };
    // Cancellation deliberately stops here: cache commit is the atomic,
    // non-cancellable publication boundary and does not alter activation state.
    cache
        .commit_candidate_admitted(&lease, &identity, |root| {
            verify_flat_inventory(root, &inventory)
        })
        .map_err(|error| match error {
            CandidateAdmissionError::NoSpace(detail) => AcquisitionError::NoSpace(detail),
            CandidateAdmissionError::Cache(detail) => AcquisitionError::Cache(detail),
        })?;
    Ok(identity)
}

fn stage_all<T: GenerationTransport, C: Fn() -> bool>(
    lease: &CandidateLease,
    transport: &mut T,
    cancelled: &C,
    controls: &StagedControls<'_>,
) -> Result<(), AcquisitionError> {
    for (name, bytes) in [
        (DISCOVERY_FILENAME, controls.discovery_bytes),
        (DISCOVERY_SIGNATURE_FILENAME, controls.discovery_signature),
        (
            controls.discovery.generation.manifest_filename.as_str(),
            controls.manifest_bytes,
        ),
        (
            controls.discovery.generation.signature_filename.as_str(),
            controls.manifest_signature,
        ),
        (TRUST_RECORD_FILENAME, controls.trust_record),
    ] {
        poll_cancelled(cancelled)?;
        write_create_new(lease, name, bytes)?;
    }
    for artifact in controls.payload_requests {
        poll_cancelled(cancelled)?;
        let mut reader = transport
            .open_authenticated_payload(artifact)
            .map_err(|error| {
                AcquisitionError::Transport(format!(
                    "Could not request {}: {error}",
                    artifact.filename()
                ))
            })?;
        write_stream_exact(lease, artifact, &mut reader, cancelled)?;
    }
    Ok(())
}

fn fetch_bounded<T: GenerationTransport, C: Fn() -> bool>(
    transport: &mut T,
    name: &str,
    limit: u64,
    cancelled: &C,
) -> Result<Vec<u8>, AcquisitionError> {
    let mut reader = transport.open(name).map_err(|error| {
        AcquisitionError::Transport(format!("Could not request {name}: {error}"))
    })?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; STREAM_BUFFER_BYTES];
    loop {
        poll_cancelled(cancelled)?;
        let read = reader.read(&mut chunk).map_err(map_io)?;
        if read == 0 {
            break;
        }
        if (bytes.len() as u64).saturating_add(read as u64) > limit {
            return Err(AcquisitionError::Contract(format!(
                "Downloaded {name} exceeds its bound."
            )));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    if bytes.is_empty() {
        return Err(AcquisitionError::Contract(format!(
            "Downloaded {name} is empty."
        )));
    }
    Ok(bytes)
}

fn fetch_exact<T: GenerationTransport, C: Fn() -> bool>(
    transport: &mut T,
    name: &str,
    size: u64,
    sha256: &str,
    cancelled: &C,
) -> Result<Vec<u8>, AcquisitionError> {
    let bytes = fetch_bounded(transport, name, size, cancelled)?;
    require_size_hash(name, &bytes, size, sha256)?;
    Ok(bytes)
}

fn write_create_new(
    lease: &CandidateLease,
    name: &str,
    bytes: &[u8],
) -> Result<(), AcquisitionError> {
    let mut file = lease.create_file(name).map_err(map_io)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(map_io)
}

fn write_stream_exact<C: Fn() -> bool>(
    lease: &CandidateLease,
    artifact: &AuthenticatedPayloadRequest,
    reader: &mut dyn Read,
    cancelled: &C,
) -> Result<(), AcquisitionError> {
    let mut file = lease.create_file(artifact.filename()).map_err(map_io)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; STREAM_BUFFER_BYTES];
    loop {
        poll_cancelled(cancelled)?;
        let read = reader.read(&mut chunk).map_err(map_io)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            AcquisitionError::Contract("Generation artifact size overflowed.".into())
        })?;
        if total > artifact.expected_size() {
            return Err(AcquisitionError::Contract(format!(
                "Generation artifact {} exceeds its declared size.",
                artifact.filename()
            )));
        }
        file.write_all(&chunk[..read]).map_err(map_io)?;
        digest.update(&chunk[..read]);
    }
    if total != artifact.expected_size()
        || format!("{:x}", digest.finalize()) != artifact.expected_sha256()
    {
        return Err(AcquisitionError::Contract(format!(
            "Generation artifact {} does not match its identity.",
            artifact.filename()
        )));
    }
    file.sync_all().map_err(map_io)
}

fn expected_inventory(
    discovery: &GenerationDiscovery,
    manifest: &GenerationManifest,
    discovery_bytes: &[u8],
    discovery_signature: &[u8],
    manifest_bytes: &[u8],
    manifest_signature: &[u8],
    trust_record: &[u8],
) -> Result<BTreeMap<String, (u64, String)>, AcquisitionError> {
    let mut inventory = BTreeMap::new();
    for (name, bytes) in [
        (DISCOVERY_FILENAME, discovery_bytes),
        (DISCOVERY_SIGNATURE_FILENAME, discovery_signature),
        (
            discovery.generation.manifest_filename.as_str(),
            manifest_bytes,
        ),
        (
            discovery.generation.signature_filename.as_str(),
            manifest_signature,
        ),
        (TRUST_RECORD_FILENAME, trust_record),
    ] {
        insert_inventory(&mut inventory, name, bytes.len() as u64, hash(bytes))?;
    }
    for artifact in &manifest.files {
        insert_inventory(
            &mut inventory,
            &artifact.filename,
            artifact.size,
            artifact.sha256.clone(),
        )?;
    }
    Ok(inventory)
}

fn insert_inventory(
    inventory: &mut BTreeMap<String, (u64, String)>,
    name: &str,
    size: u64,
    sha256: String,
) -> Result<(), AcquisitionError> {
    let folded = name.to_ascii_lowercase();
    if inventory
        .keys()
        .any(|existing| existing.to_ascii_lowercase() == folded)
        || inventory.insert(name.into(), (size, sha256)).is_some()
    {
        return Err(AcquisitionError::Contract(
            "Generation flat inventory collides with a control artifact.".into(),
        ));
    }
    Ok(())
}

fn verify_flat_inventory(
    root: &Path,
    expected: &BTreeMap<String, (u64, String)>,
) -> Result<(), String> {
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Non-UTF-8 inventory name")?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || !actual.insert(name.clone())
        {
            return Err("Generation staging inventory is not exact and flat.".into());
        }
        let (size, sha256) = expected
            .get(&name)
            .ok_or("Generation staging inventory contains an extra file.")?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(entry.path())
            .map_err(|error| error.to_string())?;
        let opened = file.metadata().map_err(|error| error.to_string())?;
        use std::os::unix::fs::MetadataExt as _;
        if !opened.is_file()
            || opened.nlink() != 1
            || opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.len() != *size
        {
            return Err("Generation staging file changed while opening.".into());
        }
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut chunk = [0_u8; STREAM_BUFFER_BYTES];
        loop {
            let read = file.read(&mut chunk).map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or("Generation staging verification size overflowed.")?;
            if total > *size {
                return Err("Generation staging file exceeds its expected size.".into());
            }
            digest.update(&chunk[..read]);
        }
        let after = file.metadata().map_err(|error| error.to_string())?;
        if total != *size
            || format!("{:x}", digest.finalize()) != *sha256
            || opened.dev() != after.dev()
            || opened.ino() != after.ino()
            || opened.len() != after.len()
            || opened.mtime() != after.mtime()
            || opened.mtime_nsec() != after.mtime_nsec()
            || after.nlink() != 1
        {
            return Err("Generation staging file failed disk verification.".into());
        }
    }
    if actual.len() != expected.len() || expected.keys().any(|name| !actual.contains(name)) {
        return Err("Generation staging inventory is incomplete.".into());
    }
    Ok(())
}

fn reservation_bytes(
    discovery: &[u8],
    discovery_signature: &[u8],
    manifest: &[u8],
    manifest_signature: &[u8],
    trust_record: &[u8],
    generation: &GenerationManifest,
) -> Result<u64, AcquisitionError> {
    let controls = [
        discovery,
        discovery_signature,
        manifest,
        manifest_signature,
        trust_record,
    ]
    .into_iter()
    .try_fold(0_u64, |total, bytes| total.checked_add(bytes.len() as u64))
    .ok_or_else(|| AcquisitionError::Contract("Generation reservation overflowed.".into()))?;
    let payload = generation
        .files
        .iter()
        .try_fold(0_u64, |total, file| total.checked_add(file.size))
        .ok_or_else(|| AcquisitionError::Contract("Generation reservation overflowed.".into()))?;
    let total = controls
        .checked_add(payload)
        .ok_or_else(|| AcquisitionError::Contract("Generation reservation overflowed.".into()))?;
    if total == 0 || total > MAX_GENERATION_STORAGE_BYTES {
        return Err(AcquisitionError::Contract(
            "Generation storage reservation is invalid.".into(),
        ));
    }
    Ok(total)
}

fn require_exact_target(
    discovery: &GenerationDiscovery,
    manifest: &GenerationManifest,
    expected: &GenerationTarget,
) -> Result<(), AcquisitionError> {
    let discovery_match = discovery
        .targets
        .iter()
        .filter(|record| &record.target == expected)
        .count();
    let manifest_match = manifest
        .target_locks
        .iter()
        .filter(|record| &record.target == expected)
        .count();
    if discovery_match != 1 || manifest_match != 1 {
        return Err(AcquisitionError::Contract(
            "Generation does not contain the exact selected target.".into(),
        ));
    }
    Ok(())
}

fn require_size_hash(
    name: &str,
    bytes: &[u8],
    size: u64,
    sha256: &str,
) -> Result<(), AcquisitionError> {
    if bytes.len() as u64 != size || hash(bytes) != sha256 {
        return Err(AcquisitionError::Contract(format!(
            "Downloaded {name} does not match its identity."
        )));
    }
    Ok(())
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn poll_cancelled<C: Fn() -> bool>(cancelled: &C) -> Result<(), AcquisitionError> {
    if cancelled() {
        Err(AcquisitionError::Cancelled)
    } else {
        Ok(())
    }
}

fn map_verifier_error<C: Fn() -> bool>(error: String, cancelled: &C) -> AcquisitionError {
    if cancelled() {
        AcquisitionError::Cancelled
    } else {
        AcquisitionError::Authentication(error)
    }
}

fn map_io(error: std::io::Error) -> AcquisitionError {
    if error.raw_os_error() == Some(libc::ENOSPC) || error.kind() == ErrorKind::StorageFull {
        AcquisitionError::NoSpace(error.to_string())
    } else {
        AcquisitionError::Io(error.to_string())
    }
}

fn abort_with_context(
    cache: &CoreGenerationCache,
    lease: &CandidateLease,
    original: AcquisitionError,
) -> Result<CoreGenerationIdentity, AcquisitionError> {
    match cache.abort_candidate(lease) {
        Ok(()) => Err(original),
        Err(cleanup) => Err(AcquisitionError::Cleanup {
            original: Box::new(original),
            cleanup,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_generation_bootstrap::{
        expected_generation_authority, BootstrapAuthority, BootstrapChannel,
        BootstrapCompatibility, BootstrapPolicy, BootstrapReplayPolicy, MAX_KEYRING_BYTES,
        MAX_POLICY_BYTES,
    };
    use crate::core_generation_cache::FilesystemCapacity;
    use crate::core_generation_contracts::{
        validate_discovery_bytes, validate_manifest_bytes, DiscoveryGeneration,
        GenerationCompatibility, GenerationFile, GenerationLock, GenerationTargetLock,
        DISCOVERY_SIGNATURE_SCHEME, MANIFEST_MAX_BYTES, MAX_GENERATION_BYTES,
        MAX_LINEAGE_GENERATIONS, OPENPGP_HASH_ALGORITHM_IDS,
    };
    use crate::core_generation_verifier::parse_verifier_evidence_record;
    use std::{
        io::Cursor,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicBool, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct MemoryTransport {
        files: BTreeMap<String, Vec<u8>>,
        requests: Vec<String>,
    }

    impl GenerationTransport for MemoryTransport {
        fn open(&mut self, name: &str) -> Result<Box<dyn Read>, String> {
            self.requests.push(name.into());
            self.files
                .get(name)
                .cloned()
                .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn Read>)
                .ok_or_else(|| "missing fixture".into())
        }

        fn open_authenticated_payload(
            &mut self,
            request: &AuthenticatedPayloadRequest,
        ) -> Result<Box<dyn Read>, String> {
            assert!(request.path().ends_with(request.filename()));
            assert!(request.url().ends_with(request.path()));
            self.open(request.filename())
        }
    }

    struct DevelopmentVerifier {
        reject_discovery: bool,
        reject_manifest: bool,
    }

    #[derive(Clone, Copy)]
    struct FixedCapacity(FilesystemCapacity);

    impl FilesystemCapacityProbe for FixedCapacity {
        fn probe(&self, _pinned_root: &fs::File) -> std::io::Result<FilesystemCapacity> {
            Ok(self.0)
        }
    }

    fn ample_capacity() -> FixedCapacity {
        FixedCapacity(FilesystemCapacity {
            available_bytes: u64::MAX,
            allocation_unit_bytes: 4096,
            available_inodes: None,
        })
    }

    fn policy<'a>(
        policy_payload: &'a [u8],
        keyring_payload: &'a [u8],
        target: &'a GenerationTarget,
        capacity_probe: &'a dyn FilesystemCapacityProbe,
    ) -> InactiveAcquisitionPolicy<'a> {
        InactiveAcquisitionPolicy {
            policy_payload,
            keyring_payload,
            target,
            capacity_probe,
        }
    }

    struct PanicCapacity;

    impl FilesystemCapacityProbe for PanicCapacity {
        fn probe(&self, _pinned_root: &fs::File) -> std::io::Result<FilesystemCapacity> {
            panic!("capacity probe must not run after cancellation")
        }
    }

    struct ErrorCapacity(i32);

    impl FilesystemCapacityProbe for ErrorCapacity {
        fn probe(&self, _pinned_root: &fs::File) -> std::io::Result<FilesystemCapacity> {
            Err(std::io::Error::from_raw_os_error(self.0))
        }
    }

    fn valid_status(signing: char, primary: char) -> Vec<u8> {
        format!(
            "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG {} 2026-09-03 1788436800 0 4 0 1 8 00 {}\n",
            signing.to_string().repeat(40),
            primary.to_string().repeat(40)
        )
        .into_bytes()
    }

    impl DevelopmentVerifier {
        fn verify(
            &mut self,
            document: &[u8],
            signature: &[u8],
            _keyring: &[u8],
            role: &str,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<DetachedVerifierOutput, String> {
            if cancelled() {
                return Err("verification cancelled".into());
            }
            let rejected = if role == "discovery" {
                self.reject_discovery || signature != b"discovery-signature"
            } else {
                self.reject_manifest || signature != b"manifest-signature"
            };
            if rejected {
                return Err(format!("{role} authentication rejected"));
            }
            assert_eq!(hash(document).len(), 64);
            Ok(DetachedVerifierOutput {
                exit_status: 0,
                status: if role == "discovery" {
                    valid_status('B', 'A')
                } else {
                    valid_status('C', 'A')
                },
            })
        }
    }

    fn canonical<T: serde::Serialize>(value: &T) -> Vec<u8> {
        let value = serde_json::to_value(value).unwrap();
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn fixture() -> (Vec<u8>, Vec<u8>, GenerationTarget, MemoryTransport) {
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
            sha256: hash(&payload),
            size: payload.len() as u64,
        };
        let target_lock = GenerationTargetLock {
            target: target.clone(),
            lock: lock.clone(),
        };
        let keyring = b"fixture-generation-keyring".to_vec();
        let bootstrap_policy = BootstrapPolicy {
            schema_version: 1,
            kind: "opemos-userspace-lock-bootstrap-policy".into(),
            status: "active".into(),
            policy_id: "opemos-userspace-lock-generations".into(),
            policy_schema_version: 1,
            authority: BootstrapAuthority {
                keyring_filename: "opemos-userspace-lock-generations.gpg".into(),
                keyring_sha256: hash(&keyring),
                primary_signing_fingerprint: "A".repeat(40),
                signature_scheme: DISCOVERY_SIGNATURE_SCHEME.into(),
                allowed_hash_algorithm_ids: OPENPGP_HASH_ALGORITHM_IDS.to_vec(),
            },
            channel: BootstrapChannel {
                origin: "https://updates.opemos.invalid".into(),
                discovery_path: "/userspace-locks/reviewed/opemos-userspace-lock-discovery-v1.json"
                    .into(),
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
        let policy_payload = canonical(&bootstrap_policy);
        let authority = expected_generation_authority(&bootstrap_policy, &policy_payload).unwrap();
        let manifest = GenerationManifest {
            schema_version: 1,
            kind: "opemos-userspace-lock-generation".into(),
            channel: "reviewed".into(),
            sequence: 1,
            published_at: "2026-01-01T00:00:00Z".into(),
            authority: authority.clone(),
            previous_manifest_sha256: None,
            target_locks: vec![target_lock.clone()],
            files: vec![GenerationFile {
                role: "userspace-lock".into(),
                filename: lock.filename.clone(),
                size: lock.size,
                sha256: lock.sha256.clone(),
            }],
        };
        let manifest_bytes = canonical(&manifest);
        let manifest_signature = b"manifest-signature".to_vec();
        let tag = "opemos-userspace-lock-generation-v1-s1";
        let discovery = GenerationDiscovery {
            schema_version: 1,
            kind: "opemos-userspace-lock-discovery".into(),
            channel: "reviewed".into(),
            sequence: 1,
            published_at: "2026-01-01T00:00:00Z".into(),
            authority,
            compatibility: GenerationCompatibility {
                discovery_schema_version: 1,
                generation_manifest_schema_version: 1,
                userspace_lock_schema_version: 1,
                minimum_installer_result_schema_version: 1,
            },
            generation: DiscoveryGeneration {
                release_tag: tag.into(),
                manifest_filename: format!("{tag}.manifest.json"),
                manifest_sha256: hash(&manifest_bytes),
                manifest_size: manifest_bytes.len() as u64,
                signature_filename: format!("{tag}.manifest.json.sig"),
                signature_sha256: hash(&manifest_signature),
                signature_size: manifest_signature.len() as u64,
                previous_manifest_sha256: None,
            },
            targets: vec![target_lock],
        };
        let mut files = BTreeMap::new();
        files.insert(DISCOVERY_FILENAME.into(), canonical(&discovery));
        files.insert(
            DISCOVERY_SIGNATURE_FILENAME.into(),
            b"discovery-signature".to_vec(),
        );
        files.insert(discovery.generation.manifest_filename, manifest_bytes);
        files.insert(discovery.generation.signature_filename, manifest_signature);
        files.insert(lock.filename, payload);
        (
            policy_payload,
            keyring,
            target,
            MemoryTransport {
                files,
                requests: Vec::new(),
            },
        )
    }

    fn temporary_cache(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "opemos-acquisition-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn cleanup(root: &Path) {
        fn writable(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                for entry in fs::read_dir(path).unwrap().flatten() {
                    writable(&entry.path());
                }
            } else if metadata.is_file() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        writable(root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn acquisition_commits_inactive_generation_and_repeat_is_already_present() {
        let root = temporary_cache("success");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        let first = acquire_inactive_generation(
            &cache,
            "acquire-first",
            &policy(&policy_bytes, &keyring, &target, &ample_capacity()),
            &mut transport,
            &mut |payload, signature, keyring, role, cancelled| {
                verifier.verify(payload, signature, keyring, role, cancelled)
            },
            || false,
        )
        .unwrap();
        assert!(cache.load_state().unwrap().active.is_none());
        assert_eq!(
            transport.requests,
            vec![
                DISCOVERY_FILENAME,
                DISCOVERY_SIGNATURE_FILENAME,
                "opemos-userspace-lock-generation-v1-s1.manifest.json",
                "opemos-userspace-lock-generation-v1-s1.manifest.json.sig",
                "userspace-lock.json",
            ]
        );
        let trust_record = fs::read(
            root.join("generations")
                .join(&first.generation_id)
                .join(TRUST_RECORD_FILENAME),
        )
        .unwrap();
        parse_verifier_evidence_record(&trust_record).unwrap();

        let (policy_bytes, keyring, target, mut transport) = fixture();
        let second = acquire_inactive_generation(
            &cache,
            "acquire-repeat",
            &policy(&policy_bytes, &keyring, &target, &ample_capacity()),
            &mut transport,
            &mut |payload, signature, keyring, role, cancelled| {
                verifier.verify(payload, signature, keyring, role, cancelled)
            },
            || false,
        )
        .unwrap();
        assert_eq!(first, second);
        assert!(cache.load_state().unwrap().active.is_none());
        cleanup(&root);
    }

    #[test]
    fn discovery_authentication_rejection_prevents_derived_requests_and_cache_writes() {
        let root = temporary_cache("auth-reject");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        transport
            .files
            .insert(DISCOVERY_FILENAME.into(), b"not-json".to_vec());
        let mut verifier = DevelopmentVerifier {
            reject_discovery: true,
            reject_manifest: false,
        };
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "reject",
                &policy(&policy_bytes, &keyring, &target, &ample_capacity()),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || false
            ),
            Err(AcquisitionError::Authentication(_))
        ));
        assert_eq!(
            transport.requests,
            vec![DISCOVERY_FILENAME, DISCOVERY_SIGNATURE_FILENAME]
        );
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        cleanup(&root);
    }

    #[test]
    fn payload_hash_failure_cleans_candidate_without_activation() {
        let root = temporary_cache("hash-failure");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        transport
            .files
            .insert("userspace-lock.json".into(), b"wrong".to_vec());
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "bad-hash",
                &policy(&policy_bytes, &keyring, &target, &ample_capacity()),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || false
            ),
            Err(AcquisitionError::Contract(_))
        ));
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert!(cache.load_state().unwrap().active.is_none());
        cleanup(&root);
    }

    #[test]
    fn installed_authority_mismatch_stops_before_manifest_requests() {
        let root = temporary_cache("authority-mismatch");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, mut keyring, target, mut transport) = fixture();
        keyring.push(0);
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "wrong-authority",
                &policy(&policy_bytes, &keyring, &target, &ample_capacity()),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || false
            ),
            Err(AcquisitionError::Authentication(_))
        ));
        assert_eq!(
            transport.requests,
            vec![DISCOVERY_FILENAME, DISCOVERY_SIGNATURE_FILENAME]
        );
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        cleanup(&root);
    }

    #[test]
    fn rotated_policy_with_same_signer_cannot_reuse_old_discovery() {
        let root = temporary_cache("policy-rotation");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        let mut rotated: BootstrapPolicy = serde_json::from_slice(&policy_bytes).unwrap();
        rotated.channel.origin = "https://mirror.opemos.invalid".into();
        let rotated_policy = canonical(&rotated);
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "rotated-policy",
                &policy(&rotated_policy, &keyring, &target, &ample_capacity()),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || false,
            ),
            Err(AcquisitionError::Authentication(_))
        ));
        assert_eq!(
            transport.requests,
            vec![DISCOVERY_FILENAME, DISCOVERY_SIGNATURE_FILENAME]
        );
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(cache.load_state().unwrap(), Default::default());
        cleanup(&root);
    }

    #[test]
    fn manifest_from_another_session_cannot_cross_discovery_boundary() {
        let root = temporary_cache("mixed-session");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        let discovery = validate_discovery_bytes(&transport.files[DISCOVERY_FILENAME]).unwrap();
        transport.files.insert(
            discovery.generation.manifest_filename.clone(),
            b"{\"differentSession\":true}\n".to_vec(),
        );
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "mixed-session",
                &policy(&policy_bytes, &keyring, &target, &ample_capacity()),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || false,
            ),
            Err(AcquisitionError::Contract(_))
        ));
        assert_eq!(
            transport.requests,
            vec![
                DISCOVERY_FILENAME,
                DISCOVERY_SIGNATURE_FILENAME,
                discovery.generation.manifest_filename.as_str(),
            ]
        );
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(cache.load_state().unwrap(), Default::default());
        cleanup(&root);
    }

    #[test]
    fn cancellation_before_acquisition_makes_no_requests_or_cache_writes() {
        let root = temporary_cache("cancel-before-lease");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert_eq!(
            acquire_inactive_generation(
                &cache,
                "cancelled",
                &policy(&policy_bytes, &keyring, &target, &PanicCapacity),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || true
            ),
            Err(AcquisitionError::Cancelled)
        );
        assert!(transport.requests.is_empty());
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(cache.load_state().unwrap(), Default::default());
        cleanup(&root);
    }

    #[test]
    fn cancellation_raised_during_discovery_verification_stops_derived_work() {
        let root = temporary_cache("cancel-in-verifier");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        let cancelled = AtomicBool::new(false);
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert_eq!(
            acquire_inactive_generation(
                &cache,
                "cancel-in-verifier",
                &policy(&policy_bytes, &keyring, &target, &PanicCapacity),
                &mut transport,
                &mut |payload, signature, keyring, role, cancellation| {
                    assert!(!cancellation());
                    let output = verifier.verify(payload, signature, keyring, role, cancellation);
                    cancelled.store(true, Ordering::SeqCst);
                    output
                },
                || cancelled.load(Ordering::SeqCst),
            ),
            Err(AcquisitionError::Cancelled)
        );
        assert_eq!(
            transport.requests,
            vec![DISCOVERY_FILENAME, DISCOVERY_SIGNATURE_FILENAME]
        );
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(cache.load_state().unwrap(), Default::default());
        cleanup(&root);
    }

    #[test]
    fn verifier_rejects_oversized_snapshots_before_ownership() {
        let (policy_bytes, keyring, _target, transport) = fixture();
        let discovery_bytes = &transport.files[DISCOVERY_FILENAME];
        let discovery = validate_discovery_bytes(discovery_bytes).unwrap();
        let discovery_signature = &transport.files[DISCOVERY_SIGNATURE_FILENAME];
        let manifest_signature = &transport.files[&discovery.generation.signature_filename];
        let never_verify = |_: &[u8],
                            _: &[u8],
                            _: &[u8],
                            _: &str,
                            _: &dyn Fn() -> bool|
         -> Result<DetachedVerifierOutput, String> {
            panic!("oversized snapshots must fail before verifier execution")
        };

        assert!(authenticate_discovery_snapshot(
            &vec![b'x'; MAX_POLICY_BYTES + 1],
            &keyring,
            discovery_bytes,
            discovery_signature,
            &|| false,
            never_verify,
        )
        .is_err());
        assert!(authenticate_discovery_snapshot(
            &policy_bytes,
            &vec![b'x'; MAX_KEYRING_BYTES + 1],
            discovery_bytes,
            discovery_signature,
            &|| false,
            never_verify,
        )
        .is_err());
        assert!(authenticate_discovery_snapshot(
            &policy_bytes,
            &keyring,
            &vec![b'x'; DISCOVERY_MAX_BYTES + 1],
            discovery_signature,
            &|| false,
            never_verify,
        )
        .is_err());

        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        let pending = authenticate_discovery_snapshot(
            &policy_bytes,
            &keyring,
            discovery_bytes,
            discovery_signature,
            &|| false,
            |payload, signature, keyring, role, cancelled| {
                verifier.verify(payload, signature, keyring, role, cancelled)
            },
        )
        .unwrap();
        assert!(authenticate_manifest_snapshot(
            pending,
            &vec![b'x'; MANIFEST_MAX_BYTES + 1],
            manifest_signature,
            &|| false,
            never_verify,
        )
        .is_err());
    }

    #[test]
    fn physical_admission_shortage_maps_to_no_space_without_cache_state_change() {
        let root = temporary_cache("admission-no-space");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        let no_capacity = FixedCapacity(FilesystemCapacity {
            available_bytes: 0,
            allocation_unit_bytes: 4096,
            available_inodes: Some(0),
        });
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "no-space",
                &policy(&policy_bytes, &keyring, &target, &no_capacity),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || false,
            ),
            Err(AcquisitionError::NoSpace(_))
        ));
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.join("leases")).unwrap().count(), 0);
        assert_eq!(cache.load_state().unwrap(), Default::default());
        cleanup(&root);
    }

    #[test]
    fn enospc_probe_failure_is_preserved_as_typed_no_space() {
        let root = temporary_cache("probe-enospc");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, target, mut transport) = fixture();
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "probe-enospc",
                &policy(
                    &policy_bytes,
                    &keyring,
                    &target,
                    &ErrorCapacity(libc::ENOSPC),
                ),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || false,
            ),
            Err(AcquisitionError::NoSpace(_))
        ));
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        assert_eq!(cache.load_state().unwrap(), Default::default());
        cleanup(&root);
    }

    #[test]
    fn exact_target_mismatch_fails_before_candidate_creation() {
        let root = temporary_cache("target-mismatch");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (policy_bytes, keyring, _target, mut transport) = fixture();
        let different = GenerationTarget {
            steamos_version: "3.8.14".into(),
            kernel_version: "6.11.11-valve1-1-neptune-611".into(),
            nvidia_version: "999.1".into(),
            architecture: "x86_64".into(),
        };
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "wrong-target",
                &policy(&policy_bytes, &keyring, &different, &ample_capacity()),
                &mut transport,
                &mut |payload, signature, keyring, role, cancelled| {
                    verifier.verify(payload, signature, keyring, role, cancelled)
                },
                || false
            ),
            Err(AcquisitionError::Contract(_))
        ));
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        cleanup(&root);
    }

    #[test]
    fn storage_envelope_includes_payload_max_and_bounded_controls() {
        let (_policy_bytes, _keyring, _target, transport) = fixture();
        let discovery_bytes = &transport.files[DISCOVERY_FILENAME];
        let discovery = validate_discovery_bytes(discovery_bytes).unwrap();
        let manifest_bytes = &transport.files[&discovery.generation.manifest_filename];
        let mut manifest = validate_manifest_bytes(manifest_bytes).unwrap();
        manifest.files[0].size = MAX_GENERATION_BYTES;
        let total = reservation_bytes(
            discovery_bytes,
            &transport.files[DISCOVERY_SIGNATURE_FILENAME],
            manifest_bytes,
            &transport.files[&discovery.generation.signature_filename],
            b"{\"schemaVersion\":1}\n",
            &manifest,
        )
        .unwrap();
        assert!(total > MAX_GENERATION_BYTES);
        assert!(total <= MAX_GENERATION_STORAGE_BYTES);

        manifest.files[0].size = MAX_GENERATION_STORAGE_BYTES;
        assert!(reservation_bytes(
            discovery_bytes,
            &transport.files[DISCOVERY_SIGNATURE_FILENAME],
            manifest_bytes,
            &transport.files[&discovery.generation.signature_filename],
            b"{\"schemaVersion\":1}\n",
            &manifest,
        )
        .is_err());
    }
}
