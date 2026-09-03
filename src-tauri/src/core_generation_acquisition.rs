use crate::{
    core_generation_cache::{CandidateLease, CoreGenerationCache, CoreGenerationIdentity},
    core_generation_contracts::{
        validate_discovery_bytes, validate_manifest_bytes, validate_openpgp_status, validate_pair,
        GenerationAuthority, GenerationDiscovery, GenerationFile, GenerationManifest,
        GenerationTarget, OpenPgpValidSignature, DISCOVERY_FILENAME, DISCOVERY_MAX_BYTES,
        DISCOVERY_SIGNATURE_FILENAME, DISCOVERY_SIGNATURE_SCHEME, MAX_GENERATION_STORAGE_BYTES,
        MAX_OPENPGP_STATUS_BYTES, MAX_SIGNATURE_BYTES, MAX_TRUST_RECORD_BYTES,
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

pub(crate) trait GenerationTransport {
    // A production implementation must bound open/read time and own, cancel,
    // terminate, and reap any helper process. This inactive trait deliberately
    // has no network implementation yet.
    fn open(&mut self, canonical_filename: &str) -> Result<Box<dyn Read>, String>;
}

pub(crate) trait InactiveTrustVerifier {
    // Implementations must snapshot the installed policy/keyring independently
    // of the document and honor cancellation while terminating/reaping helpers.
    // Production wiring remains forbidden until that concrete handle exists.
    fn authenticate_discovery(
        &mut self,
        canonical_discovery: &[u8],
        detached_signature: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AuthenticatedOpenPgpEvidence, AcquisitionError>;

    fn authenticate_manifest(
        &mut self,
        canonical_manifest: &[u8],
        detached_signature: &[u8],
        discovery: &GenerationDiscovery,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<AuthenticatedOpenPgpEvidence, AcquisitionError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedOpenPgpEvidence {
    /// Bounded stdout from a successful `gpgv --status-fd` invocation.
    pub(crate) status: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatedTrustRecord<'a> {
    schema_version: u32,
    kind: &'static str,
    signature_scheme: &'static str,
    primary_fingerprint: &'a str,
    discovery_signing_fingerprint: &'a str,
    discovery_hash_algorithm_id: u32,
    discovery_sha256: String,
    manifest_signing_fingerprint: &'a str,
    manifest_hash_algorithm_id: u32,
    manifest_sha256: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum AcquisitionError {
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
    manifest: &'a GenerationManifest,
    discovery_bytes: &'a [u8],
    discovery_signature: &'a [u8],
    manifest_bytes: &'a [u8],
    manifest_signature: &'a [u8],
    trust_record: &'a [u8],
}

pub(crate) fn acquire_inactive_generation<T, V, C>(
    cache: &CoreGenerationCache,
    operation_id: &str,
    expected_authority: &GenerationAuthority,
    expected_target: &GenerationTarget,
    transport: &mut T,
    verifier: &mut V,
    cancelled: C,
) -> Result<CoreGenerationIdentity, AcquisitionError>
where
    T: GenerationTransport,
    V: InactiveTrustVerifier,
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
    let discovery_evidence =
        verifier.authenticate_discovery(&discovery_bytes, &discovery_signature, &cancelled)?;
    poll_cancelled(&cancelled)?;
    let discovery_signature_status =
        validate_authenticated_evidence(discovery_evidence, expected_authority)?;
    let discovery =
        validate_discovery_bytes(&discovery_bytes).map_err(AcquisitionError::Contract)?;
    if &discovery.authority != expected_authority {
        return Err(AcquisitionError::Authentication(
            "Validated discovery authority differs from installed policy.".into(),
        ));
    }

    poll_cancelled(&cancelled)?;
    let manifest_bytes = fetch_exact(
        transport,
        &discovery.generation.manifest_filename,
        discovery.generation.manifest_size,
        &discovery.generation.manifest_sha256,
        &cancelled,
    )?;
    poll_cancelled(&cancelled)?;
    let manifest_signature = fetch_exact(
        transport,
        &discovery.generation.signature_filename,
        discovery.generation.signature_size,
        &discovery.generation.signature_sha256,
        &cancelled,
    )?;
    let manifest_evidence = verifier.authenticate_manifest(
        &manifest_bytes,
        &manifest_signature,
        &discovery,
        &cancelled,
    )?;
    poll_cancelled(&cancelled)?;
    let manifest_signature_status =
        validate_authenticated_evidence(manifest_evidence, expected_authority)?;
    if manifest_signature_status.primary_fingerprint
        != discovery_signature_status.primary_fingerprint
    {
        return Err(AcquisitionError::Authentication(
            "Manifest and discovery were authenticated by different primary keys.".into(),
        ));
    }
    let manifest = validate_manifest_bytes(&manifest_bytes).map_err(AcquisitionError::Contract)?;
    let manifest_hash = validate_pair(&discovery, &manifest).map_err(AcquisitionError::Contract)?;
    require_exact_target(&discovery, &manifest, expected_target)?;
    let trust_record = canonical_trust_record(
        &discovery_signature_status,
        &manifest_signature_status,
        &discovery_bytes,
        &manifest_bytes,
    )?;
    let inventory = expected_inventory(
        &discovery,
        &manifest,
        &discovery_bytes,
        &discovery_signature,
        &manifest_bytes,
        &manifest_signature,
        &trust_record,
    )?;

    let reservation = reservation_bytes(
        &discovery_bytes,
        &discovery_signature,
        &manifest_bytes,
        &manifest_signature,
        &trust_record,
        &manifest,
    )?;
    poll_cancelled(&cancelled)?;
    let lease = cache
        .create_candidate(operation_id, reservation)
        .map_err(AcquisitionError::Cache)?;
    let staged = stage_all(
        &lease,
        transport,
        &cancelled,
        &StagedControls {
            discovery: &discovery,
            manifest: &manifest,
            discovery_bytes: &discovery_bytes,
            discovery_signature: &discovery_signature,
            manifest_bytes: &manifest_bytes,
            manifest_signature: &manifest_signature,
            trust_record: &trust_record,
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
        .commit_candidate(&lease, &identity, |root| {
            verify_flat_inventory(root, &inventory)
        })
        .map_err(AcquisitionError::Cache)?;
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
    for artifact in &controls.manifest.files {
        poll_cancelled(cancelled)?;
        let mut reader = transport.open(&artifact.filename).map_err(|error| {
            AcquisitionError::Transport(format!("Could not request {}: {error}", artifact.filename))
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
    artifact: &GenerationFile,
    reader: &mut dyn Read,
    cancelled: &C,
) -> Result<(), AcquisitionError> {
    let mut file = lease.create_file(&artifact.filename).map_err(map_io)?;
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
        if total > artifact.size {
            return Err(AcquisitionError::Contract(format!(
                "Generation artifact {} exceeds its declared size.",
                artifact.filename
            )));
        }
        file.write_all(&chunk[..read]).map_err(map_io)?;
        digest.update(&chunk[..read]);
    }
    if total != artifact.size || format!("{:x}", digest.finalize()) != artifact.sha256 {
        return Err(AcquisitionError::Contract(format!(
            "Generation artifact {} does not match its identity.",
            artifact.filename
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

fn validate_authenticated_evidence(
    evidence: AuthenticatedOpenPgpEvidence,
    expected_authority: &GenerationAuthority,
) -> Result<OpenPgpValidSignature, AcquisitionError> {
    if evidence.status.is_empty() || evidence.status.len() > MAX_OPENPGP_STATUS_BYTES {
        return Err(AcquisitionError::Authentication(
            "OpenPGP verifier status is empty or excessive.".into(),
        ));
    }
    validate_openpgp_status(
        &evidence.status,
        &expected_authority.signing_key_fingerprint,
    )
    .map_err(AcquisitionError::Authentication)
}

fn canonical_trust_record(
    discovery_status: &OpenPgpValidSignature,
    manifest_status: &OpenPgpValidSignature,
    discovery: &[u8],
    manifest: &[u8],
) -> Result<Vec<u8>, AcquisitionError> {
    let record = AuthenticatedTrustRecord {
        schema_version: 1,
        kind: "opemos-inactive-host-generation-trust",
        signature_scheme: DISCOVERY_SIGNATURE_SCHEME,
        primary_fingerprint: &discovery_status.primary_fingerprint,
        discovery_signing_fingerprint: &discovery_status.signing_fingerprint,
        discovery_hash_algorithm_id: discovery_status.hash_algorithm_id,
        discovery_sha256: hash(discovery),
        manifest_signing_fingerprint: &manifest_status.signing_fingerprint,
        manifest_hash_algorithm_id: manifest_status.hash_algorithm_id,
        manifest_sha256: hash(manifest),
    };
    let value = serde_json::to_value(record)
        .map_err(|error| AcquisitionError::Authentication(error.to_string()))?;
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|error| AcquisitionError::Authentication(error.to_string()))?;
    canonical.push(b'\n');
    if canonical.len() as u64 > MAX_TRUST_RECORD_BYTES {
        return Err(AcquisitionError::Authentication(
            "Authenticated trust record is excessive.".into(),
        ));
    }
    Ok(canonical)
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
    use crate::core_generation_contracts::{
        DiscoveryGeneration, GenerationAuthority, GenerationCompatibility, GenerationLock,
        GenerationTargetLock, MAX_GENERATION_BYTES,
    };
    use std::{
        io::Cursor,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
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
    }

    struct DevelopmentVerifier {
        reject_discovery: bool,
        reject_manifest: bool,
    }

    fn valid_status(signing: char, primary: char) -> Vec<u8> {
        format!(
            "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG {} 2026-09-03 1788436800 0 4 0 1 8 00 {}\n",
            signing.to_string().repeat(40),
            primary.to_string().repeat(40)
        )
        .into_bytes()
    }

    impl InactiveTrustVerifier for DevelopmentVerifier {
        fn authenticate_discovery(
            &mut self,
            document: &[u8],
            signature: &[u8],
            cancelled: &dyn Fn() -> bool,
        ) -> Result<AuthenticatedOpenPgpEvidence, AcquisitionError> {
            if cancelled() {
                return Err(AcquisitionError::Cancelled);
            }
            if self.reject_discovery || signature != b"discovery-signature" {
                Err(AcquisitionError::Authentication(
                    "discovery authentication rejected".into(),
                ))
            } else {
                assert_eq!(hash(document).len(), 64);
                Ok(AuthenticatedOpenPgpEvidence {
                    status: valid_status('B', 'A'),
                })
            }
        }

        fn authenticate_manifest(
            &mut self,
            _document: &[u8],
            signature: &[u8],
            _discovery: &GenerationDiscovery,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<AuthenticatedOpenPgpEvidence, AcquisitionError> {
            if cancelled() {
                return Err(AcquisitionError::Cancelled);
            }
            if self.reject_manifest || signature != b"manifest-signature" {
                Err(AcquisitionError::Authentication(
                    "manifest authentication rejected".into(),
                ))
            } else {
                Ok(AuthenticatedOpenPgpEvidence {
                    status: valid_status('C', 'A'),
                })
            }
        }
    }

    fn canonical<T: serde::Serialize>(value: &T) -> Vec<u8> {
        let value = serde_json::to_value(value).unwrap();
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn fixture() -> (GenerationAuthority, GenerationTarget, MemoryTransport) {
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
        let authority = GenerationAuthority {
            policy_id: "opemos-userspace-lock-generations".into(),
            policy_schema_version: 1,
            policy_sha256: "1".repeat(64),
            keyring_filename: "generation-keyring.gpg".into(),
            keyring_sha256: "2".repeat(64),
            signing_key_fingerprint: "A".repeat(40),
        };
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
            discovery.authority.clone(),
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
        let (authority, target, mut transport) = fixture();
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        let first = acquire_inactive_generation(
            &cache,
            "acquire-first",
            &authority,
            &target,
            &mut transport,
            &mut verifier,
            || false,
        )
        .unwrap();
        assert!(cache.load_state().unwrap().active.is_none());

        let (authority, target, mut transport) = fixture();
        let second = acquire_inactive_generation(
            &cache,
            "acquire-repeat",
            &authority,
            &target,
            &mut transport,
            &mut verifier,
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
        let (authority, target, mut transport) = fixture();
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
                &authority,
                &target,
                &mut transport,
                &mut verifier,
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
        let (authority, target, mut transport) = fixture();
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
                &authority,
                &target,
                &mut transport,
                &mut verifier,
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
        let (mut authority, target, mut transport) = fixture();
        authority.policy_sha256 = "3".repeat(64);
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert!(matches!(
            acquire_inactive_generation(
                &cache,
                "wrong-authority",
                &authority,
                &target,
                &mut transport,
                &mut verifier,
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
    fn cancellation_before_acquisition_makes_no_requests_or_cache_writes() {
        let root = temporary_cache("cancel-before-lease");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (authority, target, mut transport) = fixture();
        let mut verifier = DevelopmentVerifier {
            reject_discovery: false,
            reject_manifest: false,
        };
        assert_eq!(
            acquire_inactive_generation(
                &cache,
                "cancelled",
                &authority,
                &target,
                &mut transport,
                &mut verifier,
                || true
            ),
            Err(AcquisitionError::Cancelled)
        );
        assert!(transport.requests.is_empty());
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        cleanup(&root);
    }

    #[test]
    fn exact_target_mismatch_fails_before_candidate_creation() {
        let root = temporary_cache("target-mismatch");
        let cache = CoreGenerationCache::open(&root).unwrap();
        let (authority, _target, mut transport) = fixture();
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
                &authority,
                &different,
                &mut transport,
                &mut verifier,
                || false
            ),
            Err(AcquisitionError::Contract(_))
        ));
        assert_eq!(fs::read_dir(root.join("candidates")).unwrap().count(), 0);
        cleanup(&root);
    }

    #[test]
    fn storage_envelope_includes_payload_max_and_bounded_controls() {
        let (_authority, _target, transport) = fixture();
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
