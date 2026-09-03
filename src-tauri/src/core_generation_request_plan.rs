//! Inactive compatibility consumer for Core's immutable generation request
//! plan. It derives data only and has no HTTP, endpoint activation, keyring,
//! cache, command, UI, or production callsite.

use crate::{
    core_contracts::reject_duplicate_contract_keys,
    core_generation_bootstrap::{
        expected_generation_authority, parse_bootstrap_policy, BootstrapPolicy,
    },
    core_generation_contracts::{
        validate_discovery_bytes, validate_manifest_bytes, validate_pair, GenerationDiscovery,
        MAX_FILES, MAX_GENERATION_STORAGE_BYTES, MAX_SIGNATURE_BYTES,
    },
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) const MAX_REQUESTS: usize = MAX_FILES + 4;
pub(crate) const MAX_URL_BYTES: usize = 2048;
pub(crate) const MAX_REQUEST_METADATA_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_PLAN_BYTES: usize = 32 * 1024 * 1024;

const PLAN_KIND: &str = "opemos-userspace-lock-generation-request-plan";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationRequestPlan {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) policy_sha256: String,
    pub(crate) keyring_sha256: String,
    pub(crate) primary_signing_fingerprint: String,
    pub(crate) discovery_hash_algorithm_id: u32,
    pub(crate) manifest_hash_algorithm_id: u32,
    pub(crate) sequence: u64,
    pub(crate) release_tag: String,
    pub(crate) origin: String,
    pub(crate) redirects: bool,
    pub(crate) request_count: usize,
    pub(crate) aggregate_expected_bytes: u64,
    pub(crate) aggregate_metadata_bytes: u64,
    pub(crate) requests: Vec<GenerationRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationRequest {
    pub(crate) request_kind: String,
    pub(crate) asset_role: String,
    pub(crate) filename: String,
    pub(crate) path: String,
    pub(crate) url: String,
    pub(crate) expected_size: u64,
    pub(crate) expected_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticationRecord {
    schema_version: u32,
    status: String,
    policy_sha256: String,
    keyring_sha256: String,
    primary_signing_fingerprint: String,
    discovery_payload_sha256: String,
    discovery_signature_sha256: String,
    discovery_hash_algorithm_id: u32,
    manifest_payload_sha256: String,
    manifest_signature_sha256: String,
    manifest_hash_algorithm_id: u32,
}

/// Opaque evidence produced only after an internal verifier binds its exact
/// policy/keyring snapshot and authenticated document bytes. There is
/// intentionally no public constructor or Deserialize implementation: caller
/// assertions and wire documents are never accepted as proof.
#[derive(Clone, Debug)]
pub(crate) struct SnapshotBoundAuthenticationEvidence {
    record: AuthenticationRecord,
}

pub(crate) struct RequestPlanInputs<'a> {
    pub(crate) policy_payload: &'a [u8],
    pub(crate) discovery_payload: &'a [u8],
    pub(crate) discovery_signature: &'a [u8],
    pub(crate) manifest_payload: &'a [u8],
    pub(crate) manifest_signature: &'a [u8],
    pub(crate) payloads: &'a BTreeMap<String, Vec<u8>>,
}

fn parse_canonical<T: DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
    label: &str,
) -> Result<T, String> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(format!("{label} is empty or exceeds its size limit."));
    }
    reject_duplicate_contract_keys(bytes, label)?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| format!("{label} is malformed."))?;
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("Could not canonicalize {label}: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(format!("{label} is not canonical JSON."));
    }
    serde_json::from_value(value).map_err(|_| format!("{label} is invalid."))
}

pub(crate) fn build_request_plan(
    inputs: &RequestPlanInputs<'_>,
    evidence: &SnapshotBoundAuthenticationEvidence,
) -> Result<GenerationRequestPlan, String> {
    let policy = parse_bootstrap_policy(inputs.policy_payload)?;
    let discovery = validate_discovery_bytes(inputs.discovery_payload)?;
    let manifest = validate_manifest_bytes(inputs.manifest_payload)?;
    validate_pair(&discovery, &manifest)?;
    let expected_authority = expected_generation_authority(&policy, inputs.policy_payload)?;
    if discovery.authority != expected_authority {
        return Err("Authenticated discovery authority differs from bootstrap policy.".into());
    }
    require_supported_compatibility(&policy, &discovery)?;
    if !(1..=MAX_SIGNATURE_BYTES as usize).contains(&inputs.discovery_signature.len())
        || !(1..=MAX_SIGNATURE_BYTES as usize).contains(&inputs.manifest_signature.len())
    {
        return Err("Authenticated detached signature is empty or excessive.".into());
    }
    let channel = &policy.channel;
    let generation = &discovery.generation;
    if generation.release_tag != format!("{}{}", channel.release_tag_prefix, discovery.sequence)
        || generation.signature_size != inputs.manifest_signature.len() as u64
        || generation.signature_sha256 != sha256(inputs.manifest_signature)
    {
        return Err("Generation identity differs from authenticated inputs.".into());
    }
    validate_snapshot_evidence(&evidence.record, &policy, inputs)?;
    if inputs.payloads.len() != manifest.files.len()
        || manifest
            .files
            .iter()
            .any(|file| !inputs.payloads.contains_key(&file.filename))
    {
        return Err("Generation payload set differs from authenticated manifest.".into());
    }

    let origin = &channel.origin;
    let discovery_parent = channel
        .discovery_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .ok_or("Bootstrap discovery path has no parent.")?;
    let release_root = format!(
        "{}{}{}/",
        origin, channel.immutable_release_path_prefix, generation.release_tag
    );
    let mut requests = vec![
        request_record(
            "metadata",
            "discovery",
            &channel.discovery_filename,
            &channel.discovery_path,
            &format!("{}{}", origin, channel.discovery_path),
            inputs.discovery_payload,
        )?,
        request_record(
            "metadata",
            "discovery-signature",
            &channel.discovery_signature_filename,
            &format!(
                "{discovery_parent}/{}",
                channel.discovery_signature_filename
            ),
            &format!(
                "{origin}{discovery_parent}/{}",
                channel.discovery_signature_filename
            ),
            inputs.discovery_signature,
        )?,
        request_record(
            "metadata",
            "generation-manifest",
            &generation.manifest_filename,
            &format!(
                "{}{}/{}",
                channel.immutable_release_path_prefix,
                generation.release_tag,
                generation.manifest_filename
            ),
            &format!("{release_root}{}", generation.manifest_filename),
            inputs.manifest_payload,
        )?,
        request_record(
            "metadata",
            "generation-manifest-signature",
            &generation.signature_filename,
            &format!(
                "{}{}/{}",
                channel.immutable_release_path_prefix,
                generation.release_tag,
                generation.signature_filename
            ),
            &format!("{release_root}{}", generation.signature_filename),
            inputs.manifest_signature,
        )?,
    ];
    for file in &manifest.files {
        let payload = &inputs.payloads[&file.filename];
        if payload.len() as u64 != file.size || sha256(payload) != file.sha256 {
            return Err("Generation payload differs from authenticated manifest.".into());
        }
        requests.push(request_record(
            "payload",
            &file.role,
            &file.filename,
            &format!(
                "{}{}/{}",
                channel.immutable_release_path_prefix, generation.release_tag, file.filename
            ),
            &format!("{release_root}{}", file.filename),
            payload,
        )?);
    }
    if !(5..=MAX_REQUESTS).contains(&requests.len()) {
        return Err("Generation request count is invalid or excessive.".into());
    }
    let aggregate_expected_bytes = requests
        .iter()
        .try_fold(0_u64, |total, request| {
            total.checked_add(request.expected_size)
        })
        .ok_or("Generation request byte count overflowed.")?;
    let aggregate_metadata_bytes = requests.iter().try_fold(0_u64, |total, request| {
        let record = request
            .filename
            .len()
            .checked_add(request.path.len())
            .and_then(|value| value.checked_add(request.url.len()))
            .and_then(|value| u64::try_from(value).ok())
            .ok_or("Generation request metadata count overflowed.")?;
        total
            .checked_add(record)
            .ok_or("Generation request metadata count overflowed.")
    })?;
    if aggregate_expected_bytes > MAX_GENERATION_STORAGE_BYTES
        || aggregate_metadata_bytes > MAX_REQUEST_METADATA_BYTES
    {
        return Err("Generation request plan is excessive.".into());
    }
    let record = &evidence.record;
    let plan = GenerationRequestPlan {
        schema_version: 1,
        kind: PLAN_KIND.into(),
        policy_sha256: sha256(inputs.policy_payload),
        keyring_sha256: record.keyring_sha256.clone(),
        primary_signing_fingerprint: record.primary_signing_fingerprint.clone(),
        discovery_hash_algorithm_id: record.discovery_hash_algorithm_id,
        manifest_hash_algorithm_id: record.manifest_hash_algorithm_id,
        sequence: discovery.sequence,
        release_tag: generation.release_tag.clone(),
        origin: origin.clone(),
        redirects: false,
        request_count: requests.len(),
        aggregate_expected_bytes,
        aggregate_metadata_bytes,
        requests,
    };
    if canonical_bytes(&plan)?.len() > MAX_PLAN_BYTES {
        return Err("Generation request plan document is excessive.".into());
    }
    Ok(plan)
}

pub(crate) fn parse_request_plan(
    payload: &[u8],
    inputs: &RequestPlanInputs<'_>,
    evidence: &SnapshotBoundAuthenticationEvidence,
) -> Result<GenerationRequestPlan, String> {
    let plan: GenerationRequestPlan =
        parse_canonical(payload, MAX_PLAN_BYTES, "Core generation request plan")?;
    let expected = build_request_plan(inputs, evidence)?;
    if plan != expected {
        return Err("Generation request plan differs from authenticated inputs.".into());
    }
    Ok(plan)
}

fn request_record(
    request_kind: &str,
    asset_role: &str,
    filename: &str,
    path: &str,
    url: &str,
    payload: &[u8],
) -> Result<GenerationRequest, String> {
    if payload.is_empty()
        || url.len() > MAX_URL_BYTES
        || !url.is_ascii()
        || !path.is_ascii()
        || !url.starts_with("https://")
        || url.contains('?')
        || url.contains('#')
        || !path.starts_with('/')
    {
        return Err("Request asset or URL is empty, noncanonical, or excessive.".into());
    }
    Ok(GenerationRequest {
        request_kind: request_kind.into(),
        asset_role: asset_role.into(),
        filename: filename.into(),
        path: path.into(),
        url: url.into(),
        expected_size: payload.len() as u64,
        expected_sha256: sha256(payload),
    })
}

fn validate_snapshot_evidence(
    record: &AuthenticationRecord,
    policy: &BootstrapPolicy,
    inputs: &RequestPlanInputs<'_>,
) -> Result<(), String> {
    let authority = &policy.authority;
    if record.schema_version != 1
        || record.status != "authenticated"
        || record.policy_sha256 != sha256(inputs.policy_payload)
        || record.keyring_sha256 != authority.keyring_sha256
        || record.primary_signing_fingerprint != authority.primary_signing_fingerprint
        || record.discovery_payload_sha256 != sha256(inputs.discovery_payload)
        || record.discovery_signature_sha256 != sha256(inputs.discovery_signature)
        || record.manifest_payload_sha256 != sha256(inputs.manifest_payload)
        || record.manifest_signature_sha256 != sha256(inputs.manifest_signature)
        || !authority
            .allowed_hash_algorithm_ids
            .contains(&record.discovery_hash_algorithm_id)
        || !authority
            .allowed_hash_algorithm_ids
            .contains(&record.manifest_hash_algorithm_id)
    {
        return Err("Request inputs lack exact snapshot-bound authentication evidence.".into());
    }
    Ok(())
}

fn require_supported_compatibility(
    policy: &BootstrapPolicy,
    discovery: &GenerationDiscovery,
) -> Result<(), String> {
    let required = &discovery.compatibility;
    let supported = &policy.compatibility;
    if !supported
        .discovery_schema_versions
        .contains(&required.discovery_schema_version)
        || !supported
            .generation_manifest_schema_versions
            .contains(&required.generation_manifest_schema_version)
        || !supported
            .userspace_lock_schema_versions
            .contains(&required.userspace_lock_schema_version)
        || !supported
            .installer_result_schema_versions
            .contains(&required.minimum_installer_result_schema_version)
    {
        return Err("Authenticated discovery requires an unsupported schema.".into());
    }
    Ok(())
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("Could not encode request plan: {error}"))?;
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("Could not encode request plan: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{
        collections::HashSet,
        fs,
        io::Read,
        os::unix::process::CommandExt as _,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const CONTRACT_COMMIT: &str = "ed3917cc3126aa4401eb96ce070e2081ecbbdd4f";
    const FIXTURE_LIMIT: usize = 1024 * 1024;
    const STDERR_LIMIT: usize = 64 * 1024;
    static EXPORT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    type FixtureArguments = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        BTreeMap<String, Vec<u8>>,
    );

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureEnvelope {
        schema_version: u32,
        kind: String,
        limits: FixtureLimits,
        cases: Vec<FixtureCase>,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureLimits {
        max_requests: usize,
        max_url_bytes: usize,
        max_request_metadata_bytes: u64,
        max_plan_bytes: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureCase {
        name: String,
        expected: FixtureExpected,
        inputs: FixtureInputs,
        #[serde(default)]
        plan: Option<serde_json::Value>,
        #[serde(default)]
        raw_plan: Option<String>,
        #[serde(default)]
        raw_plan_recipe: Option<RawPlanRecipe>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureExpected {
        inputs_accepted: bool,
        plan_accepted: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureInputs {
        policy: serde_json::Value,
        discovery: serde_json::Value,
        discovery_signature: String,
        manifest: serde_json::Value,
        manifest_signature: String,
        authentication: Option<serde_json::Value>,
        payloads: BTreeMap<String, String>,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureAuthentication {
        schema_version: u32,
        status: String,
        policy_sha256: String,
        keyring_sha256: String,
        primary_signing_fingerprint: String,
        discovery_payload_sha256: String,
        discovery_signature_sha256: String,
        discovery_hash_algorithm_id: u32,
        manifest_payload_sha256: String,
        manifest_signature_sha256: String,
        manifest_hash_algorithm_id: u32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawPlanRecipe {
        text: String,
        count: usize,
    }

    fn canonical(value: &serde_json::Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn local_core_repository() -> Option<PathBuf> {
        let configured = std::env::var_os("OPEMOS_CORE_CONTRACT_ROOT").map(PathBuf::from);
        let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .parent()?
            .join("open-gpu-kernel-modules-steamos-support");
        let required = configured.is_some();
        let repository = configured.unwrap_or(fallback);
        core_repository_with_git(repository, required, Path::new("git"))
    }

    fn core_repository_with_git(
        repository: PathBuf,
        required: bool,
        git_program: &Path,
    ) -> Option<PathBuf> {
        if !repository.join(".git").exists() {
            assert!(!required, "configured immutable Core repository is absent");
            return None;
        }
        let output = match Command::new(git_program)
            .args(["cat-file", "-e", &format!("{CONTRACT_COMMIT}^{{commit}}")])
            .current_dir(&repository)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                assert!(
                    !required,
                    "could not inspect configured immutable Core repository: {error}"
                );
                eprintln!("skipping local Core request-plan fixtures: git could not run: {error}");
                return None;
            }
        };
        assert!(
            output.status.success(),
            "configured Core repository lacks request-plan contract commit {CONTRACT_COMMIT}"
        );
        Some(repository)
    }

    fn export_fixture_sources(repository: &Path) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "opemos-core-request-plan-fixtures-{}-{nonce}-{}",
            std::process::id(),
            EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        for relative in [
            "lib/generate_userspace_lock_request_plan_fixtures.py",
            "lib/generate_userspace_lock_bootstrap_fixtures.py",
            "lib/generate_userspace_lock_generation_fixtures.py",
            "lib/userspace_lock_request_plan.py",
            "lib/userspace_lock_bootstrap_contract.py",
            "lib/userspace_lock_generation_contract.py",
        ] {
            let output = Command::new("git")
                .args(["show", &format!("{CONTRACT_COMMIT}:{relative}")])
                .current_dir(repository)
                .output()
                .unwrap();
            assert!(output.status.success() && output.stderr.is_empty());
            assert!(!output.stdout.is_empty() && output.stdout.len() <= 1024 * 1024);
            let destination = root.join(relative);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(destination, output.stdout).unwrap();
        }
        fs::canonicalize(root).unwrap()
    }

    fn bounded_pipe<R: Read>(mut pipe: R, limit: usize) -> (Vec<u8>, bool) {
        let mut output = Vec::with_capacity(limit.min(64 * 1024));
        let mut excessive = false;
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            let count = pipe.read(&mut chunk).unwrap();
            if count == 0 {
                return (output, excessive);
            }
            let remaining = limit.saturating_sub(output.len());
            output.extend_from_slice(&chunk[..count.min(remaining)]);
            excessive |= count > remaining;
            if excessive {
                return (output, true);
            }
        }
    }

    fn run_generator(path: &Path) -> Vec<u8> {
        run_generator_with_timeout(path, Duration::from_secs(15))
    }

    fn kill_process_group_and_reap(child: &mut Child) {
        let pid = child.id();
        if let Ok(pid) = i32::try_from(pid) {
            // The command was placed in a fresh process group whose ID is its
            // PID, so descendants are terminated before the leader is reaped.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        } else {
            let _ = child.kill();
        }
        let _ = child.wait();
    }

    fn run_generator_with_timeout(path: &Path, timeout: Duration) -> Vec<u8> {
        let mut command = Command::new("python3");
        command
            .arg(path)
            .current_dir("/")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.process_group(0);
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let stdout_thread = thread::spawn(move || bounded_pipe(stdout, FIXTURE_LIMIT));
        let stderr_thread = thread::spawn(move || bounded_pipe(stderr, STDERR_LIMIT));
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                kill_process_group_and_reap(&mut child);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                panic!("Core request-plan fixture generator exceeded its deadline");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stdout_excessive) = stdout_thread.join().unwrap();
        let (stderr, stderr_excessive) = stderr_thread.join().unwrap();
        assert!(!stdout_excessive && !stderr_excessive);
        assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
        assert!(stderr.is_empty() && stdout.ends_with(b"\n"));
        stdout
    }

    fn fixture_arguments(case: &FixtureCase) -> FixtureArguments {
        let inputs = &case.inputs;
        (
            canonical(&inputs.policy),
            canonical(&inputs.discovery),
            inputs.discovery_signature.as_bytes().to_vec(),
            canonical(&inputs.manifest),
            inputs.manifest_signature.as_bytes().to_vec(),
            inputs
                .payloads
                .iter()
                .map(|(name, payload)| (name.clone(), payload.as_bytes().to_vec()))
                .collect(),
        )
    }

    fn fixture_evidence(
        authentication: &serde_json::Value,
    ) -> Result<SnapshotBoundAuthenticationEvidence, String> {
        // Test-only stand-in for the future internal verifier. Production code
        // cannot deserialize or construct the opaque evidence type.
        let authentication: FixtureAuthentication = serde_json::from_value(authentication.clone())
            .map_err(|_| "authentication evidence is invalid".to_string())?;
        Ok(SnapshotBoundAuthenticationEvidence {
            record: AuthenticationRecord {
                schema_version: authentication.schema_version,
                status: authentication.status.clone(),
                policy_sha256: authentication.policy_sha256.clone(),
                keyring_sha256: authentication.keyring_sha256.clone(),
                primary_signing_fingerprint: authentication.primary_signing_fingerprint.clone(),
                discovery_payload_sha256: authentication.discovery_payload_sha256.clone(),
                discovery_signature_sha256: authentication.discovery_signature_sha256.clone(),
                discovery_hash_algorithm_id: authentication.discovery_hash_algorithm_id,
                manifest_payload_sha256: authentication.manifest_payload_sha256.clone(),
                manifest_signature_sha256: authentication.manifest_signature_sha256.clone(),
                manifest_hash_algorithm_id: authentication.manifest_hash_algorithm_id,
            },
        })
    }

    #[test]
    fn local_core_request_plan_matrix_matches_rust_contract() {
        let Some(repository) = local_core_repository() else {
            return;
        };
        let exported = export_fixture_sources(&repository);
        let generator = exported.join("lib/generate_userspace_lock_request_plan_fixtures.py");
        let bytes = run_generator(&generator);
        assert_eq!(bytes, run_generator(&generator));
        reject_duplicate_contract_keys(&bytes, "Core request-plan fixtures").unwrap();
        let fixture_value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(canonical(&fixture_value), bytes);
        let fixtures: FixtureEnvelope = serde_json::from_value(fixture_value).unwrap();
        assert_eq!(fixtures.schema_version, 1);
        assert_eq!(
            fixtures.kind,
            "opemos-userspace-lock-request-plan-compatibility"
        );
        assert_eq!(
            fixtures.limits,
            FixtureLimits {
                max_requests: MAX_REQUESTS,
                max_url_bytes: MAX_URL_BYTES,
                max_request_metadata_bytes: MAX_REQUEST_METADATA_BYTES,
                max_plan_bytes: MAX_PLAN_BYTES,
            }
        );
        assert_eq!(fixtures.cases.len(), 41);
        let expected = [
            "valid-canonical-plan",
            "unauthenticated-policy",
            "unauthenticated-discovery",
            "unauthenticated-discovery-signature",
            "unauthenticated-manifest",
            "unauthenticated-manifest-signature",
            "unauthenticated-status",
            "missing-authentication-evidence",
            "unknown-authentication-field",
            "weak-signature-hash",
            "missing-payload",
            "unexpected-payload",
            "payload-hash-mismatch",
            "release-tag-sequence-mismatch",
            "redirects-enabled",
            "cross-origin-substitution",
            "mutable-release-ref",
            "path-traversal",
            "path-field-substitution",
            "percent-encoded-path",
            "query-component",
            "fragment-component",
            "excessive-url",
            "missing-request",
            "duplicate-request",
            "extra-request",
            "case-colliding-filename",
            "wrong-release-tag",
            "wrong-keyring-identity",
            "wrong-signer-identity",
            "wrong-signature-algorithm",
            "wrong-sequence",
            "wrong-request-count",
            "wrong-aggregate-size",
            "wrong-aggregate-metadata",
            "unknown-plan-field",
            "unknown-request-field",
            "malformed-plan-json",
            "duplicate-plan-key",
            "non-finite-plan-number",
            "oversized-plan",
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        assert_eq!(
            fixtures
                .cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<HashSet<_>>(),
            expected
        );

        for case in &fixtures.cases {
            let (policy, discovery, discovery_signature, manifest, manifest_signature, payloads) =
                fixture_arguments(case);
            let inputs = RequestPlanInputs {
                policy_payload: &policy,
                discovery_payload: &discovery,
                discovery_signature: &discovery_signature,
                manifest_payload: &manifest,
                manifest_signature: &manifest_signature,
                payloads: &payloads,
            };
            let input_result = case
                .inputs
                .authentication
                .as_ref()
                .ok_or_else(|| "authentication evidence is absent".to_string())
                .and_then(fixture_evidence)
                .and_then(|evidence| build_request_plan(&inputs, &evidence));
            assert_eq!(
                input_result.is_ok(),
                case.expected.inputs_accepted,
                "{} inputs",
                case.name
            );
            if case.plan.is_some() || case.raw_plan.is_some() || case.raw_plan_recipe.is_some() {
                let plan = if let Some(value) = &case.plan {
                    canonical(value)
                } else if let Some(raw) = &case.raw_plan {
                    raw.as_bytes().to_vec()
                } else {
                    let recipe = case.raw_plan_recipe.as_ref().unwrap();
                    assert_eq!(recipe.text, " ");
                    vec![b' '; recipe.count]
                };
                let plan_result = case
                    .inputs
                    .authentication
                    .as_ref()
                    .ok_or_else(|| "authentication evidence is absent".to_string())
                    .and_then(fixture_evidence)
                    .and_then(|evidence| parse_request_plan(&plan, &inputs, &evidence));
                assert_eq!(
                    plan_result.is_ok(),
                    case.expected.plan_accepted,
                    "{} plan",
                    case.name
                );
            }
        }

        let valid = fixtures
            .cases
            .iter()
            .find(|case| case.name == "valid-canonical-plan")
            .unwrap();
        let (policy, discovery, discovery_signature, manifest, manifest_signature, payloads) =
            fixture_arguments(valid);
        let inputs = RequestPlanInputs {
            policy_payload: &policy,
            discovery_payload: &discovery,
            discovery_signature: &discovery_signature,
            manifest_payload: &manifest,
            manifest_signature: &manifest_signature,
            payloads: &payloads,
        };
        let evidence = fixture_evidence(valid.inputs.authentication.as_ref().unwrap()).unwrap();
        let plan = build_request_plan(&inputs, &evidence).unwrap();
        assert!(!plan.redirects);
        assert_eq!(plan.keyring_sha256, evidence.record.keyring_sha256);
        assert_eq!(
            plan.primary_signing_fingerprint,
            evidence.record.primary_signing_fingerprint
        );
        assert_eq!(plan.discovery_hash_algorithm_id, 10);
        assert_eq!(plan.manifest_hash_algorithm_id, 8);
        assert_eq!(plan.request_count, plan.requests.len());
        assert_eq!(
            plan.requests
                .iter()
                .take(4)
                .map(|request| request.asset_role.as_str())
                .collect::<Vec<_>>(),
            [
                "discovery",
                "discovery-signature",
                "generation-manifest",
                "generation-manifest-signature",
            ]
        );
        assert!(plan.requests.iter().all(|request| {
            request.url == format!("{}{}", plan.origin, request.path)
                && !request.url.contains('?')
                && !request.url.contains('#')
                && !request.url.contains('%')
                && !request.url.contains("..")
        }));
        assert_eq!(
            plan.aggregate_expected_bytes,
            plan.requests
                .iter()
                .map(|request| request.expected_size)
                .sum::<u64>()
        );
        assert_eq!(
            plan.aggregate_metadata_bytes,
            plan.requests
                .iter()
                .map(|request| {
                    u64::try_from(request.filename.len() + request.path.len() + request.url.len())
                        .unwrap()
                })
                .sum::<u64>()
        );
        fs::remove_dir_all(exported).unwrap();
    }

    #[test]
    fn bounded_pipe_stops_reading_at_the_limit() {
        struct OneReadThenPanic(bool);

        impl Read for OneReadThenPanic {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                assert!(!self.0, "bounded reader continued after detecting excess");
                self.0 = true;
                buffer[..4].copy_from_slice(b"xxxx");
                Ok(4)
            }
        }

        let (bytes, excessive) = bounded_pipe(OneReadThenPanic(false), 3);
        assert_eq!(bytes, b"xxx");
        assert!(excessive);
    }

    #[test]
    fn configured_core_repository_does_not_skip_git_spawn_failure() {
        let root = std::env::temp_dir().join(format!(
            "opemos-core-request-plan-git-failure-{}-{}",
            std::process::id(),
            EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join(".git")).unwrap();
        let missing_git = root.join("missing-git-executable");
        let result =
            std::panic::catch_unwind(|| core_repository_with_git(root.clone(), true, &missing_git));
        assert!(result.is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_generator_timeout_kills_and_reaps_process_group() {
        let root = std::env::temp_dir().join(format!(
            "opemos-core-request-plan-timeout-{}-{}",
            std::process::id(),
            EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let generator = root.join("hang.py");
        fs::write(&generator, b"import time\ntime.sleep(60)\n").unwrap();
        let started = Instant::now();
        let result = std::panic::catch_unwind(|| {
            run_generator_with_timeout(&generator, Duration::from_millis(50))
        });
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        fs::remove_dir_all(root).unwrap();
    }
}
