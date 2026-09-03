//! Inactive compatibility consumer for Core's immutable generation request
//! plan. It derives data only and has no HTTP, endpoint activation, keyring,
//! cache, command, UI, or production callsite.

#[cfg(test)]
use crate::core_generation_verifier::{
    parse_verifier_evidence_record, verify_generation_snapshots, DetachedVerifierOutput,
    MAX_EVIDENCE_BYTES,
};
use crate::core_generation_verifier::{
    AuthenticatedGeneration, RequestPlanInputs, SnapshotBoundAuthenticationEvidence,
};
use crate::{
    core_contracts::reject_duplicate_contract_keys,
    core_generation_bootstrap::{expected_generation_authority, BootstrapPolicy},
    core_generation_contracts::{
        validate_pair, GenerationDiscovery, MAX_FILES, MAX_GENERATION_STORAGE_BYTES,
        MAX_SIGNATURE_BYTES,
    },
    core_generation_verifier::validate_evidence_capability,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// A payload request derived inside this module from one sealed authenticated
/// generation. Its fields cannot be caller-constructed or mutated before the
/// inactive acquisition transport consumes them.
pub(crate) struct AuthenticatedPayloadRequest {
    request: GenerationRequest,
    _seal: RequestSeal,
}

struct RequestSeal;

impl AuthenticatedPayloadRequest {
    pub(crate) fn filename(&self) -> &str {
        &self.request.filename
    }

    pub(crate) fn expected_size(&self) -> u64 {
        self.request.expected_size
    }

    pub(crate) fn expected_sha256(&self) -> &str {
        &self.request.expected_sha256
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &str {
        &self.request.path
    }

    #[cfg(test)]
    pub(crate) fn url(&self) -> &str {
        &self.request.url
    }
}

pub(crate) fn authenticated_payload_requests(
    generation: &AuthenticatedGeneration,
) -> Result<Vec<AuthenticatedPayloadRequest>, String> {
    let inputs = generation.request_plan_inputs();
    let plan = build_request_plan(&inputs, generation)?;
    if plan.redirects || plan.requests.len() < 5 {
        return Err("Authenticated request plan has no payload inventory.".into());
    }
    plan.requests
        .into_iter()
        .skip(4)
        .map(|request| {
            if request.request_kind != "payload" {
                return Err("Authenticated request plan contains a non-payload request.".into());
            }
            Ok(AuthenticatedPayloadRequest {
                request,
                _seal: RequestSeal,
            })
        })
        .collect()
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
    validate_evidence_capability(evidence, inputs)?;
    let policy = evidence.policy();
    let discovery = evidence.discovery();
    let manifest = evidence.manifest();
    validate_pair(discovery, manifest)?;
    let expected_authority = expected_generation_authority(policy, inputs.policy_payload)?;
    if evidence.authority() != &expected_authority || discovery.authority != expected_authority {
        return Err("Authenticated discovery authority differs from bootstrap policy.".into());
    }
    require_supported_compatibility(policy, discovery)?;
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
    if evidence.record().keyring_sha256 != policy.authority.keyring_sha256
        || evidence.record().primary_signing_fingerprint
            != policy.authority.primary_signing_fingerprint
    {
        return Err("Verifier evidence authority differs from bootstrap policy.".into());
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
            inputs.discovery_payload.len() as u64,
            &sha256(inputs.discovery_payload),
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
            inputs.discovery_signature.len() as u64,
            &sha256(inputs.discovery_signature),
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
            inputs.manifest_payload.len() as u64,
            &sha256(inputs.manifest_payload),
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
            inputs.manifest_signature.len() as u64,
            &sha256(inputs.manifest_signature),
        )?,
    ];
    for file in &manifest.files {
        requests.push(request_record(
            "payload",
            &file.role,
            &file.filename,
            &format!(
                "{}{}/{}",
                channel.immutable_release_path_prefix, generation.release_tag, file.filename
            ),
            &format!("{release_root}{}", file.filename),
            file.size,
            &file.sha256,
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
    let record = evidence.record();
    let plan = GenerationRequestPlan {
        schema_version: 1,
        kind: PLAN_KIND.into(),
        policy_sha256: sha256(inputs.policy_payload),
        keyring_sha256: record.keyring_sha256.clone(),
        primary_signing_fingerprint: record.primary_signing_fingerprint.clone(),
        discovery_hash_algorithm_id: record.documents[0].hash_algorithm_id,
        manifest_hash_algorithm_id: record.documents[1].hash_algorithm_id,
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
    expected_size: u64,
    expected_sha256: &str,
) -> Result<GenerationRequest, String> {
    if expected_size == 0
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
        expected_size,
        expected_sha256: expected_sha256.into(),
    })
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
        collections::{BTreeMap, HashSet},
        fs,
        io::Read,
        os::unix::process::CommandExt as _,
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus, Stdio},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const CONTRACT_COMMIT: &str = "1fde359025031a99055763dca76e0d709486ffac";
    const FIXTURE_LIMIT: usize = 1024 * 1024;
    const STDERR_LIMIT: usize = 64 * 1024;
    static EXPORT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
    type FixtureArguments = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    struct BoundedCommandOutput {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

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
        keyring_payload: String,
        discovery: serde_json::Value,
        discovery_signature: String,
        manifest: serde_json::Value,
        manifest_signature: String,
        verifier: FixtureVerifier,
        evidence_record: serde_json::Value,
        #[serde(rename = "payloads")]
        _payloads: BTreeMap<String, String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureVerifier {
        discovery_exit_status: i32,
        discovery_status: String,
        manifest_exit_status: i32,
        manifest_status: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawPlanRecipe {
        text: String,
        count: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct EvidenceFixtureEnvelope {
        schema_version: u32,
        kind: String,
        limits: EvidenceFixtureLimits,
        cases: Vec<EvidenceFixtureCase>,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct EvidenceFixtureLimits {
        max_evidence_bytes: usize,
        max_cases: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct EvidenceFixtureCase {
        name: String,
        expected: EvidenceFixtureExpected,
        inputs: FixtureInputs,
        #[serde(default)]
        record: Option<serde_json::Value>,
        #[serde(default)]
        raw_record: Option<String>,
        #[serde(default)]
        raw_record_recipe: Option<RawPlanRecipe>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct EvidenceFixtureExpected {
        capability_accepted: bool,
        record_accepted: bool,
    }

    fn canonical(value: &serde_json::Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn bounded_recipe_bytes(recipe: &RawPlanRecipe, maximum: usize) -> Result<Vec<u8>, String> {
        let allocation_limit = maximum
            .checked_add(1)
            .ok_or_else(|| "Fixture recipe limit overflowed.".to_string())?;
        if recipe.text != " " || recipe.count > allocation_limit {
            return Err("Fixture recipe is invalid or excessive.".into());
        }
        Ok(vec![b' '; recipe.count])
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
        let mut command = Command::new(git_program);
        command
            .args(["cat-file", "-e", &format!("{CONTRACT_COMMIT}^{{commit}}")])
            .current_dir(&repository);
        let output = match run_bounded_command(
            &mut command,
            1024,
            STDERR_LIMIT,
            COMMAND_TIMEOUT,
            "inspect immutable Core repository",
        ) {
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
            "lib/generate_userspace_lock_verifier_evidence_fixtures.py",
            "lib/generate_userspace_lock_bootstrap_fixtures.py",
            "lib/generate_userspace_lock_generation_fixtures.py",
            "lib/generate_openpgp_status_fixtures.py",
            "lib/userspace_lock_request_plan.py",
            "lib/userspace_lock_verifier_evidence.py",
            "lib/userspace_lock_bootstrap_contract.py",
            "lib/userspace_lock_generation_contract.py",
        ] {
            let mut command = Command::new("git");
            command
                .args(["show", &format!("{CONTRACT_COMMIT}:{relative}")])
                .current_dir(repository);
            let output = run_bounded_command(
                &mut command,
                1024 * 1024,
                STDERR_LIMIT,
                COMMAND_TIMEOUT,
                "export exact Core fixture source",
            )
            .unwrap();
            assert!(output.status.success() && output.stderr.is_empty());
            assert!(!output.stdout.is_empty());
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
        run_generator_with_timeout(path, COMMAND_TIMEOUT)
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

    fn run_bounded_command(
        command: &mut Command,
        stdout_limit: usize,
        stderr_limit: usize,
        timeout: Duration,
        label: &str,
    ) -> Result<BoundedCommandOutput, String> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command.process_group(0);
        let mut child = command
            .spawn()
            .map_err(|error| format!("Could not {label}: {error}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("Could not capture {label} stdout."))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| format!("Could not capture {label} stderr."))?;
        let stdout_thread = thread::spawn(move || bounded_pipe(stdout, stdout_limit));
        let stderr_thread = thread::spawn(move || bounded_pipe(stderr, stderr_limit));
        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // The leader can exit while descendants retain its pipes.
                    // End the isolated group before joining either reader.
                    kill_process_group_and_reap(&mut child);
                    break status;
                }
                Ok(None) => {}
                Err(error) => {
                    kill_process_group_and_reap(&mut child);
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    return Err(format!("Could not wait for {label}: {error}"));
                }
            }
            if Instant::now() >= deadline {
                kill_process_group_and_reap(&mut child);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(format!("{label} exceeded its deadline."));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stdout_excessive) = stdout_thread
            .join()
            .map_err(|_| format!("Could not read {label} stdout."))?;
        let (stderr, stderr_excessive) = stderr_thread
            .join()
            .map_err(|_| format!("Could not read {label} stderr."))?;
        if stdout_excessive || stderr_excessive {
            return Err(format!("{label} output exceeded its bound."));
        }
        Ok(BoundedCommandOutput {
            status,
            stdout,
            stderr,
        })
    }

    fn run_generator_with_timeout(path: &Path, timeout: Duration) -> Vec<u8> {
        let mut command = Command::new("python3");
        command
            .arg(path)
            .current_dir("/")
            .env("PYTHONDONTWRITEBYTECODE", "1");
        let output = run_bounded_command(
            &mut command,
            FIXTURE_LIMIT,
            STDERR_LIMIT,
            timeout,
            "run Core request-plan fixture generator",
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty() && output.stdout.ends_with(b"\n"));
        output.stdout
    }

    fn fixture_arguments(inputs: &FixtureInputs) -> FixtureArguments {
        (
            canonical(&inputs.policy),
            canonical(&inputs.discovery),
            inputs.discovery_signature.as_bytes().to_vec(),
            canonical(&inputs.manifest),
            inputs.manifest_signature.as_bytes().to_vec(),
        )
    }

    fn fixture_evidence(
        fixture: &FixtureInputs,
        inputs: &RequestPlanInputs<'_>,
    ) -> Result<SnapshotBoundAuthenticationEvidence, String> {
        // Only this defining module can exchange exact verifier output for the
        // sealed capability. The fixture's serialized audit record is ignored.
        verify_generation_snapshots(
            inputs,
            fixture.keyring_payload.as_bytes(),
            &|| false,
            |_payload, _signature, _keyring, role, _cancelled| {
                let (exit_status, status) = if role == "discovery" {
                    (
                        fixture.verifier.discovery_exit_status,
                        &fixture.verifier.discovery_status,
                    )
                } else {
                    (
                        fixture.verifier.manifest_exit_status,
                        &fixture.verifier.manifest_status,
                    )
                };
                Ok(DetachedVerifierOutput {
                    exit_status,
                    status: status.as_bytes().to_vec(),
                })
            },
        )
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
        assert_eq!(fixtures.cases.len(), 35);
        let expected = [
            "valid-canonical-plan",
            "unauthenticated-policy",
            "unauthenticated-keyring",
            "discovery-verifier-failed",
            "manifest-weak-signature-hash",
            "manifest-wrong-primary",
            "forged-json-evidence-ignored",
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
            let (policy, discovery, discovery_signature, manifest, manifest_signature) =
                fixture_arguments(&case.inputs);
            let inputs = RequestPlanInputs {
                policy_payload: &policy,
                discovery_payload: &discovery,
                discovery_signature: &discovery_signature,
                manifest_payload: &manifest,
                manifest_signature: &manifest_signature,
            };
            let input_result = fixture_evidence(&case.inputs, &inputs)
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
                    bounded_recipe_bytes(recipe, MAX_PLAN_BYTES).unwrap()
                };
                let plan_result = fixture_evidence(&case.inputs, &inputs)
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
        let (policy, discovery, discovery_signature, manifest, manifest_signature) =
            fixture_arguments(&valid.inputs);
        let inputs = RequestPlanInputs {
            policy_payload: &policy,
            discovery_payload: &discovery,
            discovery_signature: &discovery_signature,
            manifest_payload: &manifest,
            manifest_signature: &manifest_signature,
        };
        let evidence = fixture_evidence(&valid.inputs, &inputs).unwrap();
        let plan = build_request_plan(&inputs, &evidence).unwrap();
        assert!(!plan.redirects);
        assert_eq!(plan.keyring_sha256, evidence.record().keyring_sha256);
        assert_eq!(
            plan.primary_signing_fingerprint,
            evidence.record().primary_signing_fingerprint
        );
        assert_eq!(plan.discovery_hash_algorithm_id, 10);
        assert_eq!(plan.manifest_hash_algorithm_id, 8);
        assert_eq!(plan.request_count, plan.requests.len());
        assert_eq!(
            plan.request_count,
            valid.inputs.manifest["files"].as_array().unwrap().len() + 4
        );
        for (request, artifact) in plan.requests[4..]
            .iter()
            .zip(valid.inputs.manifest["files"].as_array().unwrap())
        {
            assert_eq!(request.filename, artifact["filename"]);
            assert_eq!(request.expected_size, artifact["size"]);
            assert_eq!(request.expected_sha256, artifact["sha256"]);
        }
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
        let forged = fixtures
            .cases
            .iter()
            .find(|case| case.name == "forged-json-evidence-ignored")
            .unwrap();
        assert_ne!(forged.inputs.evidence_record, valid.inputs.evidence_record);
        let (policy, discovery, discovery_signature, manifest, manifest_signature) =
            fixture_arguments(&forged.inputs);
        let forged_inputs = RequestPlanInputs {
            policy_payload: &policy,
            discovery_payload: &discovery,
            discovery_signature: &discovery_signature,
            manifest_payload: &manifest,
            manifest_signature: &manifest_signature,
        };
        let capability = fixture_evidence(&forged.inputs, &forged_inputs).unwrap();
        assert!(build_request_plan(&forged_inputs, &capability).is_ok());
        fs::remove_dir_all(exported).unwrap();
    }

    fn evidence_record_payload(case: &EvidenceFixtureCase) -> Result<Vec<u8>, String> {
        if let Some(record) = &case.record {
            Ok(canonical(record))
        } else if let Some(raw) = &case.raw_record {
            Ok(raw.as_bytes().to_vec())
        } else {
            let recipe = case.raw_record_recipe.as_ref().unwrap();
            bounded_recipe_bytes(recipe, MAX_EVIDENCE_BYTES)
        }
    }

    #[test]
    fn local_core_verifier_evidence_matrix_matches_sealed_rust_capability() {
        let Some(repository) = local_core_repository() else {
            return;
        };
        let exported = export_fixture_sources(&repository);
        let generator = exported.join("lib/generate_userspace_lock_verifier_evidence_fixtures.py");
        let bytes = run_generator(&generator);
        assert_eq!(bytes, run_generator(&generator));
        reject_duplicate_contract_keys(&bytes, "Core verifier-evidence fixtures").unwrap();
        let fixture_value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(canonical(&fixture_value), bytes);
        let fixtures: EvidenceFixtureEnvelope = serde_json::from_value(fixture_value).unwrap();
        assert_eq!(fixtures.schema_version, 1);
        assert_eq!(
            fixtures.kind,
            "opemos-userspace-lock-verifier-evidence-compatibility"
        );
        assert_eq!(
            fixtures.limits,
            EvidenceFixtureLimits {
                max_evidence_bytes: MAX_EVIDENCE_BYTES,
                max_cases: 48,
            }
        );
        assert_eq!(fixtures.cases.len(), 28);
        let expected = [
            "valid-subkey-evidence",
            "valid-primary-and-subkey",
            "wrong-keyring",
            "discovery-verifier-nonzero",
            "manifest-verifier-nonzero",
            "weak-hash",
            "wrong-primary",
            "multiple-signatures",
            "malformed-status",
            "excessive-status",
            "empty-signature",
            "manifest-signature-snapshot-mismatch",
            "generation-authority-mismatch",
            "unknown-evidence-field",
            "missing-evidence-field",
            "wrong-verification-profile",
            "reordered-documents",
            "duplicate-document",
            "missing-document",
            "extra-document",
            "structural-document-hash-change",
            "zero-document-size",
            "wrong-document-primary",
            "unknown-document-field",
            "malformed-json",
            "duplicate-json-key",
            "non-finite-json",
            "oversized-record",
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
            let (policy, discovery, discovery_signature, manifest, manifest_signature) =
                fixture_arguments(&case.inputs);
            let inputs = RequestPlanInputs {
                policy_payload: &policy,
                discovery_payload: &discovery,
                discovery_signature: &discovery_signature,
                manifest_payload: &manifest,
                manifest_signature: &manifest_signature,
            };
            assert_eq!(
                fixture_evidence(&case.inputs, &inputs).is_ok(),
                case.expected.capability_accepted,
                "{} capability",
                case.name
            );
            if case.record.is_some()
                || case.raw_record.is_some()
                || case.raw_record_recipe.is_some()
            {
                assert_eq!(
                    evidence_record_payload(case)
                        .and_then(|payload| parse_verifier_evidence_record(&payload))
                        .is_ok(),
                    case.expected.record_accepted,
                    "{} audit record",
                    case.name
                );
            }
        }

        let valid = fixtures
            .cases
            .iter()
            .find(|case| case.name == "valid-subkey-evidence")
            .unwrap();
        let (policy, discovery, discovery_signature, manifest, manifest_signature) =
            fixture_arguments(&valid.inputs);
        let inputs = RequestPlanInputs {
            policy_payload: &policy,
            discovery_payload: &discovery,
            discovery_signature: &discovery_signature,
            manifest_payload: &manifest,
            manifest_signature: &manifest_signature,
        };
        let mut calls = Vec::new();
        let capability = verify_generation_snapshots(
            &inputs,
            valid.inputs.keyring_payload.as_bytes(),
            &|| false,
            |payload, signature, keyring, role, _cancelled| {
                calls.push((
                    payload.to_vec(),
                    signature.to_vec(),
                    keyring.to_vec(),
                    role.to_string(),
                ));
                let (exit_status, status) = if role == "discovery" {
                    (
                        valid.inputs.verifier.discovery_exit_status,
                        &valid.inputs.verifier.discovery_status,
                    )
                } else {
                    (
                        valid.inputs.verifier.manifest_exit_status,
                        &valid.inputs.verifier.manifest_status,
                    )
                };
                Ok(DetachedVerifierOutput {
                    exit_status,
                    status: status.as_bytes().to_vec(),
                })
            },
        )
        .unwrap();
        assert_eq!(
            calls.iter().map(|call| call.3.as_str()).collect::<Vec<_>>(),
            ["discovery", "generation-manifest"]
        );
        assert_eq!(calls[0].0, discovery);
        assert_eq!(calls[0].1, discovery_signature);
        assert_eq!(calls[0].2, valid.inputs.keyring_payload.as_bytes());
        assert_eq!(
            canonical_bytes(capability.record()).unwrap(),
            canonical(valid.record.as_ref().unwrap())
        );
        let parsed =
            parse_verifier_evidence_record(&canonical(valid.record.as_ref().unwrap())).unwrap();
        assert_eq!(&parsed, capability.record());
        let different_discovery = [inputs.discovery_payload, b" "].concat();
        let different_inputs = RequestPlanInputs {
            policy_payload: inputs.policy_payload,
            discovery_payload: &different_discovery,
            discovery_signature: inputs.discovery_signature,
            manifest_payload: inputs.manifest_payload,
            manifest_signature: inputs.manifest_signature,
        };
        assert!(validate_evidence_capability(&capability, &different_inputs).is_err());
        let error = verify_generation_snapshots(
            &inputs,
            valid.inputs.keyring_payload.as_bytes(),
            &|| false,
            |_payload, _signature, _keyring, _role, _cancelled| {
                Err("sensitive verifier failure".into())
            },
        )
        .err()
        .unwrap();
        assert_eq!(error, "Detached signature verifier failed.");
        assert!(!error.contains("sensitive"));
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
    fn fixture_recipes_reject_counts_before_allocation() {
        let excessive_plan = RawPlanRecipe {
            text: " ".into(),
            count: MAX_PLAN_BYTES.checked_add(2).unwrap(),
        };
        let excessive_evidence = RawPlanRecipe {
            text: " ".into(),
            count: MAX_EVIDENCE_BYTES.checked_add(2).unwrap(),
        };
        let overflowing_limit = RawPlanRecipe {
            text: " ".into(),
            count: 1,
        };
        assert!(bounded_recipe_bytes(&excessive_plan, MAX_PLAN_BYTES).is_err());
        assert!(bounded_recipe_bytes(&excessive_evidence, MAX_EVIDENCE_BYTES).is_err());
        assert!(bounded_recipe_bytes(&overflowing_limit, usize::MAX).is_err());
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

    #[test]
    fn completed_fixture_leader_cannot_leave_descendant_pipes_open() {
        let root = std::env::temp_dir().join(format!(
            "opemos-core-request-plan-descendant-pipe-{}-{}",
            std::process::id(),
            EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let generator = root.join("descendant.py");
        fs::write(
            &generator,
            b"import subprocess, sys\nprint('{}', flush=True)\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n",
        )
        .unwrap();
        let started = Instant::now();
        assert_eq!(
            run_generator_with_timeout(&generator, Duration::from_secs(2)),
            b"{}\n"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        fs::remove_dir_all(root).unwrap();
    }
}
