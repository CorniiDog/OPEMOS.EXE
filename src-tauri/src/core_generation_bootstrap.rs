//! Inactive compatibility consumer for Core's userspace-lock bootstrap trust
//! contract. This module validates data only; it contains no authority,
//! endpoint, network transport, cache activation, command, or UI wiring.

use crate::{
    core_contracts::reject_duplicate_contract_keys,
    core_generation_contracts::{
        validate_activation, validate_pair, DurableGenerationIdentity, GenerationActivationState,
        GenerationAuthority, GenerationDiscovery, GenerationManifest, GenerationTarget,
        DISCOVERY_FILENAME, DISCOVERY_SIGNATURE_FILENAME, DISCOVERY_SIGNATURE_SCHEME,
        MAX_LINEAGE_GENERATIONS, OPENPGP_HASH_ALGORITHM_IDS,
    },
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const MAX_POLICY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_CHECKPOINT_BYTES: usize = 16 * 1024;
pub(crate) const MAX_KEYRING_BYTES: usize = 16 * 1024 * 1024;

const POLICY_KIND: &str = "opemos-userspace-lock-bootstrap-policy";
const CHECKPOINT_KIND: &str = "opemos-userspace-lock-bootstrap-checkpoint";
const POLICY_ID: &str = "opemos-userspace-lock-generations";
const KEYRING_FILENAME: &str = "opemos-userspace-lock-generations.gpg";
const RELEASE_TAG_PREFIX: &str = "opemos-userspace-lock-generation-v1-s";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BootstrapPolicy {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) policy_id: String,
    pub(crate) policy_schema_version: u32,
    pub(crate) authority: BootstrapAuthority,
    pub(crate) channel: BootstrapChannel,
    pub(crate) compatibility: BootstrapCompatibility,
    pub(crate) replay_policy: BootstrapReplayPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BootstrapAuthority {
    pub(crate) keyring_filename: String,
    pub(crate) keyring_sha256: String,
    pub(crate) primary_signing_fingerprint: String,
    pub(crate) signature_scheme: String,
    pub(crate) allowed_hash_algorithm_ids: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BootstrapChannel {
    pub(crate) origin: String,
    pub(crate) discovery_path: String,
    pub(crate) discovery_filename: String,
    pub(crate) discovery_signature_filename: String,
    pub(crate) immutable_release_path_prefix: String,
    pub(crate) release_tag_prefix: String,
    pub(crate) allow_redirects: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BootstrapCompatibility {
    pub(crate) discovery_schema_versions: Vec<u32>,
    pub(crate) generation_manifest_schema_versions: Vec<u32>,
    pub(crate) userspace_lock_schema_versions: Vec<u32>,
    pub(crate) installer_result_schema_versions: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BootstrapReplayPolicy {
    pub(crate) require_monotonic_high_water: bool,
    pub(crate) require_immediate_predecessor: bool,
    pub(crate) allow_authenticated_lineage_catchup: bool,
    pub(crate) maximum_lineage_generations: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BootstrapCheckpoint {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) policy_sha256: String,
    pub(crate) minimum_sequence: u64,
    pub(crate) minimum_manifest_sha256: String,
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

pub(crate) fn parse_bootstrap_policy(bytes: &[u8]) -> Result<BootstrapPolicy, String> {
    let policy = parse_canonical(bytes, MAX_POLICY_BYTES, "Core bootstrap policy")?;
    validate_policy(&policy)?;
    Ok(policy)
}

pub(crate) fn parse_bootstrap_checkpoint(
    bytes: &[u8],
    policy_payload: &[u8],
) -> Result<BootstrapCheckpoint, String> {
    let policy = parse_bootstrap_policy(policy_payload)?;
    let checkpoint = parse_canonical(bytes, MAX_CHECKPOINT_BYTES, "Core bootstrap checkpoint")?;
    validate_checkpoint(&checkpoint, &policy, policy_payload)?;
    Ok(checkpoint)
}

fn validate_policy(policy: &BootstrapPolicy) -> Result<(), String> {
    if policy.schema_version != 1
        || policy.kind != POLICY_KIND
        || policy.status != "active"
        || policy.policy_id != POLICY_ID
        || policy.policy_schema_version != 1
    {
        return Err("Core bootstrap policy identity is unsupported.".into());
    }
    let authority = &policy.authority;
    if authority.keyring_filename != KEYRING_FILENAME
        || !lower_hex_hash(&authority.keyring_sha256)
        || !upper_hex_fingerprint(&authority.primary_signing_fingerprint)
        || authority.signature_scheme != DISCOVERY_SIGNATURE_SCHEME
        || authority.allowed_hash_algorithm_ids != OPENPGP_HASH_ALGORITHM_IDS
    {
        return Err("Core bootstrap signing authority is unsupported.".into());
    }
    let channel = &policy.channel;
    if channel.discovery_filename != DISCOVERY_FILENAME
        || channel.discovery_signature_filename != DISCOVERY_SIGNATURE_FILENAME
        || channel.release_tag_prefix != RELEASE_TAG_PREFIX
        || channel.allow_redirects
        || !valid_origin(&channel.origin)
        || !valid_channel_path(&channel.discovery_path, false, Some(DISCOVERY_FILENAME))
        || !valid_channel_path(&channel.immutable_release_path_prefix, true, None)
    {
        return Err("Core bootstrap channel identity is unsupported.".into());
    }
    let compatibility = &policy.compatibility;
    if compatibility.discovery_schema_versions != [1]
        || compatibility.generation_manifest_schema_versions != [1]
        || compatibility.userspace_lock_schema_versions != [1]
        || compatibility.installer_result_schema_versions != [1]
    {
        return Err("Core bootstrap schema compatibility is unsupported.".into());
    }
    let replay = &policy.replay_policy;
    if !replay.require_monotonic_high_water
        || !replay.require_immediate_predecessor
        || !replay.allow_authenticated_lineage_catchup
        || replay.maximum_lineage_generations != MAX_LINEAGE_GENERATIONS
    {
        return Err("Core bootstrap replay policy is unsupported.".into());
    }
    Ok(())
}

fn validate_checkpoint(
    checkpoint: &BootstrapCheckpoint,
    policy: &BootstrapPolicy,
    policy_payload: &[u8],
) -> Result<(), String> {
    validate_policy(policy)?;
    if checkpoint.schema_version != 1
        || checkpoint.kind != CHECKPOINT_KIND
        || checkpoint.policy_sha256 != sha256(policy_payload)
        || checkpoint.minimum_sequence == 0
        || !lower_hex_hash(&checkpoint.minimum_manifest_sha256)
    {
        return Err("Core bootstrap checkpoint is invalid or belongs to another policy.".into());
    }
    Ok(())
}

pub(crate) fn expected_generation_authority(
    policy: &BootstrapPolicy,
    policy_payload: &[u8],
) -> Result<GenerationAuthority, String> {
    let parsed = parse_bootstrap_policy(policy_payload)?;
    if &parsed != policy {
        return Err("Core bootstrap policy payload differs from policy.".into());
    }
    Ok(GenerationAuthority {
        policy_id: policy.policy_id.clone(),
        policy_schema_version: policy.policy_schema_version,
        policy_sha256: sha256(policy_payload),
        keyring_filename: policy.authority.keyring_filename.clone(),
        keyring_sha256: policy.authority.keyring_sha256.clone(),
        signing_key_fingerprint: policy.authority.primary_signing_fingerprint.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
// This raw fixture adapter is module-private and must not be exposed as
// production authority. Future reachability must enter through the sealed,
// verifier-owned activation capability.
fn validate_bootstrap_activation(
    policy: &BootstrapPolicy,
    policy_payload: &[u8],
    keyring_payload: &[u8],
    checkpoint: &BootstrapCheckpoint,
    discovery: &GenerationDiscovery,
    manifest: &GenerationManifest,
    expected_target: &GenerationTarget,
    state: &GenerationActivationState,
    lineage: &[(&GenerationDiscovery, &GenerationManifest)],
) -> Result<DurableGenerationIdentity, String> {
    let expected_authority = expected_generation_authority(policy, policy_payload)?;
    validate_checkpoint(checkpoint, policy, policy_payload)?;
    if keyring_payload.is_empty()
        || keyring_payload.len() > MAX_KEYRING_BYTES
        || sha256(keyring_payload) != policy.authority.keyring_sha256
    {
        return Err("Core bootstrap keyring identity differs from policy.".into());
    }
    validate_pair(discovery, manifest)?;
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
        return Err("Core generation requires an unsupported schema version.".into());
    }
    let bootstrap = DurableGenerationIdentity {
        sequence: checkpoint.minimum_sequence,
        manifest_sha256: checkpoint.minimum_manifest_sha256.clone(),
    };
    validate_activation(
        discovery,
        manifest,
        &expected_authority,
        expected_target,
        state,
        lineage,
        Some(&bootstrap),
    )
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn upper_hex_fingerprint(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn valid_origin(value: &str) -> bool {
    if value.len() > 512 {
        return false;
    }
    let Some(host) = value.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').count() >= 2
        && host
            .rsplit_once('.')
            .is_some_and(|(_, suffix)| suffix.bytes().any(|byte| byte.is_ascii_lowercase()))
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with("xn--")
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label.as_bytes().first() != Some(&b'-')
                && label.as_bytes().last() != Some(&b'-')
        })
}

fn valid_channel_path(value: &str, prefix: bool, filename: Option<&str>) -> bool {
    if !(2..=1024).contains(&value.len())
        || !value.starts_with('/')
        || value.contains("//")
        || prefix != value.ends_with('/')
    {
        return false;
    }
    let body = if prefix {
        &value[1..value.len() - 1]
    } else {
        &value[1..]
    };
    let segments = body.split('/').collect::<Vec<_>>();
    if segments.is_empty()
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > 128
                || segment.starts_with('.')
                || segment.ends_with('.')
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'~' | b'-')
                })
                || windows_reserved_segment(segment)
                || matches!(
                    segment.to_ascii_lowercase().as_str(),
                    "." | ".." | "head" | "latest" | "main" | "master" | "refs" | "heads"
                )
        })
    {
        return false;
    }
    filename.is_none_or(|expected| segments.last() == Some(&expected))
}

fn windows_reserved_segment(segment: &str) -> bool {
    matches!(
        segment.split('.').next().unwrap_or_default(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_generation_contracts::{validate_discovery_bytes, validate_manifest_bytes};
    use serde::Deserialize;
    use std::{
        collections::{HashMap, HashSet},
        fs,
        io::Read,
        os::unix::process::CommandExt as _,
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus, Stdio},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const CONTRACT_COMMIT: &str = "0c16ccd7ba68095ea8a6655b0d2bb8b6e97d32f3";
    const FIXTURE_LIMIT: usize = 512 * 1024;
    const STDERR_LIMIT: usize = 64 * 1024;
    static EXPORT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

    #[derive(Debug)]
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
        policy_schema_version: u32,
        checkpoint_schema_version: u32,
        limits: FixtureLimits,
        cases: Vec<FixtureCase>,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureLimits {
        max_policy_bytes: usize,
        max_checkpoint_bytes: usize,
        max_cases: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureCase {
        name: String,
        expected: FixtureExpected,
        #[serde(default)]
        policy: Option<serde_json::Value>,
        #[serde(default)]
        raw_policy: Option<String>,
        #[serde(default)]
        document_recipe: Option<FixtureRecipe>,
        #[serde(default)]
        checkpoint: Option<serde_json::Value>,
        #[serde(default)]
        raw_checkpoint: Option<String>,
        #[serde(default)]
        checkpoint_recipe: Option<FixtureRecipe>,
        #[serde(default)]
        keyring_payload: Option<String>,
        #[serde(default)]
        discovery: Option<serde_json::Value>,
        #[serde(default)]
        manifest: Option<serde_json::Value>,
        #[serde(default)]
        target: Option<GenerationTarget>,
        #[serde(default)]
        state: Option<FixtureState>,
        #[serde(default)]
        lineage: Vec<[serde_json::Value; 2]>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureExpected {
        policy_accepted: bool,
        checkpoint_accepted: bool,
        activation_accepted: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureRecipe {
        kind: String,
        base_case: String,
        padding_bytes: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureState {
        high_water_sequence: u64,
        active_sequence: Option<u64>,
        active_manifest_sha256: Option<String>,
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
                eprintln!("skipping local Core bootstrap fixtures: git could not run: {error}");
                return None;
            }
        };
        assert!(
            output.status.success(),
            "configured Core repository lacks bootstrap contract commit {CONTRACT_COMMIT}"
        );
        Some(repository)
    }

    fn export_fixture_sources(repository: &Path) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "opemos-core-bootstrap-fixtures-{}-{nonce}-{}",
            std::process::id(),
            EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        for relative in [
            "lib/generate_userspace_lock_bootstrap_fixtures.py",
            "lib/generate_userspace_lock_generation_fixtures.py",
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
                "export exact Core bootstrap fixture source",
            )
            .expect("export exact Core bootstrap fixture source");
            assert!(
                output.status.success(),
                "missing pinned Core file {relative}"
            );
            assert!(output.stderr.is_empty());
            assert!(!output.stdout.is_empty() && output.stdout.len() <= 1024 * 1024);
            let destination = root.join(relative);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(destination, output.stdout).unwrap();
        }
        fs::canonicalize(root).unwrap()
    }

    fn bounded_pipe<R: Read>(mut pipe: R, limit: usize) -> (Vec<u8>, bool) {
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        let mut excessive = false;
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            let count = pipe.read(&mut chunk).unwrap();
            if count == 0 {
                break;
            }
            let remaining = limit.saturating_sub(bytes.len());
            bytes.extend_from_slice(&chunk[..count.min(remaining)]);
            excessive |= count > remaining;
            if excessive {
                return (bytes, true);
            }
        }
        (bytes, excessive)
    }

    fn run_fixture_generator(path: &Path) -> Vec<u8> {
        run_fixture_generator_with_timeout(path, COMMAND_TIMEOUT)
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
        let child = command
            .spawn()
            .map_err(|error| format!("Could not {label}: {error}"))?;
        collect_bounded_child(child, stdout_limit, stderr_limit, timeout, label)
    }

    fn collect_bounded_child(
        mut child: Child,
        stdout_limit: usize,
        stderr_limit: usize,
        timeout: Duration,
        label: &str,
    ) -> Result<BoundedCommandOutput, String> {
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                kill_process_group_and_reap(&mut child);
                return Err(format!("Could not capture {label} stdout."));
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                kill_process_group_and_reap(&mut child);
                drop(stdout);
                return Err(format!("Could not capture {label} stderr."));
            }
        };
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

    fn run_fixture_generator_with_timeout(path: &Path, timeout: Duration) -> Vec<u8> {
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
            "run Core bootstrap fixture generator",
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

    fn policy_payload<'a>(
        case: &'a FixtureCase,
        bases: &HashMap<&str, &'a FixtureCase>,
    ) -> Vec<u8> {
        if let Some(raw) = &case.raw_policy {
            return raw.as_bytes().to_vec();
        }
        if let Some(recipe) = &case.document_recipe {
            assert_eq!(recipe.kind, "top-level-padding");
            let mut value = bases[recipe.base_case.as_str()].policy.clone().unwrap();
            value["padding"] = serde_json::Value::String("x".repeat(recipe.padding_bytes));
            return canonical(&value);
        }
        canonical(case.policy.as_ref().unwrap())
    }

    fn checkpoint_payload<'a>(
        case: &'a FixtureCase,
        bases: &HashMap<&str, &'a FixtureCase>,
    ) -> Option<Vec<u8>> {
        if let Some(raw) = &case.raw_checkpoint {
            return Some(raw.as_bytes().to_vec());
        }
        if let Some(recipe) = &case.checkpoint_recipe {
            assert_eq!(recipe.kind, "top-level-padding");
            let mut value = bases[recipe.base_case.as_str()].checkpoint.clone().unwrap();
            value["padding"] = serde_json::Value::String("x".repeat(recipe.padding_bytes));
            return Some(canonical(&value));
        }
        case.checkpoint.as_ref().map(canonical)
    }

    #[test]
    fn local_core_bootstrap_matrix_matches_closed_rust_contract() {
        let Some(repository) = local_core_repository() else {
            eprintln!("skipping local Core bootstrap fixtures: immutable repository is absent");
            return;
        };
        let exported = export_fixture_sources(&repository);
        let generator = exported.join("lib/generate_userspace_lock_bootstrap_fixtures.py");
        let bytes = run_fixture_generator(&generator);
        assert_eq!(bytes, run_fixture_generator(&generator));
        reject_duplicate_contract_keys(&bytes, "Core bootstrap fixtures").unwrap();
        let fixtures: FixtureEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(fixtures.schema_version, 1);
        assert_eq!(
            fixtures.kind,
            "opemos-userspace-lock-bootstrap-compatibility-fixtures"
        );
        assert_eq!(fixtures.policy_schema_version, 1);
        assert_eq!(fixtures.checkpoint_schema_version, 1);
        assert_eq!(
            fixtures.limits,
            FixtureLimits {
                max_policy_bytes: MAX_POLICY_BYTES,
                max_checkpoint_bytes: MAX_CHECKPOINT_BYTES,
                max_cases: 64,
            }
        );
        assert_eq!(fixtures.cases.len(), 49);
        let expected_names = [
            "valid-fresh-exact-checkpoint",
            "valid-existing-forward",
            "valid-authenticated-lineage-catchup",
            "unknown-policy-field",
            "unknown-authority-field",
            "future-policy-schema",
            "weak-hash-policy",
            "ambiguous-hash-policy",
            "wrong-primary-fingerprint",
            "wrong-signature-scheme",
            "http-origin",
            "origin-with-userinfo",
            "origin-with-port",
            "origin-with-query",
            "invalid-origin-label",
            "punycode-origin",
            "unicode-origin",
            "ipv4-origin",
            "ipv6-origin",
            "trailing-dot-origin",
            "single-label-origin",
            "numeric-top-level-origin",
            "uppercase-origin",
            "redirect-policy-enabled",
            "mutable-discovery-ref",
            "mutable-release-ref",
            "percent-encoded-path",
            "portable-path-trailing-dot",
            "portable-path-device-name",
            "wrong-discovery-name",
            "wrong-discovery-signature-name",
            "future-discovery-schema",
            "weakened-replay-policy",
            "checkpoint-policy-mismatch",
            "future-checkpoint-schema",
            "generation-older-than-checkpoint",
            "checkpoint-manifest-mismatch",
            "generation-authority-mismatch",
            "generation-requests-signer-rotation",
            "generation-future-lock-schema",
            "existing-state-replay",
            "existing-state-downgrade",
            "keyring-payload-mismatch",
            "duplicate-policy-key",
            "non-finite-checkpoint",
            "duplicate-checkpoint-key",
            "malformed-policy",
            "oversized-policy",
            "oversized-checkpoint",
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        assert_eq!(
            fixtures
                .cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<HashSet<_>>(),
            expected_names
        );
        let bases = fixtures
            .cases
            .iter()
            .filter(|case| case.policy.is_some())
            .map(|case| (case.name.as_str(), case))
            .collect::<HashMap<_, _>>();

        for case in &fixtures.cases {
            let policy_bytes = policy_payload(case, &bases);
            let policy = parse_bootstrap_policy(&policy_bytes);
            assert_eq!(
                policy.is_ok(),
                case.expected.policy_accepted,
                "{} policy",
                case.name
            );
            let checkpoint_bytes = checkpoint_payload(case, &bases);
            let checkpoint = policy.as_ref().ok().and_then(|_| {
                checkpoint_bytes
                    .as_ref()
                    .and_then(|bytes| parse_bootstrap_checkpoint(bytes, &policy_bytes).ok())
            });
            assert_eq!(
                checkpoint.is_some(),
                case.expected.checkpoint_accepted,
                "{} checkpoint",
                case.name
            );
            let activation = if let (
                Ok(policy),
                Some(checkpoint),
                Some(discovery),
                Some(manifest),
                Some(target),
                Some(state),
                Some(keyring),
            ) = (
                policy.as_ref(),
                checkpoint.as_ref(),
                case.discovery.as_ref(),
                case.manifest.as_ref(),
                case.target.as_ref(),
                case.state.as_ref(),
                case.keyring_payload.as_ref(),
            ) {
                let discovery = validate_discovery_bytes(&canonical(discovery));
                let manifest = validate_manifest_bytes(&canonical(manifest));
                let lineage = case
                    .lineage
                    .iter()
                    .map(|pair| {
                        (
                            validate_discovery_bytes(&canonical(&pair[0])).unwrap(),
                            validate_manifest_bytes(&canonical(&pair[1])).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();
                let lineage_refs = lineage
                    .iter()
                    .map(|(discovery, manifest)| (discovery, manifest))
                    .collect::<Vec<_>>();
                let active = match (&state.active_sequence, &state.active_manifest_sha256) {
                    (Some(sequence), Some(manifest_sha256)) => Some(DurableGenerationIdentity {
                        sequence: *sequence,
                        manifest_sha256: manifest_sha256.clone(),
                    }),
                    (None, None) => None,
                    _ => panic!("fixture has partial active identity"),
                };
                discovery
                    .and_then(|discovery| {
                        manifest.and_then(|manifest| {
                            validate_bootstrap_activation(
                                policy,
                                &policy_bytes,
                                keyring.as_bytes(),
                                checkpoint,
                                &discovery,
                                &manifest,
                                target,
                                &GenerationActivationState {
                                    high_water_sequence: state.high_water_sequence,
                                    active,
                                },
                                &lineage_refs,
                            )
                        })
                    })
                    .is_ok()
            } else {
                false
            };
            assert_eq!(
                activation, case.expected.activation_accepted,
                "{} activation",
                case.name
            );
        }
        fs::remove_dir_all(exported).unwrap();
    }

    #[test]
    fn bootstrap_parser_boundaries_are_closed_and_bounded() {
        assert!(parse_bootstrap_policy(b"{}").is_err());
        assert!(parse_bootstrap_policy(&vec![b'x'; MAX_POLICY_BYTES + 1]).is_err());
        assert!(parse_bootstrap_checkpoint(b"{}\n", b"{}\n").is_err());
        for origin in [
            "https://updates..example.invalid",
            "https://xn--updates-9za.example.invalid",
            "https://updatés.example.invalid",
            "https://192.0.2.1",
            "https://[2001:db8::1]",
            "https://localhost",
            "https://updates.example.123",
            "https://Updates.example.invalid",
            "https://updates.example.invalid.",
        ] {
            assert!(!valid_origin(origin), "accepted unsafe origin {origin}");
        }
        for path in [
            "/opemos/latest/file/",
            "/opemos/%72eleases/file/",
            "/opemos/.hidden/file/",
            "/opemos/releases./file/",
            "/opemos/con/file/",
            "/opemos/com1.txt/file/",
        ] {
            assert!(
                !valid_channel_path(path, true, None),
                "accepted unsafe channel path {path}"
            );
        }
    }

    #[test]
    fn bootstrap_activation_rejects_oversized_keyring() {
        let Some(repository) = local_core_repository() else {
            return;
        };
        let exported = export_fixture_sources(&repository);
        let bytes = run_fixture_generator(
            &exported.join("lib/generate_userspace_lock_bootstrap_fixtures.py"),
        );
        let fixtures: FixtureEnvelope = serde_json::from_slice(&bytes).unwrap();
        let case = fixtures
            .cases
            .iter()
            .find(|case| case.name == "valid-fresh-exact-checkpoint")
            .unwrap();
        for pointer in ["", "/authority", "/channel"] {
            let mut closed = case.policy.clone().unwrap();
            closed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("future".into(), serde_json::Value::Bool(true));
            assert!(parse_bootstrap_policy(&canonical(&closed)).is_err());
        }
        let policy_bytes = canonical(case.policy.as_ref().unwrap());
        let policy = parse_bootstrap_policy(&policy_bytes).unwrap();
        let checkpoint_bytes = canonical(case.checkpoint.as_ref().unwrap());
        let checkpoint = parse_bootstrap_checkpoint(&checkpoint_bytes, &policy_bytes).unwrap();
        let discovery =
            validate_discovery_bytes(&canonical(case.discovery.as_ref().unwrap())).unwrap();
        let manifest =
            validate_manifest_bytes(&canonical(case.manifest.as_ref().unwrap())).unwrap();
        assert!(validate_bootstrap_activation(
            &policy,
            &policy_bytes,
            &vec![b'x'; MAX_KEYRING_BYTES + 1],
            &checkpoint,
            &discovery,
            &manifest,
            case.target.as_ref().unwrap(),
            &GenerationActivationState {
                high_water_sequence: 0,
                active: None
            },
            &[],
        )
        .is_err());
        fs::remove_dir_all(exported).unwrap();
    }

    #[test]
    fn configured_core_repository_does_not_skip_git_spawn_failure() {
        let root = std::env::temp_dir().join(format!(
            "opemos-core-bootstrap-git-failure-{}-{}",
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
    fn fixture_generator_output_is_bounded() {
        let root = std::env::temp_dir().join(format!(
            "opemos-core-bootstrap-output-cap-{}-{}",
            std::process::id(),
            EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let generator = root.join("excessive.py");
        fs::write(
            &generator,
            format!(
                "import sys\nsys.stdout.write('x' * {})\n",
                FIXTURE_LIMIT + 1
            ),
        )
        .unwrap();
        let result = std::panic::catch_unwind(|| {
            run_fixture_generator_with_timeout(&generator, Duration::from_secs(2))
        });
        assert!(result.is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_captured_pipe_kills_and_reaps_process_group() {
        fn sleeping_child() -> Child {
            let mut command = Command::new("python3");
            command
                .args(["-c", "import time; time.sleep(60)"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command.process_group(0);
            command.spawn().unwrap()
        }

        let started = Instant::now();
        let mut missing_stdout = sleeping_child();
        let held_stdout = missing_stdout.stdout.take().unwrap();
        let error = collect_bounded_child(
            missing_stdout,
            FIXTURE_LIMIT,
            STDERR_LIMIT,
            Duration::from_secs(2),
            "capture-test child",
        )
        .unwrap_err();
        assert!(error.contains("stdout"));
        drop(held_stdout);

        let mut missing_stderr = sleeping_child();
        let held_stderr = missing_stderr.stderr.take().unwrap();
        let error = collect_bounded_child(
            missing_stderr,
            FIXTURE_LIMIT,
            STDERR_LIMIT,
            Duration::from_secs(2),
            "capture-test child",
        )
        .unwrap_err();
        assert!(error.contains("stderr"));
        drop(held_stderr);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn fixture_generator_timeout_kills_and_reaps_process_group() {
        let root = std::env::temp_dir().join(format!(
            "opemos-core-bootstrap-timeout-{}-{}",
            std::process::id(),
            EXPORT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let generator = root.join("hang.py");
        fs::write(&generator, b"import time\ntime.sleep(60)\n").unwrap();
        let started = Instant::now();
        let result = std::panic::catch_unwind(|| {
            run_fixture_generator_with_timeout(&generator, Duration::from_millis(50))
        });
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_fixture_leader_cannot_leave_descendant_pipes_open() {
        let root = std::env::temp_dir().join(format!(
            "opemos-core-bootstrap-descendant-pipe-{}-{}",
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
            run_fixture_generator_with_timeout(&generator, Duration::from_secs(2)),
            b"{}\n"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        fs::remove_dir_all(root).unwrap();
    }
}
