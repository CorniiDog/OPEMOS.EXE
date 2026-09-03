use crate::core_contracts::reject_duplicate_contract_keys;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) const DISCOVERY_MAX_BYTES: usize = 256 * 1024;
pub(crate) const MANIFEST_MAX_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_TARGETS: usize = 256;
pub(crate) const MAX_FILES: usize = 4096;
pub(crate) const MAX_LOCK_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const MAX_GENERATION_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub(crate) const MAX_SIGNATURE_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_LINEAGE_GENERATIONS: usize = 64;

const POLICY_ID: &str = "opemos-userspace-lock-generations";
const DISCOVERY_KIND: &str = "opemos-userspace-lock-discovery";
const MANIFEST_KIND: &str = "opemos-userspace-lock-generation";
const CHANNEL: &str = "reviewed";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationTarget {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) architecture: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationAuthority {
    pub(crate) policy_id: String,
    pub(crate) policy_schema_version: u32,
    pub(crate) policy_sha256: String,
    pub(crate) keyring_filename: String,
    pub(crate) keyring_sha256: String,
    pub(crate) signing_key_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationCompatibility {
    pub(crate) discovery_schema_version: u32,
    pub(crate) generation_manifest_schema_version: u32,
    pub(crate) userspace_lock_schema_version: u32,
    pub(crate) minimum_installer_result_schema_version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationLock {
    pub(crate) filename: String,
    pub(crate) schema_version: u32,
    pub(crate) sha256: String,
    pub(crate) size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationTargetLock {
    pub(crate) target: GenerationTarget,
    pub(crate) lock: GenerationLock,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DiscoveryGeneration {
    pub(crate) release_tag: String,
    pub(crate) manifest_filename: String,
    pub(crate) manifest_sha256: String,
    pub(crate) manifest_size: u64,
    pub(crate) signature_filename: String,
    pub(crate) signature_sha256: String,
    pub(crate) signature_size: u64,
    pub(crate) previous_manifest_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationDiscovery {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) channel: String,
    pub(crate) sequence: u64,
    pub(crate) published_at: String,
    pub(crate) authority: GenerationAuthority,
    pub(crate) compatibility: GenerationCompatibility,
    pub(crate) generation: DiscoveryGeneration,
    pub(crate) targets: Vec<GenerationTargetLock>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationFile {
    pub(crate) role: String,
    pub(crate) filename: String,
    pub(crate) size: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GenerationManifest {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) channel: String,
    pub(crate) sequence: u64,
    pub(crate) published_at: String,
    pub(crate) authority: GenerationAuthority,
    pub(crate) previous_manifest_sha256: Option<String>,
    pub(crate) target_locks: Vec<GenerationTargetLock>,
    pub(crate) files: Vec<GenerationFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DurableGenerationIdentity {
    pub(crate) sequence: u64,
    pub(crate) manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GenerationActivationState {
    pub(crate) high_water_sequence: u64,
    pub(crate) active: Option<DurableGenerationIdentity>,
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
        serde_json::from_slice(bytes).map_err(|error| format!("{label} is malformed: {error}"))?;
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("Could not canonicalize {label}: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(format!("{label} is not canonical JSON."));
    }
    serde_json::from_value(value).map_err(|error| format!("{label} is invalid: {error}"))
}

pub(crate) fn validate_discovery_bytes(bytes: &[u8]) -> Result<GenerationDiscovery, String> {
    let discovery: GenerationDiscovery =
        parse_canonical(bytes, DISCOVERY_MAX_BYTES, "Core generation discovery")?;
    validate_discovery(&discovery)?;
    Ok(discovery)
}

pub(crate) fn validate_manifest_bytes(bytes: &[u8]) -> Result<GenerationManifest, String> {
    let manifest: GenerationManifest =
        parse_canonical(bytes, MANIFEST_MAX_BYTES, "Core generation manifest")?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_discovery(discovery: &GenerationDiscovery) -> Result<(), String> {
    if discovery.schema_version != 1
        || discovery.kind != DISCOVERY_KIND
        || discovery.channel != CHANNEL
        || discovery.sequence == 0
        || !valid_timestamp(&discovery.published_at)
    {
        return Err("Core generation discovery identity is invalid.".into());
    }
    validate_authority(&discovery.authority)?;
    let compatibility = &discovery.compatibility;
    if compatibility.discovery_schema_version != 1
        || compatibility.generation_manifest_schema_version != 1
        || compatibility.userspace_lock_schema_version != 1
        || compatibility.minimum_installer_result_schema_version != 1
    {
        return Err("Core generation compatibility is unsupported.".into());
    }
    let generation = &discovery.generation;
    let expected_tag = format!(
        "opemos-userspace-lock-generation-v1-s{}",
        discovery.sequence
    );
    if generation.release_tag != expected_tag
        || generation.manifest_filename != format!("{expected_tag}.manifest.json")
        || generation.signature_filename != format!("{expected_tag}.manifest.json.sig")
        || !lower_hex(&generation.manifest_sha256)
        || !(1..=MANIFEST_MAX_BYTES as u64).contains(&generation.manifest_size)
        || !lower_hex(&generation.signature_sha256)
        || !(1..=MAX_SIGNATURE_BYTES).contains(&generation.signature_size)
    {
        return Err("Core generation discovery payload identity is invalid.".into());
    }
    validate_predecessor(
        discovery.sequence,
        generation.previous_manifest_sha256.as_deref(),
    )?;
    validate_target_locks(&discovery.targets)
}

fn validate_manifest(manifest: &GenerationManifest) -> Result<(), String> {
    if manifest.schema_version != 1
        || manifest.kind != MANIFEST_KIND
        || manifest.channel != CHANNEL
        || manifest.sequence == 0
        || !valid_timestamp(&manifest.published_at)
    {
        return Err("Core generation manifest identity is invalid.".into());
    }
    validate_authority(&manifest.authority)?;
    validate_predecessor(
        manifest.sequence,
        manifest.previous_manifest_sha256.as_deref(),
    )?;
    validate_target_locks(&manifest.target_locks)?;
    validate_files(&manifest.files)?;

    let expected = manifest
        .target_locks
        .iter()
        .map(|record| (&record.lock.filename, record.lock.size, &record.lock.sha256))
        .collect::<HashSet<_>>();
    let actual = manifest
        .files
        .iter()
        .filter(|record| record.role == "userspace-lock")
        .map(|record| (&record.filename, record.size, &record.sha256))
        .collect::<HashSet<_>>();
    if expected != actual {
        return Err("Core generation lock files differ from target locks.".into());
    }
    Ok(())
}

pub(crate) fn validate_pair(
    discovery: &GenerationDiscovery,
    manifest: &GenerationManifest,
) -> Result<String, String> {
    validate_discovery(discovery)?;
    validate_manifest(manifest)?;
    let manifest_bytes = canonical_bytes(manifest)?;
    let manifest_sha256 = format!("{:x}", Sha256::digest(&manifest_bytes));
    let reserved = [
        discovery.generation.manifest_filename.to_ascii_lowercase(),
        discovery.generation.signature_filename.to_ascii_lowercase(),
    ];
    if manifest
        .files
        .iter()
        .any(|file| reserved.contains(&file.filename.to_ascii_lowercase()))
        || discovery.sequence != manifest.sequence
        || discovery.published_at != manifest.published_at
        || discovery.authority != manifest.authority
        || discovery.generation.previous_manifest_sha256 != manifest.previous_manifest_sha256
        || discovery.targets != manifest.target_locks
        || discovery.generation.manifest_size != manifest_bytes.len() as u64
        || discovery.generation.manifest_sha256 != manifest_sha256
    {
        return Err("Core discovery and generation manifest do not match.".into());
    }
    Ok(manifest_sha256)
}

pub(crate) fn validate_activation(
    discovery: &GenerationDiscovery,
    manifest: &GenerationManifest,
    expected_authority: &GenerationAuthority,
    expected_target: &GenerationTarget,
    state: &GenerationActivationState,
    lineage: &[(&GenerationDiscovery, &GenerationManifest)],
    bootstrap: Option<&DurableGenerationIdentity>,
) -> Result<DurableGenerationIdentity, String> {
    let current_hash = validate_pair(discovery, manifest)?;
    if lineage.len() > MAX_LINEAGE_GENERATIONS || &discovery.authority != expected_authority {
        return Err("Core generation authority or lineage is invalid.".into());
    }
    if (state.high_water_sequence == 0) != state.active.is_none()
        || state.active.as_ref().is_some_and(|active| {
            active.sequence == 0
                || active.sequence > state.high_water_sequence
                || !lower_hex(&active.manifest_sha256)
        })
        || discovery.sequence <= state.high_water_sequence
    {
        return Err("Core generation activation state is invalid or replayed.".into());
    }

    let (mut prior_sequence, mut prior_hash) = if state.high_water_sequence == 0 {
        let checkpoint = bootstrap.ok_or("Core generation bootstrap checkpoint is missing.")?;
        if checkpoint.sequence == 0 || !lower_hex(&checkpoint.manifest_sha256) {
            return Err("Core generation bootstrap checkpoint is invalid.".into());
        }
        if discovery.sequence < checkpoint.sequence {
            return Err("Core generation predates its bootstrap checkpoint.".into());
        }
        if discovery.sequence == checkpoint.sequence {
            if !lineage.is_empty() || current_hash != checkpoint.manifest_sha256 {
                return Err("Core generation differs from its bootstrap checkpoint.".into());
            }
            (None, None)
        } else {
            (
                Some(checkpoint.sequence),
                Some(checkpoint.manifest_sha256.clone()),
            )
        }
    } else {
        let active = state.active.as_ref().expect("validated active state");
        (Some(active.sequence), Some(active.manifest_sha256.clone()))
    };

    for (older_discovery, older_manifest) in lineage {
        let older_hash = validate_pair(older_discovery, older_manifest)?;
        if &older_discovery.authority != expected_authority
            || prior_sequence.is_none()
            || older_discovery.sequence <= prior_sequence.unwrap()
            || older_discovery.sequence >= discovery.sequence
            || older_discovery.generation.previous_manifest_sha256 != prior_hash
        {
            return Err("Core generation lineage is broken or unordered.".into());
        }
        prior_sequence = Some(older_discovery.sequence);
        prior_hash = Some(older_hash);
    }
    if prior_hash.is_some() && discovery.generation.previous_manifest_sha256 != prior_hash {
        return Err("Core generation predecessor differs from its lineage.".into());
    }
    validate_target(expected_target)?;
    if !discovery
        .targets
        .iter()
        .any(|item| item.target == *expected_target)
    {
        return Err("Core generation lacks the exact requested target.".into());
    }
    Ok(DurableGenerationIdentity {
        sequence: discovery.sequence,
        manifest_sha256: current_hash,
    })
}

fn validate_authority(authority: &GenerationAuthority) -> Result<(), String> {
    if authority.policy_id != POLICY_ID
        || authority.policy_schema_version != 1
        || !lower_hex(&authority.policy_sha256)
        || !plain_filename(&authority.keyring_filename)
        || !lower_hex(&authority.keyring_sha256)
        || !upper_hex_fingerprint(&authority.signing_key_fingerprint)
    {
        return Err("Core generation authority is invalid.".into());
    }
    Ok(())
}

fn validate_target_locks(records: &[GenerationTargetLock]) -> Result<(), String> {
    if records.is_empty() || records.len() > MAX_TARGETS {
        return Err("Core generation target set is invalid.".into());
    }
    let mut prior: Option<&GenerationTarget> = None;
    let mut lock_names = HashSet::new();
    for record in records {
        validate_target(&record.target)?;
        validate_lock(&record.lock)?;
        if prior.is_some_and(|value| value >= &record.target)
            || !lock_names.insert(record.lock.filename.to_ascii_lowercase())
        {
            return Err("Core generation targets are unsorted or duplicated.".into());
        }
        prior = Some(&record.target);
    }
    Ok(())
}

fn validate_target(target: &GenerationTarget) -> Result<(), String> {
    if !version(&target.steamos_version)
        || !kernel(&target.kernel_version)
        || !version(&target.nvidia_version)
        || target.architecture != "x86_64"
    {
        return Err("Core generation target is invalid.".into());
    }
    Ok(())
}

fn validate_lock(lock: &GenerationLock) -> Result<(), String> {
    if !plain_filename(&lock.filename)
        || !lock.filename.ends_with(".json")
        || lock.schema_version != 1
        || !lower_hex(&lock.sha256)
        || !(1..=MAX_LOCK_BYTES).contains(&lock.size)
    {
        return Err("Core generation lock identity is invalid.".into());
    }
    Ok(())
}

fn validate_files(files: &[GenerationFile]) -> Result<(), String> {
    if files.is_empty() || files.len() > MAX_FILES {
        return Err("Core generation file set is invalid.".into());
    }
    let mut prior: Option<(&str, &str)> = None;
    let mut names = HashSet::new();
    let mut total = 0_u64;
    for file in files {
        let identity = (file.role.as_str(), file.filename.as_str());
        if !matches!(
            file.role.as_str(),
            "gaming-profile"
                | "keyring"
                | "package"
                | "package-signature"
                | "provenance"
                | "signer-policy"
                | "target-policy"
                | "userspace-lock"
        ) || !plain_filename(&file.filename)
            || !lower_hex(&file.sha256)
            || !(1..=MAX_FILE_BYTES).contains(&file.size)
            || prior.is_some_and(|value| value >= identity)
            || !names.insert(file.filename.to_ascii_lowercase())
        {
            return Err("Core generation file inventory is invalid.".into());
        }
        total = total
            .checked_add(file.size)
            .ok_or("Core generation size overflowed.")?;
        if total > MAX_GENERATION_BYTES {
            return Err("Core generation is too large.".into());
        }
        prior = Some(identity);
    }
    Ok(())
}

fn validate_predecessor(sequence: u64, predecessor: Option<&str>) -> Result<(), String> {
    if (sequence == 1 && predecessor.is_some())
        || (sequence > 1 && !predecessor.is_some_and(lower_hex))
    {
        return Err("Core generation predecessor is invalid.".into());
    }
    Ok(())
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("Could not represent Core generation document: {error}"))?;
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("Could not serialize Core generation document: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn lower_hex(value: &str) -> bool {
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

fn plain_filename(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 255
        || value.ends_with('.')
        || matches!(value, "." | "..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'~' | b'-')
        })
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    matches!(parts.len(), 2 | 3)
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn kernel(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'-')
        })
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        bytes[start..end].iter().try_fold(0_u32, |value, byte| {
            value.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))
        })
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    if year == 0 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    const FIXTURE_LIMIT: usize = 512 * 1024;
    const CONTRACT_COMMIT: &str = "e9ad58a1c1d5908627186782ef32388d45c21187";

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureEnvelope {
        schema_version: u32,
        kind: String,
        status: String,
        authority: GenerationAuthority,
        activation_state: FixtureActivationState,
        bootstrap_checkpoint: DurableGenerationIdentity,
        expected_target: GenerationTarget,
        consumer_handoff: ConsumerHandoff,
        limits: FixtureLimits,
        durable_state_fixtures: Vec<DurableStateFixture>,
        cases: Vec<FixtureCase>,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureActivationState {
        high_water_sequence: u64,
        active_manifest_sha256: Option<String>,
        #[serde(default)]
        active_sequence: Option<u64>,
    }

    impl FixtureActivationState {
        fn runtime(&self) -> GenerationActivationState {
            let sequence = self.active_sequence.unwrap_or(self.high_water_sequence);
            GenerationActivationState {
                high_water_sequence: self.high_water_sequence,
                active: self.active_manifest_sha256.as_ref().map(|hash| {
                    DurableGenerationIdentity {
                        sequence,
                        manifest_sha256: hash.clone(),
                    }
                }),
            }
        }
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ConsumerHandoff {
        generation_id_source: String,
        manifest_sha256_source: String,
        sequence_source: String,
        durable_identity_fields: Vec<String>,
        high_water_invariant: String,
        rollback_invariant: String,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureLimits {
        discovery_max_bytes: usize,
        manifest_max_bytes: usize,
        max_targets: usize,
        max_files: usize,
        max_file_bytes: u64,
        max_generation_bytes: u64,
        max_lineage_generations: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct DurableStateFixture {
        name: String,
        before: DurableFixtureState,
        #[serde(default)]
        candidate: Option<DurableGenerationIdentity>,
        after: DurableFixtureState,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct DurableFixtureState {
        active: Option<DurableGenerationIdentity>,
        last_known_good: Option<DurableGenerationIdentity>,
        high_water_sequence: u64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureCase {
        name: String,
        expected: FixtureExpected,
        #[serde(default)]
        discovery: Option<serde_json::Value>,
        #[serde(default)]
        manifest: Option<serde_json::Value>,
        #[serde(default)]
        raw_discovery: Option<String>,
        #[serde(default)]
        raw_manifest: Option<String>,
        #[serde(default)]
        discovery_recipe: Option<FixtureRecipe>,
        #[serde(default)]
        manifest_recipe: Option<FixtureRecipe>,
        #[serde(default)]
        expected_target: Option<GenerationTarget>,
        #[serde(default)]
        activation_state: Option<FixtureActivationState>,
        #[serde(default)]
        lineage: Vec<FixtureLineage>,
        #[serde(default)]
        bootstrap_checkpoint: Option<DurableGenerationIdentity>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureExpected {
        discovery_accepted: bool,
        manifest_accepted: bool,
        pair_accepted: bool,
        activation_accepted: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureRecipe {
        kind: String,
        base_case: String,
        #[serde(default)]
        padding_bytes: Option<usize>,
        #[serde(default)]
        count: Option<usize>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureLineage {
        discovery: serde_json::Value,
        manifest: serde_json::Value,
    }

    fn canonical_value(value: &serde_json::Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn fixture_payload(
        case: &FixtureCase,
        discovery: bool,
        bases: &HashMap<&str, (&serde_json::Value, &serde_json::Value)>,
    ) -> Result<Vec<u8>, String> {
        let (direct, raw, recipe, label) = if discovery {
            (
                case.discovery.as_ref(),
                case.raw_discovery.as_ref(),
                case.discovery_recipe.as_ref(),
                "discovery",
            )
        } else {
            (
                case.manifest.as_ref(),
                case.raw_manifest.as_ref(),
                case.manifest_recipe.as_ref(),
                "manifest",
            )
        };
        if usize::from(direct.is_some())
            + usize::from(raw.is_some())
            + usize::from(recipe.is_some())
            != 1
        {
            return Err(format!(
                "fixture must provide exactly one {label} representation"
            ));
        }
        if let Some(value) = direct {
            return Ok(canonical_value(value));
        }
        if let Some(value) = raw {
            return Ok(value.as_bytes().to_vec());
        }
        let recipe = recipe.unwrap();
        let (base_discovery, base_manifest) = bases
            .get(recipe.base_case.as_str())
            .ok_or_else(|| format!("unknown recipe base {}", recipe.base_case))?;
        let mut value = if discovery {
            (*base_discovery).clone()
        } else {
            (*base_manifest).clone()
        };
        match recipe.kind.as_str() {
            "top-level-padding" => {
                if recipe.count.is_some() {
                    return Err("padding recipe contains a count".into());
                }
                let count = recipe.padding_bytes.ok_or("padding recipe has no size")?;
                value["padding"] = serde_json::Value::String("x".repeat(count));
            }
            "excessive-targets" if discovery => {
                if recipe.padding_bytes.is_some() {
                    return Err("target recipe contains padding".into());
                }
                let count = recipe.count.ok_or("target recipe has no count")?;
                let template = value["targets"]
                    .as_array()
                    .and_then(|items| items.first())
                    .cloned()
                    .ok_or("target recipe base is empty")?;
                let mut records = Vec::with_capacity(count);
                for index in 0..count {
                    let mut record = template.clone();
                    record["target"]["kernelVersion"] =
                        serde_json::Value::String(format!("kernel-{index:04}"));
                    record["lock"]["filename"] =
                        serde_json::Value::String(format!("lock-{index:04}.json"));
                    record["lock"]["sha256"] =
                        serde_json::Value::String(format!("{:064x}", index + 1));
                    records.push(record);
                }
                value["targets"] = serde_json::Value::Array(records);
            }
            "excessive-files" if !discovery => {
                if recipe.padding_bytes.is_some() {
                    return Err("file recipe contains padding".into());
                }
                let count = recipe.count.ok_or("file recipe has no count")?;
                value["files"] = serde_json::Value::Array(
                    (0..count)
                        .map(|index| {
                            serde_json::json!({
                                "role": "package",
                                "filename": format!("package-{index:04}.pkg.tar.zst"),
                                "size": 1,
                                "sha256": format!("{:064x}", index + 1),
                            })
                        })
                        .collect(),
                );
            }
            _ => return Err(format!("unknown or misplaced recipe {}", recipe.kind)),
        }
        Ok(canonical_value(&value))
    }

    fn local_core_repository() -> Option<PathBuf> {
        let configured = std::env::var_os("OPEMOS_CORE_CONTRACT_ROOT").map(PathBuf::from);
        let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .parent()?
            .join("open-gpu-kernel-modules-steamos-support");
        let required = configured.is_some();
        let repository = configured.unwrap_or(fallback);
        if !repository.join(".git").exists() {
            assert!(!required, "configured immutable Core repository is absent");
            return None;
        }
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&repository)
            .output()
            .ok()?;
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            CONTRACT_COMMIT
        );
        Some(repository)
    }

    fn export_fixture_sources(repository: &Path) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "opemos-core-generation-fixtures-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        for relative in [
            "lib/generate_userspace_lock_generation_fixtures.py",
            "lib/userspace_lock_generation_contract.py",
        ] {
            let output = Command::new("git")
                .args(["show", &format!("{CONTRACT_COMMIT}:{relative}")])
                .current_dir(repository)
                .output()
                .expect("export exact Core generation fixture source");
            assert!(
                output.status.success(),
                "missing pinned Core file {relative}"
            );
            let destination = root.join(relative);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(destination, output.stdout).unwrap();
        }
        root
    }

    fn exact_case_names() -> HashSet<&'static str> {
        [
            "valid-next-generation",
            "valid-forward-skip",
            "valid-fresh-current-bootstrap",
            "valid-first-generation-record",
            "fresh-historical-replay",
            "invalid-fresh-bootstrap-checkpoint",
            "maximum-sequence",
            "valid-missed-generation-catchup",
            "missing-catchup-generation",
            "valid-after-rollback-catchup",
            "replay-after-rollback",
            "tampered-catchup-generation",
            "forked-catchup-generation",
            "excessive-catchup-lineage",
            "unknown-discovery-schema",
            "unknown-manifest-schema",
            "unknown-policy-id",
            "unknown-policy-schema",
            "unknown-compatibility",
            "unknown-discovery-field",
            "unknown-authority-field",
            "unknown-manifest-field",
            "discovery-manifest-authority-mismatch",
            "structural-alternate-authority",
            "valid-multiple-targets",
            "unsorted-targets",
            "duplicate-targets",
            "duplicate-lock-filenames",
            "casefold-duplicate-lock-filenames",
            "empty-targets",
            "unsafe-lock-filename",
            "windows-reserved-lock-filename",
            "colon-in-manifest-filename",
            "trailing-dot-keyring-filename",
            "oversized-kernel-identity",
            "excessive-target-count",
            "expected-target-missing",
            "discovery-manifest-target-mismatch",
            "duplicate-files",
            "unsorted-files",
            "unknown-file-role",
            "unsafe-file-name",
            "unknown-file-field",
            "empty-files",
            "missing-target-lock-file",
            "target-lock-file-hash-mismatch",
            "unexpected-lock-file",
            "duplicate-filename-across-roles",
            "casefold-duplicate-file-names",
            "payload-collides-with-manifest",
            "oversized-file-record",
            "excessive-file-count",
            "excessive-generation-total",
            "sequence-mismatch",
            "zero-discovery-sequence",
            "missing-predecessor",
            "first-generation-with-predecessor",
            "broken-immediate-predecessor",
            "replayed-sequence",
            "downgraded-sequence",
            "malformed-manifest-hash",
            "malformed-signature-hash",
            "zero-signature-size",
            "release-tag-sequence-mismatch",
            "manifest-filename-mismatch",
            "signature-filename-mismatch",
            "invalid-published-at",
            "published-at-mismatch",
            "duplicate-discovery-key",
            "duplicate-manifest-key",
            "non-finite-discovery",
            "noncanonical-discovery-json",
            "oversized-discovery-document",
            "oversized-manifest-document",
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn hostile_timestamp_text_fails_closed_without_panicking() {
        assert!(!valid_timestamp("😀😀😀😀😀"));
        assert!(!valid_timestamp("0000-01-01T00:00:00Z"));
        assert!(valid_timestamp("2028-02-29T23:59:59Z"));
        assert!(!valid_timestamp("2027-02-29T23:59:59Z"));
    }

    #[test]
    fn local_core_generation_matrix_matches_closed_rust_contract() {
        let Some(repository) = local_core_repository() else {
            eprintln!("skipping local Core generation fixtures: immutable repository is absent");
            return;
        };
        let exported = export_fixture_sources(&repository);
        let generator = exported.join("lib/generate_userspace_lock_generation_fixtures.py");
        let generate = || {
            let output = Command::new("python3")
                .arg(&generator)
                .current_dir("/")
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .output()
                .expect("run Core generation fixture generator");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stderr.is_empty());
            output.stdout
        };
        let bytes = generate();
        assert_eq!(
            bytes,
            generate(),
            "Core generation fixtures are nondeterministic"
        );
        assert!(!bytes.is_empty() && bytes.len() <= FIXTURE_LIMIT);
        reject_duplicate_contract_keys(&bytes, "Core generation fixtures").unwrap();
        let fixtures: FixtureEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(fixtures.schema_version, 1);
        assert_eq!(
            fixtures.kind,
            "opemos-userspace-lock-generation-compatibility-fixtures"
        );
        assert_eq!(fixtures.status, "inactive-design-contract");
        assert_eq!(
            fixtures.limits,
            FixtureLimits {
                discovery_max_bytes: DISCOVERY_MAX_BYTES,
                manifest_max_bytes: MANIFEST_MAX_BYTES,
                max_targets: MAX_TARGETS,
                max_files: MAX_FILES,
                max_file_bytes: MAX_FILE_BYTES,
                max_generation_bytes: MAX_GENERATION_BYTES,
                max_lineage_generations: MAX_LINEAGE_GENERATIONS,
            }
        );
        assert_eq!(
            fixtures.consumer_handoff,
            ConsumerHandoff {
                generation_id_source: "generation.manifestSha256".into(),
                manifest_sha256_source: "generation.manifestSha256".into(),
                sequence_source: "sequence".into(),
                durable_identity_fields: vec!["sequence".into(), "manifestSha256".into()],
                high_water_invariant: "maximum-activated-sequence-never-decreases".into(),
                rollback_invariant: "active-may-return-to-lkg-high-water-unchanged".into(),
            }
        );
        assert_eq!(fixtures.cases.len(), 74);
        assert_eq!(
            fixtures
                .cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<HashSet<_>>(),
            exact_case_names()
        );

        let bases = fixtures
            .cases
            .iter()
            .filter_map(|case| {
                Some((
                    case.name.as_str(),
                    (case.discovery.as_ref()?, case.manifest.as_ref()?),
                ))
            })
            .collect::<HashMap<_, _>>();
        for case in &fixtures.cases {
            let discovery_bytes = fixture_payload(case, true, &bases).unwrap();
            let manifest_bytes = fixture_payload(case, false, &bases).unwrap();
            let discovery = validate_discovery_bytes(&discovery_bytes);
            let manifest = validate_manifest_bytes(&manifest_bytes);
            assert_eq!(
                discovery.is_ok(),
                case.expected.discovery_accepted,
                "{} discovery: {:?}",
                case.name,
                discovery.as_ref().err()
            );
            assert_eq!(
                manifest.is_ok(),
                case.expected.manifest_accepted,
                "{} manifest: {:?}",
                case.name,
                manifest.as_ref().err()
            );
            let pair = discovery
                .as_ref()
                .ok()
                .zip(manifest.as_ref().ok())
                .map(|(left, right)| validate_pair(left, right));
            let pair_ok = pair.as_ref().is_some_and(|result| result.is_ok());
            assert_eq!(
                pair_ok,
                case.expected.pair_accepted,
                "{} pair: {:?}",
                case.name,
                pair.and_then(Result::err)
            );

            let activation_ok = if let (Ok(discovery), Ok(manifest)) = (&discovery, &manifest) {
                let lineage = case
                    .lineage
                    .iter()
                    .map(|item| {
                        let discovery_bytes = canonical_value(&item.discovery);
                        let manifest_bytes = canonical_value(&item.manifest);
                        (
                            validate_discovery_bytes(&discovery_bytes).unwrap(),
                            validate_manifest_bytes(&manifest_bytes).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();
                let lineage_refs = lineage
                    .iter()
                    .map(|(left, right)| (left, right))
                    .collect::<Vec<_>>();
                let state = case
                    .activation_state
                    .as_ref()
                    .unwrap_or(&fixtures.activation_state)
                    .runtime();
                let target = case
                    .expected_target
                    .as_ref()
                    .unwrap_or(&fixtures.expected_target);
                let checkpoint = case
                    .bootstrap_checkpoint
                    .as_ref()
                    .unwrap_or(&fixtures.bootstrap_checkpoint);
                validate_activation(
                    discovery,
                    manifest,
                    &fixtures.authority,
                    target,
                    &state,
                    &lineage_refs,
                    Some(checkpoint),
                )
                .is_ok()
            } else {
                false
            };
            assert_eq!(
                activation_ok, case.expected.activation_accepted,
                "{} activation",
                case.name
            );
        }

        assert_eq!(fixtures.durable_state_fixtures.len(), 2);
        let activated = &fixtures.durable_state_fixtures[0];
        assert_eq!(activated.name, "activate-newer");
        assert_eq!(activated.candidate, activated.after.active);
        assert!(activated.after.high_water_sequence > activated.before.high_water_sequence);
        let rolled_back = &fixtures.durable_state_fixtures[1];
        assert_eq!(rolled_back.name, "rollback-active");
        assert_eq!(rolled_back.after.active, rolled_back.before.last_known_good);
        assert_eq!(
            rolled_back.after.last_known_good,
            rolled_back.before.last_known_good
        );
        assert_eq!(
            rolled_back.after.high_water_sequence,
            rolled_back.before.high_water_sequence
        );
        fs::remove_dir_all(exported).unwrap();
    }
}
