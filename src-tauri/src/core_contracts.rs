use super::*;
use serde::de::DeserializeSeed as _;

pub(crate) const CORE_RESOLVER_RESULT_LIMIT: usize = 1024 * 1024;
pub(crate) const CORE_PROGRESS_RECORD_LIMIT: usize = 4096;
pub(crate) const CORE_BUNDLE_MANIFEST_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const CORE_RESOLVER_FIXTURE_LIMIT: usize = 512 * 1024;
pub(crate) const CORE_INSTALLER_RESULT_FIXTURE_LIMIT: usize = 512 * 1024;
pub(crate) const CORE_INSTALLER_VALIDATION_FIXTURE_LIMIT: usize = 512 * 1024;
pub(crate) const CORE_INSTALLER_PROGRESS_FIXTURE_LIMIT: usize = 512 * 1024;
pub(crate) const CORE_PROGRESS_STREAM_LIMIT: usize = 16 * 1024 * 1024;
const CORE_PROGRESS_PREFIX: &str = "STEAMOS_NVIDIA_PROGRESS ";
const CORE_BUNDLE_FILE_LIMIT: u64 = 128 * 1024 * 1024;
const CORE_BUNDLE_TOTAL_LIMIT: u64 = 256 * 1024 * 1024;
const CORE_BUNDLE_FILE_COUNT_LIMIT: usize = 256;
const CORE_RESOLVER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreResolverTarget {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) architecture: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct CoreResolverAsset {
    pub(crate) name: String,
    pub(crate) url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct CoreResolverChecksum {
    pub(crate) algorithm: String,
    pub(crate) name: String,
    pub(crate) url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreResolverTrust {
    pub(crate) classification: String,
    pub(crate) source: String,
    pub(crate) required_verification: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct CoreResolverArtifact {
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) checksum: CoreResolverChecksum,
    pub(crate) provenance: CoreResolverAsset,
    pub(crate) trust: CoreResolverTrust,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreResolverPublication {
    pub(crate) tag: String,
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) published_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreResolverNextAction {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) entrypoint: String,
    pub(crate) execution_architecture: String,
    pub(crate) kernel_policy: String,
    #[serde(default)]
    pub(crate) build_plan: Option<CoreResolverBuildPlan>,
    #[serde(flatten)]
    pub(crate) extensions: HashMap<String, serde_json::Value>,
}

impl CoreResolverNextAction {
    fn is_exact_target_build(&self, target: &CoreResolverTarget) -> bool {
        self.schema_version == 1
            && self.kind == "build_exact_target"
            && self.entrypoint == "bootstrap/build_for_target.sh"
            && self.execution_architecture == "x86_64"
            && self.kernel_policy == "exact"
            && self
                .build_plan
                .as_ref()
                .is_none_or(|plan| plan.is_valid_for(target))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreResolverBuildPlan {
    pub(crate) schema_version: u32,
    pub(crate) policy: CoreResolverBuildPolicy,
    pub(crate) target: CoreResolverBuildTarget,
    pub(crate) source: CoreResolverBuildSource,
    pub(crate) baseline: CoreResolverBuildBaseline,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct CoreResolverBuildPolicy {
    pub(crate) name: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreResolverBuildTarget {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) nvidia_version: String,
    pub(crate) architecture: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct CoreResolverBuildSource {
    pub(crate) repository: String,
    #[serde(rename = "ref")]
    pub(crate) reference: String,
    pub(crate) commit: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreResolverBuildBaseline {
    pub(crate) release_tag: String,
    pub(crate) archive_sha256: String,
    pub(crate) provenance_sha256: String,
    pub(crate) trust: String,
}

impl CoreResolverBuildPlan {
    fn is_valid_for(&self, outer: &CoreResolverTarget) -> bool {
        let branch = format!("refs/heads/nvidia/{}", self.target.nvidia_version);
        let exact_lower_hex = |value: &str, length: usize| {
            value.len() == length
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        self.schema_version == 1
            && self.policy.name == "exact-target-builds-v1.json"
            && exact_lower_hex(&self.policy.sha256, 64)
            && self.target.steamos_version == outer.steamos_version
            && self.target.kernel_version == outer.kernel_version
            && self.target.architecture == outer.architecture
            && self.target.architecture == "x86_64"
            && valid_three_part_version(&self.target.steamos_version)
            && valid_nvidia_version(&self.target.nvidia_version)
            && safe_token(&self.target.kernel_version, 255)
            && self.source.repository == NVIDIA_SOURCE_REPOSITORY
            && self.source.reference == branch
            && exact_lower_hex(&self.source.commit, 40)
            && exact_lower_hex(&self.baseline.archive_sha256, 64)
            && exact_lower_hex(&self.baseline.provenance_sha256, 64)
            && matches!(
                self.baseline.trust.as_str(),
                "locally-built-verified" | "certified-published"
            )
            && published_release_identity(&self.baseline.release_tag)
                .is_some_and(|identity| identity.nvidia_version == self.target.nvidia_version)
    }
}

pub(crate) fn core_exact_target_build_plan(
    result: &CoreResolverResult,
    manifest: &CoreBundleManifest,
) -> Result<Option<NvidiaOnDemandBuildPlan>, String> {
    validate_core_resolver_result(result)?;
    let Some(action) = result.next_action.as_ref() else {
        return Ok(None);
    };
    let plan = action
        .build_plan
        .as_ref()
        .ok_or("OPEMOS Core exact-target action omitted its reviewed source authorization.")?;
    if manifest.support_commit.len() != 40
        || !manifest
            .support_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Authenticated OPEMOS Core bundle has an invalid support commit.".into());
    }
    let policy_path = format!("policies/{}", plan.policy.name);
    let policy_files = manifest
        .files
        .iter()
        .filter(|file| file.path == policy_path)
        .collect::<Vec<_>>();
    if policy_files.len() != 1
        || policy_files[0].role != "build-policy"
        || policy_files[0].mode != "0644"
        || policy_files[0].size == 0
        || policy_files[0].sha256 != plan.policy.sha256
    {
        return Err(
            "OPEMOS Core build authorization does not match its authenticated bundle manifest."
                .into(),
        );
    }
    Ok(Some(NvidiaOnDemandBuildPlan {
        steamos_version: plan.target.steamos_version.clone(),
        kernel_version: plan.target.kernel_version.clone(),
        nvidia_version: plan.target.nvidia_version.clone(),
        baseline_release: plan.baseline.release_tag.clone(),
        support_commit: manifest.support_commit.clone(),
        expected_trust: "locally-built-verified".into(),
        source_origin: "project".into(),
        source_repository: plan.source.repository.clone(),
        source_branch: plan
            .source
            .reference
            .strip_prefix("refs/heads/")
            .ok_or("OPEMOS Core build source is not a branch reference.")?
            .into(),
        source_commit: plan.source.commit.clone(),
        core_authorization: Some(NvidiaCoreBuildAuthorization {
            policy_name: plan.policy.name.clone(),
            policy_sha256: plan.policy.sha256.clone(),
            baseline_archive_sha256: plan.baseline.archive_sha256.clone(),
            baseline_provenance_sha256: plan.baseline.provenance_sha256.clone(),
            baseline_trust: plan.baseline.trust.clone(),
        }),
    }))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreResolverResult {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) target: CoreResolverTarget,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) compatibility: Option<String>,
    #[serde(default)]
    pub(crate) publication: Option<CoreResolverPublication>,
    #[serde(default)]
    pub(crate) artifact: Option<CoreResolverArtifact>,
    #[serde(default)]
    pub(crate) capabilities: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) next_action: Option<CoreResolverNextAction>,
    #[serde(flatten)]
    pub(crate) extensions: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreResolverCompatibilityFixtures {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) repository: String,
    pub(crate) resolver_schema_version: u32,
    pub(crate) cases: Vec<CoreResolverCompatibilityCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreResolverCompatibilityCase {
    pub(crate) name: String,
    pub(crate) target: CoreResolverTarget,
    pub(crate) releases: serde_json::Value,
    pub(crate) expected: serde_json::Value,
    pub(crate) absent_fields: Vec<String>,
}

pub(crate) fn parse_core_resolver_compatibility_fixtures(
    bytes: &[u8],
) -> Result<CoreResolverCompatibilityFixtures, String> {
    if bytes.is_empty() || bytes.len() > CORE_RESOLVER_FIXTURE_LIMIT {
        return Err("OPEMOS Core resolver fixtures are empty or exceed 512 KiB.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core resolver fixtures")?;
    let fixtures: CoreResolverCompatibilityFixtures = serde_json::from_slice(bytes)
        .map_err(|error| format!("OPEMOS Core resolver fixtures are invalid JSON: {error}"))?;
    let required_names = HashSet::from([
        "invalid-steamos",
        "invalid-kernel",
        "unsupported-architecture",
        "malformed-release-metadata",
        "duplicate-release-metadata",
        "incomplete-canonical-assets",
        "duplicate-canonical-asset",
        "unreviewed-exact-target",
        "reviewed-exact-target-build",
    ]);
    let mut names = HashSet::new();
    if fixtures.schema_version != 1
        || fixtures.kind != "opemos-resolver-compatibility-fixtures"
        || fixtures.repository != NVIDIA_RELEASE_REPOSITORY
        || fixtures.resolver_schema_version != 2
        || !(1..=64).contains(&fixtures.cases.len())
    {
        return Err("OPEMOS Core resolver fixture envelope is invalid.".into());
    }
    for case in &fixtures.cases {
        let releases = case
            .releases
            .as_array()
            .ok_or("OPEMOS Core resolver fixture releases are not an array.")?;
        let expected = case
            .expected
            .as_object()
            .filter(|value| !value.is_empty())
            .ok_or("OPEMOS Core resolver fixture expected result is empty or invalid.")?;
        let status = expected
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let mut absent = HashSet::new();
        if !safe_kebab_token(&case.name, 64)
            || !names.insert(case.name.as_str())
            || releases.len() > 2_000
            || !matches!(
                status,
                "invalid_target"
                    | "unsupported_target"
                    | "resolver_error"
                    | "no_compatible_artifact"
                    | "compatible"
            )
            || case.target.steamos_version.len() > 64
            || case.target.kernel_version.len() > 255
            || case.target.architecture.len() > 64
            || [
                &case.target.steamos_version,
                &case.target.kernel_version,
                &case.target.architecture,
            ]
            .iter()
            .any(|value| value.is_empty() || value.contains('\0'))
            || case.absent_fields.len() > 16
            || case
                .absent_fields
                .iter()
                .any(|field| !safe_camel_token(field, 64) || !absent.insert(field.as_str()))
        {
            return Err("OPEMOS Core resolver fixture case is unsafe or incomplete.".into());
        }
    }
    if names != required_names {
        return Err("OPEMOS Core resolver fixture matrix omits a required safety case.".into());
    }
    Ok(fixtures)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerResultCompatibilityFixtures {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) result_schema_version: u32,
    pub(crate) unfrozen_fields: Vec<String>,
    pub(crate) cases: Vec<CoreInstallerResultCompatibilityCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerResultCompatibilityCase {
    pub(crate) name: String,
    pub(crate) expected: CoreInstallerResultCompatibilityExpectation,
    #[serde(default)]
    pub(crate) document: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) raw_document: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerResultCompatibilityExpectation {
    pub(crate) accepted: bool,
    #[serde(default)]
    pub(crate) status: Option<String>,
}

pub(crate) fn parse_core_installer_result_compatibility_fixtures(
    bytes: &[u8],
) -> Result<CoreInstallerResultCompatibilityFixtures, String> {
    if bytes.is_empty() || bytes.len() > CORE_INSTALLER_RESULT_FIXTURE_LIMIT {
        return Err("OPEMOS Core installer-result fixtures are empty or exceed 512 KiB.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core installer-result fixtures")?;
    let fixtures: CoreInstallerResultCompatibilityFixtures = serde_json::from_slice(bytes)
        .map_err(|error| {
            format!("OPEMOS Core installer-result fixtures are invalid JSON: {error}")
        })?;
    let required_names = HashSet::from([
        "validated-success",
        "mutation-success",
        "safe-additive-fields",
        "missing-module-verification",
        "missing-userspace-verification",
        "missing-workspace-verification",
        "missing-initramfs-verification",
        "missing-payload-receipt",
        "target-proof-mismatch",
        "module-payload-binding-mismatch",
        "unsafe-input-identity",
        "cleanup-incomplete",
        "malformed-json",
        "duplicate-json-key",
    ]);
    if fixtures.schema_version != 1
        || fixtures.kind != "opemos-installer-result-compatibility-fixtures"
        || fixtures.result_schema_version != 1
        || fixtures.unfrozen_fields != ["message"]
        || !(1..=64).contains(&fixtures.cases.len())
    {
        return Err("OPEMOS Core installer-result fixture envelope is invalid.".into());
    }
    let mut names = HashSet::new();
    for case in &fixtures.cases {
        let has_document = case.document.is_some();
        let has_raw_document = case.raw_document.is_some();
        let expected_status = case.expected.status.as_deref();
        let expected_contract = match case.name.as_str() {
            "validated-success" => (true, Some("validated"), false),
            "mutation-success" | "safe-additive-fields" => (true, Some("success"), false),
            "malformed-json" | "duplicate-json-key" => (false, None, true),
            _ => (false, None, false),
        };
        let document_status = case
            .document
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|document| document.get("status"))
            .and_then(serde_json::Value::as_str);
        if !safe_kebab_token(&case.name, 64)
            || !names.insert(case.name.as_str())
            || has_document == has_raw_document
            || case.expected.accepted != expected_contract.0
            || expected_status != expected_contract.1
            || has_raw_document != expected_contract.2
            || case.raw_document.as_ref().is_some_and(|raw| {
                raw.is_empty() || raw.len() > CORE_INSTALLER_RESULT_FIXTURE_LIMIT
            })
            || (case.expected.accepted
                && (!matches!(expected_status, Some("validated" | "success"))
                    || document_status != expected_status
                    || !has_document))
            || (!case.expected.accepted && expected_status.is_some())
        {
            return Err(
                "OPEMOS Core installer-result fixture case is unsafe or incomplete.".into(),
            );
        }
    }
    if names != required_names {
        return Err(
            "OPEMOS Core installer-result fixture matrix omits a required safety case.".into(),
        );
    }
    Ok(fixtures)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerValidationCompatibilityFixtures {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) validation_schema_version: u32,
    pub(crate) unfrozen_fields: Vec<String>,
    pub(crate) cases: Vec<CoreInstallerValidationCompatibilityCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerValidationCompatibilityCase {
    pub(crate) name: String,
    pub(crate) expected: CoreInstallerValidationCompatibilityExpectation,
    #[serde(default)]
    pub(crate) document: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) raw_document: Option<String>,
    #[serde(default)]
    pub(crate) document_recipe: Option<CoreInstallerValidationDocumentRecipe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerValidationCompatibilityExpectation {
    pub(crate) accepted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerValidationDocumentRecipe {
    pub(crate) kind: String,
    pub(crate) base_case: String,
    pub(crate) additional_records: usize,
}

pub(crate) fn parse_core_installer_validation_compatibility_fixtures(
    bytes: &[u8],
) -> Result<CoreInstallerValidationCompatibilityFixtures, String> {
    if bytes.is_empty() || bytes.len() > CORE_INSTALLER_VALIDATION_FIXTURE_LIMIT {
        return Err(
            "OPEMOS Core installer-validation fixtures are empty or exceed 512 KiB.".into(),
        );
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core installer-validation fixtures")?;
    let fixtures: CoreInstallerValidationCompatibilityFixtures = serde_json::from_slice(bytes)
        .map_err(|error| {
            format!("OPEMOS Core installer-validation fixtures are invalid JSON: {error}")
        })?;
    let accepted_names = HashSet::from([
        "valid-direct-input",
        "valid-authenticated-bundle-input",
        "safe-additive-fields",
    ]);
    let required_names = accepted_names
        .iter()
        .copied()
        .chain([
            "missing-input-source",
            "missing-archive-identity",
            "missing-boot-policy",
            "missing-storage",
            "input-source-identity-mismatch",
            "invalid-archive-hash",
            "unsafe-lock-filename",
            "boot-policy-mismatch",
            "dependency-version-mismatch",
            "duplicate-package-identity",
            "compression-storage-mismatch",
            "root-metadata-reserve-mismatch",
            "var-reserve-mismatch",
            "dependency-closure-limit",
            "malformed-json",
            "duplicate-json-key",
            "non-finite-json",
        ])
        .collect::<HashSet<_>>();
    if fixtures.schema_version != 1
        || fixtures.kind != "opemos-installer-validation-compatibility-fixtures"
        || fixtures.validation_schema_version != 1
        || fixtures.unfrozen_fields != ["message"]
        || !(1..=64).contains(&fixtures.cases.len())
    {
        return Err("OPEMOS Core installer-validation fixture envelope is invalid.".into());
    }
    let mut names = HashSet::new();
    for case in &fixtures.cases {
        let accepted = accepted_names.contains(case.name.as_str());
        let variants = usize::from(case.document.is_some())
            + usize::from(case.raw_document.is_some())
            + usize::from(case.document_recipe.is_some());
        let expected_variant = match case.name.as_str() {
            "malformed-json" | "duplicate-json-key" | "non-finite-json" => "raw",
            "dependency-closure-limit" => "recipe",
            _ => "document",
        };
        if !safe_kebab_token(&case.name, 64)
            || !names.insert(case.name.as_str())
            || case.expected.accepted != accepted
            || variants != 1
            || (case.document.is_some()) != (expected_variant == "document")
            || (case.raw_document.is_some()) != (expected_variant == "raw")
            || (case.document_recipe.is_some()) != (expected_variant == "recipe")
            || case.raw_document.as_ref().is_some_and(|raw| {
                raw.is_empty() || raw.len() > CORE_INSTALLER_VALIDATION_FIXTURE_LIMIT
            })
            || (accepted && case.document.is_none())
        {
            return Err(
                "OPEMOS Core installer-validation fixture case is unsafe or incomplete.".into(),
            );
        }
        if let Some(recipe) = &case.document_recipe {
            if case.name != "dependency-closure-limit"
                || recipe.kind != "extend-dependency-closure"
                || recipe.base_case != "valid-direct-input"
                || recipe.additional_records != 4_091
            {
                return Err("OPEMOS Core installer-validation fixture recipe is invalid.".into());
            }
        }
    }
    if names != required_names {
        return Err(
            "OPEMOS Core installer-validation fixture matrix omits a required safety case.".into(),
        );
    }
    Ok(fixtures)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerProgressCompatibilityFixtures {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) progress_schema_version: u32,
    pub(crate) unfrozen_fields: Vec<String>,
    pub(crate) limits: CoreInstallerProgressFixtureLimits,
    pub(crate) cases: Vec<CoreInstallerProgressCompatibilityCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerProgressFixtureLimits {
    pub(crate) max_line_bytes: usize,
    pub(crate) max_stream_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerProgressCompatibilityCase {
    pub(crate) name: String,
    pub(crate) expected: CoreInstallerProgressCompatibilityExpectation,
    #[serde(default)]
    pub(crate) stream: Option<String>,
    #[serde(default)]
    pub(crate) stream_recipe: Option<CoreInstallerProgressStreamRecipe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerProgressCompatibilityExpectation {
    pub(crate) accepted: bool,
    #[serde(default)]
    pub(crate) progress_records: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreInstallerProgressStreamRecipe {
    pub(crate) kind: String,
    pub(crate) text: String,
    pub(crate) count: usize,
}

pub(crate) fn parse_core_installer_progress_compatibility_fixtures(
    bytes: &[u8],
) -> Result<CoreInstallerProgressCompatibilityFixtures, String> {
    if bytes.is_empty() || bytes.len() > CORE_INSTALLER_PROGRESS_FIXTURE_LIMIT {
        return Err("OPEMOS Core installer-progress fixtures are empty or exceed 512 KiB.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core installer-progress fixtures")?;
    let fixtures: CoreInstallerProgressCompatibilityFixtures = serde_json::from_slice(bytes)
        .map_err(|error| {
            format!("OPEMOS Core installer-progress fixtures are invalid JSON: {error}")
        })?;
    let accepted_names = HashSet::from([
        "indeterminate-heartbeats",
        "monotonic-bytes",
        "monotonic-items",
        "phase-transition-reset",
        "attempt-advancement-reset",
        "unknown-additive-fields",
        "unknown-phase-token",
        "non-protocol-noise-ignored",
    ]);
    let required_names = accepted_names
        .iter()
        .copied()
        .chain([
            "attempt-regression",
            "completed-regression",
            "total-change",
            "unit-change",
            "determinate-fields-on-indeterminate",
            "missing-determinate-fields",
            "completed-exceeds-total",
            "zero-total",
            "unsupported-schema-version",
            "invalid-phase-token",
            "malformed-json",
            "duplicate-json-key",
            "non-finite-json",
            "oversized-line",
            "oversized-stream",
            "no-progress-records",
        ])
        .collect::<HashSet<_>>();
    if fixtures.schema_version != 1
        || fixtures.kind != "opemos-installer-progress-compatibility-fixtures"
        || fixtures.progress_schema_version != 1
        || fixtures.unfrozen_fields != ["message"]
        || fixtures.limits.max_line_bytes != CORE_PROGRESS_RECORD_LIMIT
        || fixtures.limits.max_stream_bytes != CORE_PROGRESS_STREAM_LIMIT
        || !(1..=64).contains(&fixtures.cases.len())
    {
        return Err("OPEMOS Core installer-progress fixture envelope is invalid.".into());
    }
    let mut names = HashSet::new();
    for case in &fixtures.cases {
        let accepted = accepted_names.contains(case.name.as_str());
        let has_stream = case.stream.is_some();
        let has_recipe = case.stream_recipe.is_some();
        if !safe_kebab_token(&case.name, 64)
            || !names.insert(case.name.as_str())
            || case.expected.accepted != accepted
            || has_stream == has_recipe
            || (accepted
                && (!has_stream || !matches!(case.expected.progress_records, Some(1..=100_000))))
            || (!accepted && case.expected.progress_records.is_some())
            || case.stream.as_ref().is_some_and(|stream| {
                stream.is_empty() || stream.len() > CORE_PROGRESS_STREAM_LIMIT
            })
        {
            return Err(
                "OPEMOS Core installer-progress fixture case is unsafe or incomplete.".into(),
            );
        }
        if let Some(recipe) = &case.stream_recipe {
            let expanded = recipe.text.len().checked_mul(recipe.count);
            if case.name != "oversized-stream"
                || recipe.kind != "repeat"
                || recipe.text.is_empty()
                || recipe.count == 0
                || expanded.is_none_or(|bytes| bytes <= CORE_PROGRESS_STREAM_LIMIT)
            {
                return Err("OPEMOS Core installer-progress fixture recipe is invalid.".into());
            }
        }
    }
    if names != required_names {
        return Err(
            "OPEMOS Core installer-progress fixture matrix omits a required safety case.".into(),
        );
    }
    Ok(fixtures)
}

fn safe_kebab_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase()
            } else {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
            }
        })
}

fn safe_camel_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_alphabetic()
            } else {
                byte.is_ascii_alphanumeric()
            }
        })
}

fn safe_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+~-".contains(&byte))
}

fn valid_three_part_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_nvidia_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_https_url(value: &str) -> bool {
    value.len() <= 2048 && value.starts_with("https://") && !value.contains(char::is_whitespace)
}

pub(crate) fn parse_core_resolver_result(bytes: &[u8]) -> Result<CoreResolverResult, String> {
    if bytes.is_empty() || bytes.len() > CORE_RESOLVER_RESULT_LIMIT {
        return Err("OPEMOS Core resolver result is empty or exceeds 1 MiB.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core resolver result")?;
    let result: CoreResolverResult = serde_json::from_slice(bytes)
        .map_err(|error| format!("OPEMOS Core resolver result is invalid JSON: {error}"))?;
    validate_core_resolver_result(&result)?;
    Ok(result)
}

pub(crate) fn validate_core_resolver_result(result: &CoreResolverResult) -> Result<(), String> {
    if result.schema_version != 2 {
        return Err(format!(
            "Unsupported OPEMOS Core resolver schema version {}.",
            result.schema_version
        ));
    }
    if result.target.steamos_version.len() > 64
        || result.target.kernel_version.len() > 255
        || result.target.architecture.len() > 64
    {
        return Err("OPEMOS Core resolver target exceeds its contract bounds.".into());
    }
    let compatible = result.status == "compatible";
    if compatible {
        if result.target.architecture != "x86_64"
            || !valid_three_part_version(&result.target.steamos_version)
            || !safe_token(&result.target.kernel_version, 255)
            || !matches!(
                result.compatibility.as_deref(),
                Some("exact" | "same_series_fallback")
            )
        {
            return Err("OPEMOS Core returned an invalid compatible target.".into());
        }
        let publication = result
            .publication
            .as_ref()
            .ok_or("OPEMOS Core compatible result omitted publication metadata.")?;
        let artifact = result
            .artifact
            .as_ref()
            .ok_or("OPEMOS Core compatible result omitted artifact metadata.")?;
        if result.next_action.is_some()
            || result.capabilities.is_none()
            || !valid_three_part_version(&publication.steamos_version)
            || !safe_token(&publication.kernel_version, 255)
            || !valid_nvidia_version(&publication.nvidia_version)
            || publication.tag.is_empty()
            || publication.tag.len() > 1024
            || artifact.name.is_empty()
            || artifact.name.len() > 255
            || artifact.checksum.algorithm != "sha256"
            || artifact.trust.classification != "pending-provenance-verification"
            || artifact.trust.source.is_empty()
            || artifact.trust.source.len() > 255
            || artifact.trust.required_verification.is_empty()
            || ![
                &artifact.url,
                &artifact.checksum.url,
                &artifact.provenance.url,
            ]
            .iter()
            .all(|url| valid_https_url(url))
            || [
                &artifact.name,
                &artifact.checksum.name,
                &artifact.provenance.name,
            ]
            .iter()
            .any(|name| name.is_empty() || name.len() > 255)
        {
            return Err("OPEMOS Core compatible result violates schema 2.".into());
        }
    } else {
        if !matches!(
            result.status.as_str(),
            "invalid_target" | "no_compatible_artifact" | "resolver_error" | "unsupported_target"
        ) || result.reason.as_deref().is_none_or(|reason| {
            reason.is_empty()
                || reason.len() > 128
                || !reason.bytes().enumerate().all(|(index, byte)| {
                    if index == 0 {
                        byte.is_ascii_lowercase()
                    } else {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    }
                })
        }) || result
            .message
            .as_deref()
            .is_none_or(|message| message.is_empty() || message.len() > 2048)
        {
            return Err("OPEMOS Core incompatible result violates schema 2.".into());
        }
        if result.artifact.is_some() {
            return Err(
                "OPEMOS Core incompatible result unexpectedly contains an artifact.".into(),
            );
        }
        let exact_build_absence = result.status == "no_compatible_artifact"
            && result.reason.as_deref() == Some("no_compatible_release");
        if exact_build_absence
            != result
                .next_action
                .as_ref()
                .is_some_and(|action| action.is_exact_target_build(&result.target))
        {
            return Err(
                "OPEMOS Core exact-target build action is missing or attached to an unsafe result."
                    .into(),
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoreInstallerProgress {
    pub(crate) schema_version: u32,
    pub(crate) attempt: u64,
    pub(crate) phase: String,
    pub(crate) indeterminate: bool,
    #[serde(default)]
    pub(crate) completed: Option<u64>,
    #[serde(default)]
    pub(crate) total: Option<u64>,
    #[serde(default)]
    pub(crate) unit: Option<String>,
    #[serde(flatten)]
    pub(crate) extensions: HashMap<String, serde_json::Value>,
}

impl CoreInstallerProgress {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.attempt > 1_000_000
            || self.phase.is_empty()
            || self.phase.len() > 64
            || !self.phase.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                }
            })
        {
            return Err("OPEMOS Core installer progress identity is invalid.".into());
        }
        if self.indeterminate {
            if self.completed.is_some() || self.total.is_some() || self.unit.is_some() {
                return Err(
                    "Indeterminate OPEMOS Core progress contains fabricated counters.".into(),
                );
            }
        } else {
            let completed = self
                .completed
                .ok_or("Determinate Core progress omitted completed.")?;
            let total = self
                .total
                .ok_or("Determinate Core progress omitted total.")?;
            if total == 0
                || completed > total
                || !matches!(self.unit.as_deref(), Some("bytes" | "items"))
            {
                return Err("Determinate OPEMOS Core progress counters are invalid.".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn parse_core_installer_progress(bytes: &[u8]) -> Result<CoreInstallerProgress, String> {
    if bytes.is_empty() || bytes.len() > CORE_PROGRESS_RECORD_LIMIT {
        return Err("OPEMOS Core installer progress is empty or exceeds 4 KiB.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core installer progress")?;
    let record: CoreInstallerProgress = serde_json::from_slice(bytes)
        .map_err(|error| format!("OPEMOS Core installer progress is invalid JSON: {error}"))?;
    record.validate()?;
    Ok(record)
}

#[derive(Default)]
pub(crate) struct CoreProgressStream {
    latest_attempt: Option<u64>,
    determinate: HashMap<(u64, String), (u64, u64, String)>,
}

impl CoreProgressStream {
    pub(crate) fn accept(&mut self, record: &CoreInstallerProgress) -> Result<(), String> {
        record.validate()?;
        if self
            .latest_attempt
            .is_some_and(|latest| record.attempt < latest)
        {
            return Err("OPEMOS Core installer progress attempt regressed.".into());
        }
        if self
            .latest_attempt
            .is_none_or(|latest| record.attempt > latest)
        {
            self.latest_attempt = Some(record.attempt);
            self.determinate.clear();
        }
        if let (Some(completed), Some(total), Some(unit)) =
            (record.completed, record.total, record.unit.as_ref())
        {
            let key = (record.attempt, record.phase.clone());
            if let Some((prior_completed, prior_total, prior_unit)) = self.determinate.get(&key) {
                if completed < *prior_completed || total != *prior_total || unit != prior_unit {
                    return Err("OPEMOS Core installer progress regressed within a phase.".into());
                }
            }
            self.determinate
                .insert(key, (completed, total, unit.clone()));
        }
        Ok(())
    }
}

pub(crate) fn validate_core_installer_progress_stream(bytes: &[u8]) -> Result<usize, String> {
    if bytes.len() > CORE_PROGRESS_STREAM_LIMIT {
        return Err("OPEMOS Core installer progress stream exceeds 16 MiB.".into());
    }
    let mut state = CoreProgressStream::default();
    let mut records = 0_usize;
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if !line.starts_with(CORE_PROGRESS_PREFIX.as_bytes()) {
            continue;
        }
        if line.len() > CORE_PROGRESS_RECORD_LIMIT {
            return Err("OPEMOS Core installer progress line exceeds 4 KiB.".into());
        }
        let record = parse_core_installer_progress(&line[CORE_PROGRESS_PREFIX.len()..])?;
        state.accept(&record)?;
        records = records
            .checked_add(1)
            .ok_or("OPEMOS Core installer progress record count overflowed.")?;
    }
    if records == 0 {
        return Err("OPEMOS Core installer progress stream contains no records.".into());
    }
    Ok(records)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreBundleFile {
    pub(crate) path: String,
    pub(crate) role: String,
    pub(crate) mode: String,
    pub(crate) size: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreBundleManifest {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) repository: String,
    pub(crate) support_commit: String,
    pub(crate) files: Vec<CoreBundleFile>,
    pub(crate) bundle_id: String,
}

#[derive(Debug)]
pub(crate) enum CoreBundleManifestAvailability {
    Verified(CoreBundleManifest),
    Unavailable(String),
}

#[derive(Debug)]
pub(crate) struct AuthenticatedCoreBundle {
    pub(crate) root: PathBuf,
    pub(crate) manifest: CoreBundleManifest,
}

pub(crate) fn core_bundle_release_url() -> String {
    let tag = format!("opemos-installer-bundle-{OPEMOS_CORE_COMPATIBILITY_COMMIT}");
    format!("https://github.com/{NVIDIA_SUPPORT_REPOSITORY}/releases/download/{tag}/{tag}.json")
}

fn read_bounded_response(
    response: &mut reqwest::blocking::Response,
    limit: usize,
    description: &str,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(format!("{description} exceeds its size limit."));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = response
            .read(&mut buffer)
            .map_err(|_| format!("Could not read {description}."))?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > limit {
            return Err(format!("{description} exceeds its size limit."));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

pub(crate) fn acquire_core_bundle_manifest(
    client: &reqwest::blocking::Client,
) -> Result<CoreBundleManifestAvailability, String> {
    let mut response = match client
        .get(core_bundle_release_url())
        .header("Accept", "application/octet-stream")
        .send()
    {
        Ok(response) => response,
        Err(_) => {
            return Ok(CoreBundleManifestAvailability::Unavailable(
                "The immutable OPEMOS Core bundle release is currently unreachable.".into(),
            ));
        }
    };
    if !response.status().is_success() {
        return Ok(CoreBundleManifestAvailability::Unavailable(format!(
            "The immutable OPEMOS Core bundle release is unavailable (HTTP {}).",
            response.status().as_u16()
        )));
    }
    let bytes = read_bounded_response(
        &mut response,
        CORE_BUNDLE_MANIFEST_LIMIT,
        "the OPEMOS Core bundle manifest",
    )?;
    let manifest = parse_core_bundle_manifest(
        &bytes,
        OPEMOS_CORE_COMPATIBILITY_MANIFEST_SHA256,
        OPEMOS_CORE_COMPATIBILITY_COMMIT,
    )?;
    if manifest.bundle_id != OPEMOS_CORE_COMPATIBILITY_BUNDLE_ID {
        return Err("OPEMOS Core bundle manifest has an unexpected bundle identity.".into());
    }
    Ok(CoreBundleManifestAvailability::Verified(manifest))
}

fn stage_core_bundle_with_loader<F>(
    runtime_dir: &Path,
    manifest: CoreBundleManifest,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
    mut load: F,
) -> Result<AuthenticatedCoreBundle, String>
where
    F: FnMut(&CoreBundleFile) -> Result<Vec<u8>, String>,
{
    validate_core_bundle_manifest(&manifest, OPEMOS_CORE_COMPATIBILITY_COMMIT)?;
    if manifest.bundle_id != OPEMOS_CORE_COMPATIBILITY_BUNDLE_ID {
        return Err("Refusing to stage an unexpected OPEMOS Core bundle identity.".into());
    }
    let total = manifest.files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.size)
            .filter(|value| *value <= CORE_BUNDLE_TOTAL_LIMIT)
            .ok_or("OPEMOS Core bundle exceeds its aggregate size limit.")
    })?;
    let root = runtime_dir.join(format!("opemos-core-{}", manifest.bundle_id));
    fs::create_dir(&root)
        .map_err(|error| format!("Could not create OPEMOS Core bundle staging: {error}"))?;
    let mut root_guard = StagingDirectoryGuard {
        path: root.clone(),
        armed: true,
    };
    let mut completed = 0_u64;
    for file in &manifest.files {
        if cancel.load(Ordering::Relaxed) {
            return Err("OPEMOS Core bundle staging cancelled.".into());
        }
        let bytes = load(file)?;
        if bytes.len() as u64 != file.size || format!("{:x}", Sha256::digest(&bytes)) != file.sha256
        {
            return Err(format!(
                "OPEMOS Core bundle file failed manifest verification: {}.",
                file.path
            ));
        }
        let destination = root.join(&file.path);
        let parent = destination
            .parent()
            .ok_or("OPEMOS Core bundle file omitted its parent directory.")?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create OPEMOS Core directory: {error}"))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut output = options
            .open(&destination)
            .map_err(|error| format!("Could not stage OPEMOS Core file: {error}"))?;
        output
            .write_all(&bytes)
            .and_then(|_| output.flush())
            .map_err(|error| format!("Could not finish OPEMOS Core file: {error}"))?;
        drop(output);
        apply_pinned_file_permissions(&destination, file.mode == "0755")?;
        completed += file.size;
        progress("downloading-opemos-core-bundle", completed, total);
    }
    validate_core_bundle_tree(&root, &manifest)?;
    root_guard.armed = false;
    Ok(AuthenticatedCoreBundle { root, manifest })
}

pub(crate) fn download_and_stage_core_bundle(
    runtime_dir: &Path,
    client: &reqwest::blocking::Client,
    manifest: CoreBundleManifest,
    cancel: &AtomicBool,
    progress: &impl Fn(&str, u64, u64),
) -> Result<AuthenticatedCoreBundle, String> {
    stage_core_bundle_with_loader(runtime_dir, manifest, cancel, progress, |file| {
        let url = format!(
            "https://raw.githubusercontent.com/{NVIDIA_SUPPORT_REPOSITORY}/{}/{path}",
            OPEMOS_CORE_COMPATIBILITY_COMMIT,
            path = file.path
        );
        let mut response = client
            .get(url)
            .header("Accept", "application/octet-stream")
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|_| format!("Could not download authenticated Core file {}.", file.path))?;
        read_bounded_response(
            &mut response,
            file.size as usize,
            "an authenticated OPEMOS Core file",
        )
    })
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_bundle_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !Path::new(path).is_absolute()
        && path.split('/').all(|part| {
            !matches!(part, "" | "." | "..")
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte))
        })
}

fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| format!("Could not canonicalize Core JSON: {error}"))
}

pub(crate) fn parse_core_bundle_manifest(
    bytes: &[u8],
    expected_sha256: &str,
    expected_commit: &str,
) -> Result<CoreBundleManifest, String> {
    if bytes.is_empty() || bytes.len() > CORE_BUNDLE_MANIFEST_LIMIT {
        return Err("OPEMOS Core bundle manifest is empty or exceeds 2 MiB.".into());
    }
    if !lowercase_hex(expected_sha256, 64)
        || format!("{:x}", Sha256::digest(bytes)) != expected_sha256
    {
        return Err("OPEMOS Core bundle manifest failed its independent SHA-256 pin.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core bundle manifest")?;
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("OPEMOS Core bundle manifest is invalid JSON: {error}"))?;
    let mut canonical = canonical_json(&value)?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("OPEMOS Core bundle manifest is not canonical JSON.".into());
    }
    let manifest: CoreBundleManifest = serde_json::from_value(value)
        .map_err(|error| format!("OPEMOS Core bundle manifest is invalid: {error}"))?;
    validate_core_bundle_manifest(&manifest, expected_commit)?;
    Ok(manifest)
}

pub(crate) fn validate_core_bundle_manifest(
    manifest: &CoreBundleManifest,
    expected_commit: &str,
) -> Result<(), String> {
    if manifest.schema_version != 1
        || manifest.kind != "opemos-installer-bundle"
        || manifest.repository != NVIDIA_SUPPORT_REPOSITORY
        || manifest.support_commit != expected_commit
        || !lowercase_hex(expected_commit, 40)
        || !lowercase_hex(&manifest.bundle_id, 64)
        || manifest.files.is_empty()
        || manifest.files.len() > CORE_BUNDLE_FILE_COUNT_LIMIT
    {
        return Err("OPEMOS Core bundle manifest identity is invalid.".into());
    }
    let mut prior = "";
    let mut paths = HashSet::new();
    for file in &manifest.files {
        if !safe_bundle_path(&file.path)
            || file.path.as_str() <= prior
            || !paths.insert(file.path.as_str())
            || !matches!(file.mode.as_str(), "0644" | "0755")
            || file.size == 0
            || file.size > CORE_BUNDLE_FILE_LIMIT
            || !lowercase_hex(&file.sha256, 64)
            || file.role.is_empty()
            || file.role.len() > 64
            || !file.role.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                }
            })
        {
            return Err("OPEMOS Core bundle manifest contains an unsafe file record.".into());
        }
        prior = &file.path;
    }
    let identity = serde_json::json!({
        "schemaVersion": manifest.schema_version,
        "kind": manifest.kind,
        "repository": manifest.repository,
        "supportCommit": manifest.support_commit,
        "files": manifest.files,
    });
    if format!("{:x}", Sha256::digest(canonical_json(&identity)?)) != manifest.bundle_id {
        return Err("OPEMOS Core bundle identity hash is invalid.".into());
    }
    Ok(())
}

pub(crate) fn validate_core_bundle_tree(
    root: &Path,
    manifest: &CoreBundleManifest,
) -> Result<(), String> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("Could not inspect the Core bundle root: {error}"))?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err("OPEMOS Core bundle root is not a safe directory.".into());
    }
    let expected = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<HashMap<_, _>>();
    let expected_directories = manifest
        .files
        .iter()
        .flat_map(|file| {
            let mut parents = Vec::new();
            let mut path = Path::new(&file.path).parent();
            while let Some(parent) = path {
                if parent.as_os_str().is_empty() {
                    break;
                }
                parents.push(parent.to_string_lossy().into_owned());
                path = parent.parent();
            }
            parents
        })
        .collect::<HashSet<_>>();
    let mut discovered = HashSet::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, relative)) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("Could not inspect the Core bundle: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("Could not inspect the Core bundle: {error}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "OPEMOS Core bundle contains a non-UTF-8 path.")?;
            let child_relative = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            if !safe_bundle_path(&child_relative) {
                return Err("OPEMOS Core bundle contains an unsafe path.".into());
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("Could not inspect Core bundle entry: {error}"))?;
            if metadata.file_type().is_dir() {
                if !expected_directories.contains(&child_relative) {
                    return Err(format!(
                        "OPEMOS Core bundle contains unexpected directory {child_relative}."
                    ));
                }
                pending.push((entry.path(), child_relative));
                continue;
            }
            let file = expected.get(child_relative.as_str()).ok_or_else(|| {
                format!("OPEMOS Core bundle contains unexpected file {child_relative}.")
            })?;
            if !metadata.file_type().is_file()
                || metadata.len() != file.size
                || sha256_file(&entry.path())? != file.sha256
            {
                return Err(format!(
                    "OPEMOS Core bundle file does not match its manifest: {child_relative}."
                ));
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o7777
                != if file.mode == "0755" { 0o755 } else { 0o644 }
            {
                return Err(format!(
                    "OPEMOS Core bundle file mode is invalid: {child_relative}."
                ));
            }
            discovered.insert(child_relative);
        }
    }
    if discovered.len() != expected.len() {
        return Err("OPEMOS Core bundle is missing one or more manifest files.".into());
    }
    Ok(())
}

struct UniqueContractJson;

impl<'de> serde::de::DeserializeSeed<'de> for UniqueContractJson {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueContractVisitor)
    }
}

struct UniqueContractVisitor;

impl<'de> serde::de::Visitor<'de> for UniqueContractVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueContractJson.deserialize(deserializer)
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while sequence.next_element_seed(UniqueContractJson)?.is_some() {}
        Ok(())
    }
    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            map.next_value_seed(UniqueContractJson)?;
        }
        Ok(())
    }
}

fn reject_duplicate_contract_keys(bytes: &[u8], description: &str) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    UniqueContractJson
        .deserialize(&mut deserializer)
        .map_err(|error| format!("{description} is invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("{description} is invalid JSON: {error}"))
}

pub(crate) fn invoke_core_resolver(
    bundle_root: &Path,
    runtime_dir: &Path,
    target: &NvidiaTargetReadiness,
    releases: &[GithubRelease],
) -> Result<CoreResolverResult, String> {
    let steamos = target
        .steamos_version
        .as_deref()
        .ok_or("Core resolver target omitted SteamOS version.")?;
    let kernel = target
        .kernel_version
        .as_deref()
        .ok_or("Core resolver target omitted kernel version.")?;
    let resolver = bundle_root.join("lib/resolve_target.py");
    let python =
        find_binary("python3").ok_or("Python 3 is required to run OPEMOS Core resolver.")?;
    let sequence = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let release_path = runtime_dir.join(format!(
        ".core-releases-{}-{sequence}.json",
        std::process::id()
    ));
    let mut release_guard = PartialOutputGuard {
        path: release_path.clone(),
        armed: true,
    };
    let release_bytes = serde_json::to_vec(releases)
        .map_err(|error| format!("Could not serialize Core resolver input: {error}"))?;
    if release_bytes.len() > 32 * 1024 * 1024 {
        return Err("OPEMOS Core resolver input exceeds 32 MiB.".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut input = options
        .open(&release_path)
        .map_err(|error| format!("Could not stage Core resolver input: {error}"))?;
    input
        .write_all(&release_bytes)
        .map_err(|error| format!("Could not stage Core resolver input: {error}"))?;
    input
        .flush()
        .map_err(|error| format!("Could not finish Core resolver input: {error}"))?;
    drop(input);
    let resolver_text = resolver.to_string_lossy().into_owned();
    let releases_text = release_path.to_string_lossy().into_owned();
    let arguments = [
        resolver_text.as_str(),
        "--steamos",
        steamos,
        "--kernel",
        kernel,
        "--architecture",
        target.architecture.as_str(),
        "--releases",
        releases_text.as_str(),
        "--repository",
        NVIDIA_RELEASE_REPOSITORY,
    ];
    let (status, stdout, stderr) = bounded_command_output_with_limits(
        &python,
        &arguments,
        "run the pinned OPEMOS Core resolver",
        CORE_RESOLVER_TIMEOUT,
        CORE_RESOLVER_RESULT_LIMIT,
    )?;
    fs::remove_file(&release_path)
        .map_err(|error| format!("Could not remove Core resolver input: {error}"))?;
    release_guard.armed = false;
    if !status.success() {
        return Err(format!(
            "Pinned OPEMOS Core resolver failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    parse_core_resolver_result(&stdout)
}

pub(crate) fn compare_core_and_legacy_resolver(
    core: &CoreResolverResult,
    legacy: &NvidiaPublishedResolution,
) -> Result<(), String> {
    validate_core_resolver_result(core)?;
    let exact_build_equivalent = core.status == "no_compatible_artifact"
        && core.reason.as_deref() == Some("no_compatible_release")
        && core
            .next_action
            .as_ref()
            .is_some_and(|action| action.is_exact_target_build(&core.target))
        && legacy.status == "build_required"
        && legacy.reason == "exact_kernel_artifact_missing"
        && legacy.compatibility.as_deref() == Some("on_demand_exact_kernel")
        && legacy.build_plan.as_ref().is_some_and(|plan| {
            let baseline = published_release_identity(&plan.baseline_release);
            let core_plan = core
                .next_action
                .as_ref()
                .and_then(|action| action.build_plan.as_ref());
            plan.steamos_version == core.target.steamos_version
                && plan.kernel_version == core.target.kernel_version
                && plan.expected_trust == "locally-built-verified"
                && plan.source_origin == "project"
                && plan.source_repository == NVIDIA_SOURCE_REPOSITORY
                && plan.source_branch == format!("nvidia/{}", plan.nvidia_version)
                && valid_nvidia_version(&plan.nvidia_version)
                && baseline.as_ref().is_some_and(|identity| {
                    identity.nvidia_version == plan.nvidia_version
                        && numeric_version(&identity.steamos_version, 3..=3)
                            .zip(numeric_version(&plan.steamos_version, 3..=3))
                            .is_some_and(|(baseline_version, target_version)| {
                                baseline_version[..2] == target_version[..2]
                            })
                })
                && match core_plan {
                    None => {
                        plan.support_commit == NVIDIA_SUPPORT_BUILD_COMMIT
                            && plan.source_commit.is_empty()
                            && plan.core_authorization.is_none()
                            && baseline.as_ref().is_some_and(|identity| {
                                numeric_version(&identity.steamos_version, 3..=3)
                                    .zip(numeric_version(&plan.steamos_version, 3..=3))
                                    .is_some_and(|(baseline_version, target_version)| {
                                        baseline_version <= target_version
                                    })
                            })
                    }
                    Some(core_plan) => {
                        plan.support_commit.len() == 40
                            && plan
                                .support_commit
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                            && plan.source_commit == core_plan.source.commit
                            && plan
                                .core_authorization
                                .as_ref()
                                .is_some_and(|authorization| {
                                    authorization.policy_name == core_plan.policy.name
                                        && authorization.policy_sha256 == core_plan.policy.sha256
                                        && authorization.baseline_archive_sha256
                                            == core_plan.baseline.archive_sha256
                                        && authorization.baseline_provenance_sha256
                                            == core_plan.baseline.provenance_sha256
                                        && authorization.baseline_trust == core_plan.baseline.trust
                                })
                    }
                }
        });
    if core.status != legacy.status && !exact_build_equivalent {
        return Err("OPEMOS Core and legacy Rust resolver decisions are not equivalent.".into());
    }
    let compatibility_equivalent = core.compatibility == legacy.compatibility
        || core.compatibility.is_none()
            && core.publication.as_ref().is_some_and(|publication| {
                let derived = if publication.steamos_version == core.target.steamos_version {
                    "exact"
                } else {
                    "same_series_fallback"
                };
                legacy.compatibility.as_deref() == Some(derived)
            });
    if core.target.steamos_version != legacy.target.steamos_version.as_deref().unwrap_or_default()
        || core.target.kernel_version != legacy.target.kernel_version.as_deref().unwrap_or_default()
        || core.target.architecture != legacy.target.architecture
        || (!exact_build_equivalent && !compatibility_equivalent)
    {
        return Err("OPEMOS Core and legacy Rust resolver decisions are not equivalent.".into());
    }
    match (&core.publication, &legacy.publication) {
        (Some(core_publication), Some(legacy_publication))
            if core_publication.tag == legacy_publication.tag
                && core_publication.steamos_version == legacy_publication.steamos_version
                && core_publication.kernel_version == legacy_publication.kernel_version
                && core_publication.nvidia_version == legacy_publication.nvidia_version
                && core_publication.published_at == legacy_publication.published_at => {}
        (None, None) => {}
        _ => return Err("OPEMOS Core and legacy Rust resolver publications differ.".into()),
    }
    if core.status != "compatible"
        && !exact_build_equivalent
        && core.reason.as_deref() != Some(legacy.reason.as_str())
    {
        return Err("OPEMOS Core and legacy Rust resolver failure reasons differ.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures/opemos-core")
                .join(name),
        )
        .expect("read OPEMOS Core consumer fixture")
    }

    #[test]
    fn resolver_schema_two_accepts_additive_fields_and_rejects_unsafe_results() {
        let compatible = parse_core_resolver_result(&fixture("resolver-compatible-v2.json"))
            .expect("parse compatible Core result");
        assert_eq!(compatible.status, "compatible");
        assert!(compatible
            .capabilities
            .as_ref()
            .and_then(|value| value.get("safeAdditiveField"))
            .is_some());
        let incompatible = parse_core_resolver_result(&fixture("resolver-incompatible-v2.json"))
            .expect("parse incompatible Core result");
        assert_eq!(
            incompatible.reason.as_deref(),
            Some("no_compatible_release")
        );
        assert!(incompatible
            .next_action
            .as_ref()
            .is_some_and(|action| action.is_exact_target_build(&incompatible.target)));

        let mut authorized: serde_json::Value =
            serde_json::from_slice(&fixture("resolver-incompatible-v2.json")).unwrap();
        authorized["nextAction"]["buildPlan"] = serde_json::json!({
            "schemaVersion": 1,
            "policy": {
                "name": "exact-target-builds-v1.json",
                "sha256": "1".repeat(64),
            },
            "target": {
                "steamosVersion": "3.8.14",
                "kernelVersion": "fixture",
                "nvidiaVersion": "575.64.05",
                "architecture": "x86_64",
            },
            "source": {
                "repository": NVIDIA_SOURCE_REPOSITORY,
                "ref": "refs/heads/nvidia/575.64.05",
                "commit": "2".repeat(40),
            },
            "baseline": {
                "releaseTag": "steamos-3.8.16-nvidia-575.64.05-kbaseline-fixture",
                "archiveSha256": "3".repeat(64),
                "provenanceSha256": "4".repeat(64),
                "trust": "locally-built-verified",
            },
        });
        let authorized =
            parse_core_resolver_result(&serde_json::to_vec(&authorized).unwrap()).unwrap();
        let manifest = CoreBundleManifest {
            schema_version: 1,
            kind: "opemos-installer-bundle".into(),
            repository: NVIDIA_SUPPORT_REPOSITORY.into(),
            support_commit: "5".repeat(40),
            files: vec![CoreBundleFile {
                path: "policies/exact-target-builds-v1.json".into(),
                role: "build-policy".into(),
                mode: "0644".into(),
                size: 827,
                sha256: "1".repeat(64),
            }],
            bundle_id: "6".repeat(64),
        };
        let mapped = core_exact_target_build_plan(&authorized, &manifest)
            .unwrap()
            .expect("map reviewed Core build plan");
        assert_eq!(mapped.nvidia_version, "575.64.05");
        assert_eq!(mapped.source_branch, "nvidia/575.64.05");
        assert_eq!(mapped.source_commit, "2".repeat(40));
        assert_eq!(
            mapped
                .core_authorization
                .as_ref()
                .expect("retain Core authorization")
                .baseline_archive_sha256,
            "3".repeat(64)
        );
        let mut wrong_manifest = manifest.clone();
        wrong_manifest.files[0].sha256 = "7".repeat(64);
        assert!(core_exact_target_build_plan(&authorized, &wrong_manifest).is_err());
        let legacy_from_core = NvidiaPublishedResolution {
            schema_version: 2,
            status: "build_required".into(),
            reason: "exact_kernel_artifact_missing".into(),
            message: "reviewed Core build plan".into(),
            compatibility: Some("on_demand_exact_kernel".into()),
            target: NvidiaTargetReadiness {
                ready: true,
                status: "exact-target".into(),
                message: "fixture".into(),
                steamos_version: Some("3.8.14".into()),
                kernel_version: Some("fixture".into()),
                architecture: "x86_64".into(),
            },
            publication: None,
            artifact: None,
            build_plan: Some(mapped),
        };
        compare_core_and_legacy_resolver(&authorized, &legacy_from_core).unwrap();

        let mut wrong_source: serde_json::Value = serde_json::to_value(&authorized).unwrap();
        wrong_source["nextAction"]["buildPlan"]["source"]["ref"] =
            "refs/heads/nvidia/580.1.1".into();
        assert!(parse_core_resolver_result(&serde_json::to_vec(&wrong_source).unwrap()).is_err());

        let mut missing_action: serde_json::Value =
            serde_json::from_slice(&fixture("resolver-incompatible-v2.json")).unwrap();
        missing_action.as_object_mut().unwrap().remove("nextAction");
        assert!(parse_core_resolver_result(&serde_json::to_vec(&missing_action).unwrap()).is_err());
        let mut misplaced_action: serde_json::Value =
            serde_json::from_slice(&fixture("resolver-incompatible-v2.json")).unwrap();
        misplaced_action["reason"] = "release_assets_missing".into();
        assert!(
            parse_core_resolver_result(&serde_json::to_vec(&misplaced_action).unwrap()).is_err()
        );
        let mut unsafe_action: serde_json::Value =
            serde_json::from_slice(&fixture("resolver-incompatible-v2.json")).unwrap();
        unsafe_action["nextAction"]["kernelPolicy"] = "closest".into();
        assert!(parse_core_resolver_result(&serde_json::to_vec(&unsafe_action).unwrap()).is_err());

        let duplicate = br#"{"schemaVersion":2,"schemaVersion":2,"status":"unsupported_target","target":{"steamosVersion":"3.8.14","kernelVersion":"k","architecture":"aarch64"},"reason":"unsupported_architecture","message":"unsupported"}"#;
        assert!(parse_core_resolver_result(duplicate).is_err());
        let mut future_major: serde_json::Value =
            serde_json::from_slice(&fixture("resolver-incompatible-v2.json")).unwrap();
        future_major["schemaVersion"] = 3.into();
        assert!(parse_core_resolver_result(&serde_json::to_vec(&future_major).unwrap()).is_err());
        assert!(parse_core_resolver_result(&vec![b' '; CORE_RESOLVER_RESULT_LIMIT + 1]).is_err());
    }

    #[test]
    fn progress_schema_one_preserves_indeterminate_and_monotonic_semantics() {
        let determinate =
            parse_core_installer_progress(&fixture("progress-determinate-v1.json")).unwrap();
        let indeterminate =
            parse_core_installer_progress(&fixture("progress-indeterminate-v1.json")).unwrap();
        let mut stream = CoreProgressStream::default();
        stream.accept(&determinate).unwrap();
        stream.accept(&indeterminate).unwrap();
        let mut advanced = determinate.clone();
        advanced.completed = Some(7);
        stream.accept(&advanced).unwrap();
        let mut regressed = advanced;
        regressed.completed = Some(6);
        assert!(stream.accept(&regressed).is_err());
        let mut next_attempt = determinate.clone();
        next_attempt.attempt += 1;
        next_attempt.completed = Some(0);
        stream.accept(&next_attempt).unwrap();
        let mut prior_attempt = next_attempt;
        prior_attempt.attempt -= 1;
        assert!(stream.accept(&prior_attempt).is_err());
        let mut fabricated = indeterminate;
        fabricated.completed = Some(1);
        fabricated.total = Some(2);
        fabricated.unit = Some("items".into());
        assert!(fabricated.validate().is_err());
        assert!(parse_core_installer_progress(
            br#"{"schemaVersion":1,"attempt":1,"attempt":2,"phase":"hashing","indeterminate":true}"#
        )
        .is_err());
    }

    fn canonical_manifest_fixture(root: &Path) -> (Vec<u8>, String, CoreBundleManifest) {
        let payload = b"#!/bin/sh\nexit 0\n";
        let file = CoreBundleFile {
            path: "lib/tool.sh".into(),
            role: "runtime-helper".into(),
            mode: "0755".into(),
            size: payload.len() as u64,
            sha256: format!("{:x}", Sha256::digest(payload)),
        };
        let identity = serde_json::json!({
            "schemaVersion": 1,
            "kind": "opemos-installer-bundle",
            "repository": NVIDIA_SUPPORT_REPOSITORY,
            "supportCommit": OPEMOS_CORE_COMPATIBILITY_COMMIT,
            "files": [file],
        });
        let bundle_id = format!("{:x}", Sha256::digest(canonical_json(&identity).unwrap()));
        let document = serde_json::json!({
            "schemaVersion": 1,
            "kind": "opemos-installer-bundle",
            "repository": NVIDIA_SUPPORT_REPOSITORY,
            "supportCommit": OPEMOS_CORE_COMPATIBILITY_COMMIT,
            "files": identity["files"],
            "bundleId": bundle_id,
        });
        let mut bytes = canonical_json(&document).unwrap();
        bytes.push(b'\n');
        let digest = format!("{:x}", Sha256::digest(&bytes));
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::write(root.join("lib/tool.sh"), payload).unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.join("lib/tool.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        let manifest =
            parse_core_bundle_manifest(&bytes, &digest, OPEMOS_CORE_COMPATIBILITY_COMMIT).unwrap();
        (bytes, digest, manifest)
    }

    #[test]
    fn canonical_manifest_is_independently_pinned_and_enforces_a_closed_tree() {
        let root = std::env::temp_dir().join(format!(
            "opemos-core-bundle-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let (bytes, digest, manifest) = canonical_manifest_fixture(&root);
        validate_core_bundle_tree(&root, &manifest).unwrap();
        assert!(parse_core_bundle_manifest(
            &bytes,
            &"0".repeat(64),
            OPEMOS_CORE_COMPATIBILITY_COMMIT,
        )
        .is_err());
        fs::write(root.join("unexpected"), b"x").unwrap();
        assert!(validate_core_bundle_tree(&root, &manifest).is_err());
        fs::remove_file(root.join("unexpected")).unwrap();
        fs::write(root.join("lib/tool.sh"), b"tampered").unwrap();
        assert!(validate_core_bundle_tree(&root, &manifest).is_err());
        assert_eq!(digest.len(), 64);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn supplied_core_manifest_digest_is_scoped_to_the_compatibility_commit() {
        assert_eq!(OPEMOS_CORE_COMPATIBILITY_COMMIT.len(), 40);
        assert_eq!(OPEMOS_CORE_COMPATIBILITY_MANIFEST_SHA256.len(), 64);
        assert_ne!(OPEMOS_CORE_COMPATIBILITY_COMMIT, NVIDIA_INSTALLER_COMMIT);
    }

    fn core_repository() -> Option<PathBuf> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let candidate = root.join("open-gpu-kernel-modules-steamos-support");
        candidate.join(".git").exists().then_some(candidate)
    }

    fn assert_json_subset(actual: &serde_json::Value, expected: &serde_json::Value) {
        if let Some(expected) = expected.as_object() {
            let actual = actual.as_object().expect("fixture result object");
            for (key, value) in expected {
                assert_json_subset(
                    actual.get(key).unwrap_or_else(|| panic!("missing {key}")),
                    value,
                );
            }
        } else {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn local_successor_resolver_fixtures_are_bounded_complete_and_reproducible() {
        let Some(repository) = core_repository() else {
            eprintln!("skipping local successor fixtures: sibling Core repository is absent");
            return;
        };
        let path = repository.join("contracts/fixtures/resolver-compatibility-v2.json");
        let bytes = fs::read(&path).expect("read Core resolver fixtures");
        let fixtures = parse_core_resolver_compatibility_fixtures(&bytes)
            .expect("consume bounded Core resolver fixtures");
        let runtime = std::env::temp_dir().join(format!(
            "opemos-core-fixtures-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&runtime).unwrap();
        for case in &fixtures.cases {
            if case.name == "malformed-release-metadata" {
                assert!(
                    serde_json::from_value::<Vec<GithubRelease>>(case.releases.clone()).is_err()
                );
                continue;
            }
            let releases = case
                .releases
                .as_array()
                .unwrap()
                .iter()
                .map(|release| {
                    let release = release.as_object().expect("release fixture object");
                    GithubRelease {
                        tag_name: release["tag_name"].as_str().unwrap().into(),
                        draft: release["draft"].as_bool().unwrap(),
                        prerelease: release["prerelease"].as_bool().unwrap(),
                        published_at: release["published_at"].as_str().map(str::to_owned),
                        assets: release["assets"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|asset| GithubReleaseAsset {
                                name: asset["name"].as_str().unwrap().into(),
                                browser_download_url: "https://example.invalid/fixture".into(),
                                size: 1,
                                digest: None,
                            })
                            .collect(),
                    }
                })
                .collect::<Vec<_>>();
            let target = NvidiaTargetReadiness {
                ready: true,
                status: "exact-target".into(),
                message: "fixture".into(),
                steamos_version: Some(case.target.steamos_version.clone()),
                kernel_version: Some(case.target.kernel_version.clone()),
                architecture: case.target.architecture.clone(),
            };
            let first_result =
                invoke_core_resolver(&repository, &runtime, &target, &releases).unwrap();
            let second_result =
                invoke_core_resolver(&repository, &runtime, &target, &releases).unwrap();
            for absent in &case.absent_fields {
                let absent = match absent.as_str() {
                    "artifact" => first_result.artifact.is_none(),
                    "nextAction" => first_result.next_action.is_none(),
                    _ => false,
                };
                assert!(absent, "{} exposed an expected-absent field", case.name);
            }
            let first = serde_json::to_value(first_result).unwrap();
            let second = serde_json::to_value(second_result).unwrap();
            assert_eq!(first, second, "fixture {} was nondeterministic", case.name);
            assert_json_subset(&first, &case.expected);
        }
        fs::remove_dir_all(runtime).unwrap();

        let mut missing_case: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        missing_case["cases"].as_array_mut().unwrap().pop();
        assert!(parse_core_resolver_compatibility_fixtures(
            &serde_json::to_vec(&missing_case).unwrap()
        )
        .is_err());
        assert!(parse_core_resolver_compatibility_fixtures(&vec![
            b' ';
            CORE_RESOLVER_FIXTURE_LIMIT + 1
        ])
        .is_err());
    }

    #[test]
    fn local_successor_installer_result_fixtures_are_bounded_and_rust_compatible() {
        let Some(repository) = core_repository() else {
            eprintln!(
                "skipping local successor installer-result fixtures: sibling Core repository is absent"
            );
            return;
        };
        let generator = repository.join("lib/generate_installer_result_fixtures.py");
        let generate = || {
            let output = Command::new("python3")
                .arg(&generator)
                .current_dir(&repository)
                .output()
                .expect("run Core installer-result fixture generator");
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            output.stdout
        };
        let first = generate();
        let second = generate();
        assert_eq!(
            first, second,
            "Core installer-result fixtures changed between runs"
        );
        let fixtures = parse_core_installer_result_compatibility_fixtures(&first)
            .expect("consume bounded Core installer-result fixtures");
        for case in &fixtures.cases {
            if !case.expected.accepted {
                continue;
            }
            let result: SupportInstallResult = serde_json::from_value(
                case.document
                    .clone()
                    .expect("accepted installer fixture document"),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "accepted Core installer-result fixture {} is incompatible with Rust: {error}",
                    case.name
                )
            });
            assert_eq!(result.schema_version, fixtures.result_schema_version);
            assert_eq!(
                Some(result.status.as_str()),
                case.expected.status.as_deref()
            );
            assert!(matches!(
                result.validation,
                Some(SupportInstallValidationDocument::Verified(_))
            ));
            assert!(result.initramfs_workspace.is_some());
            if result.status == "success" {
                assert!(result.module_verification.is_some());
                assert!(result.userspace_verification.is_some());
                assert!(result.initramfs_verification.is_some());
                assert!(result.payload_receipt.is_some());
            } else {
                assert!(result.module_verification.is_none());
                assert!(result.userspace_verification.is_none());
                assert!(result.initramfs_verification.is_none());
                assert!(result.payload_receipt.is_none());
            }
        }

        let mut missing_case: serde_json::Value = serde_json::from_slice(&first).unwrap();
        missing_case["cases"].as_array_mut().unwrap().pop();
        assert!(parse_core_installer_result_compatibility_fixtures(
            &serde_json::to_vec(&missing_case).unwrap()
        )
        .is_err());
        let mut relabelled: serde_json::Value = serde_json::from_slice(&first).unwrap();
        relabelled["cases"][0]["expected"] = serde_json::json!({"accepted": false});
        assert!(parse_core_installer_result_compatibility_fixtures(
            &serde_json::to_vec(&relabelled).unwrap()
        )
        .is_err());
        let duplicate_key = first
            .strip_suffix(b"\n")
            .unwrap()
            .strip_suffix(b"}")
            .unwrap()
            .iter()
            .copied()
            .chain(b",\"schemaVersion\":1}".iter().copied())
            .collect::<Vec<_>>();
        assert!(parse_core_installer_result_compatibility_fixtures(&duplicate_key).is_err());
        assert!(parse_core_installer_result_compatibility_fixtures(&vec![
            b' ';
            CORE_INSTALLER_RESULT_FIXTURE_LIMIT
                + 1
        ])
        .is_err());
    }

    #[test]
    fn local_successor_installer_validation_fixtures_match_rust_semantics() {
        let Some(repository) = core_repository() else {
            eprintln!(
                "skipping local successor installer-validation fixtures: sibling Core repository is absent"
            );
            return;
        };
        let generator = repository.join("lib/generate_installer_validation_fixtures.py");
        let generate = || {
            let output = Command::new("python3")
                .arg(&generator)
                .current_dir(&repository)
                .output()
                .expect("run Core installer-validation fixture generator");
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            output.stdout
        };
        let first = generate();
        assert_eq!(
            first,
            generate(),
            "Core installer-validation fixtures were nondeterministic"
        );
        let fixtures = parse_core_installer_validation_compatibility_fixtures(&first)
            .expect("consume bounded Core installer-validation fixtures");
        let base_document = fixtures
            .cases
            .iter()
            .find(|case| case.name == "valid-direct-input")
            .and_then(|case| case.document.clone())
            .expect("validation fixture base document");
        for case in &fixtures.cases {
            let document_bytes = if let Some(document) = &case.document {
                serde_json::to_vec(document).expect("serialize Core validation fixture")
            } else if let Some(raw) = &case.raw_document {
                raw.as_bytes().to_vec()
            } else {
                let recipe = case
                    .document_recipe
                    .as_ref()
                    .expect("validation fixture recipe");
                let mut document = base_document.clone();
                let closure = document["packageDependencyClosure"]
                    .as_array_mut()
                    .expect("base dependency closure");
                for index in 0..recipe.additional_records {
                    closure.push(serde_json::json!({
                        "name": format!("fixture-dependency-{index}"),
                        "version": "1-1",
                        "source": "installed",
                    }));
                }
                serde_json::to_vec(&document).expect("expand validation fixture recipe")
            };
            let result = reject_duplicate_contract_keys(
                &document_bytes,
                "OPEMOS Core installer-validation fixture document",
            )
            .and_then(|()| {
                serde_json::from_slice::<SupportInstallValidation>(&document_bytes)
                    .map_err(|error| format!("validation document is invalid: {error}"))
            })
            .and_then(|validation| validate_support_validation_contract(&validation));
            assert_eq!(
                result.is_ok(),
                case.expected.accepted,
                "Rust validation acceptance diverged for {}: {:?}",
                case.name,
                result.as_ref().err()
            );
        }

        let mut relabelled: serde_json::Value = serde_json::from_slice(&first).unwrap();
        relabelled["cases"][0]["expected"] = serde_json::json!({"accepted": false});
        assert!(parse_core_installer_validation_compatibility_fixtures(
            &serde_json::to_vec(&relabelled).unwrap()
        )
        .is_err());
        let mut missing_case: serde_json::Value = serde_json::from_slice(&first).unwrap();
        missing_case["cases"].as_array_mut().unwrap().pop();
        assert!(parse_core_installer_validation_compatibility_fixtures(
            &serde_json::to_vec(&missing_case).unwrap()
        )
        .is_err());
        assert!(
            parse_core_installer_validation_compatibility_fixtures(&vec![
                b' ';
                CORE_INSTALLER_VALIDATION_FIXTURE_LIMIT
                    + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn local_successor_installer_progress_fixtures_match_rust_stream_semantics() {
        let Some(repository) = core_repository() else {
            eprintln!(
                "skipping local successor installer-progress fixtures: sibling Core repository is absent"
            );
            return;
        };
        let generator = repository.join("lib/generate_installer_progress_fixtures.py");
        let generate = || {
            let output = Command::new("python3")
                .arg(&generator)
                .current_dir(&repository)
                .output()
                .expect("run Core installer-progress fixture generator");
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            output.stdout
        };
        let first = generate();
        assert_eq!(
            first,
            generate(),
            "Core progress fixtures were nondeterministic"
        );
        let fixtures = parse_core_installer_progress_compatibility_fixtures(&first)
            .expect("consume bounded Core installer-progress fixtures");
        for case in &fixtures.cases {
            let result = if let Some(stream) = &case.stream {
                validate_core_installer_progress_stream(stream.as_bytes())
            } else {
                let recipe = case.stream_recipe.as_ref().expect("fixture stream recipe");
                assert!(recipe
                    .text
                    .len()
                    .checked_mul(recipe.count)
                    .is_some_and(|bytes| bytes > CORE_PROGRESS_STREAM_LIMIT));
                validate_core_installer_progress_stream(&vec![b'x'; CORE_PROGRESS_STREAM_LIMIT + 1])
            };
            assert_eq!(
                result.is_ok(),
                case.expected.accepted,
                "Rust progress acceptance diverged for {}: {:?}",
                case.name,
                result.as_ref().err()
            );
            if let Some(expected) = case.expected.progress_records {
                assert_eq!(result.unwrap(), expected, "{} record count", case.name);
            }
        }

        let mut relabelled: serde_json::Value = serde_json::from_slice(&first).unwrap();
        relabelled["cases"][0]["expected"] = serde_json::json!({"accepted": false});
        assert!(parse_core_installer_progress_compatibility_fixtures(
            &serde_json::to_vec(&relabelled).unwrap()
        )
        .is_err());
        let mut missing_case: serde_json::Value = serde_json::from_slice(&first).unwrap();
        missing_case["cases"].as_array_mut().unwrap().pop();
        assert!(parse_core_installer_progress_compatibility_fixtures(
            &serde_json::to_vec(&missing_case).unwrap()
        )
        .is_err());
        assert!(parse_core_installer_progress_compatibility_fixtures(&vec![
            b' ';
            CORE_INSTALLER_PROGRESS_FIXTURE_LIMIT
                + 1
        ])
        .is_err());
    }

    fn extract_core_file(repository: &Path, root: &Path, path: &str) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args([
                "show",
                &format!("{OPEMOS_CORE_COMPATIBILITY_COMMIT}:{path}"),
            ])
            .output()
            .expect("read pinned Core fixture from Git");
        assert!(
            output.status.success(),
            "pinned Core file unavailable: {path}"
        );
        let destination = root.join(path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(destination, output.stdout).unwrap();
    }

    #[test]
    fn pinned_core_generator_reproduces_supplied_manifest_digest() {
        let Some(repository) = core_repository() else {
            eprintln!(
                "skipping local pinned-Core manifest integration: sibling repository is absent"
            );
            return;
        };
        let root = std::env::temp_dir().join(format!(
            "opemos-core-manifest-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        extract_core_file(&repository, &root, "lib/installer_bundle_manifest.py");
        let output = Command::new(find_binary("python3").unwrap())
            .arg(root.join("lib/installer_bundle_manifest.py"))
            .args([
                "create",
                "--root",
                repository.to_str().unwrap(),
                "--support-commit",
                OPEMOS_CORE_COMPATIBILITY_COMMIT,
                "--dry-run",
            ])
            .output()
            .expect("run pinned Core manifest generator");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&output.stdout)),
            OPEMOS_CORE_COMPATIBILITY_MANIFEST_SHA256
        );
        let manifest = parse_core_bundle_manifest(
            &output.stdout,
            OPEMOS_CORE_COMPATIBILITY_MANIFEST_SHA256,
            OPEMOS_CORE_COMPATIBILITY_COMMIT,
        )
        .expect("consume canonical pinned Core manifest");
        assert_eq!(manifest.files.len(), 55);
        assert_eq!(manifest.bundle_id, OPEMOS_CORE_COMPATIBILITY_BUNDLE_ID);
        assert!(manifest.files.iter().any(|file| {
            file.path == "lib/resolve_target.py" && file.role == "resolver" && file.mode == "0755"
        }));
        assert!(manifest.files.iter().any(|file| {
            file.path == "locks/userspace/steamos-3.8.14-nvidia-575.64.05.json"
                && file.role == "userspace-lock"
        }));
        assert_eq!(
            core_bundle_release_url(),
            format!(
                "https://github.com/{NVIDIA_SUPPORT_REPOSITORY}/releases/download/\
                 opemos-installer-bundle-{OPEMOS_CORE_COMPATIBILITY_COMMIT}/\
                 opemos-installer-bundle-{OPEMOS_CORE_COMPATIBILITY_COMMIT}.json"
            )
        );

        let staging = root.join("staging");
        fs::create_dir(&staging).unwrap();
        let cancel = AtomicBool::new(false);
        let staged = stage_core_bundle_with_loader(
            &staging,
            manifest.clone(),
            &cancel,
            &|_, _, _| {},
            |file| {
                let output = Command::new("git")
                    .arg("-C")
                    .arg(&repository)
                    .args([
                        "show",
                        &format!("{OPEMOS_CORE_COMPATIBILITY_COMMIT}:{}", file.path),
                    ])
                    .output()
                    .map_err(|error| format!("could not load pinned Core blob: {error}"))?;
                if !output.status.success() {
                    return Err("pinned Core blob is unavailable".into());
                }
                Ok(output.stdout)
            },
        )
        .expect("stage the complete authenticated Core tree");
        assert_eq!(staged.manifest.files.len(), 55);
        validate_core_bundle_tree(&staged.root, &staged.manifest).unwrap();

        let cancelled_staging = root.join("cancelled-staging");
        fs::create_dir(&cancelled_staging).unwrap();
        let cancelled = AtomicBool::new(true);
        assert!(stage_core_bundle_with_loader(
            &cancelled_staging,
            manifest.clone(),
            &cancelled,
            &|_, _, _| {},
            |_| Ok(Vec::new()),
        )
        .is_err());
        assert_eq!(fs::read_dir(&cancelled_staging).unwrap().count(), 0);

        let corrupt_staging = root.join("corrupt-staging");
        fs::create_dir(&corrupt_staging).unwrap();
        assert!(stage_core_bundle_with_loader(
            &corrupt_staging,
            manifest,
            &AtomicBool::new(false),
            &|_, _, _| {},
            |_| Ok(b"tampered".to_vec()),
        )
        .is_err());
        assert_eq!(fs::read_dir(&corrupt_staging).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "downloads the announced immutable OPEMOS Core release"]
    fn live_successor_core_bundle_downloads_and_stages() {
        let runtime = std::env::temp_dir().join(format!(
            "opemos-core-live-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&runtime).unwrap();
        let client = nvidia_http_client().unwrap();
        let manifest = match acquire_core_bundle_manifest(&client).unwrap() {
            CoreBundleManifestAvailability::Verified(manifest) => manifest,
            CoreBundleManifestAvailability::Unavailable(message) => panic!("{message}"),
        };
        let bundle = download_and_stage_core_bundle(
            &runtime,
            &client,
            manifest,
            &AtomicBool::new(false),
            &|_, _, _| {},
        )
        .unwrap();
        validate_core_bundle_tree(&bundle.root, &bundle.manifest).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn pinned_core_resolver_matches_legacy_exact_release_decision() {
        let Some(repository) = core_repository() else {
            eprintln!("skipping local pinned-Core integration: sibling repository is absent");
            return;
        };
        let root = std::env::temp_dir().join(format!(
            "opemos-core-resolver-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        for path in [
            "lib/resolve_target.py",
            "lib/select_release.py",
            "lib/gaming_payload_profiles.py",
            "profiles/gaming/reviewed-policy-v1.json",
        ] {
            extract_core_file(&repository, &root, path);
        }
        let kernel = "6.16.12-valve24.4-fixture";
        let tag = format!("steamos-3.8.14-nvidia-575.64.05-k{kernel}");
        let archive = format!("nvidia-open-{tag}-x86_64.tar.gz");
        let releases = vec![GithubRelease {
            tag_name: tag.clone(),
            draft: false,
            prerelease: false,
            published_at: Some("2026-01-01T00:00:00Z".into()),
            assets: [
                archive.clone(),
                format!("{archive}.sha256"),
                format!("{}.provenance.json", archive.trim_end_matches(".tar.gz")),
            ]
            .into_iter()
            .map(|name| GithubReleaseAsset {
                name,
                browser_download_url: "https://example.invalid/asset".into(),
                size: 1,
                digest: None,
            })
            .collect(),
        }];
        let target = NvidiaTargetReadiness {
            ready: true,
            status: "exact-target".into(),
            message: "fixture".into(),
            steamos_version: Some("3.8.14".into()),
            kernel_version: Some(kernel.into()),
            architecture: "x86_64".into(),
        };
        let core = invoke_core_resolver(&root, &root, &target, &releases).unwrap();
        let (legacy_identity, legacy_release, legacy_compatibility) =
            select_published_nvidia_release(&target, &releases)
                .expect("run the legacy Rust resolver")
                .expect("legacy Rust resolver selects the fixture");
        let legacy = NvidiaPublishedResolution {
            schema_version: 2,
            status: "compatible".into(),
            reason: "published_exact_match".into(),
            message: "fixture".into(),
            compatibility: Some(legacy_compatibility),
            target,
            publication: Some(NvidiaPublishedPublication {
                tag: legacy_identity.tag,
                steamos_version: legacy_identity.steamos_version,
                kernel_version: legacy_identity.kernel_version,
                nvidia_version: legacy_identity.nvidia_version,
                published_at: legacy_release.published_at,
            }),
            artifact: None,
            build_plan: None,
        };
        compare_core_and_legacy_resolver(&core, &legacy).unwrap();

        let mut non_equivalent = legacy.clone();
        non_equivalent.status = "build_required".into();
        non_equivalent.reason = "exact_kernel_artifact_missing".into();
        non_equivalent.compatibility = Some("on_demand_exact_kernel".into());
        non_equivalent.publication = None;
        assert!(compare_core_and_legacy_resolver(&core, &non_equivalent).is_err());

        let missing_target = NvidiaTargetReadiness {
            kernel_version: Some("6.16.12-valve24.5-fixture".into()),
            ..legacy.target.clone()
        };
        let core_missing = invoke_core_resolver(&root, &root, &missing_target, &releases).unwrap();
        assert_eq!(
            core_missing.reason.as_deref(),
            Some("no_compatible_release")
        );
        assert!(core_missing.next_action.is_some());
        let baseline = select_nvidia_build_baseline(&missing_target, &releases)
            .unwrap()
            .expect("legacy resolver finds an exact-build baseline");
        let build_plan = NvidiaOnDemandBuildPlan {
            steamos_version: missing_target.steamos_version.clone().unwrap(),
            kernel_version: missing_target.kernel_version.clone().unwrap(),
            nvidia_version: baseline.nvidia_version.clone(),
            baseline_release: baseline.tag,
            support_commit: NVIDIA_SUPPORT_BUILD_COMMIT.into(),
            expected_trust: "locally-built-verified".into(),
            source_origin: "project".into(),
            source_repository: NVIDIA_SOURCE_REPOSITORY.into(),
            source_branch: format!("nvidia/{}", baseline.nvidia_version),
            source_commit: String::new(),
            core_authorization: None,
        };
        let legacy_build = NvidiaPublishedResolution {
            schema_version: 2,
            status: "build_required".into(),
            reason: "exact_kernel_artifact_missing".into(),
            message: "fixture".into(),
            compatibility: Some("on_demand_exact_kernel".into()),
            target: missing_target,
            publication: None,
            artifact: None,
            build_plan: Some(build_plan),
        };
        compare_core_and_legacy_resolver(&core_missing, &legacy_build).unwrap();
        let mut wrong_kernel = legacy_build;
        wrong_kernel.build_plan.as_mut().unwrap().kernel_version = "wrong".into();
        assert!(compare_core_and_legacy_resolver(&core_missing, &wrong_kernel).is_err());

        let mut incomplete_releases = releases.clone();
        incomplete_releases[0].assets.clear();
        let incomplete =
            invoke_core_resolver(&root, &root, &legacy.target, &incomplete_releases).unwrap();
        assert_eq!(incomplete.reason.as_deref(), Some("release_assets_missing"));
        assert!(incomplete.next_action.is_none());
        let legacy_incomplete = resolve_published_nvidia_for_target(
            legacy.target.clone(),
            &root,
            &nvidia_http_client().unwrap(),
            &incomplete_releases,
            &AtomicBool::new(false),
            &|_, _, _| {},
        )
        .unwrap();
        compare_core_and_legacy_resolver(&incomplete, &legacy_incomplete).unwrap();

        let duplicated_release = invoke_core_resolver(
            &root,
            &root,
            &legacy.target,
            &[releases[0].clone(), releases[0].clone()],
        )
        .unwrap();
        assert_eq!(
            duplicated_release.reason.as_deref(),
            Some("release_metadata_ambiguous")
        );
        assert!(duplicated_release.next_action.is_none());
        assert!(select_published_nvidia_release(
            &legacy.target,
            &[releases[0].clone(), releases[0].clone(),]
        )
        .is_err());

        let mut duplicated_assets = releases.clone();
        let duplicated_asset = duplicated_assets[0].assets[0].clone();
        duplicated_assets[0].assets.push(duplicated_asset);
        let core_duplicated_assets =
            invoke_core_resolver(&root, &root, &legacy.target, &duplicated_assets).unwrap();
        assert_eq!(
            core_duplicated_assets.reason.as_deref(),
            Some("release_assets_ambiguous")
        );
        assert!(core_duplicated_assets.next_action.is_none());
        assert!(resolve_published_nvidia_for_target(
            legacy.target.clone(),
            &root,
            &nvidia_http_client().unwrap(),
            &duplicated_assets,
            &AtomicBool::new(false),
            &|_, _, _| {},
        )
        .is_err());

        let fallback_target = NvidiaTargetReadiness {
            steamos_version: Some("3.8.15".into()),
            ..legacy.target.clone()
        };
        let core_fallback =
            invoke_core_resolver(&root, &root, &fallback_target, &releases).unwrap();
        let (fallback_identity, fallback_release, fallback_compatibility) =
            select_published_nvidia_release(&fallback_target, &releases)
                .unwrap()
                .expect("legacy Rust resolver selects the same-series fixture");
        let legacy_fallback = NvidiaPublishedResolution {
            schema_version: 2,
            status: "compatible".into(),
            reason: "published_exact_match".into(),
            message: "fixture".into(),
            compatibility: Some(fallback_compatibility),
            target: fallback_target,
            publication: Some(NvidiaPublishedPublication {
                tag: fallback_identity.tag,
                steamos_version: fallback_identity.steamos_version,
                kernel_version: fallback_identity.kernel_version,
                nvidia_version: fallback_identity.nvidia_version,
                published_at: fallback_release.published_at,
            }),
            artifact: None,
            build_plan: None,
        };
        compare_core_and_legacy_resolver(&core_fallback, &legacy_fallback).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
