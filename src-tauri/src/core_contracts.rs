use super::*;
use serde::de::DeserializeSeed as _;

pub(crate) const CORE_RESOLVER_RESULT_LIMIT: usize = 1024 * 1024;
pub(crate) const CORE_PROGRESS_RECORD_LIMIT: usize = 4096;
pub(crate) const CORE_BUNDLE_MANIFEST_LIMIT: usize = 2 * 1024 * 1024;
const CORE_BUNDLE_FILE_LIMIT: u64 = 128 * 1024 * 1024;
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
    #[serde(flatten)]
    pub(crate) extensions: HashMap<String, serde_json::Value>,
}

impl CoreResolverNextAction {
    fn is_exact_target_build(&self) -> bool {
        self.schema_version == 1
            && self.kind == "build_exact_target"
            && self.entrypoint == "bootstrap/build_for_target.sh"
            && self.execution_architecture == "x86_64"
            && self.kernel_policy == "exact"
    }
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
                .is_some_and(CoreResolverNextAction::is_exact_target_build)
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
    determinate: HashMap<(u64, String), (u64, u64, String)>,
}

impl CoreProgressStream {
    pub(crate) fn accept(&mut self, record: &CoreInstallerProgress) -> Result<(), String> {
        record.validate()?;
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
            .is_some_and(CoreResolverNextAction::is_exact_target_build)
        && legacy.status == "build_required"
        && legacy.reason == "exact_kernel_artifact_missing"
        && legacy.compatibility.as_deref() == Some("on_demand_exact_kernel")
        && legacy.build_plan.as_ref().is_some_and(|plan| {
            let baseline = published_release_identity(&plan.baseline_release);
            plan.steamos_version == core.target.steamos_version
                && plan.kernel_version == core.target.kernel_version
                && plan.support_commit == NVIDIA_SUPPORT_BUILD_COMMIT
                && plan.expected_trust == "locally-built-verified"
                && plan.source_origin == "project"
                && plan.source_repository == NVIDIA_SOURCE_REPOSITORY
                && plan.source_branch == format!("nvidia/{}", plan.nvidia_version)
                && plan.source_commit.is_empty()
                && valid_nvidia_version(&plan.nvidia_version)
                && baseline.as_ref().is_some_and(|identity| {
                    identity.nvidia_version == plan.nvidia_version
                        && numeric_version(&identity.steamos_version, 3..=3)
                            .zip(numeric_version(&plan.steamos_version, 3..=3))
                            .is_some_and(|(baseline_version, target_version)| {
                                baseline_version[..2] == target_version[..2]
                                    && baseline_version <= target_version
                            })
                })
        });
    if core.status != legacy.status && !exact_build_equivalent {
        return Err("OPEMOS Core and legacy Rust resolver decisions are not equivalent.".into());
    }
    if core.target.steamos_version != legacy.target.steamos_version.as_deref().unwrap_or_default()
        || core.target.kernel_version != legacy.target.kernel_version.as_deref().unwrap_or_default()
        || core.target.architecture != legacy.target.architecture
        || (!exact_build_equivalent && core.compatibility != legacy.compatibility)
    {
        return Err("OPEMOS Core and legacy Rust resolver decisions are not equivalent.".into());
    }
    if core.status == "compatible" {
        let core_publication = core
            .publication
            .as_ref()
            .ok_or("Core publication missing.")?;
        let legacy_publication = legacy
            .publication
            .as_ref()
            .ok_or("Legacy publication missing.")?;
        if core_publication.tag != legacy_publication.tag
            || core_publication.steamos_version != legacy_publication.steamos_version
            || core_publication.kernel_version != legacy_publication.kernel_version
            || core_publication.nvidia_version != legacy_publication.nvidia_version
            || core_publication.published_at != legacy_publication.published_at
        {
            return Err("OPEMOS Core and legacy Rust resolver publications differ.".into());
        }
    } else if !exact_build_equivalent && core.reason.as_deref() != Some(legacy.reason.as_str()) {
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
            .is_some_and(CoreResolverNextAction::is_exact_target_build));

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
        fs::remove_dir_all(root).unwrap();
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
