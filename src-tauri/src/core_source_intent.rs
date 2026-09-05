use crate::core_contracts::{
    parse_core_resolver_result, reject_duplicate_contract_keys, CoreResolverNextAction,
    CoreResolverTarget,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const SOURCE_INTENT_LIMIT: usize = 64 * 1024;
const SOURCE_AUTHORIZATION_LIMIT: usize = 1024 * 1024;
const SOURCE_FIXTURE_LIMIT: usize = 512 * 1024;
const MAX_SOURCE_FIXTURE_CASES: usize = 32;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreSourceTarget {
    pub(crate) steamos_version: String,
    pub(crate) kernel_version: String,
    pub(crate) architecture: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreSourceIdentity {
    pub(crate) repository: String,
    #[serde(rename = "ref")]
    pub(crate) reference: String,
    pub(crate) commit: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreSourceIntent {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) mode: String,
    pub(crate) target: CoreSourceTarget,
    pub(crate) selection: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreSourceCompatibilityFixtures {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) max_cases: usize,
    pub(crate) cases: Vec<CoreSourceCompatibilityCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreSourceCompatibilityCase {
    pub(crate) name: String,
    pub(crate) intent: serde_json::Value,
    pub(crate) releases: serde_json::Value,
    pub(crate) expected: CoreSourceExpectedDecision,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreSourceExpectedDecision {
    pub(crate) status: String,
    pub(crate) reason: String,
    #[serde(default)]
    pub(crate) action_kind: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CoreSourceAuthorization {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) reason: String,
    pub(crate) intent_sha256: String,
    pub(crate) target: Option<CoreSourceTarget>,
    #[serde(default)]
    pub(crate) action: Option<serde_json::Value>,
}

fn numeric_version(value: &str, components: std::ops::RangeInclusive<usize>) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    components.contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn safe_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+~-".contains(&byte))
}

fn safe_kebab(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase() || byte.is_ascii_digit()
            } else {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
            }
        })
}

fn exact_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_repository(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 || value.matches('/').count() != 1 {
        return false;
    }
    value.split('/').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    })
}

fn valid_target(target: &CoreSourceTarget) -> bool {
    numeric_version(&target.steamos_version, 3..=3)
        && safe_token(&target.kernel_version, 255)
        && target.architecture == "x86_64"
}

fn parse_source_identity(value: &serde_json::Value) -> Result<CoreSourceIdentity, String> {
    let source: CoreSourceIdentity = serde_json::from_value(value.clone())
        .map_err(|error| format!("OPEMOS Core source identity is invalid: {error}"))?;
    if !valid_repository(&source.repository)
        || source.reference.is_empty()
        || source.reference.len() > 1024
        || !exact_lower_hex(&source.commit, 40)
    {
        return Err("OPEMOS Core source identity violates schema 1.".into());
    }
    Ok(source)
}

pub(crate) fn parse_core_source_intent(bytes: &[u8]) -> Result<CoreSourceIntent, String> {
    if bytes.is_empty() || bytes.len() > SOURCE_INTENT_LIMIT {
        return Err("OPEMOS Core source intent is empty or exceeds 64 KiB.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core source intent")?;
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("OPEMOS Core source intent is invalid JSON: {error}"))?;
    if canonical_bytes(&value)? != bytes {
        return Err("OPEMOS Core source intent is not canonical JSON.".into());
    }
    let intent: CoreSourceIntent = serde_json::from_value(value)
        .map_err(|error| format!("OPEMOS Core source intent violates schema 1: {error}"))?;
    validate_core_source_intent(&intent)?;
    Ok(intent)
}

pub(crate) fn validate_core_source_intent(intent: &CoreSourceIntent) -> Result<(), String> {
    if intent.schema_version != 1
        || intent.kind != "opemos-source-intent"
        || !valid_target(&intent.target)
    {
        return Err("OPEMOS Core source intent identity or target is invalid.".into());
    }
    let selection = &intent.selection;
    match intent.mode.as_str() {
        "automatic" if selection.is_null() => Ok(()),
        "exact-published-artifact" => {
            let object = selection
                .as_object()
                .filter(|value| value.len() == 1)
                .ok_or("Published source selection is invalid.")?;
            let tag = object
                .get("releaseTag")
                .and_then(serde_json::Value::as_str)
                .filter(|value| safe_token(value, 1024))
                .ok_or("Published source selection is invalid.")?;
            if tag.is_empty() {
                Err("Published source selection is invalid.".into())
            } else {
                Ok(())
            }
        }
        "exact-target-local-build" => validate_version_selection(selection, false),
        "reviewed-project-source" => validate_version_selection(selection, true),
        "upstream-development" => {
            let object = selection
                .as_object()
                .filter(|value| value.len() == 3)
                .ok_or("Upstream development selection is invalid.")?;
            validate_nvidia_version(object.get("nvidiaVersion"))?;
            parse_source_identity(
                object
                    .get("source")
                    .ok_or("Upstream development source is absent.")?,
            )?;
            if !object
                .get("developmentAcknowledged")
                .is_some_and(serde_json::Value::is_boolean)
            {
                return Err("Upstream development acknowledgement is invalid.".into());
            }
            Ok(())
        }
        _ => Err("OPEMOS Core source intent mode or selection is invalid.".into()),
    }
}

fn validate_nvidia_version(value: Option<&serde_json::Value>) -> Result<&str, String> {
    value
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.len() <= 64 && numeric_version(value, 2..=3))
        .ok_or_else(|| "NVIDIA source version is invalid.".into())
}

fn validate_version_selection(
    selection: &serde_json::Value,
    with_source: bool,
) -> Result<(), String> {
    let expected = if with_source { 2 } else { 1 };
    let object = selection
        .as_object()
        .filter(|value| value.len() == expected)
        .ok_or("Exact source selection is invalid.")?;
    validate_nvidia_version(object.get("nvidiaVersion"))?;
    if with_source {
        parse_source_identity(
            object
                .get("source")
                .ok_or("Reviewed project source is absent.")?,
        )?;
    }
    Ok(())
}

fn canonical_bytes(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    fn write_string(value: &str, output: &mut String) {
        output.push('"');
        for character in value.chars() {
            match character {
                '"' => output.push_str("\\\""),
                '\\' => output.push_str("\\\\"),
                '\u{0008}' => output.push_str("\\b"),
                '\u{000c}' => output.push_str("\\f"),
                '\n' => output.push_str("\\n"),
                '\r' => output.push_str("\\r"),
                '\t' => output.push_str("\\t"),
                character if character <= '\u{001f}' => {
                    output.push_str(&format!("\\u{:04x}", character as u32));
                }
                character if character.is_ascii() => output.push(character),
                character if (character as u32) <= 0xffff => {
                    output.push_str(&format!("\\u{:04x}", character as u32));
                }
                character => {
                    let scalar = character as u32 - 0x1_0000;
                    let high = 0xd800 + (scalar >> 10);
                    let low = 0xdc00 + (scalar & 0x3ff);
                    output.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                }
            }
        }
        output.push('"');
    }

    fn write_value(value: &serde_json::Value, output: &mut String) -> Result<(), String> {
        match value {
            serde_json::Value::Null => output.push_str("null"),
            serde_json::Value::Bool(value) => {
                output.push_str(if *value { "true" } else { "false" });
            }
            serde_json::Value::Number(value) if value.is_i64() || value.is_u64() => {
                output.push_str(&value.to_string());
            }
            serde_json::Value::Number(_) => {
                return Err(
                    "OPEMOS Core source intent contains a non-integral JSON number.".into(),
                );
            }
            serde_json::Value::String(value) => write_string(value, output),
            serde_json::Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_value(value, output)?;
                }
                output.push(']');
            }
            serde_json::Value::Object(values) => {
                output.push('{');
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_string(key, output);
                    output.push(':');
                    write_value(value, output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }

    let mut output = String::new();
    write_value(value, &mut output)?;
    output.push('\n');
    Ok(output.into_bytes())
}

fn source_target_as_resolver(target: &CoreSourceTarget) -> CoreResolverTarget {
    CoreResolverTarget {
        steamos_version: target.steamos_version.clone(),
        kernel_version: target.kernel_version.clone(),
        architecture: target.architecture.clone(),
    }
}

fn action_kind(action: &serde_json::Value) -> Option<&str> {
    action.get("kind").and_then(serde_json::Value::as_str)
}

pub(crate) fn parse_core_source_authorization(
    bytes: &[u8],
    intent_value: &serde_json::Value,
) -> Result<CoreSourceAuthorization, String> {
    if bytes.is_empty() || bytes.len() > SOURCE_AUTHORIZATION_LIMIT {
        return Err("OPEMOS Core source authorization is empty or exceeds 1 MiB.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core source authorization")?;
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("OPEMOS Core source authorization is invalid JSON: {error}"))?;
    if canonical_bytes(&value)? != bytes {
        return Err("OPEMOS Core source authorization is not canonical JSON.".into());
    }
    let object = value
        .as_object()
        .ok_or("OPEMOS Core source authorization is not an object.")?;
    if !object.contains_key("target") {
        return Err("OPEMOS Core source authorization omitted required target.".into());
    }
    let action_present = object.contains_key("action");
    let authorization: CoreSourceAuthorization = serde_json::from_value(value)
        .map_err(|error| format!("OPEMOS Core source authorization violates schema 1: {error}"))?;
    if authorization.schema_version != 1
        || authorization.kind != "opemos-source-authorization"
        || !exact_lower_hex(&authorization.intent_sha256, 64)
        || authorization.intent_sha256
            != format!("{:x}", Sha256::digest(canonical_bytes(intent_value)?))
    {
        return Err("OPEMOS Core source authorization identity is invalid.".into());
    }
    let parsed_intent = serde_json::from_value::<CoreSourceIntent>(intent_value.clone())
        .ok()
        .filter(|intent| validate_core_source_intent(intent).is_ok());
    match (&authorization.target, &parsed_intent) {
        (Some(target), Some(intent)) if target == &intent.target => {}
        (None, None) if authorization.reason == "source_intent_invalid" => {}
        _ => {
            return Err("OPEMOS Core source authorization target does not match its intent.".into())
        }
    }
    let authorized = authorization.status == "authorized";
    if !authorized && authorization.status != "rejected" {
        return Err("OPEMOS Core source authorization status is invalid.".into());
    }
    if (authorized && (!action_present || authorization.action.is_none()))
        || (!authorized && action_present)
    {
        return Err("OPEMOS Core source authorization action does not match its status.".into());
    }
    let expected_action = match authorization.reason.as_str() {
        "published_artifact_authorized" => Some("use_published_artifact"),
        "exact_target_build_authorized" | "reviewed_project_source_authorized" => {
            Some("build_exact_target")
        }
        "upstream_development_authorized" => Some("build_upstream_development"),
        "automatic_no_authorized_action"
        | "explicit_development_acknowledgement_required"
        | "requested_publication_unavailable"
        | "resolver_failed"
        | "reviewed_build_plan_unavailable"
        | "reviewed_project_source_mismatch"
        | "source_intent_invalid"
        | "unsupported_development_source" => None,
        _ => return Err("OPEMOS Core source authorization reason is invalid.".into()),
    };
    if let Some(intent) = &parsed_intent {
        let reason_matches_mode = match authorization.reason.as_str() {
            "published_artifact_authorized" => {
                matches!(
                    intent.mode.as_str(),
                    "automatic" | "exact-published-artifact"
                )
            }
            "exact_target_build_authorized" => {
                matches!(
                    intent.mode.as_str(),
                    "automatic" | "exact-target-local-build"
                )
            }
            "reviewed_project_source_authorized" | "reviewed_project_source_mismatch" => {
                intent.mode == "reviewed-project-source"
            }
            "upstream_development_authorized"
            | "explicit_development_acknowledgement_required"
            | "unsupported_development_source" => intent.mode == "upstream-development",
            "automatic_no_authorized_action" => intent.mode == "automatic",
            "requested_publication_unavailable" => intent.mode == "exact-published-artifact",
            "resolver_failed" => {
                matches!(
                    intent.mode.as_str(),
                    "automatic" | "exact-published-artifact"
                )
            }
            "reviewed_build_plan_unavailable" => matches!(
                intent.mode.as_str(),
                "exact-target-local-build" | "reviewed-project-source"
            ),
            "source_intent_invalid" => false,
            _ => false,
        };
        if !reason_matches_mode {
            return Err(
                "OPEMOS Core source authorization reason does not match its intent mode.".into(),
            );
        }
    }
    if authorization.action.as_ref().and_then(action_kind) != expected_action {
        return Err("OPEMOS Core source authorization reason and action disagree.".into());
    }
    if let (Some(intent), Some(action)) = (&parsed_intent, &authorization.action) {
        validate_authorized_action(intent, action)?;
    }
    Ok(authorization)
}

fn validate_authorized_action(
    intent: &CoreSourceIntent,
    action: &serde_json::Value,
) -> Result<(), String> {
    match action_kind(action) {
        Some("use_published_artifact") => {
            if !matches!(
                intent.mode.as_str(),
                "automatic" | "exact-published-artifact"
            ) {
                return Err(
                    "Published-artifact authorization does not match its intent mode.".into(),
                );
            }
            let object = action
                .as_object()
                .filter(|value| value.len() == 4)
                .ok_or("Published-artifact authorization is not closed schema 1.")?;
            if object
                .get("schemaVersion")
                .and_then(serde_json::Value::as_u64)
                != Some(1)
            {
                return Err("Published-artifact authorization schema is invalid.".into());
            }
            let resolver_value = object
                .get("resolverResult")
                .ok_or("Published-artifact authorization omitted its resolver result.")?;
            let resolver = parse_core_resolver_result(&canonical_bytes(resolver_value)?)?;
            let expected_digest = format!("{:x}", Sha256::digest(canonical_bytes(resolver_value)?));
            if object
                .get("resolverResultSha256")
                .and_then(serde_json::Value::as_str)
                != Some(expected_digest.as_str())
                || resolver.status != "compatible"
                || resolver.target != source_target_as_resolver(&intent.target)
            {
                return Err(
                    "Published-artifact authorization is not bound to its resolver result.".into(),
                );
            }
            if intent.mode == "exact-published-artifact" {
                let requested = intent
                    .selection
                    .get("releaseTag")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("Exact publication intent omitted its release tag.")?;
                if resolver
                    .publication
                    .as_ref()
                    .map(|publication| publication.tag.as_str())
                    != Some(requested)
                {
                    return Err(
                        "Published-artifact authorization substituted another release tag.".into(),
                    );
                }
            }
            Ok(())
        }
        Some("build_exact_target") => {
            let build: CoreResolverNextAction = serde_json::from_value(action.clone())
                .map_err(|error| format!("Exact-target authorization is invalid: {error}"))?;
            if build.schema_version != 1
                || build.kind != "build_exact_target"
                || build.entrypoint != "bootstrap/build_for_target.sh"
                || build.execution_architecture != "x86_64"
                || build.kernel_policy != "exact"
                || build.build_plan.as_ref().is_none_or(|plan| {
                    !plan.is_valid_for(&source_target_as_resolver(&intent.target))
                })
            {
                return Err("Exact-target authorization violates schema 1.".into());
            }
            let plan = build
                .build_plan
                .as_ref()
                .ok_or("Source authorization omitted its reviewed Core build plan.")?;
            match intent.mode.as_str() {
                "automatic" => {}
                "exact-target-local-build" | "reviewed-project-source" => {
                    let selection = intent
                        .selection
                        .as_object()
                        .ok_or("Explicit source authorization has an invalid source selection.")?;
                    let selected_version = validate_nvidia_version(selection.get("nvidiaVersion"))?;
                    if plan.target.nvidia_version != selected_version {
                        return Err(
                            "Core build plan does not match the selected NVIDIA version.".into(),
                        );
                    }
                    if intent.mode == "reviewed-project-source" {
                        let selected_source =
                            parse_source_identity(selection.get("source").ok_or(
                                "Reviewed source authorization omitted source identity.",
                            )?)?;
                        if plan.source.repository != selected_source.repository
                            || plan.source.reference != selected_source.reference
                            || plan.source.commit != selected_source.commit
                        {
                            return Err(
                                "Core build plan does not match the reviewed source identity."
                                    .into(),
                            );
                        }
                    }
                }
                _ => {
                    return Err("Exact-target authorization does not match its intent mode.".into())
                }
            }
            Ok(())
        }
        Some("build_upstream_development") => {
            if intent.mode != "upstream-development" {
                return Err("Upstream authorization does not match its intent mode.".into());
            }
            let object = action
                .as_object()
                .filter(|value| value.len() == 9)
                .ok_or("Upstream-development authorization is not closed schema 1.")?;
            if object
                .get("schemaVersion")
                .and_then(serde_json::Value::as_u64)
                != Some(1)
                || object.get("entrypoint").and_then(serde_json::Value::as_str)
                    != Some("bootstrap/build_for_target.sh")
                || object
                    .get("executionArchitecture")
                    .and_then(serde_json::Value::as_str)
                    != Some("x86_64")
                || object
                    .get("kernelPolicy")
                    .and_then(serde_json::Value::as_str)
                    != Some("exact")
                || object.get("trust").and_then(serde_json::Value::as_str)
                    != Some("development-unverified")
                || object
                    .get("publicationPermitted")
                    .and_then(serde_json::Value::as_bool)
                    != Some(false)
            {
                return Err("Upstream-development authorization violates schema 1.".into());
            }
            let source = parse_source_identity(
                object
                    .get("source")
                    .ok_or("Upstream authorization omitted source identity.")?,
            )?;
            let target = object
                .get("target")
                .and_then(serde_json::Value::as_object)
                .filter(|value| value.len() == 4)
                .ok_or("Upstream authorization omitted its exact target.")?;
            let version = target
                .get("nvidiaVersion")
                .and_then(serde_json::Value::as_str)
                .ok_or("Upstream authorization omitted NVIDIA version.")?;
            let selection = intent
                .selection
                .as_object()
                .ok_or("Upstream intent selection is invalid.")?;
            let selected_source = parse_source_identity(
                selection
                    .get("source")
                    .ok_or("Upstream intent omitted source identity.")?,
            )?;
            let selected_version = validate_nvidia_version(selection.get("nvidiaVersion"))?;
            if source.repository != "NVIDIA/open-gpu-kernel-modules"
                || source.reference != format!("refs/tags/{version}")
                || source != selected_source
                || version != selected_version
                || selection
                    .get("developmentAcknowledged")
                    .and_then(serde_json::Value::as_bool)
                    != Some(true)
                || target
                    .get("steamosVersion")
                    .and_then(serde_json::Value::as_str)
                    != Some(intent.target.steamos_version.as_str())
                || target
                    .get("kernelVersion")
                    .and_then(serde_json::Value::as_str)
                    != Some(intent.target.kernel_version.as_str())
                || target
                    .get("architecture")
                    .and_then(serde_json::Value::as_str)
                    != Some("x86_64")
            {
                return Err(
                    "Upstream-development authorization is not bound to its intent.".into(),
                );
            }
            Ok(())
        }
        _ => Err("OPEMOS Core source authorization action is unsupported.".into()),
    }
}

pub(crate) fn parse_core_source_compatibility_fixtures(
    bytes: &[u8],
) -> Result<CoreSourceCompatibilityFixtures, String> {
    if bytes.is_empty() || bytes.len() > SOURCE_FIXTURE_LIMIT {
        return Err("OPEMOS Core source fixtures are empty or exceed 512 KiB.".into());
    }
    reject_duplicate_contract_keys(bytes, "OPEMOS Core source fixtures")?;
    let fixtures: CoreSourceCompatibilityFixtures = serde_json::from_slice(bytes)
        .map_err(|error| format!("OPEMOS Core source fixtures are invalid JSON: {error}"))?;
    if fixtures.schema_version != 1
        || fixtures.kind != "opemos-source-intent-compatibility-fixtures"
        || fixtures.max_cases != MAX_SOURCE_FIXTURE_CASES
        || fixtures.cases.is_empty()
        || fixtures.cases.len() > MAX_SOURCE_FIXTURE_CASES
    {
        return Err("OPEMOS Core source fixture envelope is invalid.".into());
    }
    let expected = expected_fixture_outcomes();
    let mut names = HashSet::new();
    for case in &fixtures.cases {
        let releases = case
            .releases
            .as_array()
            .ok_or("OPEMOS Core source fixture releases are not an array.")?;
        let actual = (
            case.expected.status.as_str(),
            case.expected.reason.as_str(),
            case.expected.action_kind.as_deref(),
        );
        if !safe_kebab(&case.name, 64)
            || !names.insert(case.name.as_str())
            || releases.len() > 2_000
            || expected.get(case.name.as_str()).copied() != Some(actual)
            // The matrix intentionally carries non-canonical malformed JSON
            // values. Bound their encoded size without applying the production
            // canonicalizer that the case is specifically expected to fail.
            || serde_json::to_vec(&case.intent)
                .map_err(|error| format!("OPEMOS Core source fixture is not encodable: {error}"))?
                .len()
                > SOURCE_INTENT_LIMIT
        {
            return Err(
                "OPEMOS Core source fixture case is unsafe or changed unexpectedly.".into(),
            );
        }
        let valid_intent = serde_json::from_value::<CoreSourceIntent>(case.intent.clone())
            .ok()
            .is_some_and(|intent| validate_core_source_intent(&intent).is_ok());
        if valid_intent
            == matches!(
                case.name.as_str(),
                "malformed-project-source"
                    | "malformed-automatic-selection"
                    | "floating-schema-version"
                    | "fractional-selection-version"
                    | "non-scalar-mode"
                    | "unknown-mode"
                    | "unsupported-architecture"
            )
        {
            return Err("OPEMOS Core source fixture intent validity changed unexpectedly.".into());
        }
        let malformed_releases = releases.iter().any(|release| !release.is_object());
        if malformed_releases != (case.name == "automatic-malformed-publications") {
            return Err("OPEMOS Core source fixture release shape changed unexpectedly.".into());
        }
    }
    if names != expected.keys().copied().collect::<HashSet<_>>() {
        return Err("OPEMOS Core source fixtures omit a required compatibility case.".into());
    }
    Ok(fixtures)
}

fn expected_fixture_outcomes(
) -> HashMap<&'static str, (&'static str, &'static str, Option<&'static str>)> {
    HashMap::from([
        (
            "automatic-published",
            (
                "authorized",
                "published_artifact_authorized",
                Some("use_published_artifact"),
            ),
        ),
        (
            "automatic-reviewed-build",
            (
                "authorized",
                "exact_target_build_authorized",
                Some("build_exact_target"),
            ),
        ),
        (
            "automatic-unreviewed-target",
            ("rejected", "automatic_no_authorized_action", None),
        ),
        (
            "exact-published-match",
            (
                "authorized",
                "published_artifact_authorized",
                Some("use_published_artifact"),
            ),
        ),
        (
            "exact-published-mismatch",
            ("rejected", "requested_publication_unavailable", None),
        ),
        (
            "automatic-malformed-publications",
            ("rejected", "resolver_failed", None),
        ),
        (
            "exact-reviewed-build",
            (
                "authorized",
                "exact_target_build_authorized",
                Some("build_exact_target"),
            ),
        ),
        (
            "exact-unreviewed-version",
            ("rejected", "reviewed_build_plan_unavailable", None),
        ),
        (
            "reviewed-project-source",
            (
                "authorized",
                "reviewed_project_source_authorized",
                Some("build_exact_target"),
            ),
        ),
        (
            "unreviewed-project-source",
            ("rejected", "reviewed_project_source_mismatch", None),
        ),
        (
            "malformed-project-source",
            ("rejected", "source_intent_invalid", None),
        ),
        (
            "explicit-upstream-development",
            (
                "authorized",
                "upstream_development_authorized",
                Some("build_upstream_development"),
            ),
        ),
        (
            "upstream-not-acknowledged",
            (
                "rejected",
                "explicit_development_acknowledgement_required",
                None,
            ),
        ),
        (
            "upstream-source-substitution",
            ("rejected", "unsupported_development_source", None),
        ),
        (
            "malformed-automatic-selection",
            ("rejected", "source_intent_invalid", None),
        ),
        (
            "floating-schema-version",
            ("rejected", "source_intent_invalid", None),
        ),
        (
            "fractional-selection-version",
            ("rejected", "source_intent_invalid", None),
        ),
        (
            "non-scalar-mode",
            ("rejected", "source_intent_invalid", None),
        ),
        ("unknown-mode", ("rejected", "source_intent_invalid", None)),
        (
            "unsupported-architecture",
            ("rejected", "source_intent_invalid", None),
        ),
        (
            "duplicate-publication-identity",
            ("rejected", "resolver_failed", None),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsStr,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    // One exact, explicitly non-production Core generation backs every
    // cross-repository migration test. Keep this aligned with
    // development_integration.rs; it is not the production bundle pin.
    const CORE_SOURCE_INTENT_COMMIT: &str = "7f90e45c4c154fdfda81ff594611cf533e4fb894";

    struct TemporaryRoot(PathBuf);

    impl TemporaryRoot {
        fn create() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "opemos-source-intent-integration-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn core_repository() -> PathBuf {
        crate::core_test_repository::required_github_core_repository(CORE_SOURCE_INTENT_COMMIT)
    }

    fn export(repository: &Path, root: &Path, relative: &str) {
        let output = Command::new("git")
            .args(["show", &format!("{CORE_SOURCE_INTENT_COMMIT}:{relative}")])
            .current_dir(repository)
            .output()
            .unwrap();
        assert!(output.status.success(), "missing Core source {relative}");
        let destination = root.join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(destination, output.stdout).unwrap();
    }

    fn run_python(script: &Path, arguments: &[&OsStr], root: &Path) -> std::process::Output {
        Command::new("python3")
            .arg(script)
            .args(arguments)
            .current_dir(root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .unwrap()
    }

    fn fixture_input_bytes(value: &serde_json::Value) -> Vec<u8> {
        // Compatibility matrices deliberately contain malformed values that
        // the production canonicalizer must reject (for example, 1.0 where an
        // integer schema version is required). Preserve those JSON values so
        // both implementations can exercise the rejection path.
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn intent_parser_rejects_duplicate_unknown_and_unbounded_input() {
        let intent = serde_json::json!({
            "schemaVersion": 1,
            "kind": "opemos-source-intent",
            "mode": "automatic",
            "target": {
                "steamosVersion": "3.8.14",
                "kernelVersion": "6.16.12-valve24.4-1-neptune-616-fixture",
                "architecture": "x86_64"
            },
            "selection": null
        });
        let canonical = canonical_bytes(&intent).unwrap();
        assert!(parse_core_source_intent(&canonical).is_ok());
        assert!(parse_core_source_intent(&serde_json::to_vec_pretty(&intent).unwrap()).is_err());
        let duplicate = br#"{"schemaVersion":1,"schemaVersion":1,"kind":"opemos-source-intent","mode":"automatic","target":{"steamosVersion":"3.8.14","kernelVersion":"fixture","architecture":"x86_64"},"selection":null}"#;
        assert!(parse_core_source_intent(duplicate).is_err());
        let mut unknown = intent;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(parse_core_source_intent(&canonical_bytes(&unknown).unwrap()).is_err());
        assert!(parse_core_source_intent(&vec![b' '; SOURCE_INTENT_LIMIT + 1]).is_err());
    }

    #[test]
    fn canonical_intent_hashing_matches_python_ascii_escaping() {
        let value = serde_json::json!({"astral": "🚀", "ref": "refs/heads/α"});
        assert_eq!(
            String::from_utf8(canonical_bytes(&value).unwrap()).unwrap(),
            "{\"astral\":\"\\ud83d\\ude80\",\"ref\":\"refs/heads/\\u03b1\"}\n"
        );
        assert!(canonical_bytes(&serde_json::json!({"invalid": 1.5})).is_err());
    }

    #[test]
    fn authorization_is_bound_to_intent_target_source_and_reason() {
        let source = serde_json::json!({
            "repository": "NVIDIA/open-gpu-kernel-modules",
            "ref": "refs/tags/575.64.05",
            "commit": "1111111111111111111111111111111111111111"
        });
        let target = serde_json::json!({
            "steamosVersion": "3.8.14",
            "kernelVersion": "6.16.12-valve24.4-1-neptune-616-fixture",
            "architecture": "x86_64"
        });
        let intent = serde_json::json!({
            "schemaVersion": 1,
            "kind": "opemos-source-intent",
            "mode": "upstream-development",
            "target": target,
            "selection": {
                "nvidiaVersion": "575.64.05",
                "source": source,
                "developmentAcknowledged": true
            }
        });
        let intent_sha256 = format!("{:x}", Sha256::digest(canonical_bytes(&intent).unwrap()));
        let mut authorization = serde_json::json!({
            "schemaVersion": 1,
            "kind": "opemos-source-authorization",
            "status": "authorized",
            "reason": "upstream_development_authorized",
            "intentSha256": intent_sha256,
            "target": intent["target"],
            "action": {
                "schemaVersion": 1,
                "kind": "build_upstream_development",
                "entrypoint": "bootstrap/build_for_target.sh",
                "executionArchitecture": "x86_64",
                "kernelPolicy": "exact",
                "trust": "development-unverified",
                "publicationPermitted": false,
                "target": {
                    "steamosVersion": "3.8.14",
                    "kernelVersion": "6.16.12-valve24.4-1-neptune-616-fixture",
                    "nvidiaVersion": "575.64.05",
                    "architecture": "x86_64"
                },
                "source": intent["selection"]["source"]
            }
        });
        assert!(parse_core_source_authorization(
            &canonical_bytes(&authorization).unwrap(),
            &intent
        )
        .is_ok());

        let mut missing_target = authorization.clone();
        missing_target.as_object_mut().unwrap().remove("target");
        assert!(parse_core_source_authorization(
            &canonical_bytes(&missing_target).unwrap(),
            &intent
        )
        .is_err());

        let mut rejected = authorization.clone();
        rejected["status"] = serde_json::json!("rejected");
        rejected["reason"] = serde_json::json!("unsupported_development_source");
        rejected.as_object_mut().unwrap().remove("action");
        assert!(
            parse_core_source_authorization(&canonical_bytes(&rejected).unwrap(), &intent).is_ok()
        );
        rejected["action"] = serde_json::Value::Null;
        assert!(
            parse_core_source_authorization(&canonical_bytes(&rejected).unwrap(), &intent).is_err()
        );

        authorization["action"]["source"]["commit"] = serde_json::json!("2".repeat(40));
        assert!(parse_core_source_authorization(
            &canonical_bytes(&authorization).unwrap(),
            &intent
        )
        .is_err());
        authorization["action"]["source"]["commit"] = serde_json::json!("1".repeat(40));
        authorization["reason"] = serde_json::json!("published_artifact_authorized");
        assert!(parse_core_source_authorization(
            &canonical_bytes(&authorization).unwrap(),
            &intent
        )
        .is_err());
        authorization["reason"] = serde_json::json!("upstream_development_authorized");
        authorization["target"]["kernelVersion"] = serde_json::json!("other-kernel");
        assert!(parse_core_source_authorization(
            &canonical_bytes(&authorization).unwrap(),
            &intent
        )
        .is_err());
    }

    #[test]
    #[ignore = "requires the exact unpublished Core development generation"]
    fn exact_core_source_intent_matrix_matches_rust_contract() {
        let repository = core_repository();
        let present = Command::new("git")
            .args([
                "cat-file",
                "-e",
                &format!("{CORE_SOURCE_INTENT_COMMIT}^{{commit}}"),
            ])
            .current_dir(&repository)
            .status()
            .unwrap();
        assert!(
            present.success(),
            "exact Core source-intent commit is absent"
        );
        let temporary = TemporaryRoot::create();
        for relative in [
            "lib/generate_source_intent_fixtures.py",
            "lib/source_intent_contract.py",
            "lib/resolve_target.py",
            "lib/select_release.py",
            "lib/gaming_payload_profiles.py",
            "profiles/gaming/reviewed-policy-v1.json",
            "policies/exact-target-builds-v1.json",
        ] {
            export(&repository, &temporary.0, relative);
        }
        let generator = temporary.0.join("lib/generate_source_intent_fixtures.py");
        let generated = run_python(&generator, &[], &temporary.0);
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let fixtures = parse_core_source_compatibility_fixtures(&generated.stdout).unwrap();
        let contract = temporary.0.join("lib/source_intent_contract.py");
        for (index, case) in fixtures.cases.iter().enumerate() {
            let intent_path = temporary.0.join(format!("intent-{index}.json"));
            let releases_path = temporary.0.join(format!("releases-{index}.json"));
            fs::write(&intent_path, fixture_input_bytes(&case.intent)).unwrap();
            fs::write(&releases_path, fixture_input_bytes(&case.releases)).unwrap();
            let output = run_python(
                &contract,
                &[
                    OsStr::new("--intent"),
                    intent_path.as_os_str(),
                    OsStr::new("--releases"),
                    releases_path.as_os_str(),
                    OsStr::new("--repository"),
                    OsStr::new("CorniiDog/OPEMOS"),
                ],
                &temporary.0,
            );
            assert!(
                output.status.success(),
                "{}: {}",
                case.name,
                String::from_utf8_lossy(&output.stderr)
            );
            if canonical_bytes(&case.intent).is_err() {
                assert!(
                    parse_core_source_authorization(&output.stdout, &case.intent).is_err(),
                    "{} must remain fail-closed in the Rust consumer",
                    case.name
                );
                let rejected: CoreSourceAuthorization =
                    serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(rejected.status, case.expected.status, "{}", case.name);
                assert_eq!(rejected.reason, case.expected.reason, "{}", case.name);
                assert!(rejected.action.is_none(), "{}", case.name);
                continue;
            }
            let authorization =
                parse_core_source_authorization(&output.stdout, &case.intent).unwrap();
            assert_eq!(authorization.status, case.expected.status, "{}", case.name);
            assert_eq!(authorization.reason, case.expected.reason, "{}", case.name);
            assert_eq!(
                authorization.action.as_ref().and_then(action_kind),
                case.expected.action_kind.as_deref(),
                "{}",
                case.name
            );
            if case.name == "automatic-reviewed-build" {
                let mut missing_plan: serde_json::Value =
                    serde_json::from_slice(&output.stdout).unwrap();
                missing_plan["action"]
                    .as_object_mut()
                    .unwrap()
                    .remove("buildPlan");
                assert!(parse_core_source_authorization(
                    &canonical_bytes(&missing_plan).unwrap(),
                    &case.intent
                )
                .is_err());
            }
            if case.name == "exact-published-match" {
                let mut substituted: serde_json::Value =
                    serde_json::from_slice(&output.stdout).unwrap();
                substituted["action"]["resolverResult"]["publication"]["tag"] =
                    serde_json::json!("steamos-3.8.14-nvidia-575.64.05-kother-kernel");
                let resolver_bytes =
                    canonical_bytes(&substituted["action"]["resolverResult"]).unwrap();
                substituted["action"]["resolverResultSha256"] =
                    serde_json::json!(format!("{:x}", Sha256::digest(resolver_bytes)));
                assert!(parse_core_source_authorization(
                    &canonical_bytes(&substituted).unwrap(),
                    &case.intent
                )
                .is_err());
            }
        }

        let mut missing: serde_json::Value = serde_json::from_slice(&generated.stdout).unwrap();
        missing["cases"].as_array_mut().unwrap().pop();
        assert!(parse_core_source_compatibility_fixtures(&fixture_input_bytes(&missing)).is_err());
        let duplicate = String::from_utf8(generated.stdout).unwrap().replacen(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            1,
        );
        assert!(parse_core_source_compatibility_fixtures(duplicate.as_bytes()).is_err());
        assert!(
            parse_core_source_compatibility_fixtures(&vec![b' '; SOURCE_FIXTURE_LIMIT + 1])
                .is_err()
        );
    }
}
