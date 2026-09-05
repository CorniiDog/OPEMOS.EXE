//! Read-only host presentation. Parsed documents are never authentication,
//! source authorization, a generation handle, or an executable request.
use crate::core_contracts::{parse_core_resolver_result, CoreResolverResult};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{fs::OpenOptions, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum CompatibilityPreviewRequest {
    Document { document: String },
    File { path: String },
    Fixture { name: String },
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationPreviewIdentity {
    sequence: u64,
    generation_id: &'static str,
    manifest_sha256: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationStatePreview {
    available: Vec<GenerationPreviewIdentity>,
    selected: Option<GenerationPreviewIdentity>,
    active: Option<GenerationPreviewIdentity>,
    last_known_good: Option<GenerationPreviewIdentity>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CompatibilityPreview {
    origin: &'static str,
    result: CoreResolverResult,
    generation_state: Option<GenerationStatePreview>,
}

fn development_generation_state() -> GenerationStatePreview {
    let active = GenerationPreviewIdentity {
        sequence: 41,
        generation_id: "development-fixture-active",
        manifest_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
    };
    let selected = GenerationPreviewIdentity {
        sequence: 42,
        generation_id: "development-fixture-selected",
        manifest_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
    };
    GenerationStatePreview {
        available: vec![active.clone(), selected.clone()],
        selected: Some(selected),
        active: Some(active.clone()),
        last_known_good: Some(active),
    }
}

fn fixture_bytes(name: &str, enabled: bool) -> Result<&'static [u8], String> {
    if !enabled {
        return Err("Compatibility fixtures are available only in debug builds.".into());
    }
    match name {
        "compatible" => Ok(include_bytes!(
            "../../tests/fixtures/opemos-core/resolver-compatible-v2.json"
        )),
        "no-artifact" => Ok(include_bytes!(
            "../../tests/fixtures/opemos-core/resolver-incompatible-v2.json"
        )),
        _ => Err("Unknown compatibility fixture.".into()),
    }
}

fn read_unverified_preview_file(path: &str) -> Result<Vec<u8>, String> {
    use crate::core_contracts::CORE_RESOLVER_RESULT_LIMIT;
    let path = Path::new(path);
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err("Choose an absolute local resolver JSON path.".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|_| "Could not open the selected local resolver JSON file.".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "Could not inspect the selected local resolver JSON file.".to_string())?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > CORE_RESOLVER_RESULT_LIMIT as u64
    {
        return Err("Choose a nonempty Core resolver JSON file no larger than 1 MiB.".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(CORE_RESOLVER_RESULT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read the selected local resolver JSON file.".to_string())?;
    let final_len = file
        .metadata()
        .map_err(|_| "Could not revalidate the selected local resolver JSON file.".to_string())?
        .len();
    if bytes.len() != metadata.len() as usize || final_len != metadata.len() {
        return Err("The selected local resolver JSON file changed while it was read.".into());
    }
    Ok(bytes)
}

#[tauri::command]
pub(crate) fn preview_core_compatibility(
    request: CompatibilityPreviewRequest,
) -> Result<CompatibilityPreview, String> {
    let (origin, result, generation_state) = match request {
        CompatibilityPreviewRequest::Document { document } => (
            "unverified-document",
            parse_core_resolver_result(document.as_bytes())?,
            None,
        ),
        CompatibilityPreviewRequest::File { path } => (
            "unverified-document",
            parse_core_resolver_result(&read_unverified_preview_file(&path)?)?,
            None,
        ),
        CompatibilityPreviewRequest::Fixture { name } => (
            "development-fixture",
            parse_core_resolver_result(fixture_bytes(&name, cfg!(debug_assertions))?)?,
            Some(development_generation_state()),
        ),
    };
    Ok(CompatibilityPreview {
        origin,
        result,
        generation_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_contracts::CORE_RESOLVER_RESULT_LIMIT;

    fn document(value: String) -> Result<CompatibilityPreview, String> {
        preview_core_compatibility(CompatibilityPreviewRequest::Document { document: value })
    }

    #[test]
    fn preview_preserves_core_results_and_never_upgrades_origin() {
        for name in ["compatible", "no-artifact"] {
            let bytes = fixture_bytes(name, true).unwrap();
            let expected =
                serde_json::to_value(parse_core_resolver_result(bytes).unwrap()).unwrap();
            let result = document(String::from_utf8(bytes.to_vec()).unwrap()).unwrap();
            assert_eq!(result.origin, "unverified-document");
            assert!(result.generation_state.is_none());
            assert_eq!(serde_json::to_value(result.result).unwrap(), expected);
            if cfg!(debug_assertions) {
                let fixture = preview_core_compatibility(CompatibilityPreviewRequest::Fixture {
                    name: name.into(),
                })
                .unwrap();
                assert_eq!(fixture.origin, "development-fixture");
                let generation = fixture.generation_state.as_ref().unwrap();
                assert_eq!(generation.available.len(), 2);
                assert_eq!(generation.selected.as_ref().unwrap().sequence, 42);
                assert_eq!(generation.active.as_ref().unwrap().sequence, 41);
                assert_eq!(generation.last_known_good.as_ref().unwrap().sequence, 41);
                assert_eq!(serde_json::to_value(fixture.result).unwrap(), expected);
            }
        }
    }

    #[test]
    fn preview_uses_existing_closed_bounded_core_parser() {
        let fixture = std::str::from_utf8(fixture_bytes("compatible", true).unwrap()).unwrap();
        for input in [
            String::new(),
            "null".into(),
            "{".into(),
            fixture.replace("\"schemaVersion\":2", "\"schemaVersion\":99"),
            fixture.replacen('{', "{\"schemaVersion\":2,", 1),
            fixture.replace("pending-provenance-verification", "trusted"),
            " ".repeat(CORE_RESOLVER_RESULT_LIMIT + 1),
            "é".repeat(CORE_RESOLVER_RESULT_LIMIT / 2 + 1),
        ] {
            assert!(document(input).is_err());
        }
        let mut at_limit = fixture.to_string();
        at_limit.extend(std::iter::repeat_n(
            ' ',
            CORE_RESOLVER_RESULT_LIMIT - fixture.len(),
        ));
        assert!(document(at_limit.clone()).is_ok());
        at_limit.push(' ');
        assert!(document(at_limit).is_err());
    }

    #[test]
    fn local_preview_file_is_bounded_absolute_regular_and_no_follow() {
        use std::fs;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "opemos-compatibility-preview-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture = fixture_bytes("compatible", true).unwrap();
        let valid = root.join("valid.json");
        fs::write(&valid, fixture).unwrap();
        let result = preview_core_compatibility(CompatibilityPreviewRequest::File {
            path: valid.to_string_lossy().into_owned(),
        })
        .unwrap();
        assert_eq!(result.origin, "unverified-document");
        assert!(result.generation_state.is_none());

        let empty = root.join("empty.json");
        fs::write(&empty, []).unwrap();
        let oversized = root.join("oversized.json");
        fs::write(&oversized, vec![b' '; CORE_RESOLVER_RESULT_LIMIT + 1]).unwrap();
        for path in [
            Path::new("relative.json"),
            empty.as_path(),
            oversized.as_path(),
            root.as_path(),
        ] {
            assert!(
                preview_core_compatibility(CompatibilityPreviewRequest::File {
                    path: path.to_string_lossy().into_owned(),
                })
                .is_err()
            );
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&valid, root.join("link.json")).unwrap();
            assert!(
                preview_core_compatibility(CompatibilityPreviewRequest::File {
                    path: root.join("link.json").to_string_lossy().into_owned(),
                })
                .is_err()
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_gate_and_request_shape_cannot_be_overridden() {
        assert!(fixture_bytes("compatible", false).is_err());
        for name in [
            "",
            "../resolver-compatible-v2.json",
            "https://example.com",
            "Compatible",
        ] {
            assert!(fixture_bytes(name, true).is_err());
        }
        for input in [
            r#"{"source":"trusted","document":"{}"}"#,
            r#"{"source":"fixture","name":"compatible","enabled":true}"#,
            r#"{"source":"fixture","name":"compatible","document":"{}"}"#,
            r#"{"source":"document","document":"{}","origin":"development-fixture"}"#,
        ] {
            assert!(serde_json::from_str::<CompatibilityPreviewRequest>(input).is_err());
        }
    }
}
