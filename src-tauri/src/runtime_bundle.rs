use super::*;
use std::sync::OnceLock;

const MANIFEST_NAME: &str = "runtime-manifest.json";
const EXPECTED_MANIFEST_SHA256: Option<&str> = option_env!("OPEMOS_RUNTIME_MANIFEST_SHA256");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeManifest {
    schema_version: u8,
    platform: String,
    commands: HashMap<String, String>,
    files: Vec<RuntimeFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeFile {
    path: String,
    sha256: String,
    size: u64,
}

static VERIFIED_RUNTIME: OnceLock<Result<HashMap<String, PathBuf>, String>> = OnceLock::new();

pub(crate) fn bundled_runtime_required() -> bool {
    EXPECTED_MANIFEST_SHA256.is_some()
}

fn verified_runtime() -> Result<&'static HashMap<String, PathBuf>, String> {
    VERIFIED_RUNTIME
        .get_or_init(|| {
            let root = match std::env::var_os("OPEMOS_RUNTIME_ROOT") {
                Some(value) => {
                    let requested = PathBuf::from(value);
                    if !requested.is_absolute() {
                        return Err("OPEMOS_RUNTIME_ROOT must be an absolute path.".into());
                    }
                    requested
                }
                None => {
                    let executable = std::env::current_exe().map_err(|error| {
                        format!("Could not locate the packaged executable: {error}")
                    })?;
                    executable
                        .parent()
                        .ok_or("The packaged executable has no parent directory.")?
                        .join("runtime")
                }
            };
            verify_runtime_bundle(&root, EXPECTED_MANIFEST_SHA256.unwrap_or_default())
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub(crate) fn bundled_runtime_binary(name: &str) -> Option<PathBuf> {
    verified_runtime()
        .ok()
        .and_then(|commands| commands.get(name).cloned())
}

pub fn activate_runtime_bundle() -> Result<(), String> {
    if !bundled_runtime_required() {
        return Ok(());
    }
    let commands = verified_runtime()?;
    let mut directories = Vec::new();
    for path in commands.values() {
        let parent = path
            .parent()
            .ok_or("A packaged runtime command has no parent directory.")?
            .to_path_buf();
        if !directories.contains(&parent) {
            directories.push(parent);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        directories.extend(std::env::split_paths(&path));
    }
    let path = std::env::join_paths(directories)
        .map_err(|_| "The packaged runtime search path is invalid.".to_string())?;
    std::env::set_var("PATH", path);
    Ok(())
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_runtime_bundle(
    root: &Path,
    expected_manifest_sha256: &str,
) -> Result<HashMap<String, PathBuf>, String> {
    if !valid_sha256(expected_manifest_sha256) {
        return Err("The compiled runtime manifest SHA-256 is invalid.".into());
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("The packaged runtime directory is unavailable: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("The packaged runtime root must be a real directory.".into());
    }
    let manifest_path = root.join(MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| format!("The packaged runtime manifest is unavailable: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err("The packaged runtime manifest must be a bounded regular file.".into());
    }
    let bytes = fs::read(&manifest_path)
        .map_err(|error| format!("Could not read the packaged runtime manifest: {error}"))?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected_manifest_sha256 {
        return Err("The packaged runtime manifest does not match the compiled SHA-256.".into());
    }
    let manifest: RuntimeManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("The packaged runtime manifest is invalid: {error}"))?;
    if manifest.schema_version != 1 || manifest.platform != std::env::consts::OS {
        return Err("The packaged runtime manifest targets a different platform.".into());
    }
    if manifest.files.is_empty() || manifest.commands.is_empty() {
        return Err("The packaged runtime manifest is incomplete.".into());
    }

    let mut declared = HashSet::new();
    for file in &manifest.files {
        if !valid_relative_path(&file.path) || !valid_sha256(&file.sha256) || file.size == 0 {
            return Err("The packaged runtime manifest contains an invalid file identity.".into());
        }
        if !declared.insert(file.path.clone()) {
            return Err("The packaged runtime manifest contains a duplicate path.".into());
        }
        let path = root.join(&file.path);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| format!("A packaged runtime file is missing: {}.", file.path))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != file.size {
            return Err(format!(
                "A packaged runtime file has changed: {}.",
                file.path
            ));
        }
        let observed = fs::read(&path)
            .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
            .map_err(|error| format!("Could not verify {}: {error}", file.path))?;
        if observed != file.sha256 {
            return Err(format!(
                "A packaged runtime file has changed: {}.",
                file.path
            ));
        }
    }

    let mut commands = HashMap::new();
    for (name, relative) in manifest.commands {
        if name.is_empty()
            || Path::new(&name).components().count() != 1
            || !declared.contains(&relative)
        {
            return Err("The packaged runtime command map is invalid.".into());
        }
        commands.insert(name, root.join(relative));
    }
    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, String) {
        let root = std::env::temp_dir().join(format!(
            "opemos-runtime-bundle-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("bin")).unwrap();
        let tool = b"bounded tool fixture";
        fs::write(root.join("bin/tool"), tool).unwrap();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "platform": std::env::consts::OS,
            "commands": {"tool": "bin/tool"},
            "files": [{
                "path": "bin/tool",
                "sha256": format!("{:x}", Sha256::digest(tool)),
                "size": tool.len()
            }]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(root.join(MANIFEST_NAME), &bytes).unwrap();
        let hash = format!("{:x}", Sha256::digest(&bytes));
        (root, hash)
    }

    #[test]
    fn verified_runtime_is_hash_bound() {
        let (root, hash) = fixture();
        let commands = verify_runtime_bundle(&root, &hash).unwrap();
        assert_eq!(commands["tool"], root.join("bin/tool"));
        fs::write(root.join("bin/tool"), b"changed tool fixture").unwrap();
        assert!(verify_runtime_bundle(&root, &hash).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_manifest_refuses_wrong_platform() {
        let (root, _) = fixture();
        let manifest_path = root.join(MANIFEST_NAME);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["platform"] = serde_json::json!("unsupported");
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(&manifest_path, &bytes).unwrap();
        let hash = format!("{:x}", Sha256::digest(&bytes));
        assert!(verify_runtime_bundle(&root, &hash).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
