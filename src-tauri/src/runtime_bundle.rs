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
    components: Vec<RuntimeComponent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeFile {
    path: String,
    sha256: String,
    size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeComponent {
    name: String,
    version: String,
    license_files: Vec<String>,
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

    if manifest.components.is_empty() {
        return Err("The packaged runtime component inventory is empty.".into());
    }
    let mut component_names = HashSet::new();
    for component in &manifest.components {
        if component.name.is_empty()
            || component.name.len() > 128
            || component.version.is_empty()
            || component.version.len() > 128
            || component.license_files.is_empty()
            || !component_names.insert(component.name.as_str())
            || component
                .license_files
                .iter()
                .any(|path| !declared.contains(path))
        {
            return Err("The packaged runtime component or license identity is invalid.".into());
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
    use std::process::Command;

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
            }],
            "components": [{
                "name": "fixture-tool",
                "version": "1.0",
                "license_files": ["licenses/fixture.txt"]
            }]
        });
        fs::create_dir_all(root.join("licenses")).unwrap();
        let license = b"fixture license";
        fs::write(root.join("licenses/fixture.txt"), license).unwrap();
        let mut manifest = manifest;
        manifest["files"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "path": "licenses/fixture.txt",
                "sha256": format!("{:x}", Sha256::digest(license)),
                "size": license.len()
            }));
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

    #[test]
    fn runtime_manifest_refuses_missing_or_undeclared_component_license() {
        let (root, _) = fixture();
        let manifest_path = root.join(MANIFEST_NAME);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["components"][0]["license_files"] = serde_json::json!([]);
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(&manifest_path, &bytes).unwrap();
        let hash = format!("{:x}", Sha256::digest(&bytes));
        assert!(verify_runtime_bundle(&root, &hash).is_err());
        manifest["components"][0]["license_files"] = serde_json::json!(["licenses/missing.txt"]);
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(&manifest_path, &bytes).unwrap();
        let hash = format!("{:x}", Sha256::digest(&bytes));
        assert!(verify_runtime_bundle(&root, &hash).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staged_manifest_activates_compiled_consumer() {
        let temporary = std::env::temp_dir().join(format!(
            "opemos-runtime-stage-consumer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let runtime = temporary.join("runtime");
        fs::create_dir_all(runtime.join("bin")).unwrap();
        fs::create_dir_all(runtime.join("licenses")).unwrap();
        let required: &[&str] = if cfg!(target_os = "windows") {
            &[
                "bash",
                "gh",
                "git",
                "mkisofs",
                "python",
                "qemu-img",
                "qemu-system-x86_64",
                "scp",
                "ssh",
                "ssh-keygen",
                "tar",
            ]
        } else if cfg!(target_os = "macos") {
            &[
                "bash",
                "gh",
                "git",
                "python3",
                "qemu-img",
                "qemu-system-aarch64",
                "scp",
                "ssh",
                "ssh-keygen",
                "tar",
            ]
        } else {
            &[
                "bash",
                "genisoimage",
                "gh",
                "git",
                "python3",
                "qemu-img",
                "qemu-system-x86_64",
                "scp",
                "ssh",
                "ssh-keygen",
                "tar",
            ]
        };
        let mut commands = serde_json::Map::new();
        let mut files = Vec::new();
        for name in required {
            let relative = format!("bin/{name}");
            let contents = format!("fixture {name}\n");
            fs::write(runtime.join(&relative), &contents).unwrap();
            commands.insert((*name).into(), serde_json::json!(relative));
            files.push(serde_json::json!({
                "path": relative,
                "sha256": format!("{:x}", Sha256::digest(contents.as_bytes())),
                "size": contents.len()
            }));
        }
        let license = b"fixture license\n";
        fs::write(runtime.join("licenses/fixture.txt"), license).unwrap();
        files.push(serde_json::json!({
            "path": "licenses/fixture.txt",
            "sha256": format!("{:x}", Sha256::digest(license)),
            "size": license.len()
        }));
        let manifest = serde_json::json!({
            "schema_version": 1,
            "platform": std::env::consts::OS,
            "commands": commands,
            "files": files,
            "components": [{
                "name": "fixture-runtime",
                "version": "1.0",
                "license_files": ["licenses/fixture.txt"]
            }]
        });
        fs::write(
            runtime.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let application = temporary.join("application.bin");
        fs::write(&application, b"application fixture").unwrap();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let python = if cfg!(target_os = "windows") {
            "python"
        } else {
            "python3"
        };
        let output = Command::new(python)
            .arg(repository.join("scripts/stage_runtime_bundle.py"))
            .args(["--platform", std::env::consts::OS])
            .arg("--runtime-root")
            .arg(&runtime)
            .arg("--output")
            .arg(temporary.join("output"))
            .args([
                "--source-commit",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ])
            .arg("--application")
            .arg(&application)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let hash = String::from_utf8(output.stdout).unwrap();
        let staged = temporary.join("output/runtime");
        let verified = verify_runtime_bundle(&staged, hash.trim()).unwrap();
        assert_eq!(verified.len(), required.len());
        assert!(verified.values().all(|path| path.starts_with(&staged)));
        fs::remove_dir_all(temporary).unwrap();
    }
}
