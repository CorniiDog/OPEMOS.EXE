use super::*;

const CACHE_SCHEMA: u32 = 1;
const CACHE_MANIFEST: &str = "cache-manifest.json";
const CACHE_COMPLETE: &str = "population-complete";
const REQUIRED_DIRECTORIES: [&str; 2] = ["maintainer-release-import", "maintainer-worktrees"];
static PORTABLE_STATE_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
static PORTABLE_CACHE_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CacheManifest {
    schema_version: u32,
    package_version: String,
    source_commit: String,
    executable_sha256: String,
    executable_size: u64,
    runtime_manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleProvenance {
    schema_version: u32,
    platform: String,
    source_commit: String,
    runtime_manifest_sha256: String,
    applications: Vec<BundleApplication>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleApplication {
    filename: String,
    size: u64,
    sha256: String,
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Could not open portable-state identity file: {error}"))?;
    let mut digest = Sha256::new();
    let mut block = [0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut block)
            .map_err(|error| format!("Could not read portable-state identity file: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&block[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn expected_manifest(executable: &Path, runtime: &Path) -> Result<CacheManifest, String> {
    let executable_metadata = fs::symlink_metadata(executable)
        .map_err(|error| format!("Could not inspect the packaged executable: {error}"))?;
    if !executable_metadata.is_file() || executable_metadata.file_type().is_symlink() {
        return Err("The packaged executable must be a regular file.".into());
    }
    let runtime_manifest = runtime.join("runtime-manifest.json");
    let runtime_metadata = fs::symlink_metadata(&runtime_manifest)
        .map_err(|error| format!("Could not inspect the packaged runtime manifest: {error}"))?;
    if !runtime_metadata.is_file()
        || runtime_metadata.file_type().is_symlink()
        || runtime_metadata.len() > 1024 * 1024
    {
        return Err("The packaged runtime manifest must be a bounded regular file.".into());
    }
    let executable_sha256 = sha256_file(executable)?;
    let runtime_manifest_sha256 = sha256_file(&runtime_manifest)?;
    let provenance_path = executable
        .parent()
        .ok_or("The packaged executable has no bundle directory.")?
        .join("bundle-provenance.json");
    let provenance_metadata = fs::symlink_metadata(&provenance_path)
        .map_err(|error| format!("Could not inspect packaged build provenance: {error}"))?;
    if !provenance_metadata.is_file()
        || provenance_metadata.file_type().is_symlink()
        || provenance_metadata.len() > 1024 * 1024
    {
        return Err("Packaged build provenance must be a bounded regular file.".into());
    }
    let provenance: BundleProvenance = serde_json::from_slice(
        &fs::read(&provenance_path)
            .map_err(|error| format!("Could not read packaged build provenance: {error}"))?,
    )
    .map_err(|error| format!("Packaged build provenance is invalid: {error}"))?;
    let filename = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("The packaged executable filename is invalid.")?;
    if provenance.schema_version != 1
        || provenance.platform != std::env::consts::OS
        || provenance.source_commit.len() != 40
        || !provenance
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || provenance.runtime_manifest_sha256 != runtime_manifest_sha256
        || provenance.applications.len() != 1
        || provenance.applications[0].filename != filename
        || provenance.applications[0].size != executable_metadata.len()
        || provenance.applications[0].sha256 != executable_sha256
    {
        return Err("Packaged build provenance does not match the executable and runtime.".into());
    }
    Ok(CacheManifest {
        schema_version: CACHE_SCHEMA,
        package_version: env!("CARGO_PKG_VERSION").into(),
        source_commit: provenance.source_commit,
        executable_sha256,
        executable_size: executable_metadata.len(),
        runtime_manifest_sha256,
    })
}

fn real_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

fn cache_is_valid(root: &Path, expected: &CacheManifest) -> bool {
    if !real_directory(root) {
        return false;
    }
    let manifest = root.join(CACHE_MANIFEST);
    let marker = root.join(CACHE_COMPLETE);
    let manifest_metadata = match fs::symlink_metadata(&manifest) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 16 * 1024 =>
        {
            metadata
        }
        _ => return false,
    };
    let _ = manifest_metadata;
    let observed = fs::read(&manifest)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CacheManifest>(&bytes).ok());
    let marker_valid = fs::symlink_metadata(&marker).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() == b"complete\n".len() as u64
    }) && fs::read(&marker).ok().as_deref() == Some(b"complete\n");
    let expected_entries = REQUIRED_DIRECTORIES
        .iter()
        .copied()
        .chain([CACHE_MANIFEST, CACHE_COMPLETE])
        .collect::<HashSet<_>>();
    let observed_entries = match fs::read_dir(root) {
        Ok(entries) => entries
            .map(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
            })
            .collect::<Option<HashSet<_>>>(),
        Err(_) => None,
    };
    observed.as_ref() == Some(expected)
        && marker_valid
        && observed_entries.as_ref().is_some_and(|entries| {
            entries.len() == expected_entries.len()
                && entries
                    .iter()
                    .all(|entry| expected_entries.contains(entry.as_str()))
        })
        && REQUIRED_DIRECTORIES
            .iter()
            .all(|directory| real_directory(&root.join(directory)))
}

fn populate_cache(root: &Path, expected: &CacheManifest) -> Result<(), String> {
    let parent = root
        .parent()
        .ok_or("Portable cache root has no parent directory.")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create the portable state root: {error}"))?;
    if !real_directory(parent) {
        return Err("The portable state root must be a real directory.".into());
    }
    let staging = parent.join(format!(".cache-populating-{}", std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .map_err(|error| format!("Could not remove incomplete portable cache: {error}"))?;
    }
    fs::create_dir(&staging)
        .map_err(|error| format!("Could not stage the portable cache: {error}"))?;
    let staged = (|| {
        for directory in REQUIRED_DIRECTORIES {
            fs::create_dir(staging.join(directory))
                .map_err(|error| format!("Could not stage portable cache directory: {error}"))?;
        }
        let manifest = serde_json::to_vec(expected)
            .map_err(|error| format!("Could not encode portable cache identity: {error}"))?;
        fs::write(staging.join(CACHE_MANIFEST), manifest)
            .map_err(|error| format!("Could not write portable cache identity: {error}"))?;
        fs::write(staging.join(CACHE_COMPLETE), b"complete\n")
            .map_err(|error| format!("Could not complete portable cache population: {error}"))?;
        Ok::<_, String>(())
    })();
    if let Err(error) = staged {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    let previous = parent.join(format!(".cache-replaced-{}", std::process::id()));
    if previous.exists() {
        fs::remove_dir_all(&previous)
            .map_err(|error| format!("Could not remove stale portable cache backup: {error}"))?;
    }
    if root.exists() {
        fs::rename(root, &previous)
            .map_err(|error| format!("Could not quarantine the stale portable cache: {error}"))?;
    }
    if let Err(error) = fs::rename(&staging, root) {
        if previous.exists() {
            let _ = fs::rename(&previous, root);
        }
        return Err(format!("Could not activate the portable cache: {error}"));
    }
    if previous.exists() {
        fs::remove_dir_all(&previous)
            .map_err(|error| format!("Could not remove the replaced portable cache: {error}"))?;
    }
    Ok(())
}

fn prepare_at(executable: &Path) -> Result<(PathBuf, PathBuf), String> {
    let bundle = executable
        .parent()
        .ok_or("The packaged executable has no bundle directory.")?;
    let runtime = bundle.join("runtime");
    let state = bundle.join("state");
    let cache = state.join("cache-v1");
    let expected = expected_manifest(executable, &runtime)?;
    if !cache_is_valid(&cache, &expected) {
        populate_cache(&cache, &expected)?;
    }
    let settings = state.join("settings");
    fs::create_dir_all(&settings)
        .map_err(|error| format!("Could not create portable settings state: {error}"))?;
    let webview = state.join("webview-v1");
    fs::create_dir_all(&webview)
        .map_err(|error| format!("Could not create portable WebView state: {error}"))?;
    if !real_directory(&settings) || !real_directory(&webview) {
        return Err("Portable application state must use real directories.".into());
    }
    Ok((state, cache))
}

#[cfg(any(target_os = "windows", test))]
fn webview_data_path(state: &Path) -> PathBuf {
    state.join("webview-v1")
}

pub fn prepare_portable_state() -> Result<(), String> {
    if !bundled_runtime_required() {
        return Ok(());
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("Could not locate the packaged executable: {error}"))?;
    let (state, cache) = prepare_at(&executable)?;
    #[cfg(target_os = "windows")]
    std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", webview_data_path(&state));
    PORTABLE_STATE_ROOT
        .set(state)
        .map_err(|_| "Portable state was initialized more than once.".to_string())?;
    PORTABLE_CACHE_ROOT
        .set(cache)
        .map_err(|_| "Portable cache was initialized more than once.".to_string())?;
    Ok(())
}

pub(crate) fn portable_cache_root() -> Option<&'static PathBuf> {
    PORTABLE_CACHE_ROOT.get()
}

pub(crate) fn portable_settings_path() -> Option<PathBuf> {
    PORTABLE_STATE_ROOT.get().map(|root| root.join("settings"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "opemos-portable-state-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("runtime")).unwrap();
        let runtime = b"runtime-v1";
        fs::write(root.join("runtime/runtime-manifest.json"), runtime).unwrap();
        let executable = root.join("OPEMOS.EXE");
        let bytes = b"executable-v1";
        fs::write(&executable, bytes).unwrap();
        fs::write(
            root.join("bundle-provenance.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "platform": std::env::consts::OS,
                "source_commit": "0123456789abcdef0123456789abcdef01234567",
                "runtime_manifest_sha256": format!("{:x}", Sha256::digest(runtime)),
                "applications": [{
                    "filename": "OPEMOS.EXE",
                    "size": bytes.len(),
                    "sha256": format!("{:x}", Sha256::digest(bytes))
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        (root, executable)
    }

    fn update_provenance(root: &Path, executable: &Path) {
        let bytes = fs::read(executable).unwrap();
        fs::write(
            root.join("bundle-provenance.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "platform": std::env::consts::OS,
                "source_commit": "fedcba9876543210fedcba9876543210fedcba98",
                "runtime_manifest_sha256": format!("{:x}", Sha256::digest(b"runtime-v1")),
                "applications": [{
                    "filename": "OPEMOS.EXE",
                    "size": bytes.len(),
                    "sha256": format!("{:x}", Sha256::digest(&bytes))
                }]
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn first_launch_and_same_version_reuse_are_deterministic() {
        let (root, executable) = fixture("reuse");
        let (_, cache) = prepare_at(&executable).unwrap();
        fs::write(cache.join("maintainer-worktrees/kept"), b"same-version").unwrap();
        prepare_at(&executable).unwrap();
        assert_eq!(
            fs::read(cache.join("maintainer-worktrees/kept")).unwrap(),
            b"same-version"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn changed_executable_repopulates_without_removing_settings() {
        let (root, executable) = fixture("version-change");
        let (state, cache) = prepare_at(&executable).unwrap();
        fs::write(state.join("settings/settings.json"), b"preserved").unwrap();
        fs::write(cache.join("maintainer-worktrees/stale"), b"stale").unwrap();
        fs::write(&executable, b"executable-v2").unwrap();
        update_provenance(&root, &executable);
        let (_, cache) = prepare_at(&executable).unwrap();
        assert!(!cache.join("maintainer-worktrees/stale").exists());
        assert_eq!(
            fs::read(state.join("settings/settings.json")).unwrap(),
            b"preserved"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incomplete_and_same_version_corrupt_cache_repopulate() {
        let (root, executable) = fixture("recovery");
        let (_, cache) = prepare_at(&executable).unwrap();
        fs::remove_file(cache.join(CACHE_COMPLETE)).unwrap();
        fs::write(cache.join("maintainer-worktrees/incomplete"), b"stale").unwrap();
        prepare_at(&executable).unwrap();
        assert!(!cache.join("maintainer-worktrees/incomplete").exists());
        fs::write(cache.join(CACHE_MANIFEST), b"corrupt").unwrap();
        fs::write(cache.join("maintainer-worktrees/corrupt"), b"stale").unwrap();
        prepare_at(&executable).unwrap();
        assert!(!cache.join("maintainer-worktrees/corrupt").exists());
        fs::write(cache.join("unexpected"), b"not closed").unwrap();
        prepare_at(&executable).unwrap();
        assert!(!cache.join("unexpected").exists());
        assert!(cache_is_valid(
            &cache,
            &expected_manifest(&executable, &root.join("runtime")).unwrap()
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn all_packaged_state_paths_are_beneath_the_bundle_state_root() {
        let (root, executable) = fixture("placement");
        let (state, cache) = prepare_at(&executable).unwrap();
        assert_eq!(state, root.join("state"));
        assert!(cache.starts_with(&state));
        assert!(state.join("settings").starts_with(&state));
        assert_eq!(webview_data_path(&state), state.join("webview-v1"));
        assert!(webview_data_path(&state).starts_with(&state));
        fs::remove_dir_all(root).unwrap();
    }
}
