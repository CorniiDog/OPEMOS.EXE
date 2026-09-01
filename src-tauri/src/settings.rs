use super::*;

static SETTINGS_WRITE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SETTINGS_TRANSACTION_LOCK: Mutex<()> = Mutex::new(());
const SETTINGS_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const SETTINGS_LOCK_RETRY: Duration = Duration::from_millis(20);
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

pub(crate) fn settings_transaction_lock() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    Ok(SETTINGS_TRANSACTION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
}

pub(crate) struct SettingsFileLock {
    file: File,
}

impl Drop for SettingsFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn validate_settings_parent(path: &Path) -> Result<&Path, String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or("Settings path has no parent directory.")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create the settings directory: {error}"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("Could not inspect the settings directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("The settings directory must be a real directory, not a link.".into());
    }
    Ok(parent)
}

pub(crate) fn acquire_settings_file_lock(
    path: &Path,
    timeout: Duration,
) -> Result<SettingsFileLock, String> {
    let parent = validate_settings_parent(path)?;
    let lock_path = parent.join(".settings.json.lock");
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("The settings lock must be a regular file, not a link.".into());
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(&lock_path)
        .map_err(|error| format!("Could not open the settings transaction lock: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Could not inspect the settings transaction lock: {error}"))?;
    if !metadata.is_file() {
        return Err("The settings transaction lock is not a regular file.".into());
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    format!("Could not secure the settings transaction lock: {error}")
                })?;
        }
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("The settings lock deadline overflowed.")?;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(SettingsFileLock { file }),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(SETTINGS_LOCK_RETRY);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err("Timed out waiting for another application process to finish updating settings.".into());
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(format!("Could not lock the settings transaction: {error}"));
            }
        }
    }
}

pub(crate) fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("settings.json"))
        .map_err(|error| format!("Could not determine the settings directory: {error}"))
}

pub(crate) fn load_builder_settings(app: &tauri::AppHandle) -> Result<BuilderSettings, String> {
    let _guard = settings_transaction_lock()?;
    let path = settings_path(app)?;
    let _file_guard = acquire_settings_file_lock(&path, SETTINGS_LOCK_TIMEOUT)?;
    load_builder_settings_path_unlocked(&path)
}

fn load_builder_settings_unlocked(app: &tauri::AppHandle) -> Result<BuilderSettings, String> {
    let path = settings_path(app)?;
    load_builder_settings_path_unlocked(&path)
}

pub(crate) fn load_builder_settings_path_unlocked(path: &Path) -> Result<BuilderSettings, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(BuilderSettings::default())
        }
        Err(error) => return Err(format!("Could not inspect settings.json: {error}")),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SETTINGS_BYTES
    {
        return Err("settings.json must be a nonempty bounded regular file, not a link.".into());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err("settings.json permissions must be 0600.".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|error| format!("Could not open settings.json: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("Could not inspect opened settings.json: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.dev() != opened.dev()
            || metadata.ino() != opened.ino()
            || metadata.mode() != opened.mode()
            || metadata.len() != opened.len()
        {
            return Err("settings.json changed while it was being opened.".into());
        }
    }
    #[cfg(not(unix))]
    if metadata.len() != opened.len() || !opened.is_file() {
        return Err("settings.json changed while it was being opened.".into());
    }
    let mut settings: BuilderSettings = serde_json::from_reader(file)
        .map_err(|error| format!("settings.json is invalid: {error}"))?;
    if matches!(settings.schema_version, 1 | 2) {
        if settings.schema_version == 1 {
            settings.include_upstream_nvidia_releases = false;
        }
        settings.schema_version = BUILDER_SETTINGS_SCHEMA;
        settings.omit_optional_cuda = false;
        save_builder_settings_path_unlocked(path, &settings)?;
    } else if settings.schema_version != BUILDER_SETTINGS_SCHEMA {
        return Err(format!(
            "Unsupported settings schema {}; expected {}.",
            settings.schema_version, BUILDER_SETTINGS_SCHEMA
        ));
    }
    Ok(settings)
}

#[cfg(test)]
pub(crate) fn save_builder_settings_path(
    path: &Path,
    settings: &BuilderSettings,
) -> Result<(), String> {
    let _guard = settings_transaction_lock()?;
    let _file_guard = acquire_settings_file_lock(path, SETTINGS_LOCK_TIMEOUT)?;
    save_builder_settings_path_unlocked(path, settings)
}

pub(crate) fn save_builder_settings_path_unlocked(
    path: &Path,
    settings: &BuilderSettings,
) -> Result<(), String> {
    if settings.schema_version != BUILDER_SETTINGS_SCHEMA {
        return Err(format!(
            "Only settings schema {BUILDER_SETTINGS_SCHEMA} can be saved."
        ));
    }
    let parent = validate_settings_parent(path)?;
    let sequence = SETTINGS_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".settings.json.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|error| format!("Could not serialize settings: {error}"))?;
    let staged = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("Could not stage settings.json: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("Could not write settings.json: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Could not sync settings.json: {error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("Could not finalize settings.json: {error}"))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("Could not sync the settings directory: {error}"))
    })();
    if staged.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    staged
}

pub(crate) fn github_maintainer_status() -> Result<GithubMaintainerStatus, String> {
    let Some(gh) = find_binary("gh") else {
        return Ok(GithubMaintainerStatus {
            gh_available: false,
            authenticated: false,
            authorized: false,
            username: None,
            permission: None,
            message: "GitHub CLI is not available. The packaged application must bundle it before maintainer publishing can be enabled.".into(),
        });
    };
    let auth = Command::new(&gh)
        .args(["auth", "status", "--hostname", "github.com"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("Could not check GitHub authentication: {error}"))?;
    if !auth.success() {
        return Ok(GithubMaintainerStatus {
            gh_available: true,
            authenticated: false,
            authorized: false,
            username: None,
            permission: None,
            message:
                "GitHub is not connected. Use browser login to authorize the maintainer workflow."
                    .into(),
        });
    }
    let user_output = Command::new(&gh)
        .args(["api", "user", "--jq", ".login"])
        .output()
        .map_err(|error| format!("Could not query the authenticated GitHub account: {error}"))?;
    if !user_output.status.success() {
        return Err(
            "GitHub authentication succeeded, but the account identity could not be verified."
                .into(),
        );
    }
    let username = String::from_utf8(user_output.stdout)
        .map_err(|_| "GitHub returned a non-UTF-8 account name.".to_string())?
        .trim()
        .to_string();
    if username.is_empty()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("GitHub returned an invalid account name.".into());
    }
    let permission = github_repository_permission(&gh, &username, NVIDIA_SUPPORT_REPOSITORY)?;
    let authorized = permission
        .as_deref()
        .is_some_and(github_permission_can_publish);
    Ok(GithubMaintainerStatus {
        gh_available: true,
        authenticated: true,
        authorized,
        username: Some(username.clone()),
        permission: permission.clone(),
        message: if authorized {
            format!("Connected as {username}; release permission verified.")
        } else {
            format!(
                "Connected as {username}, but release permission for {NVIDIA_SUPPORT_REPOSITORY} was not verified."
            )
        },
    })
}

pub(crate) fn parse_github_repository_permission(response: &[u8]) -> Result<String, String> {
    let permission: GithubRepositoryPermission = serde_json::from_slice(response)
        .map_err(|error| format!("GitHub returned an invalid permission response: {error}"))?;
    let permission = permission.permission.trim();
    if permission.is_empty()
        || !permission
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err("GitHub returned an invalid repository permission.".into());
    }
    Ok(permission.to_string())
}

pub(crate) fn github_repository_permission(
    gh: &Path,
    username: &str,
    repository: &str,
) -> Result<Option<String>, String> {
    if username.is_empty()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !matches!(
            repository,
            NVIDIA_SUPPORT_REPOSITORY | NVIDIA_SOURCE_REPOSITORY | GAMESCOPE_SOURCE_REPOSITORY
        )
    {
        return Err("Refusing to query permission for an unapproved repository identity.".into());
    }
    let endpoint = format!("repos/{repository}/collaborators/{username}/permission");
    let output = Command::new(gh)
        .args(["api", &endpoint])
        .output()
        .map_err(|error| format!("Could not verify {repository} permission: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    parse_github_repository_permission(&output.stdout).map(Some)
}

pub(crate) fn github_permission_can_publish(permission: &str) -> bool {
    matches!(permission, "admin" | "maintain" | "write" | "push")
}

#[tauri::command]
pub(crate) fn get_builder_settings(app: tauri::AppHandle) -> Result<BuilderSettings, String> {
    load_builder_settings(&app)
}

#[tauri::command]
pub(crate) async fn update_builder_settings(
    app: tauri::AppHandle,
    settings: BuilderSettings,
) -> Result<BuilderSettings, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = settings_transaction_lock()?;
        let path = settings_path(&app)?;
        let _file_guard = acquire_settings_file_lock(&path, SETTINGS_LOCK_TIMEOUT)?;
        let current = load_builder_settings_unlocked(&app)?;
        let mut settings = settings;
        settings.schema_version = BUILDER_SETTINGS_SCHEMA;
        if settings.omit_optional_cuda {
            return Err(
                "Optional CUDA omission is unavailable until the pinned support repository provides a reviewed gaming payload profile."
                    .into(),
            );
        }
        let enabling_auto_release =
            settings.auto_release_verified_nvidia && !current.auto_release_verified_nvidia;
        if enabling_auto_release && !github_maintainer_status()?.authorized {
            return Err(
                "Auto-release cannot be enabled until GitHub maintainer permission is verified."
                    .into(),
            );
        }
        save_builder_settings_path_unlocked(&path, &settings)?;
        Ok(settings)
    })
    .await
    .map_err(|error| format!("Settings worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn get_github_maintainer_status() -> Result<GithubMaintainerStatus, String> {
    tauri::async_runtime::spawn_blocking(github_maintainer_status)
        .await
        .map_err(|error| format!("GitHub authorization worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn connect_github_maintainer() -> Result<GithubMaintainerStatus, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let gh = find_binary("gh").ok_or(
            "GitHub CLI is not available. Install it for development; release packages will bundle it.",
        )?;

        #[cfg(target_os = "macos")]
        {
            let quoted_gh = format!("'{}'", gh.to_string_lossy().replace('\'', "'\\''"));
            let terminal_command = format!(
                "{quoted_gh} auth login --hostname github.com --git-protocol https --web --clipboard --skip-ssh-key"
            );
            let apple_script = r#"on run argv
tell application "Terminal"
    activate
    do script (item 1 of argv)
end tell
end run"#;
            let status = Command::new("/usr/bin/osascript")
                .args(["-e", apple_script, "--", &terminal_command])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .status()
                .map_err(|error| format!("Could not open GitHub login in Terminal: {error}"))?;
            if !status.success() {
                return Err("Could not open a visible GitHub login in Terminal.".into());
            }
            Ok(GithubMaintainerStatus {
                gh_available: true,
                authenticated: false,
                authorized: false,
                username: None,
                permission: None,
                message: "GitHub login opened in Terminal. Complete the browser authorization; this panel will detect it automatically.".into(),
            })
        }

        #[cfg(not(target_os = "macos"))]
        Err("Visible GitHub login is currently implemented only for the macOS development application.".into())
    })
    .await
    .map_err(|error| format!("GitHub login worker failed: {error}"))?
}
