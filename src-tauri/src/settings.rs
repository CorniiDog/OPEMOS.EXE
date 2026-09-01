use super::*;

static SETTINGS_WRITE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SETTINGS_TRANSACTION_LOCK: Mutex<()> = Mutex::new(());

fn settings_transaction_lock() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    SETTINGS_TRANSACTION_LOCK
        .lock()
        .map_err(|_| "The settings transaction lock is unavailable.".into())
}

pub(crate) fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("settings.json"))
        .map_err(|error| format!("Could not determine the settings directory: {error}"))
}

pub(crate) fn load_builder_settings(app: &tauri::AppHandle) -> Result<BuilderSettings, String> {
    let _guard = settings_transaction_lock()?;
    load_builder_settings_unlocked(app)
}

fn load_builder_settings_unlocked(app: &tauri::AppHandle) -> Result<BuilderSettings, String> {
    let path = settings_path(app)?;
    if !path.exists() {
        return Ok(BuilderSettings::default());
    }
    let mut settings: BuilderSettings = serde_json::from_reader(
        File::open(&path).map_err(|error| format!("Could not open settings.json: {error}"))?,
    )
    .map_err(|error| format!("settings.json is invalid: {error}"))?;
    if matches!(settings.schema_version, 1 | 2) {
        if settings.schema_version == 1 {
            settings.include_upstream_nvidia_releases = false;
        }
        settings.schema_version = BUILDER_SETTINGS_SCHEMA;
        settings.omit_optional_cuda = false;
        save_builder_settings_path_unlocked(&settings_path(app)?, &settings)?;
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
    save_builder_settings_path_unlocked(path, settings)
}

fn save_builder_settings_path_unlocked(
    path: &Path,
    settings: &BuilderSettings,
) -> Result<(), String> {
    if settings.schema_version != BUILDER_SETTINGS_SCHEMA {
        return Err(format!(
            "Only settings schema {BUILDER_SETTINGS_SCHEMA} can be saved."
        ));
    }
    let parent = path
        .parent()
        .ok_or("Settings path has no parent directory.")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create the settings directory: {error}"))?;
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
        save_builder_settings_path_unlocked(&settings_path(&app)?, &settings)?;
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
