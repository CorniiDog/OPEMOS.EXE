use super::require_maintainer_authorization;
use tauri::utils::config::Color;
use tauri::Manager;

#[tauri::command]
pub(crate) fn open_progress_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(progress) = app.get_webview_window("build-progress") {
        progress
            .show()
            .map_err(|error| format!("Could not show the build progress window: {error}"))?;
        progress
            .set_focus()
            .map_err(|error| format!("Could not focus the build progress window: {error}"))?;
        return Ok(());
    }
    let main = app
        .get_webview_window("main")
        .ok_or("The main application window is unavailable.")?;
    let progress = tauri::WebviewWindowBuilder::new(
        &app,
        "build-progress",
        tauri::WebviewUrl::App("build.html".into()),
    )
    .title("SteamOS NVIDIA Builder — Progress")
    .inner_size(680.0, 680.0)
    .min_inner_size(680.0, 680.0)
    .resizable(true)
    .theme(Some(tauri::Theme::Dark))
    .background_color(Color(23, 26, 33, 255))
    .visible(false)
    .parent(&main)
    .map_err(|error| format!("Could not couple the build progress window: {error}"))?
    .build()
    .map_err(|error| format!("Could not create the build progress window: {error}"))?;
    progress
        .show()
        .map_err(|error| format!("Could not show the build progress window: {error}"))?;
    progress
        .set_focus()
        .map_err(|error| format!("Could not focus the build progress window: {error}"))
}

#[tauri::command]
pub(crate) async fn open_maintainer_window(app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(require_maintainer_authorization)
        .await
        .map_err(|error| format!("Maintainer permission worker failed: {error}"))??;
    if let Some(window) = app.get_webview_window("maintainer-workspace") {
        window
            .show()
            .map_err(|error| format!("Could not show the maintainer window: {error}"))?;
        window
            .set_focus()
            .map_err(|error| format!("Could not focus the maintainer window: {error}"))?;
        return Ok(());
    }
    let main = app
        .get_webview_window("main")
        .ok_or("The main application window is unavailable.")?;
    let window = tauri::WebviewWindowBuilder::new(
        &app,
        "maintainer-workspace",
        tauri::WebviewUrl::App("maintainer.html".into()),
    )
    .title("SteamOS NVIDIA Builder — Maintainer Workspace")
    .inner_size(900.0, 720.0)
    .min_inner_size(820.0, 640.0)
    .resizable(true)
    .theme(Some(tauri::Theme::Dark))
    .background_color(Color(23, 26, 33, 255))
    .visible(false)
    .parent(&main)
    .map_err(|error| format!("Could not couple the maintainer window: {error}"))?
    .build()
    .map_err(|error| format!("Could not create the maintainer window: {error}"))?;
    window
        .show()
        .map_err(|error| format!("Could not show the maintainer window: {error}"))?;
    window
        .set_focus()
        .map_err(|error| format!("Could not focus the maintainer window: {error}"))
}
