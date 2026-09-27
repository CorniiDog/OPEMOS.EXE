use super::require_maintainer_authorization;
use tauri::window::{Color, Effect, EffectState, EffectsBuilder};
use tauri::Manager;
use tauri_plugin_opener::OpenerExt;

const VALVE_STEAMOS_DOWNLOAD_URL: &str =
    "https://store.steampowered.com/steamos/download/?ver=steamdeck";

fn glass_window_effects() -> tauri::utils::config::WindowEffectsConfig {
    EffectsBuilder::new()
        .effects([Effect::UnderWindowBackground, Effect::Acrylic])
        .state(EffectState::FollowsWindowActiveState)
        .radius(10.0)
        .color(Color(11, 17, 24, 220))
        .build()
}

fn center_over_parent(
    child: &tauri::WebviewWindow,
    parent: &tauri::WebviewWindow,
) -> Result<(), String> {
    let parent_position = parent
        .outer_position()
        .map_err(|error| format!("Could not read the main window position: {error}"))?;
    let parent_size = parent
        .outer_size()
        .map_err(|error| format!("Could not read the main window size: {error}"))?;
    let child_size = child
        .outer_size()
        .map_err(|error| format!("Could not read the companion window size: {error}"))?;
    let x = i64::from(parent_position.x)
        + (i64::from(parent_size.width) - i64::from(child_size.width)) / 2;
    let y = i64::from(parent_position.y)
        + (i64::from(parent_size.height) - i64::from(child_size.height)) / 2;
    child
        .set_position(tauri::PhysicalPosition::new(x as i32, y as i32))
        .map_err(|error| format!("Could not center the companion window: {error}"))
}

#[tauri::command]
pub(crate) fn open_valve_download_page(app: tauri::AppHandle) -> Result<(), String> {
    app.opener()
        .open_url(VALVE_STEAMOS_DOWNLOAD_URL, None::<&str>)
        .map_err(|error| format!("Could not open Valve's SteamOS download page: {error}"))
}

#[tauri::command]
pub(crate) async fn open_progress_window(app: tauri::AppHandle) -> Result<(), String> {
    let main = app
        .get_webview_window("main")
        .ok_or("The main application window is unavailable.")?;
    if let Some(progress) = app.get_webview_window("build-progress") {
        center_over_parent(&progress, &main)?;
        progress
            .show()
            .map_err(|error| format!("Could not show the build progress window: {error}"))?;
        progress
            .set_focus()
            .map_err(|error| format!("Could not focus the build progress window: {error}"))?;
        return Ok(());
    }
    let progress_builder = tauri::WebviewWindowBuilder::new(
        &app,
        "build-progress",
        tauri::WebviewUrl::App("build.html".into()),
    )
    .title("SteamOS NVIDIA Builder — Progress")
    .inner_size(680.0, 680.0)
    .min_inner_size(680.0, 680.0)
    .resizable(true)
    .theme(Some(tauri::Theme::Dark))
    .transparent(false)
    .background_color(Color(11, 17, 24, 255))
    .shadow(true)
    .visible(false);
    #[cfg(target_os = "macos")]
    let progress_builder = progress_builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true);
    let progress = progress_builder
        .parent(&main)
        .map_err(|error| format!("Could not couple the build progress window: {error}"))?
        .build()
        .map_err(|error| format!("Could not create the build progress window: {error}"))?;
    center_over_parent(&progress, &main)?;
    progress
        .show()
        .map_err(|error| format!("Could not show the build progress window: {error}"))?;
    progress
        .set_focus()
        .map_err(|error| format!("Could not focus the build progress window: {error}"))
}

#[tauri::command]
pub(crate) fn hide_progress_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(progress) = app.get_webview_window("build-progress") {
        progress
            .hide()
            .map_err(|error| format!("Could not hide the build progress window: {error}"))?;
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn open_maintainer_window(app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(require_maintainer_authorization)
        .await
        .map_err(|error| format!("Maintainer permission worker failed: {error}"))??;
    if let Some(window) = app.get_webview_window("maintainer-workspace") {
        let main = app
            .get_webview_window("main")
            .ok_or("The main application window is unavailable.")?;
        center_over_parent(&window, &main)?;
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
    let window_builder = tauri::WebviewWindowBuilder::new(
        &app,
        "maintainer-workspace",
        tauri::WebviewUrl::App("maintainer.html".into()),
    )
    .title("SteamOS NVIDIA Builder — Maintainer Workspace")
    .inner_size(900.0, 720.0)
    .min_inner_size(820.0, 640.0)
    .resizable(true)
    .theme(Some(tauri::Theme::Dark))
    .transparent(true)
    .background_color(Color(11, 17, 24, 0))
    .effects(glass_window_effects())
    .shadow(false)
    .visible(false);
    #[cfg(target_os = "macos")]
    let window_builder = window_builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true);
    let window = window_builder
        .parent(&main)
        .map_err(|error| format!("Could not couple the maintainer window: {error}"))?
        .build()
        .map_err(|error| format!("Could not create the maintainer window: {error}"))?;
    center_over_parent(&window, &main)?;
    window
        .show()
        .map_err(|error| format!("Could not show the maintainer window: {error}"))?;
    window
        .set_focus()
        .map_err(|error| format!("Could not focus the maintainer window: {error}"))
}
