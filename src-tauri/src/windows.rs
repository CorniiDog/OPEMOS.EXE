use super::require_maintainer_authorization;
use tauri::window::{Color, Effect, EffectState, EffectsBuilder};
use tauri::Manager;
use tauri_plugin_opener::OpenerExt;

const VALVE_STEAMOS_DOWNLOAD_URL: &str =
    "https://store.steampowered.com/steamos/download/?ver=steamdeck";

#[cfg(any(target_os = "macos", test))]
#[derive(Debug)]
struct UsableMainLayout {
    width: f64,
    height: f64,
    x: i32,
    y: i32,
}

#[cfg(any(target_os = "macos", test))]
fn usable_main_layout(
    position: (i32, i32),
    size: (u32, u32),
    scale: f64,
) -> Result<UsableMainLayout, String> {
    if !scale.is_finite() || scale <= 0.0 {
        return Err("Invalid native display scale.".into());
    }
    let width = 760.0;
    // Leave native frame/chrome breathing room within the actual work area,
    // not the full display containing the menu bar and Dock.
    let available_width = f64::from(size.0) / scale - 16.0;
    let height = 800.0_f64.min(f64::from(size.1) / scale - 48.0);
    if available_width < width || height < 400.0 {
        return Err("The native usable display area is too small for the builder.".into());
    }
    Ok(UsableMainLayout {
        width,
        height,
        x: position.0 + ((f64::from(size.0) - width * scale) / 2.0) as i32,
        y: position.1 + ((f64::from(size.1) - height * scale) / 2.0) as i32,
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn fit_main_to_usable_display(main: &tauri::WebviewWindow) -> Result<(), String> {
    let monitor = main
        .current_monitor()
        .map_err(|e| e.to_string())?
        .or(main.primary_monitor().map_err(|e| e.to_string())?)
        .ok_or("No native monitor is available for the main window.")?;
    let area = monitor.work_area();
    let layout = usable_main_layout(
        (area.position.x, area.position.y),
        (area.size.width, area.size.height),
        monitor.scale_factor(),
    )?;
    main.set_min_size(Some(tauri::LogicalSize::new(
        layout.width,
        layout.height.min(620.0),
    )))
    .map_err(|e| e.to_string())?;
    main.set_size(tauri::LogicalSize::new(layout.width, layout.height))
        .map_err(|e| e.to_string())?;
    main.set_position(tauri::PhysicalPosition::new(layout.x, layout.y))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod usable_layout_tests {
    use super::*;

    #[test]
    fn main_layout_preserves_actual_work_area_and_scale() {
        // Geometry only; actual native window/scroll/hit cases run in the M1 GUI.
        for (position, size, scale) in [
            ((0, 25), (1024, 680), 1.0),
            ((-2048, 50), (2048, 1360), 2.0),
            ((0, 25), (1920, 1020), 1.0),
        ] {
            let p = usable_main_layout(position, size, scale).unwrap();
            assert_eq!(p.width, 760.0);
            assert!(p.height <= 800.0);
            assert!(p.x >= position.0 && p.y >= position.1);
            assert!(f64::from(p.x - position.0) + p.width * scale <= f64::from(size.0));
            assert!(f64::from(p.y - position.1) + (p.height + 20.0) * scale <= f64::from(size.1));
        }
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(usable_main_layout((0, 0), (1024, 768), scale).is_err());
        }
        assert!(usable_main_layout((0, 0), (600, 768), 1.0).is_err());
        assert!(usable_main_layout((0, 0), (1024, 400), 1.0).is_err());
    }
}

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
pub(crate) fn is_progress_window_visible(app: tauri::AppHandle) -> Result<bool, String> {
    let Some(progress) = app.get_webview_window("build-progress") else {
        return Ok(false);
    };
    progress
        .is_visible()
        .map_err(|error| format!("Could not inspect the build progress window: {error}"))
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
