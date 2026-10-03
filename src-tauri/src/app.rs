use super::*;

#[cfg(all(debug_assertions, target_os = "linux"))]
fn linux_gui_smoke_companion() -> Option<&'static str> {
    match (
        std::env::var("OPEMOS_EXPERIMENTAL_LINUX").ok().as_deref(),
        std::env::var("OPEMOS_LINUX_GUI_SMOKE_COMPANION")
            .ok()
            .as_deref(),
    ) {
        (Some("1"), Some("build-progress")) => Some("build-progress"),
        _ => None,
    }
}

fn cleanup_managed_workers(app: &tauri::AppHandle) {
    if let Ok(mut manager) = app.state::<Mutex<UsbPreparationManager>>().lock() {
        manager.cancel_all();
    }
    if let Ok(mut manager) = app.state::<Mutex<ApplianceManager>>().lock() {
        manager.cancel_preparation.store(true, Ordering::Relaxed);
        if let Some(mut session) = manager.session.take() {
            let _ = stop_session(&mut session);
        }
    }
    if let Ok(mut manager) = app.state::<Mutex<NvidiaBuildManager>>().lock() {
        manager.cancel_build.store(true, Ordering::Relaxed);
        if let Some(mut session) = manager.session.take() {
            let _ = stop_nvidia_build_session(&mut session);
        }
    }
}

fn native_no_activate_proof() -> bool {
    #[cfg(target_os = "windows")]
    {
        std::env::var("OPEMOS_NATIVE_NO_ACTIVATE_PROOF").as_deref() == Ok("1")
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[tauri::command]
fn main_window_ready(app: tauri::AppHandle) -> Result<(), String> {
    if native_no_activate_proof() {
        return Ok(());
    }
    let main = app
        .get_webview_window("main")
        .ok_or("The main application window is unavailable.")?;
    main.show()
        .map_err(|error| format!("Could not show the main application window: {error}"))?;
    main.set_focus()
        .map_err(|error| format!("Could not focus the main application window: {error}"))?;
    if let Some(splash) = app.get_webview_window("splashscreen") {
        splash
            .close()
            .map_err(|error| format!("Could not close the startup window: {error}"))?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .on_page_load(|webview, payload| {
            if webview.label() == "main"
                && payload.event() == tauri::webview::PageLoadEvent::Finished
            {
                #[cfg(all(debug_assertions, target_os = "linux"))]
                if linux_gui_smoke_companion() == Some("build-progress") {
                    let app = webview.app_handle().clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = windows::open_progress_window(app).await;
                    });
                }
            }
        })
        .manage(Mutex::new(ApplianceManager::default()))
        .manage(Mutex::new(NvidiaBuildManager::default()))
        .manage(Mutex::new(UsbPreparationManager::default()))
        .manage(Mutex::new(MaintainerReleaseManager::default()))
        .setup(|app| {
            if !native_no_activate_proof() {
                if let Some(splash) = app.get_webview_window("splashscreen") {
                    splash.show().map_err(std::io::Error::other)?;
                }
            } else {
                if let Some(splash) = app.get_webview_window("splashscreen") {
                    splash.hide().map_err(std::io::Error::other)?;
                }
            }
            migrate_legacy_settings(app.handle()).map_err(std::io::Error::other)?;
            cleanup_abandoned_runtimes().map_err(std::io::Error::other)?;
            cleanup_abandoned_nvidia_build_runtimes().map_err(std::io::Error::other)?;
            let main = app.get_webview_window("main").ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "configured main window is unavailable during setup",
                )
            })?;
            // The hidden main webview loads behind the splash. The frontend
            // readiness command activates it after its event handlers exist.
            let _ = main;
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            main_window_ready,
            crate::compatibility_preview::preview_core_compatibility,
            check_builder_environment,
            check_nvidia_build_environment,
            get_builder_settings,
            update_builder_settings,
            get_github_maintainer_status,
            connect_github_maintainer,
            list_nvidia_source_branches,
            list_maintainer_workspace_sources,
            plan_maintainer_workspace,
            make_maintainer_worktree,
            inspect_maintainer_worktree,
            list_recent_maintainer_worktrees,
            open_maintainer_worktree_in_vscode,
            review_maintainer_staged_commit,
            create_maintainer_local_commit,
            list_maintainer_local_branches,
            review_maintainer_checkout,
            execute_maintainer_checkout,
            review_maintainer_push,
            execute_maintainer_push,
            review_maintainer_pull_request,
            create_maintainer_pull_request,
            review_maintainer_rollback,
            execute_maintainer_rollback,
            review_maintainer_version_change,
            apply_maintainer_version_change,
            prepare_maintainer_release_operation,
            import_maintainer_release_product,
            run_maintainer_release_operation,
            start_appliance,
            start_nvidia_build_appliance,
            get_appliance_status,
            get_nvidia_build_appliance_status,
            read_appliance_log,
            read_nvidia_build_appliance_log,
            guest_health,
            nvidia_build_guest_health,
            build_nvidia_target_development,
            verify_guest_transfer,
            inspect_test_disk,
            inspect_selected_image,
            verify_working_image,
            mutate_test_marker,
            mutate_selected_marker,
            assess_nvidia_target,
            resolve_published_nvidia,
            prepare_nvidia_userspace,
            prepare_nvidia_installer_bundle,
            start_nvidia_install_appliance,
            build_nvidia_target_on_demand,
            publish_on_demand_nvidia_release,
            validate_nvidia_install_handoff,
            install_nvidia_to_working_image,
            export_marker_image,
            reveal_completed_image,
            stop_appliance,
            stop_nvidia_build_appliance,
            validate_image,
            preview_image_output,
            inspect_completed_nvidia_image,
            inspect_usb_targets,
            inspect_usb_targets_for_build,
            arm_usb_write_preflight,
            cancel_usb_write_preflight,
            get_usb_write_preflight_status,
            write_image_to_usb,
            windows::open_valve_download_page,
            windows::open_progress_window,
            windows::hide_progress_window,
            windows::is_progress_window_visible,
            windows::open_maintainer_window,
        ])
        .build(tauri::generate_context!())
        .expect("error while building SteamOS NVIDIA Image Builder");

    app.run(|app_handle, event| match event {
        tauri::RunEvent::WindowEvent {
            label,
            event: tauri::WindowEvent::CloseRequested { api, .. },
            ..
        } if label == "main" => {
            let usb_write_active = app_handle
                .state::<Mutex<UsbPreparationManager>>()
                .lock()
                .map(|manager| manager.has_active_write())
                .unwrap_or(true);
            if usb_write_active {
                api.prevent_close();
                let _ = app_handle.emit(
                    "usb-write-close-refused",
                    "The application must remain open until the active USB write settles.",
                );
                return;
            }
            cleanup_managed_workers(app_handle);
            app_handle.exit(0);
        }
        tauri::RunEvent::ExitRequested { .. } => cleanup_managed_workers(app_handle),
        _ => {}
    });
}
