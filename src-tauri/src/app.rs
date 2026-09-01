use super::*;

fn cleanup_managed_workers(app: &tauri::AppHandle) {
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .on_page_load(|webview, payload| {
            if webview.label() == "main"
                && payload.event() == tauri::webview::PageLoadEvent::Finished
            {
                let _ = webview.window().show();
            }
        })
        .manage(Mutex::new(ApplianceManager::default()))
        .manage(Mutex::new(NvidiaBuildManager::default()))
        .setup(|_| {
            cleanup_abandoned_runtimes().map_err(std::io::Error::other)?;
            cleanup_abandoned_nvidia_build_runtimes().map_err(std::io::Error::other)?;
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            check_builder_environment,
            check_nvidia_build_environment,
            get_builder_settings,
            update_builder_settings,
            get_github_maintainer_status,
            connect_github_maintainer,
            list_nvidia_source_branches,
            list_maintainer_workspace_sources,
            plan_maintainer_workspace,
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
            stop_appliance,
            stop_nvidia_build_appliance,
            validate_image,
            preview_image_output,
            windows::open_progress_window,
            windows::open_maintainer_window,
        ])
        .build(tauri::generate_context!())
        .expect("error while building SteamOS NVIDIA Image Builder");

    app.run(|app_handle, event| match event {
        tauri::RunEvent::WindowEvent {
            label,
            event: tauri::WindowEvent::CloseRequested { .. },
            ..
        } if label == "main" => {
            cleanup_managed_workers(app_handle);
            app_handle.exit(0);
        }
        tauri::RunEvent::ExitRequested { .. } => cleanup_managed_workers(app_handle),
        _ => {}
    });
}
