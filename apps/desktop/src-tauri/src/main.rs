// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::anyhow;
use hybridcipher_desktop::demo;
use hybridcipher_desktop::{
    cli_schema::CliSchemaManager, client::HybridCipherClient, commands::*,
    feedback::FeedbackResponse, local_client::LocalClientProvider, mount::MountManager,
    state::AppState, DesktopCloudProviderManager,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tauri::{async_runtime::Mutex, Emitter, Manager};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tauri::command]
async fn submit_feedback(
    title: String,
    description: String,
    user_email: Option<String>,
    attachment_paths: Vec<String>,
) -> Result<FeedbackResponse, String> {
    hybridcipher_desktop::feedback::submit_feedback(
        title,
        description,
        user_email,
        attachment_paths,
    )
    .await
}

fn main() {
    // Initialize tracing for better debugging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hybridcipher_desktop=debug,tauri=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting HybridCipher Desktop Application");

    let shutting_down = Arc::new(AtomicBool::new(false));
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup({
            let shutting_down = shutting_down.clone();
            move |app| {
                // Initialize application state
                let server_url = std::env::var("HYBRIDCIPHER_SERVER_URL")
                    .unwrap_or_else(|_| "https://api.hybridcipher.com".to_string());

                let client = HybridCipherClient::new(server_url);
                let cli_schema = CliSchemaManager::new();

                let local_client = Arc::new(LocalClientProvider::new().map_err(|e| anyhow!(e))?);
                let mount_manager =
                    Arc::new(MountManager::new(local_client.clone()).map_err(|e| anyhow!(e))?);
                let cloud_provider = Arc::new(DesktopCloudProviderManager::new());

                let state = AppState {
                    client: Arc::new(client),
                    cli_schema: Arc::new(cli_schema),
                    session: Arc::new(Mutex::new(None)),
                    mount_manager,
                    local_client,
                    cloud_provider,
                };

                let app_handle = app.app_handle().clone();
                let mount_manager = state.mount_manager.clone();
                let signal_flag = shutting_down.clone();
                ctrlc::set_handler(move || {
                    if signal_flag.swap(true, Ordering::SeqCst) {
                        return;
                    }
                    tracing::info!("Received interrupt signal, cleaning up mounts");
                    let mm = mount_manager.clone();
                    tauri::async_runtime::block_on(async {
                        if let Err(e) = mm.unmount_all(false).await {
                            tracing::error!("Failed to cleanup mounts on signal: {}", e);
                        }
                    });
                    app_handle.exit(0);
                })
                .map_err(|e| anyhow!(format!("Failed to install Ctrl+C handler: {}", e)))?;

                app.manage(state);

                // Set up custom protocol for serving local assets securely
                #[cfg(target_os = "macos")]
                {
                    // macOS-specific setup for menu bar including the Edit menu for copy/paste support
                    use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};

                    let app_name = app.package_info().name.clone();

                    let about_item = MenuItemBuilder::new(format!("About {}", app_name))
                        .id("about")
                        .build(app)?;
                    let preferences_item = MenuItemBuilder::new("Preferences...")
                        .id("preferences")
                        .accelerator("Cmd+,")
                        .build(app)?;

                    let app_submenu = SubmenuBuilder::new(app, &app_name)
                        .item(&about_item)
                        .item(&preferences_item)
                        .separator()
                        .services()
                        .hide()
                        .hide_others()
                        .show_all()
                        .separator()
                        .quit()
                        .build()?;

                    let edit_submenu = SubmenuBuilder::new(app, "Edit")
                        .undo()
                        .redo()
                        .separator()
                        .cut()
                        .copy()
                        .paste()
                        .select_all()
                        .build()?;

                    let menu = MenuBuilder::new(app)
                        .item(&app_submenu)
                        .item(&edit_submenu)
                        .build()?;

                    app.set_menu(menu)?;
                }

                tracing::info!("Application setup complete");
                Ok(())
            }
        })
        .on_window_event({
            let shutting_down = shutting_down.clone();
            move |window, event| {
                // Hide on window close; explicit Quit is the only path that unmounts.
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    if shutting_down.load(Ordering::SeqCst) {
                        return;
                    }
                    api.prevent_close();
                    tracing::info!("Window close requested, hiding window");
                    if let Err(e) = window.hide() {
                        tracing::error!("Failed to hide window: {}", e);
                    }
                }
            }
        })
        .on_menu_event({
            let shutting_down = shutting_down.clone();
            move |app_handle, event| {
                // Handle menu events, particularly Quit
                if event.id() == "quit" {
                    if shutting_down.swap(true, Ordering::SeqCst) {
                        return;
                    }
                    tracing::info!("Quit menu selected, delegating quit flow to frontend");
                    if let Some(window) = app_handle.get_webview_window("main") {
                        if let Err(err) = window.emit("app_quit_requested", ()) {
                            tracing::error!("Failed to emit quit request: {}", err);
                            app_handle.exit(0);
                        }
                    } else {
                        app_handle.exit(0);
                    }
                } else if event.id() == "preferences" {
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.emit("open_settings_requested", "settingsAccountSection");
                    }
                } else if event.id() == "about" {
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.emit("open_settings_requested", "settingsLegalSection");
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            // Authentication commands
            register_user,
            login_user,
            check_password_reset_account,
            request_password_reset,
            start_password_reset,
            complete_password_reset,
            cancel_password_reset,
            check_email_confirmation,
            resend_confirmation_email,
            get_session_info,
            logout_user,
            restore_session,
            get_user_status,
            get_active_group_context,
            refresh_local_client,
            // Group management commands
            create_group,
            initialize_group,
            list_groups,
            get_group_summaries,
            get_group_info,
            // File operations commands
            encrypt_file,
            decrypt_file,
            encrypt_directory,
            list_encrypted_files,
            // Rekey operations commands
            rekey_start,
            rekey_status,
            rekey_cutover,
            get_migration_status,
            // Trust and transparency commands
            server_trust_verify,
            get_transparency_proof,
            verify_merkle_proof,
            pin_server_identity,
            // Audit and diagnostics commands
            audit_devices,
            audit_stale_devices,
            remove_stale_devices,
            get_coverage_status,
            get_settings_status,
            get_individual_home_status,
            get_operations_refresh_interval_secs,
            get_session_health_config,
            get_group_members,
            remove_group_member,
            get_group_member_details,
            get_security_status,
            get_personal_devices_overview,
            revoke_device,
            mfa_enroll_start,
            mfa_enroll_verify,
            get_pending_devices,
            get_stale_devices,
            get_unverified_devices,
            // CLI schema commands
            get_cli_schema,
            get_command_help,
            execute_cli_command,
            run_shell_command,
            start_terminal_session,
            write_terminal_stdin,
            close_terminal_session,
            record_terminal_diagnostic,
            get_cli_binary_path,
            get_platform_info,
            // Settings and configuration commands
            get_server_info,
            update_server_url,
            get_app_version,
            get_legal_documents,
            get_release_notes_payload,
            get_global_cli_install_status,
            install_global_cli_symlink,
            check_for_updates,
            install_update,
            restart_application,
            // Coverage and folder management commands
            list_enrolled_folders,
            get_coverage_center_snapshot,
            run_coverage_scan,
            get_folder_coverage_review,
            run_folder_coverage_action,
            enroll_folder,
            enroll_folder_and_hydrate,
            unenroll_folder_and_decrypt,
            mount_enrolled_folder,
            check_mount_status_by_root_id,
            list_active_mounts,
            list_mount_conflicts,
            get_mount_conflict_preview,
            resolve_mount_conflict,
            list_mount_recovery_copies,
            get_mount_recovery_copy_preview,
            resolve_mount_recovery_copy,
            get_mount_sync_status,
            unmount_all_mounts,
            unmount_mount_by_root_id,
            exit_application,
            open_path_in_shell,
            prioritize_folder_decrypt,
            // Feedback command
            submit_feedback,
            // Demo mode commands
            demo::demo_init,
            demo::demo_reset,
            demo::demo_status,
            demo::demo_run,
            demo::demo_run_step,
            demo::is_demo_mode,
            demo::set_demo_mode,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run({
            let shutting_down = shutting_down.clone();
            move |app_handle, event| {
                match event {
                    #[cfg(target_os = "macos")]
                    tauri::RunEvent::Reopen { .. } => {
                        tracing::info!("App reactivated from dock, showing window");
                        if let Some(window) = app_handle.get_webview_window("main") {
                            if let Err(e) = window.show() {
                                tracing::error!("Failed to show window on reopen: {}", e);
                            }
                            if let Err(e) = window.set_focus() {
                                tracing::error!("Failed to focus window on reopen: {}", e);
                            }
                        } else {
                            tracing::warn!("Main window not found on reopen");
                        }
                    }
                    tauri::RunEvent::Exit => {
                        // Best-effort cleanup of mount state files (not data) on exit
                        // The recovery system will handle orphaned mountpoints on next launch
                        if shutting_down.swap(true, Ordering::SeqCst) {
                            return;
                        }
                        tracing::info!("Exit event: cleaning up mount state files");
                        if let Some(state) = app_handle.try_state::<AppState>() {
                            state.mount_manager.cleanup_state_files_on_exit();
                        }
                    }
                    _ => {}
                }
            }
        });
}
