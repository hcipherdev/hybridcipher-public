use crate::{
    commands::{ConflictCommands, MountCommands, MountRecoveryCommands},
    error::{map_missing_welcome_error, CliError},
    session::SessionManager,
    ui::{self, prompts},
};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use clap::ValueEnum;
use hybridcipher_client::{
    coverage::{CoverageRoot, CoverageRootState},
    ipc::coverage_workflows,
    network::MockNetwork,
    storage::LocalFsStorage,
    Client,
};
#[cfg(target_os = "linux")]
use hybridcipher_mount_sync::mount_runner::build_mount_options;
#[cfg(target_os = "linux")]
use hybridcipher_mount_sync::mount_runner::run_fuse_mount;
use hybridcipher_mount_sync::{
    load_mount_conflict_registry, load_mount_recovery_registry,
    mount_runner::{run_sync_mount_with_config, MountStrategy},
    sync_mount_conflict_action_requests_dir, sync_mount_conflict_action_results_dir,
    sync_mount_conflict_registry_path, sync_mount_recovery_action_requests_dir,
    sync_mount_recovery_action_results_dir, sync_mount_recovery_registry_path,
    ConflictResolutionAction, ConflictResolutionRequest, ConflictResolutionResponse, LowSpaceMode,
    MountConflictRecord, MountRecoveryCopyRecord, MountSafetyReason, MountSyncRuntimeStatus,
    RecoveryCopyResolutionAction, RecoveryCopyResolutionRequest, RecoveryCopyResolutionResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command as ProcessCommand;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use std::{future::Future, pin::Pin};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use tokio::{
    signal,
    sync::watch,
    time::{interval, MissedTickBehavior},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum MountStrategyArg {
    /// Let the CLI pick the best mount strategy for this platform
    Auto,
    /// Always use the sync-based mirror
    Sync,
    /// Force the FUSE filesystem implementation (Linux only)
    Fuse,
    /// Force the Windows Cloud Files provider implementation (Windows only)
    CloudFiles,
    /// Force the macOS File Provider implementation (macOS only)
    FileProvider,
}

type LocalClient = Client<LocalFsStorage, MockNetwork>;

#[derive(Debug, Default, Serialize, Deserialize)]
struct MountPreferences {
    last_encrypted_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MountBackend {
    Sync,
    LinuxFuse,
    WindowsCloudFiles,
    #[serde(rename = "macos-file-provider")]
    MacOsFileProvider,
}

impl MountBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::LinuxFuse => "linux-fuse",
            Self::WindowsCloudFiles => "windows-cloud-files",
            Self::MacOsFileProvider => "macos-file-provider",
        }
    }

    fn is_sync(self) -> bool {
        matches!(self, Self::Sync)
    }

    fn is_windows_cloud_files(self) -> bool {
        matches!(self, Self::WindowsCloudFiles)
    }

    fn is_macos_file_provider(self) -> bool {
        matches!(self, Self::MacOsFileProvider)
    }

    fn supports_conflict_recovery(self) -> bool {
        matches!(
            self,
            Self::Sync | Self::WindowsCloudFiles | Self::MacOsFileProvider
        )
    }
}

fn mount_backend_for_strategy(strategy: MountStrategy) -> MountBackend {
    match strategy {
        MountStrategy::Sync => MountBackend::Sync,
        #[cfg(target_os = "linux")]
        MountStrategy::Fuse => MountBackend::LinuxFuse,
        #[cfg(target_os = "windows")]
        MountStrategy::CloudFiles => MountBackend::WindowsCloudFiles,
        #[cfg(target_os = "macos")]
        MountStrategy::MacOsFileProvider => MountBackend::MacOsFileProvider,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MountRuntimeState {
    root_id: Uuid,
    mountpoint: PathBuf,
    encrypted_dir: PathBuf,
    platform: String,
    #[serde(default)]
    backend: Option<MountBackend>,
    #[serde(default)]
    host_pid: Option<u32>,
    #[serde(default)]
    fallback_reason: Option<String>,
    #[serde(default = "default_mount_ready")]
    ready: bool,
    requested_unmount: bool,
}

impl MountRuntimeState {
    fn backend(&self) -> MountBackend {
        self.backend.unwrap_or(MountBackend::Sync)
    }
}

fn default_mount_ready() -> bool {
    true
}

fn ensure_sync_mount_backend(
    state: &MountRuntimeState,
    command_name: &str,
) -> Result<(), CliError> {
    if state.backend().supports_conflict_recovery() {
        return Ok(());
    }

    Err(CliError::mount(format!(
        "`hybridcipher {}` is not applicable for {} mounts.",
        command_name,
        state.backend().as_str()
    )))
}

#[cfg(target_os = "windows")]
fn resolve_windows_mount_strategy(
    strategy: MountStrategyArg,
    cloud_files_prereqs: Result<(), String>,
) -> Result<(MountStrategy, Option<String>), CliError> {
    match strategy {
        MountStrategyArg::Fuse => Err(CliError::mount(
            "The --fuse option is only supported on Linux in this build.",
        )),
        MountStrategyArg::CloudFiles => {
            cloud_files_prereqs.map_err(CliError::mount)?;
            Ok((MountStrategy::CloudFiles, None))
        }
        MountStrategyArg::FileProvider => Err(CliError::mount(
            "The --file-provider option is only supported on macOS in this build.",
        )),
        MountStrategyArg::Sync => Ok((MountStrategy::Sync, None)),
        MountStrategyArg::Auto => match cloud_files_prereqs {
            Ok(_) => Ok((MountStrategy::CloudFiles, None)),
            Err(cloud_err) => Ok((
                MountStrategy::Sync,
                Some(format!("Cloud Files unavailable: {cloud_err}")),
            )),
        },
    }
}

#[cfg(target_os = "macos")]
fn resolve_macos_mount_strategy(
    strategy: MountStrategyArg,
    file_provider_prereqs: Result<(), String>,
) -> Result<(MountStrategy, Option<String>), CliError> {
    match strategy {
        MountStrategyArg::FileProvider => {
            file_provider_prereqs.map_err(CliError::mount)?;
            Ok((MountStrategy::MacOsFileProvider, None))
        }
        MountStrategyArg::Sync => Ok((MountStrategy::Sync, None)),
        MountStrategyArg::Auto => match file_provider_prereqs {
            Ok(_) => Ok((MountStrategy::MacOsFileProvider, None)),
            Err(provider_err) => Ok((
                MountStrategy::Sync,
                Some(format!(
                    "macOS File Provider unavailable: {provider_err}"
                )),
            )),
        },
        MountStrategyArg::Fuse => Err(CliError::mount(
            "macOS builds no longer include libfuse/macFUSE support. Use --sync or the default File Provider backend instead.",
        )),
        MountStrategyArg::CloudFiles => Err(CliError::mount(
            "The --cloud-files option is only supported on Windows in this build.",
        )),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RootMountStatus {
    pub active: bool,
    pub fuse_mounted: bool,
    pub mountpoint: Option<PathBuf>,
}

impl RootMountStatus {
    fn inactive() -> Self {
        Self {
            active: false,
            fuse_mounted: false,
            mountpoint: None,
        }
    }
}

/// Run the interactive mount workflow.
pub async fn handle_mount(
    session_manager: &SessionManager,
    strategy_arg: MountStrategyArg,
    root_id: Option<Uuid>,
) -> Result<(), CliError> {
    ui::section("Mount Encrypted Files");

    session_manager.require_auth()?;

    // Determine root_id and encrypted_dir
    let (final_root_id, encrypted_dir) = if let Some(root_id) = root_id {
        // Non-interactive mode: root_id provided
        ui::info(&format!(
            "Mounting enrolled folder with root_id: {}",
            root_id
        ));
        let folder_path = find_enrolled_folder_by_root_id(session_manager, root_id).await?;
        let encrypted_dir = canonicalize_existing(folder_path)?;
        ensure_directory(&encrypted_dir)?;
        (root_id, encrypted_dir)
    } else {
        // Interactive mode: need to find root_id from selected folder
        // Interactive mode - existing logic
        let prefs = match load_mount_preferences(session_manager) {
            Ok(p) => p,
            Err(err) => {
                warn!("Failed to read mount preferences: {}", err);
                MountPreferences::default()
            }
        };

        // Surface enrolled folders to help users pick the correct source
        let enrolled_roots = match active_enrolled_roots(session_manager).await {
            Ok(list) => list,
            Err(err) => {
                warn!("Failed to load enrolled folders: {}", err);
                Vec::new()
            }
        };

        if enrolled_roots.is_empty() {
            ui::info("No enrolled folders detected yet.");
        } else {
            ui::info("Enrolled folders:");
            for (idx, root) in enrolled_roots.iter().enumerate() {
                ui::info(&format!("  {}. {}", idx + 1, root.display()));
            }
        }

        // Get the encrypted directory from user selection
        let encrypted_dir = if enrolled_roots.is_empty() {
            let encrypted_default = prefs
                .last_encrypted_dir
                .clone()
                .or_else(default_encrypted_candidate);

            if let Some(ref default) = encrypted_default {
                ui::info(&format!(
                    "Last used encrypted directory: {}",
                    default.display()
                ));
            }

            let encrypted_prompt = if encrypted_default.is_some() {
                prompts::input_with_default(
                    "Encrypted folder to mount",
                    &path_to_string(encrypted_default.as_ref().unwrap())?,
                )?
            } else {
                prompts::input("Encrypted folder to mount")?
            };

            canonicalize_existing(expand_path(&encrypted_prompt)?)?
        } else {
            let default_idx =
                default_enrolled_index(&enrolled_roots, prefs.last_encrypted_dir.as_ref())
                    .unwrap_or(0);

            if let Some(default_root) = enrolled_roots.get(default_idx) {
                ui::info(&format!(
                    "Last used enrolled folder: {}",
                    default_root.display()
                ));
            }

            let selection = prompts::input_allow_empty(
            "Press Enter to mount the last used enrolled folder or input a new enrolled folder label to mount [e.g. 1]:",
        )?;

            let selected = if selection.trim().is_empty() {
                enrolled_roots
                    .get(default_idx)
                    .cloned()
                    .ok_or_else(|| CliError::mount("No enrolled folder is available to mount"))?
            } else if let Ok(idx) = selection.trim().parse::<usize>() {
                if idx == 0 || idx > enrolled_roots.len() {
                    return Err(CliError::mount(format!(
                        "Enter a number between 1 and {}",
                        enrolled_roots.len()
                    )));
                }
                enrolled_roots[idx - 1].clone()
            } else {
                expand_path(&selection)?
            };

            let dir = canonicalize_existing(selected)?;
            ensure_directory(&dir)?;
            dir
        };

        // Find root_id for the selected folder
        let roots = active_enrolled_roots_with_ids(session_manager).await?;
        let folder_root_id = roots
            .iter()
            .find(|root| {
                // Try to match by canonical path
                if let Ok(canonical) = fs::canonicalize(&root.path) {
                    if let Ok(encrypted_canonical) = fs::canonicalize(&encrypted_dir) {
                        return canonical == encrypted_canonical;
                    }
                }
                false
            })
            .map(|root| root.root_id)
            .unwrap_or_else(|| {
                // If not found in enrolled roots, generate a UUID based on path
                // This handles the case where user manually entered a path
                let mut hasher = Sha256::new();
                hasher.update(encrypted_dir.to_string_lossy().as_bytes());
                let hash = hasher.finalize();
                Uuid::from_bytes([
                    hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                    hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
                ])
            });

        (folder_root_id, encrypted_dir)
    };

    let mountpoint = determine_mountpoint(&encrypted_dir, final_root_id)?;
    let volume_label = derive_mount_label(&encrypted_dir, final_root_id);
    let mountpoint = canonicalize_existing(mountpoint)?;

    ui::info(&format!("Encrypted source: {}", encrypted_dir.display()));
    ui::info(&format!("Decrypted view: {}", mountpoint.display()));

    // Save mount preferences (only if we have prefs, i.e., interactive mode)
    if root_id.is_none() {
        let mut prefs = match load_mount_preferences(session_manager) {
            Ok(p) => p,
            Err(err) => {
                warn!("Failed to read mount preferences: {}", err);
                MountPreferences::default()
            }
        };
        prefs.last_encrypted_dir = Some(encrypted_dir.to_path_buf());
        if let Err(err) = save_mount_preferences(session_manager, &prefs) {
            warn!("Failed to persist mount preferences: {}", err);
        }
    }

    // Check if this specific folder is already mounted
    let state_path = mount_state_path(session_manager, final_root_id)?;
    let sync_status_path = mount_sync_status_path(session_manager, final_root_id)?;
    if let Some(state) = read_runtime_state(&state_path)? {
        if !state.requested_unmount && state.root_id == final_root_id {
            if runtime_mount_state_is_stale(&state).await {
                ui::warning(&format!(
                    "Found stale mount state at {}. Cleaning it before retrying.",
                    state.mountpoint.display()
                ));
                cleanup_stale_mount_before_retry(&state_path, &sync_status_path, &state)?;
            } else if !state.ready {
                ui::warning(&format!(
                    "Found an incomplete previous mount attempt at {}. Resetting it before retrying.",
                    state.mountpoint.display()
                ));
                mark_unmount_requested(&state_path)?;
                tokio::time::sleep(Duration::from_millis(500)).await;
                clear_runtime_state(&state_path)?;
                clear_mount_sync_status(&sync_status_path)?;
            } else {
                // Same folder is already mounted
                if root_id.is_some() {
                    // Non-interactive mode: just return success (already mounted)
                    ui::info(&format!(
                        "Folder is already mounted at {}.",
                        state.mountpoint.display()
                    ));
                    return Ok(());
                } else {
                    // Interactive mode: ask for confirmation
                    ui::warning(&format!(
                        "This folder is already mounted at {}.",
                        state.mountpoint.display()
                    ));
                    if !prompts::confirm_with_default("Proceed and remount?", false)? {
                        return Err(CliError::cancelled());
                    }
                }

                // Unmount the existing mount before proceeding
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    ui::info("Unmounting existing mount...");

                    // Request unmount via state file first (if mount process is still running)
                    mark_unmount_requested(&state_path)?;

                    // Wait a moment for the mount process to see the unmount request
                    tokio::time::sleep(Duration::from_millis(500)).await;

                    // Linux FUSE mounts still need an explicit unmount request. Sync mounts exit
                    // after they observe the runtime-state flag above.
                    if let Err(err) = request_fuse_unmount(&state.mountpoint, false).await {
                        warn!("Failed to cleanly unmount existing mount: {}", err);
                        ui::warning("Attempting force unmount...");
                        request_fuse_unmount(&state.mountpoint, true).await?;
                    }

                    // Wait for unmount to complete and verify mountpoint is no longer mounted
                    let max_wait = Duration::from_secs(10);
                    let check_interval = Duration::from_millis(500);
                    let mut waited = Duration::from_millis(0);
                    let mut mountpoint_unmounted = false;

                    while waited < max_wait {
                        // Check if mountpoint still exists and is accessible
                        // If it's a FUSE mount, it should disappear or become empty after unmount
                        if mountpoint_is_detached(&state.mountpoint).await {
                            mountpoint_unmounted = true;
                            break;
                        }

                        tokio::time::sleep(check_interval).await;
                        waited += check_interval;
                    }

                    if !mountpoint_unmounted {
                        warn!(
                        "Mountpoint {} may still be mounted after {} seconds. Proceeding with caution.",
                        state.mountpoint.display(),
                        max_wait.as_secs()
                    );
                    } else {
                        ui::info("Mount successfully unmounted.");
                    }

                    // Clean up and prepare the mountpoint after unmounting
                    // This will fail safely if directory still contains files
                    if let Err(e) = clean_and_prepare_mountpoint(&state.mountpoint) {
                        warn!(
                        "Could not clean mountpoint: {}. Will attempt to use existing directory.",
                        e
                    );
                        // Don't fail completely - try to proceed with existing directory
                        // The mount will fail later if there's a real problem
                    }
                }

                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    // On Windows, just mark unmount requested and wait
                    mark_unmount_requested(&state_path)?;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    hydrate_unmanaged_files_before_mount(session_manager, final_root_id).await?;

    let strategy = if cfg!(target_os = "linux") {
        if let Some(env_override) = env_strategy_override() {
            ui::warning(
                "HYBRIDCIPHER_FORCE_FUSE is deprecated. Use --fuse/--sync instead. Applying override.",
            );
            env_override
        } else {
            strategy_arg
        }
    } else {
        strategy_arg
    };

    let mut fallback_reason: Option<String> = None;

    let effective_strategy = if cfg!(target_os = "windows") {
        #[cfg(target_os = "windows")]
        {
            let cloud_prereqs = match strategy {
                MountStrategyArg::Auto | MountStrategyArg::CloudFiles => cloud_files_prereqs(),
                _ => Err("Cloud Files was not selected.".to_string()),
            };
            let (resolved_strategy, resolved_fallback_reason) =
                resolve_windows_mount_strategy(strategy, cloud_prereqs)?;
            fallback_reason = resolved_fallback_reason;

            match resolved_strategy {
                MountStrategy::CloudFiles => {
                    if matches!(strategy, MountStrategyArg::Auto) {
                        ui::info(
                            "Auto-select: Cloud Files support detected, using Windows Cloud Files provider.",
                        );
                    } else {
                        ui::info("Using Windows Cloud Files provider strategy.");
                    }
                }
                MountStrategy::Sync => {
                    if let Some(reason) = fallback_reason.as_deref() {
                        ui::warning(&format!(
                            "Auto-select: {} Falling back to sync strategy.",
                            reason
                        ));
                    } else {
                        ui::info("Using sync mount strategy.");
                    }
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!("unexpected Windows mount strategy"),
            }

            resolved_strategy
        }
        #[cfg(not(target_os = "windows"))]
        unreachable!()
    } else if cfg!(target_os = "linux") {
        #[cfg(target_os = "linux")]
        {
            match strategy {
                MountStrategyArg::Sync => {
                    ui::info("Using sync mount strategy.");
                    MountStrategy::Sync
                }
                MountStrategyArg::FileProvider => {
                    return Err(CliError::mount(
                        "The --file-provider option is only supported on macOS in this build.",
                    ));
                }
                MountStrategyArg::Fuse => match fuse_prereqs() {
                    Ok(_) => {
                        ui::info("Using Linux FUSE mount strategy.");
                        MountStrategy::Fuse
                    }
                    Err(err) => {
                        ui::warning(&format!(
                            "Requested FUSE mount but prerequisites failed: {err}\nFalling back to sync mount."
                        ));
                        MountStrategy::Sync
                    }
                },
                MountStrategyArg::Auto => match fuse_prereqs() {
                    Ok(_) => {
                        ui::info("Auto-select: FUSE support detected, using FUSE strategy.");
                        MountStrategy::Fuse
                    }
                    Err(err) => {
                        ui::warning(&format!(
                            "Auto-select: {err} Falling back to sync strategy."
                        ));
                        MountStrategy::Sync
                    }
                },
                MountStrategyArg::CloudFiles => {
                    return Err(CliError::mount(
                        "The --cloud-files option is only supported on Windows in this build.",
                    ));
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        unreachable!()
    } else if cfg!(target_os = "macos") {
        #[cfg(target_os = "macos")]
        {
            let provider_prereqs = match strategy {
                MountStrategyArg::Auto | MountStrategyArg::FileProvider => {
                    macos_file_provider_prereqs(session_manager)
                }
                _ => Err("macOS File Provider was not selected.".to_string()),
            };
            let (resolved_strategy, resolved_fallback_reason) =
                resolve_macos_mount_strategy(strategy, provider_prereqs)?;
            fallback_reason = resolved_fallback_reason;

            match resolved_strategy {
                MountStrategy::MacOsFileProvider => {
                    if matches!(strategy, MountStrategyArg::Auto) {
                        ui::info(
                            "Auto-select: macOS File Provider support detected, using File Provider strategy.",
                        );
                    } else {
                        ui::info("Using macOS File Provider strategy.");
                    }
                }
                MountStrategy::Sync => {
                    if let Some(reason) = fallback_reason.as_deref() {
                        ui::warning(&format!(
                            "Auto-select: {} Falling back to sync strategy.",
                            reason
                        ));
                    } else {
                        ui::info("Using sync mount strategy.");
                    }
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!("unexpected macOS mount strategy"),
            }

            resolved_strategy
        }
        #[cfg(not(target_os = "macos"))]
        unreachable!()
    } else {
        match strategy {
            MountStrategyArg::Fuse => {
                return Err(CliError::mount(
                    "The --fuse option is only supported on Linux in this build.",
                ));
            }
            MountStrategyArg::CloudFiles => {
                return Err(CliError::mount(
                    "The --cloud-files option is only supported on Windows in this build.",
                ));
            }
            MountStrategyArg::FileProvider => {
                return Err(CliError::mount(
                    "The --file-provider option is only supported on macOS in this build.",
                ));
            }
            _ => {
                ui::info("Using sync mount strategy on this platform.");
                MountStrategy::Sync
            }
        }
    };

    let runtime_backend = mount_backend_for_strategy(effective_strategy);

    if let Err(err) = prepare_mountpoint_for_strategy(&mountpoint, effective_strategy) {
        return Err(err);
    }

    let _guard = MountDirGuard::new(mountpoint.clone());

    let runtime_state = MountRuntimeState {
        root_id: final_root_id,
        mountpoint: mountpoint.to_path_buf(),
        encrypted_dir: encrypted_dir.to_path_buf(),
        platform: std::env::consts::OS.to_string(),
        backend: Some(runtime_backend),
        host_pid: Some(std::process::id()),
        fallback_reason: fallback_reason.clone(),
        ready: false,
        requested_unmount: false,
    };
    write_runtime_state(&state_path, &runtime_state)?;
    if runtime_backend.is_sync() {
        clear_mount_sync_status(&sync_status_path)?;
    } else if sync_status_path.exists() {
        clear_mount_sync_status(&sync_status_path)?;
    }

    let (stop_tx, stop_rx) = watch::channel(false);

    async fn build_mount_future(
        session_manager: &SessionManager,
        strategy: MountStrategy,
        root_id: Uuid,
        _volume_label: &str,
        encrypted_dir: PathBuf,
        mountpoint: PathBuf,
        stop_rx: watch::Receiver<bool>,
        sync_status_path: PathBuf,
        ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Pin<Box<dyn Future<Output = Result<(), CliError>>>>, CliError> {
        let client = session_manager
            .create_client_with_config_overrides(|config| {
                config.migration_automation_enabled = false;
                config.coverage_watchers_enabled = false;
            })
            .await?;
        // Get user config directory for retention folder
        // This should always be available since mount requires auth
        let user_config_dir = session_manager.user_config_dir().ok_or_else(|| {
            CliError::session(
                "User config directory not available. Please ensure you are logged in.",
            )
        })?;
        let state_dir = mount_state_dir(session_manager)?;
        let conflict_registry_path =
            sync_mount_conflict_registry_path(&state_dir, &root_id.to_string());
        let conflict_request_dir =
            sync_mount_conflict_action_requests_dir(&state_dir, &root_id.to_string());
        let conflict_result_dir =
            sync_mount_conflict_action_results_dir(&state_dir, &root_id.to_string());
        let recovery_registry_path =
            sync_mount_recovery_registry_path(&state_dir, &root_id.to_string());
        let recovery_request_dir =
            sync_mount_recovery_action_requests_dir(&state_dir, &root_id.to_string());
        let recovery_result_dir =
            sync_mount_recovery_action_results_dir(&state_dir, &root_id.to_string());
        match strategy {
            #[cfg(target_os = "linux")]
            MountStrategy::Fuse => {
                let options = build_mount_options(_volume_label);
                Ok(Box::pin(async move {
                    run_fuse_mount(
                        client,
                        encrypted_dir,
                        mountpoint,
                        options,
                        stop_rx,
                        Some(ready),
                    )
                    .await
                    .map_err(|e| CliError::mount(map_missing_welcome_error(e.to_string())))
                }))
            }
            MountStrategy::Sync => {
                // Clone client for the async block
                let client_for_sync = client.clone();
                Ok(Box::pin(async move {
                    let client_crypto = hybridcipher_provider_core::ClientMountCrypto::new(
                        Arc::new(client_for_sync.clone()),
                    );
                    run_sync_mount_with_config(
                        &client_for_sync,
                        &client_crypto,
                        encrypted_dir,
                        mountpoint,
                        stop_rx,
                        Some(ready),
                        Some(&user_config_dir),
                        Some(&root_id.to_string()),
                        Some(&sync_status_path),
                        Some(&conflict_registry_path),
                        Some(&conflict_request_dir),
                        Some(&conflict_result_dir),
                        Some(&recovery_registry_path),
                        Some(&recovery_request_dir),
                        Some(&recovery_result_dir),
                    )
                    .await
                    .map_err(|e| CliError::mount(map_missing_welcome_error(e.to_string())))
                }))
            }
            #[cfg(target_os = "windows")]
            MountStrategy::CloudFiles => Ok(Box::pin(async move {
                run_cloud_files_mount(
                    client,
                    user_config_dir,
                    root_id,
                    encrypted_dir,
                    mountpoint,
                    stop_rx,
                    Some(ready),
                )
                .await
                .map_err(|e| CliError::mount(map_missing_welcome_error(e.to_string())))
            })),
            #[cfg(target_os = "macos")]
            MountStrategy::MacOsFileProvider => Ok(Box::pin(async move {
                run_macos_file_provider_mount(
                    client,
                    user_config_dir,
                    root_id,
                    encrypted_dir,
                    mountpoint,
                    stop_rx,
                    Some(ready),
                )
                .await
                .map_err(|e| CliError::mount(map_missing_welcome_error(e.to_string())))
            })),
        }
    }

    let ready_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let mut mount_future: Pin<Box<dyn Future<Output = Result<(), CliError>>>> = build_mount_future(
        session_manager,
        effective_strategy,
        final_root_id,
        &volume_label,
        encrypted_dir.to_path_buf(),
        mountpoint.to_path_buf(),
        stop_rx.clone(),
        sync_status_path.clone(),
        std::sync::Arc::clone(&ready_flag),
    )
    .await?;
    let mut poll_requested = interval(Duration::from_secs(1));
    poll_requested.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut unmount_requested = false;
    let mut ctrl_c_handled = false;
    let mut retry_attempts: u32 = 0;
    let mut mount_ready_shown = false;
    let mut recovery_notice_shown = false;

    ui::info("Press Ctrl+C or run `hybridcipher unmount` to detach.");

    loop {
        tokio::select! {
            res = &mut mount_future => {
                match res {
                    Ok(()) => {
                        // Clear state files only after confirmed clean exit
                        clear_runtime_state(&state_path)?;
                        clear_mount_sync_status(&sync_status_path)?;
                        // Only show exit message if unmount was requested
                        // If mount was successful, we already showed success when it became ready
                        if unmount_requested {
                            ui::info("Mount process exited as requested.");
                        }
                        // Don't show success here - we show it when mount becomes ready
                        return Ok(());
                    }
                    Err(err) => {
                        if retry_attempts < 3 && !unmount_requested {
                            retry_attempts += 1;
                            mount_ready_shown = false; // Reset ready flag on retry
                            ready_flag.store(false, std::sync::atomic::Ordering::Relaxed);
                            prepare_mountpoint_for_strategy(&mountpoint, effective_strategy)?;
                            ui::warning(&format!(
                                "Mount attempt {} failed: {}. Retrying...",
                                retry_attempts, err
                            ));
                            mount_future = build_mount_future(
                                session_manager,
                                effective_strategy,
                                final_root_id,
                                &volume_label,
                                encrypted_dir.to_path_buf(),
                                mountpoint.to_path_buf(),
                                stop_rx.clone(),
                                sync_status_path.clone(),
                                std::sync::Arc::clone(&ready_flag),
                            ).await?;
                            continue;
                        }
                        // All retries exhausted — clear state and propagate error
                        clear_runtime_state(&state_path)?;
                        clear_mount_sync_status(&sync_status_path)?;
                        return Err(err);
                    }
                }
            }
            _ = signal::ctrl_c(), if !ctrl_c_handled => {
                ui::info("Interrupt received – requesting unmount...");
                if mark_unmount_requested(&state_path).is_ok() {
                    let _ = stop_tx.send(true);
                    unmount_requested = true;
                }
                ctrl_c_handled = true;
            }
            _ = poll_requested.tick(), if !unmount_requested => {
                // Check for unmount request
                if runtime_state_requested_unmount(&state_path)? {
                    ui::info("Unmount requested from another command.");
                    let _ = stop_tx.send(true);
                    unmount_requested = true;
                }

                // Check if the selected backend reported real readiness. The mountpoint
                // directory exists before mounting, so existence alone is not enough.
                if !mount_ready_shown
                    && ready_flag.load(std::sync::atomic::Ordering::Relaxed)
                {
                    if let Some(mut state) = read_runtime_state(&state_path)? {
                        state.ready = true;
                        write_runtime_state(&state_path, &state)?;
                    }
                    if retry_attempts > 0 {
                        ui::success(&format!(
                            "Mount succeeded after {} retry attempt(s). Encrypted folder mounted at {}",
                            retry_attempts,
                            mountpoint.display()
                        ));
                    } else {
                        ui::success(&format!(
                            "Mount successful. Encrypted folder mounted at {}",
                            mountpoint.display()
                        ));
                    }
                    mount_ready_shown = true;
                }

                if mount_ready_shown && !recovery_notice_shown {
                    if let Some(sync_status) = read_mount_sync_status(&sync_status_path)? {
                        if sync_status.recovered_pending_copy_count > 0 {
                            let example = sync_status
                                .recovered_pending_copy_paths
                                .first()
                                .cloned()
                                .unwrap_or_else(|| mountpoint.display().to_string());
                            ui::warning(&format!(
                                "Recovered {} pending-work file(s) as local-only read-only copies after an unclean restart. Example: {}. These copies are not synced back automatically. Review them with `hybridcipher mount-recovery list --root-id {}`.",
                                sync_status.recovered_pending_copy_count,
                                example,
                                final_root_id
                            ));
                            recovery_notice_shown = true;
                        }
                    }
                }
            }
        }
    }
}

/// Handle an explicit unmount request.
pub async fn handle_unmount(
    session_manager: &SessionManager,
    root_id: Option<Uuid>,
    force: bool,
    all: bool,
) -> Result<(), CliError> {
    ui::section("Unmount Encrypted View");

    if all {
        // Unmount all active mounts
        let all_mounts = list_all_mount_states(session_manager)?;
        if all_mounts.is_empty() {
            ui::info("No active mounts found.");
            return Ok(());
        }

        ui::info(&format!(
            "Unmounting {} active mount(s)...",
            all_mounts.len()
        ));
        let mut success_count = 0;
        let mut fail_count = 0;

        for state in all_mounts {
            ui::info(&format!(
                "Unmounting {} at {}...",
                state.encrypted_dir.display(),
                state.mountpoint.display()
            ));

            let state_path = mount_state_path(session_manager, state.root_id)?;
            if let Err(e) = unmount_single_mount(session_manager, &state_path, &state, force).await
            {
                warn!("Failed to unmount {}: {}", state.mountpoint.display(), e);
                fail_count += 1;
            } else {
                success_count += 1;
            }
        }

        if fail_count > 0 {
            ui::warning(&format!(
                "Unmounted {} mount(s), {} failed.",
                success_count, fail_count
            ));
            return Err(CliError::mount(format!(
                "{} mount(s) remained mounted after the unmount attempt.",
                fail_count
            )));
        }
        ui::success(&format!(
            "Successfully unmounted {} mount(s).",
            success_count
        ));
        Ok(())
    } else if let Some(root_id) = root_id {
        // Unmount specific mount by root_id
        let state_path = mount_state_path(session_manager, root_id)?;
        let Some(state) = read_runtime_state(&state_path)? else {
            return Err(CliError::mount(format!(
                "No mount found for root_id: {}",
                root_id
            )));
        };

        if state.root_id != root_id {
            return Err(CliError::mount(format!(
                "Mount state mismatch for root_id: {}",
                root_id
            )));
        }

        unmount_single_mount(session_manager, &state_path, &state, force).await
    } else {
        // Legacy behavior: unmount the "active" mount (first one found)
        let all_mounts = list_all_mount_states(session_manager)?;
        if all_mounts.is_empty() {
            ui::warning("No active mount recorded.");
            return Ok(());
        }

        if all_mounts.len() > 1 {
            ui::warning(&format!(
                "Multiple mounts found ({}). Unmounting the first one. Use --root-id to unmount a specific mount, or --all to unmount all.",
                all_mounts.len()
            ));
        }

        let state = all_mounts[0].clone();
        let state_path = mount_state_path(session_manager, state.root_id)?;
        unmount_single_mount(session_manager, &state_path, &state, force).await
    }
}

pub async fn handle_mount_command(
    session_manager: &SessionManager,
    command: MountCommands,
) -> Result<(), CliError> {
    session_manager.require_auth()?;
    match command {
        MountCommands::Status { root_id } => handle_mount_status(session_manager, root_id).await,
        MountCommands::Dehydrate { root_id } => {
            handle_mount_dehydrate(session_manager, root_id).await
        }
        MountCommands::Reset { root_id, force } => {
            handle_mount_reset(session_manager, root_id, force).await
        }
    }
}

async fn handle_mount_status(
    session_manager: &SessionManager,
    root_id: Option<Uuid>,
) -> Result<(), CliError> {
    ui::section("Mount Status");
    let state = resolve_target_mount_state(session_manager, root_id)?;
    let status_path = mount_sync_status_path(session_manager, state.root_id)?;
    let status = read_mount_sync_status(&status_path)?;

    ui::info(&format!("Root ID: {}", state.root_id));
    ui::info(&format!("Backend: {}", state.backend().as_str()));
    ui::info(&format!("Ready: {}", state.ready));
    ui::info(&format!("Mountpoint: {}", state.mountpoint.display()));
    ui::info(&format!(
        "Encrypted source: {}",
        state.encrypted_dir.display()
    ));
    if let Some(reason) = state.fallback_reason.as_deref() {
        ui::info(&format!("Fallback reason: {}", reason));
    }

    if let Some(status) = status {
        ui::info(&format!("Safe to unmount: {}", status.safe_to_unmount));
        ui::info(&format!(
            "Pending writeback/mutation count: {}",
            status.pending_writeback_count
        ));
        ui::info(&format!(
            "Pending refresh count: {}",
            status.pending_refresh_count
        ));
        ui::info(&format!(
            "Conflict count: {}",
            status.pending_conflict_count
        ));
        ui::info(&format!(
            "Recovery copy count: {}",
            status.recovered_pending_copy_count
        ));
        if let Some(err) = status.last_error.as_deref() {
            ui::warning(&format!("Last error: {}", err));
        }
        for reason in status.unsafe_reasons {
            ui::warning(&format!(
                "Unsafe reason: {}",
                format_mount_safety_reason(&state.mountpoint, &reason)
            ));
        }
    } else {
        ui::info("Runtime status: unavailable");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn cloud_provider_host(
    session_manager: &SessionManager,
) -> Result<hybridcipher_windows_cloud_provider::CloudProviderHost, CliError> {
    let user_config_dir = session_manager
        .user_config_dir()
        .ok_or_else(|| CliError::session("No active user context configured"))?;
    Ok(hybridcipher_windows_cloud_provider::CloudProviderHost::new(
        hybridcipher_windows_cloud_provider::ProviderHostConfig {
            user_config_dir,
            pipe_name: None,
        },
    ))
}

#[cfg(target_os = "windows")]
async fn handle_mount_dehydrate(
    session_manager: &SessionManager,
    root_id: Option<Uuid>,
) -> Result<(), CliError> {
    ui::section("Dehydrate Cloud Files Mount");
    let state = resolve_target_mount_state(session_manager, root_id)?;
    if !state.backend().is_windows_cloud_files() {
        return Err(CliError::mount(format!(
            "`hybridcipher mount dehydrate` is not applicable for {} mounts.",
            state.backend().as_str()
        )));
    }
    let host = cloud_provider_host(session_manager)?;
    let summary = host
        .dehydrate_root_path(&state.mountpoint)
        .map_err(|err| CliError::mount(err.to_string()))?;
    ui::success(&format!(
        "Dehydrated {} of {} file(s) under {}.",
        summary.dehydrated_count,
        summary.attempted_count,
        summary.sync_root_path.display()
    ));
    if summary.failed_count > 0 {
        ui::warning(&format!(
            "{} file(s) failed dehydration.",
            summary.failed_count
        ));
        for failure in summary.failures.iter().take(5) {
            ui::warning(failure);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn handle_mount_dehydrate(
    _session_manager: &SessionManager,
    _root_id: Option<Uuid>,
) -> Result<(), CliError> {
    Err(CliError::mount(
        "`hybridcipher mount dehydrate` is only supported for Windows Cloud Files mounts.",
    ))
}

#[cfg(target_os = "windows")]
async fn handle_mount_reset(
    session_manager: &SessionManager,
    root_id: Option<Uuid>,
    force: bool,
) -> Result<(), CliError> {
    ui::section("Reset Cloud Files Mount");
    let state = resolve_target_mount_state(session_manager, root_id)?;
    if !state.backend().is_windows_cloud_files() {
        return Err(CliError::mount(format!(
            "`hybridcipher mount reset` is not applicable for {} mounts.",
            state.backend().as_str()
        )));
    }
    let host = cloud_provider_host(session_manager)?;
    let pending = host
        .unsafe_pending_mutation_count(state.root_id)
        .map_err(|err| CliError::mount(err.to_string()))?;
    if pending > 0 && !force {
        return Err(CliError::mount(format!(
            "Refusing to reset Cloud Files root {} because {} pending mutation(s) are still unsafe. Re-run with --force to override.",
            state.root_id, pending
        )));
    }
    if !force && !state.requested_unmount {
        return Err(CliError::mount(
            "Refusing to reset an active Cloud Files mount. Run `hybridcipher unmount --root-id <id>` first, or re-run reset with --force.".to_string(),
        ));
    }
    host.reset_root(state.root_id)
        .map_err(|err| CliError::mount(err.to_string()))?;
    let state_path = mount_state_path(session_manager, state.root_id)?;
    clear_runtime_state(&state_path)?;
    let status_path = mount_sync_status_path(session_manager, state.root_id)?;
    clear_mount_sync_status(&status_path)?;
    if let Ok(journal_path) = host.mutation_journal_path(state.root_id) {
        let _ = fs::remove_file(journal_path);
    }
    ui::success(&format!("Reset Cloud Files root {}.", state.root_id));
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn handle_mount_reset(
    _session_manager: &SessionManager,
    _root_id: Option<Uuid>,
    _force: bool,
) -> Result<(), CliError> {
    Err(CliError::mount(
        "`hybridcipher mount reset` is only supported for Windows Cloud Files mounts.",
    ))
}

pub async fn handle_conflict_command(
    session_manager: &SessionManager,
    command: ConflictCommands,
) -> Result<(), CliError> {
    session_manager.require_auth()?;
    ui::section("Sync-Mount Conflicts");

    match command {
        ConflictCommands::List { root_id } => {
            let state = resolve_target_mount_state(session_manager, root_id)?;
            ensure_sync_mount_backend(&state, "conflict")?;
            let conflicts = read_mount_conflicts(session_manager, state.root_id)?;
            if conflicts.is_empty() {
                ui::info(&format!(
                    "No unresolved conflicts for mount {}.",
                    state.mountpoint.display()
                ));
                return Ok(());
            }

            ui::info(&format!(
                "{} unresolved conflict(s) for {}:",
                conflicts.len(),
                state.mountpoint.display()
            ));
            for conflict in conflicts {
                let merge_label = if conflict.text_merge_supported {
                    "text-merge"
                } else {
                    "winner-pick"
                };
                let live_label = if conflict.live_exists {
                    "live-present"
                } else {
                    "live-missing"
                };
                let edited_label = if conflict.edited { "edited" } else { "clean" };
                ui::info(&format!(
                    "  {}  LOCAL-ONLY  {}  [{} | {} | {}]",
                    conflict.id,
                    conflict.conflict_relative_path.display(),
                    merge_label,
                    live_label,
                    edited_label
                ));
            }
            Ok(())
        }
        ConflictCommands::Show {
            root_id,
            conflict_id,
        } => {
            let state = resolve_target_mount_state(session_manager, root_id)?;
            ensure_sync_mount_backend(&state, "conflict")?;
            let conflicts = read_mount_conflicts(session_manager, state.root_id)?;
            let conflict = conflicts
                .into_iter()
                .find(|entry| entry.id == conflict_id)
                .ok_or_else(|| {
                    CliError::mount(format!("Conflict {} was not found", conflict_id))
                })?;
            ui::info(&format!("Conflict ID: {}", conflict.id));
            ui::info(&format!("Mount: {}", state.mountpoint.display()));
            ui::info(&format!(
                "Live path: {}",
                state
                    .mountpoint
                    .join(&conflict.live_relative_path)
                    .display()
            ));
            ui::info(&format!(
                "Conflict copy: {}",
                state
                    .mountpoint
                    .join(&conflict.conflict_relative_path)
                    .display()
            ));
            ui::info("Status: LOCAL-ONLY until resolved");
            ui::info(&format!("Kind: {:?}", conflict.kind));
            ui::info(&format!(
                "Live path exists: {}",
                if conflict.live_exists { "yes" } else { "no" }
            ));
            ui::info(&format!(
                "Text merge supported: {}",
                if conflict.text_merge_supported {
                    "yes"
                } else {
                    "no"
                }
            ));
            ui::info(&format!(
                "Conflict edited locally: {}",
                if conflict.edited { "yes" } else { "no" }
            ));
            Ok(())
        }
        ConflictCommands::UseMounted {
            root_id,
            conflict_id,
        } => submit_conflict_resolution_action(
            session_manager,
            root_id,
            conflict_id,
            ConflictResolutionAction::KeepMountedFile,
            None,
            None,
        ),
        ConflictCommands::UseConflict {
            root_id,
            conflict_id,
        } => submit_conflict_resolution_action(
            session_manager,
            root_id,
            conflict_id,
            ConflictResolutionAction::UseConflictCopy,
            None,
            None,
        ),
        ConflictCommands::MergeText {
            root_id,
            conflict_id,
            merged_file,
        } => {
            let merged_text = fs::read_to_string(&merged_file).map_err(|err| {
                CliError::mount(format!(
                    "Failed to read merged text file {}: {}",
                    merged_file.display(),
                    err
                ))
            })?;
            submit_conflict_resolution_action(
                session_manager,
                root_id,
                conflict_id,
                ConflictResolutionAction::MergeText,
                Some(merged_text),
                None,
            )
        }
        ConflictCommands::SaveAsNew {
            root_id,
            conflict_id,
            destination,
        } => submit_conflict_resolution_action(
            session_manager,
            root_id,
            conflict_id,
            ConflictResolutionAction::SaveConflictAsNew,
            None,
            Some(destination),
        ),
        ConflictCommands::ArchiveDismiss {
            root_id,
            conflict_id,
        } => submit_conflict_resolution_action(
            session_manager,
            root_id,
            conflict_id,
            ConflictResolutionAction::ArchiveAndDismiss,
            None,
            None,
        ),
    }
}

pub async fn handle_recovery_command(
    session_manager: &SessionManager,
    command: MountRecoveryCommands,
) -> Result<(), CliError> {
    session_manager.require_auth()?;
    ui::section("Sync-Mount Recovery Copies");

    match command {
        MountRecoveryCommands::List { root_id } => {
            let state = resolve_target_mount_state(session_manager, root_id)?;
            ensure_sync_mount_backend(&state, "mount-recovery")?;
            let records = read_mount_recovery_copies(session_manager, state.root_id)?;
            if records.is_empty() {
                ui::info(&format!(
                    "No unresolved recovery copies for mount {}.",
                    state.mountpoint.display()
                ));
                return Ok(());
            }

            ui::info(&format!(
                "{} recovery copy/copies for {}:",
                records.len(),
                state.mountpoint.display()
            ));
            for record in records {
                let merge_label = if record.text_preview_supported {
                    "text-preview"
                } else {
                    "binary-or-large"
                };
                let live_label = if record.live_exists {
                    "live-present"
                } else {
                    "live-missing"
                };
                ui::info(&format!(
                    "  LOCAL-ONLY  {}  [{} | {}]",
                    record.recovery_relative_path.display(),
                    merge_label,
                    live_label
                ));
            }
            Ok(())
        }
        MountRecoveryCommands::Show {
            root_id,
            recovery_path,
        } => {
            let state = resolve_target_mount_state(session_manager, root_id)?;
            ensure_sync_mount_backend(&state, "mount-recovery")?;
            let record = read_mount_recovery_copies(session_manager, state.root_id)?
                .into_iter()
                .find(|entry| entry.recovery_relative_path == recovery_path)
                .ok_or_else(|| {
                    CliError::mount(format!(
                        "Recovery copy {} was not found",
                        recovery_path.display()
                    ))
                })?;
            ui::info(&format!("Mount: {}", state.mountpoint.display()));
            ui::info(&format!(
                "Live path: {}",
                state.mountpoint.join(&record.live_relative_path).display()
            ));
            ui::info(&format!(
                "Recovery copy: {}",
                state
                    .mountpoint
                    .join(&record.recovery_relative_path)
                    .display()
            ));
            ui::info("Status: LOCAL-ONLY until resolved");
            ui::info(&format!(
                "Live path exists: {}",
                if record.live_exists { "yes" } else { "no" }
            ));
            ui::info(&format!(
                "Text preview available: {}",
                if record.text_preview_supported {
                    "yes"
                } else {
                    "no"
                }
            ));
            ui::info(&format!("Created: {}", record.created_at.to_rfc3339()));
            Ok(())
        }
        MountRecoveryCommands::ReplaceMounted {
            root_id,
            recovery_path,
        } => submit_recovery_resolution_action(
            session_manager,
            root_id,
            recovery_path,
            RecoveryCopyResolutionAction::ReplaceMountedFile,
            None,
        ),
        MountRecoveryCommands::SaveAsNew {
            root_id,
            recovery_path,
            destination,
        } => submit_recovery_resolution_action(
            session_manager,
            root_id,
            recovery_path,
            RecoveryCopyResolutionAction::SaveAsNew,
            Some(destination),
        ),
        MountRecoveryCommands::ArchiveDismiss {
            root_id,
            recovery_path,
        } => submit_recovery_resolution_action(
            session_manager,
            root_id,
            recovery_path,
            RecoveryCopyResolutionAction::ArchiveAndDismiss,
            None,
        ),
    }
}

fn resolve_target_mount_state(
    session_manager: &SessionManager,
    root_id: Option<Uuid>,
) -> Result<MountRuntimeState, CliError> {
    if let Some(root_id) = root_id {
        let state_path = mount_state_path(session_manager, root_id)?;
        return read_runtime_state(&state_path)?.ok_or_else(|| {
            CliError::mount(format!("No active mount found for root_id {}", root_id))
        });
    }

    let mounts = list_all_mount_states(session_manager)?;
    match mounts.as_slice() {
        [only] => Ok(only.clone()),
        [] => Err(CliError::mount(
            "No active mounts found. Mount a folder first.".to_string(),
        )),
        _ => Err(CliError::mount(
            "Multiple mounts are active. Re-run with --root-id.".to_string(),
        )),
    }
}

fn submit_conflict_resolution_action(
    session_manager: &SessionManager,
    root_id: Option<Uuid>,
    conflict_id: Uuid,
    action: ConflictResolutionAction,
    merged_text: Option<String>,
    destination_path: Option<PathBuf>,
) -> Result<(), CliError> {
    let state = resolve_target_mount_state(session_manager, root_id)?;
    ensure_sync_mount_backend(&state, "conflict")?;
    let request = ConflictResolutionRequest {
        request_id: Uuid::new_v4(),
        conflict_id,
        action,
        merged_text,
        destination_path,
        requested_at: chrono::Utc::now(),
    };
    let response = resolve_mount_conflict_request(session_manager, state.root_id, &request)?;
    if !response.success {
        return Err(CliError::mount(
            response
                .error
                .unwrap_or_else(|| "Conflict resolution failed".to_string()),
        ));
    }

    let result = response
        .result
        .ok_or_else(|| CliError::mount("Conflict resolution completed without a result"))?;
    ui::success(&format!(
        "Resolved conflict {}",
        result.resolved_conflict_id
    ));
    if let Some(path) = result.live_path {
        ui::info(&format!("Live path: {}", path.display()));
    }
    for archive_path in result.archive_paths {
        ui::info(&format!("Archived: {}", archive_path.display()));
    }
    Ok(())
}

fn submit_recovery_resolution_action(
    session_manager: &SessionManager,
    root_id: Option<Uuid>,
    recovery_relative_path: PathBuf,
    action: RecoveryCopyResolutionAction,
    destination_path: Option<PathBuf>,
) -> Result<(), CliError> {
    let state = resolve_target_mount_state(session_manager, root_id)?;
    ensure_sync_mount_backend(&state, "mount-recovery")?;
    let request = RecoveryCopyResolutionRequest {
        request_id: Uuid::new_v4(),
        recovery_relative_path: recovery_relative_path.clone(),
        action,
        destination_path,
        requested_at: chrono::Utc::now(),
    };
    let response = resolve_mount_recovery_request(session_manager, state.root_id, &request)?;
    if !response.success {
        return Err(CliError::mount(
            response
                .error
                .unwrap_or_else(|| "Recovery copy resolution failed".to_string()),
        ));
    }

    let result = response
        .result
        .ok_or_else(|| CliError::mount("Recovery resolution completed without a result"))?;
    ui::success(&format!(
        "Resolved recovery copy {}",
        result.resolved_recovery_relative_path.display()
    ));
    if let Some(path) = result.live_path {
        ui::info(&format!("Live path: {}", path.display()));
    }
    for archive_path in result.archive_paths {
        ui::info(&format!("Archived: {}", archive_path.display()));
    }
    Ok(())
}

/// Unmount a single mount
async fn unmount_single_mount(
    session_manager: &SessionManager,
    state_path: &Path,
    state: &MountRuntimeState,
    force: bool,
) -> Result<(), CliError> {
    if state.requested_unmount {
        ui::info("Unmount already requested – waiting for mount process to exit.");
        return Ok(());
    }

    if runtime_mount_state_is_stale(state).await {
        warn!(
            "Cleaning stale mount state for {} because the recorded host is no longer active",
            state.mountpoint.display()
        );
        if let Err(err) = cleanup_mountpoint_safe(&state.mountpoint) {
            warn!(
                "Safe cleanup failed for stale mountpoint {}: {}. Preserving mountpoint contents.",
                state.mountpoint.display(),
                err
            );
        }
        clear_runtime_state(state_path)?;
        let sync_status_path = mount_sync_status_path(session_manager, state.root_id)?;
        clear_mount_sync_status(&sync_status_path)?;
        ui::success(&format!(
            "Cleaned stale mount state for {}.",
            state.mountpoint.display()
        ));
        return Ok(());
    }

    if !force {
        if let Some(sync_status) =
            wait_for_safe_unmount_status(session_manager, state.root_id, &state.mountpoint).await?
        {
            if let Some(message) =
                unsafe_unmount_block_message(state.root_id, &state.mountpoint, &sync_status)
            {
                return Err(CliError::mount(message));
            }
        }
    }

    #[cfg(target_os = "windows")]
    if state.backend().is_windows_cloud_files() && !force {
        let host = cloud_provider_host(session_manager)?;
        if let Err(err) = host.dehydrate_root_path(&state.mountpoint) {
            return Err(CliError::mount(format!(
                "Cloud Files dehydration failed before unmount: {}. Re-run with --force to disconnect without dehydration.",
                err
            )));
        }
    }

    // Mark unmount requested in state file - DO NOT DELETE YET
    // The mount process needs to read this flag to exit gracefully
    let mut updated_state = state.clone();
    updated_state.requested_unmount = true;
    write_runtime_state(state_path, &updated_state)?;

    #[cfg(not(target_os = "linux"))]
    let _ = force;

    if let Err(err) = request_fuse_unmount(&state.mountpoint, force).await {
        warn!("Unmount command returned an error: {}", err);
    }

    // Wait for mount process to detect unmount request and exit
    // Poll the state file to see if mount process has cleared it
    let max_wait = Duration::from_secs(30);
    let check_interval = Duration::from_millis(500);
    let mut waited = Duration::from_millis(0);
    let mut mount_exited = false;

    while waited < max_wait {
        // Check if state file still exists and has requested_unmount flag
        if let Ok(Some(current_state)) = read_runtime_state(state_path) {
            if current_state.requested_unmount {
                // Mount process should be exiting, wait a bit more
                tokio::time::sleep(check_interval).await;
                waited += check_interval;
                continue;
            }
        } else {
            // State file was cleared by mount process - it has exited
            mount_exited = true;
            break;
        }

        if mountpoint_is_detached(&state.mountpoint).await {
            mount_exited = true;
            break;
        }

        tokio::time::sleep(check_interval).await;
        waited += check_interval;
    }

    if mountpoint_has_fuse_mount(&state.mountpoint).await {
        warn!(
            "Mountpoint {} is still mounted. Force unmounting before cleanup.",
            state.mountpoint.display()
        );
        if let Err(err) = request_fuse_unmount(&state.mountpoint, true).await {
            warn!(
                "Force unmount failed: {}. Proceeding with cleanup anyway.",
                err
            );
        } else {
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }

    if !mount_exited {
        warn!(
            "Mount process may still be running after {} seconds. Proceeding with cleanup anyway.",
            max_wait.as_secs()
        );
    }

    // Only perform non-destructive cleanup here. If the mountpoint still contains
    // files, preserve it for manual recovery or the shared stale-mount quarantine path.
    if let Err(err) = cleanup_mountpoint_safe(&state.mountpoint) {
        warn!(
            "Safe cleanup failed for mountpoint {}: {}. Preserving mountpoint contents.",
            state.mountpoint.display(),
            err
        );
    } else {
        info!(
            "Successfully cleaned up mountpoint {}",
            state.mountpoint.display()
        );
    }

    // Remove state file after cleanup
    clear_runtime_state(state_path)?;

    ui::success(&format!(
        "Unmount requested for {}. The mount process will exit shortly.",
        state.mountpoint.display()
    ));
    Ok(())
}

async fn runtime_mount_state_is_stale(state: &MountRuntimeState) -> bool {
    if mountpoint_has_fuse_mount(&state.mountpoint).await {
        return false;
    }

    if let Some(host_pid) = state.host_pid {
        if process_is_running(host_pid) {
            return false;
        }

        if state.backend().is_windows_cloud_files() {
            return true;
        }

        return state.backend().is_sync()
            || state.backend().is_macos_file_provider()
            || mountpoint_is_detached(&state.mountpoint).await;
    }

    state.backend().is_sync() && mountpoint_is_detached(&state.mountpoint).await
}

fn cleanup_stale_mount_before_retry(
    state_path: &Path,
    sync_status_path: &Path,
    state: &MountRuntimeState,
) -> Result<(), CliError> {
    let can_remove_decrypted_view = state.backend().is_sync()
        && read_mount_sync_status(sync_status_path)?
            .map(|status| status.safe_to_unmount)
            .unwrap_or(false);

    if can_remove_decrypted_view {
        cleanup_mountpoint_tree_for_safe_sync_remount(&state.mountpoint)?;
    } else {
        cleanup_mountpoint_safe(&state.mountpoint)?;
    }

    clear_runtime_state(state_path)?;
    clear_mount_sync_status(sync_status_path)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn process_is_running(pid: u32) -> bool {
    use std::os::windows::process::CommandExt;

    let filter = format!("PID eq {}", pid);
    let mut command = ProcessCommand::new("tasklist");
    command
        .args(["/FI", &filter, "/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW);
    let output = command.output();

    let Ok(output) = output else {
        return true;
    };
    if !output.status.success() {
        return true;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .any(|line| line.contains(&format!(",\"{}\",", pid)) || line.contains("hybridcipher"))
        && !stdout.contains("No tasks are running")
}

#[cfg(target_os = "macos")]
fn process_is_running(pid: u32) -> bool {
    ProcessCommand::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn process_is_running(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{}", pid)).exists()
}

async fn active_enrolled_roots(session_manager: &SessionManager) -> Result<Vec<PathBuf>, CliError> {
    let client = session_manager.create_client().await?;
    let mut roots = client.coverage_roots().await?;
    roots.retain(|root| root.state == CoverageRootState::Active);
    roots.sort_by(|a, b| a.path.to_string_lossy().cmp(&b.path.to_string_lossy()));
    Ok(roots.into_iter().map(|r| r.path).collect())
}

/// Get all active enrolled roots with their root_ids
async fn active_enrolled_roots_with_ids(
    session_manager: &SessionManager,
) -> Result<Vec<CoverageRoot>, CliError> {
    let client = session_manager.create_client().await?;
    let mut roots = client.coverage_roots().await?;
    roots.retain(|root| root.state == CoverageRootState::Active);
    roots.sort_by(|a, b| a.path.to_string_lossy().cmp(&b.path.to_string_lossy()));
    Ok(roots)
}

/// Find an enrolled folder by root_id
async fn find_enrolled_folder_by_root_id(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<PathBuf, CliError> {
    let roots = active_enrolled_roots_with_ids(session_manager).await?;
    roots
        .iter()
        .find(|root| root.root_id == root_id)
        .map(|root| root.path.clone())
        .ok_or_else(|| {
            CliError::mount(format!(
                "No enrolled folder found with root_id: {}",
                root_id
            ))
        })
}

async fn hydrate_unmanaged_files_before_mount(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<(), CliError> {
    let client = session_manager.create_client().await?;
    let mut roots = client.coverage_roots().await?;
    let Some(root) = roots
        .drain(..)
        .find(|root| root.root_id == root_id && root.state == CoverageRootState::Active)
    else {
        warn!(
            "Skipping pre-mount hydration because no active coverage root matched {}",
            root_id
        );
        return Ok(());
    };

    ui::info("Checking protected folder for unmanaged plaintext before mount...");
    let outcome = coverage_workflows::hydrate_existing_root(&client, root)
        .await
        .map_err(|err| CliError::coverage(format!("Pre-mount hydration failed: {}", err)))?;

    if outcome.hydration.newly_encrypted > 0 {
        ui::info(&format!(
            "Encrypted {} unmanaged file{} before mount.",
            outcome.hydration.newly_encrypted,
            if outcome.hydration.newly_encrypted == 1 {
                ""
            } else {
                "s"
            }
        ));
    }
    if outcome.hydration.skipped_due_to_errors > 0 {
        ui::warning(&format!(
            "{} file{} could not be encrypted before mount and may not appear in the mounted view.",
            outcome.hydration.skipped_due_to_errors,
            if outcome.hydration.skipped_due_to_errors == 1 {
                ""
            } else {
                "s"
            }
        ));
    }
    Ok(())
}

fn env_strategy_override() -> Option<MountStrategyArg> {
    match std::env::var("HYBRIDCIPHER_FORCE_FUSE") {
        Ok(value) if matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES") => {
            Some(MountStrategyArg::Fuse)
        }
        Ok(value) if matches!(value.as_str(), "0" | "false" | "FALSE" | "no" | "NO") => {
            Some(MountStrategyArg::Sync)
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn fuse_prereqs() -> Result<(), CliError> {
    hybridcipher_mount_sync::mount_runner::fuse_prereqs().map_err(|e| CliError::mount(e))
}

#[cfg(target_os = "windows")]
fn cloud_files_prereqs() -> Result<(), String> {
    let host = hybridcipher_windows_cloud_provider::CloudProviderHost::new(
        hybridcipher_windows_cloud_provider::ProviderHostConfig {
            user_config_dir: PathBuf::new(),
            pipe_name: None,
        },
    );
    let status = host.status();
    if status.available && status.native_callbacks_ready {
        Ok(())
    } else {
        Err(status.message.unwrap_or_else(|| {
            "Windows Cloud Files provider native callbacks are not ready.".to_string()
        }))
    }
}

#[cfg(target_os = "macos")]
fn macos_file_provider_prereqs(session_manager: &SessionManager) -> Result<(), String> {
    let user_config_dir = session_manager
        .user_config_dir()
        .ok_or_else(|| "No active user context configured".to_string())?;
    let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
        hybridcipher_macos_file_provider::ProviderHostConfig {
            user_config_dir,
            socket_path: None,
            provider_identifier: None,
        },
    );
    let status = host.status();
    if status.available && status.extension_ready {
        Ok(())
    } else {
        Err(status
            .message
            .unwrap_or_else(|| "macOS File Provider extension is not ready.".to_string()))
    }
}

#[cfg(target_os = "windows")]
async fn run_cloud_files_mount(
    client: LocalClient,
    user_config_dir: PathBuf,
    root_id: Uuid,
    encrypted_dir: PathBuf,
    mountpoint: PathBuf,
    mut stop_rx: watch::Receiver<bool>,
    ready: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(), String> {
    let host = hybridcipher_windows_cloud_provider::CloudProviderHost::new(
        hybridcipher_windows_cloud_provider::ProviderHostConfig {
            user_config_dir,
            pipe_name: None,
        },
    );
    let status = host.status();
    if !status.native_callbacks_ready {
        return Err(status.message.unwrap_or_else(|| {
            "Windows Cloud Files provider native callbacks are not implemented yet.".to_string()
        }));
    }

    let registration = hybridcipher_windows_cloud_provider::CloudRootRegistration {
        root_id,
        sync_root_path: mountpoint.clone(),
        encrypted_root: encrypted_dir,
        display_name: derive_mount_label(&mountpoint, root_id),
    };
    host.register_root(&registration)
        .map_err(|err| err.to_string())?;
    host.sync_placeholders(&registration)
        .map_err(|err| err.to_string())?;
    let bridge = hybridcipher_windows_cloud_provider::local_provider_bridge(Arc::new(client));
    host.start_root_with_bridge(root_id, bridge)
        .await
        .map_err(|err| err.to_string())?;
    if let Some(ready) = ready {
        ready.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    while stop_rx.changed().await.is_ok() {
        if *stop_rx.borrow() {
            host.stop_root(root_id).map_err(|err| err.to_string())?;
            host.unregister_system_domain(&registration)
                .and_then(|_| host.unregister_domain_state(root_id))
                .map_err(|err| err.to_string())?;
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn run_macos_file_provider_mount(
    client: LocalClient,
    user_config_dir: PathBuf,
    root_id: Uuid,
    encrypted_dir: PathBuf,
    mountpoint: PathBuf,
    mut stop_rx: watch::Receiver<bool>,
    ready: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(), String> {
    let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
        hybridcipher_macos_file_provider::ProviderHostConfig {
            user_config_dir,
            socket_path: None,
            provider_identifier: Some("com.hybridcipher.app.HybridCipherFileProvider".to_string()),
        },
    );
    let status = host.status();
    if !status.extension_ready {
        return Err(status
            .message
            .unwrap_or_else(|| "macOS File Provider extension is not ready.".to_string()));
    }

    let registration = hybridcipher_macos_file_provider::FileProviderDomainRegistration {
        root_id,
        domain_identifier: format!("com.hybridcipher.root.{root_id}"),
        encrypted_root: encrypted_dir,
        display_name: derive_mount_label(&mountpoint, root_id),
        user_visible_url: Some(mountpoint.clone()),
    };
    host.register_domain(&registration)
        .map_err(|err| err.to_string())?;
    host.register_system_domain(&registration)
        .map_err(|err| err.to_string())?;
    let excluded_patterns = client.excluded_file_patterns();
    let crypto = Arc::new(hybridcipher_provider_core::ClientMountCrypto::new(
        Arc::new(client),
    ));
    host.start_root_with_crypto_and_exclusions(root_id, crypto, excluded_patterns)
        .await
        .map_err(|err| err.to_string())?;
    if let Some(ready) = ready {
        ready.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    while stop_rx.changed().await.is_ok() {
        if *stop_rx.borrow() {
            host.stop_root(root_id).map_err(|err| err.to_string())?;
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn mountpoint_has_fuse_mount(path: &Path) -> bool {
    use hybridcipher_mount::platform::is_mounted as check_mounted;

    check_mounted(path).await.unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
async fn mountpoint_has_fuse_mount(_path: &Path) -> bool {
    false
}

#[cfg(target_os = "linux")]
async fn request_fuse_unmount(path: &Path, force: bool) -> Result<(), CliError> {
    if mountpoint_has_fuse_mount(path).await {
        hybridcipher_mount::unmount_hybridcipher(path, force)
            .await
            .map_err(|err| CliError::mount(format!("Failed to unmount FUSE mount: {}", err)))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
async fn request_fuse_unmount(_path: &Path, _force: bool) -> Result<(), CliError> {
    Ok(())
}

async fn mountpoint_is_detached(path: &Path) -> bool {
    if !path.exists() {
        return true;
    }

    if mountpoint_has_fuse_mount(path).await {
        return false;
    }

    is_directory_empty(path).unwrap_or(false)
}

fn preferences_path(session_manager: &SessionManager) -> Result<PathBuf, CliError> {
    let user_dir = session_manager
        .user_config_dir()
        .ok_or_else(|| CliError::session("No active user context configured"))?;
    Ok(user_dir.join("mount_preferences.json"))
}

fn load_mount_preferences(session_manager: &SessionManager) -> Result<MountPreferences, CliError> {
    let path = preferences_path(session_manager)?;
    if !path.exists() {
        return Ok(MountPreferences::default());
    }
    let raw = fs::read_to_string(&path).map_err(|e| {
        CliError::configuration(format!(
            "Failed to read mount preferences {}: {}",
            path.display(),
            e
        ))
    })?;
    serde_json::from_str(&raw)
        .map_err(|e| CliError::configuration(format!("Failed to parse mount preferences: {}", e)))
}

fn save_mount_preferences(
    session_manager: &SessionManager,
    prefs: &MountPreferences,
) -> Result<(), CliError> {
    let path = preferences_path(session_manager)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            CliError::configuration(format!(
                "Failed to prepare preference directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    let payload = serde_json::to_string_pretty(prefs).map_err(|e| {
        CliError::configuration(format!("Failed to serialize mount preferences: {}", e))
    })?;
    fs::write(&path, payload).map_err(|e| {
        CliError::configuration(format!(
            "Failed to persist mount preferences {}: {}",
            path.display(),
            e
        ))
    })
}

fn mount_state_dir(session_manager: &SessionManager) -> Result<PathBuf, CliError> {
    let user_dir = session_manager
        .user_config_dir()
        .ok_or_else(|| CliError::session("No active user context configured"))?;
    let state_dir = user_dir.join("mount_states");
    fs::create_dir_all(&state_dir).map_err(|e| {
        CliError::configuration(format!(
            "Failed to create mount state directory {}: {}",
            state_dir.display(),
            e
        ))
    })?;
    Ok(state_dir)
}

fn mount_state_path(session_manager: &SessionManager, root_id: Uuid) -> Result<PathBuf, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    Ok(state_dir.join(format!("mount_state_{}.json", root_id)))
}

fn mount_sync_status_path(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<PathBuf, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    Ok(state_dir.join(format!("mount_sync_status_{}.json", root_id)))
}

/// Get path to state file for a specific root_id (for backward compatibility and migration)
fn mount_state_path_legacy(session_manager: &SessionManager) -> Result<PathBuf, CliError> {
    let user_dir = session_manager
        .user_config_dir()
        .ok_or_else(|| CliError::session("No active user context configured"))?;
    Ok(user_dir.join("mount_state.json"))
}

fn write_runtime_state(path: &Path, state: &MountRuntimeState) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            CliError::configuration(format!(
                "Failed to create mount state directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    let payload = serde_json::to_string_pretty(state)
        .map_err(|e| CliError::configuration(format!("Failed to serialize mount state: {}", e)))?;
    fs::write(path, payload).map_err(|e| {
        CliError::configuration(format!(
            "Failed to write mount state {}: {}",
            path.display(),
            e
        ))
    })
}

fn read_runtime_state(path: &Path) -> Result<Option<MountRuntimeState>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path).map_err(|e| {
        CliError::configuration(format!(
            "Failed to read mount state {}: {}",
            path.display(),
            e
        ))
    })?;
    let state = serde_json::from_str(&raw)
        .map_err(|e| CliError::configuration(format!("Failed to parse mount state: {}", e)))?;
    Ok(Some(state))
}

fn read_mount_sync_status(path: &Path) -> Result<Option<MountSyncRuntimeStatus>, CliError> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path).map_err(|e| {
        CliError::configuration(format!(
            "Failed to read mount sync status {}: {}",
            path.display(),
            e
        ))
    })?;
    let status = serde_json::from_str(&raw).map_err(|e| {
        CliError::configuration(format!(
            "Failed to parse mount sync status {}: {}",
            path.display(),
            e
        ))
    })?;
    Ok(Some(status))
}

fn mount_conflict_registry_path(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<PathBuf, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    Ok(sync_mount_conflict_registry_path(
        &state_dir,
        &root_id.to_string(),
    ))
}

fn mount_conflict_request_dir(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<PathBuf, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    Ok(sync_mount_conflict_action_requests_dir(
        &state_dir,
        &root_id.to_string(),
    ))
}

fn mount_conflict_result_dir(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<PathBuf, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    Ok(sync_mount_conflict_action_results_dir(
        &state_dir,
        &root_id.to_string(),
    ))
}

fn mount_recovery_registry_path(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<PathBuf, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    Ok(sync_mount_recovery_registry_path(
        &state_dir,
        &root_id.to_string(),
    ))
}

fn mount_recovery_request_dir(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<PathBuf, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    Ok(sync_mount_recovery_action_requests_dir(
        &state_dir,
        &root_id.to_string(),
    ))
}

fn mount_recovery_result_dir(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<PathBuf, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    Ok(sync_mount_recovery_action_results_dir(
        &state_dir,
        &root_id.to_string(),
    ))
}

fn read_mount_conflicts(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<Vec<MountConflictRecord>, CliError> {
    let path = mount_conflict_registry_path(session_manager, root_id)?;
    load_mount_conflict_registry(&path)
        .map_err(|err| CliError::mount(format!("Failed to read conflict registry: {}", err)))
}

fn read_mount_recovery_copies(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<Vec<MountRecoveryCopyRecord>, CliError> {
    let path = mount_recovery_registry_path(session_manager, root_id)?;
    load_mount_recovery_registry(&path)
        .map_err(|err| CliError::mount(format!("Failed to read recovery registry: {}", err)))
}

fn resolve_mount_conflict_request(
    session_manager: &SessionManager,
    root_id: Uuid,
    request: &ConflictResolutionRequest,
) -> Result<ConflictResolutionResponse, CliError> {
    let request_dir = mount_conflict_request_dir(session_manager, root_id)?;
    let result_dir = mount_conflict_result_dir(session_manager, root_id)?;
    fs::create_dir_all(&request_dir).map_err(|err| {
        CliError::configuration(format!(
            "Failed to create conflict request directory {}: {}",
            request_dir.display(),
            err
        ))
    })?;
    fs::create_dir_all(&result_dir).map_err(|err| {
        CliError::configuration(format!(
            "Failed to create conflict result directory {}: {}",
            result_dir.display(),
            err
        ))
    })?;

    let request_path = request_dir.join(format!("{}.json", request.request_id));
    let payload = serde_json::to_vec_pretty(request).map_err(|err| {
        CliError::configuration(format!("Failed to serialize conflict request: {}", err))
    })?;
    fs::write(&request_path, payload).map_err(|err| {
        CliError::configuration(format!(
            "Failed to write conflict request {}: {}",
            request_path.display(),
            err
        ))
    })?;

    let result_path = result_dir.join(format!("{}.json", request.request_id));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if result_path.exists() {
            let raw = fs::read_to_string(&result_path).map_err(|err| {
                CliError::configuration(format!(
                    "Failed to read conflict result {}: {}",
                    result_path.display(),
                    err
                ))
            })?;
            let response: ConflictResolutionResponse =
                serde_json::from_str(&raw).map_err(|err| {
                    CliError::configuration(format!(
                        "Failed to parse conflict result {}: {}",
                        result_path.display(),
                        err
                    ))
                })?;
            let _ = fs::remove_file(&result_path);
            return Ok(response);
        }
        if Instant::now() >= deadline {
            return Err(CliError::mount(format!(
                "Timed out waiting for conflict resolution result for {}",
                request.conflict_id
            )));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn resolve_mount_recovery_request(
    session_manager: &SessionManager,
    root_id: Uuid,
    request: &RecoveryCopyResolutionRequest,
) -> Result<RecoveryCopyResolutionResponse, CliError> {
    let request_dir = mount_recovery_request_dir(session_manager, root_id)?;
    let result_dir = mount_recovery_result_dir(session_manager, root_id)?;
    fs::create_dir_all(&request_dir).map_err(|err| {
        CliError::configuration(format!(
            "Failed to create recovery request directory {}: {}",
            request_dir.display(),
            err
        ))
    })?;
    fs::create_dir_all(&result_dir).map_err(|err| {
        CliError::configuration(format!(
            "Failed to create recovery result directory {}: {}",
            result_dir.display(),
            err
        ))
    })?;

    let request_path = request_dir.join(format!("{}.json", request.request_id));
    let payload = serde_json::to_vec_pretty(request).map_err(|err| {
        CliError::configuration(format!("Failed to serialize recovery request: {}", err))
    })?;
    fs::write(&request_path, payload).map_err(|err| {
        CliError::configuration(format!(
            "Failed to write recovery request {}: {}",
            request_path.display(),
            err
        ))
    })?;

    let result_path = result_dir.join(format!("{}.json", request.request_id));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if result_path.exists() {
            let raw = fs::read_to_string(&result_path).map_err(|err| {
                CliError::configuration(format!(
                    "Failed to read recovery result {}: {}",
                    result_path.display(),
                    err
                ))
            })?;
            let response: RecoveryCopyResolutionResponse =
                serde_json::from_str(&raw).map_err(|err| {
                    CliError::configuration(format!(
                        "Failed to parse recovery result {}: {}",
                        result_path.display(),
                        err
                    ))
                })?;
            let _ = fs::remove_file(&result_path);
            return Ok(response);
        }
        if Instant::now() >= deadline {
            return Err(CliError::mount(format!(
                "Timed out waiting for recovery resolution result for {}",
                request.recovery_relative_path.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn mount_sync_unsafe_reasons(
    mountpoint: &Path,
    status: &MountSyncRuntimeStatus,
) -> Vec<MountSafetyReason> {
    if !status.unsafe_reasons.is_empty() {
        return status
            .unsafe_reasons
            .iter()
            .cloned()
            .map(|reason| match reason {
                MountSafetyReason::PendingWriteback {
                    count,
                    oldest_age_ms,
                    mut sample_paths,
                    last_error,
                } => {
                    if sample_paths.is_empty() {
                        sample_paths = status
                            .pending_writeback_paths
                            .iter()
                            .take(3)
                            .cloned()
                            .collect();
                    }
                    MountSafetyReason::PendingWriteback {
                        count,
                        oldest_age_ms,
                        sample_paths,
                        last_error: last_error.or_else(|| status.last_error.clone()),
                    }
                }
                other => other,
            })
            .collect();
    }

    let mut reasons = Vec::new();
    if status.pending_conflict_count > 0 {
        let sample_paths = status
            .edited_conflict_paths
            .iter()
            .chain(status.conflict_paths.iter())
            .take(3)
            .cloned()
            .collect::<Vec<_>>();
        reasons.push(MountSafetyReason::Conflict {
            count: status.pending_conflict_count,
            edited_count: status.edited_conflict_count,
            sample_paths,
        });
    }
    if status.pending_writeback_count > 0 {
        reasons.push(MountSafetyReason::PendingWriteback {
            count: status.pending_writeback_count,
            oldest_age_ms: status.pending_writeback_oldest_age_ms.unwrap_or(0),
            sample_paths: status
                .pending_writeback_paths
                .iter()
                .take(3)
                .cloned()
                .collect(),
            last_error: status.last_error.clone(),
        });
    }
    if status.pending_refresh_count > 0 {
        reasons.push(MountSafetyReason::PendingRefresh {
            count: status.pending_refresh_count,
        });
    }
    if status.pending_open_unlinked_count > 0 {
        let sample_paths = if status.open_unlinked_paths.is_empty() {
            vec![mountpoint.display().to_string()]
        } else {
            status.open_unlinked_paths.iter().take(3).cloned().collect()
        };
        reasons.push(MountSafetyReason::DeletedOpen {
            count: status.pending_open_unlinked_count,
            sample_paths,
        });
    }
    if !matches!(status.low_space_mode, LowSpaceMode::Healthy) {
        reasons.push(MountSafetyReason::LowSpaceDegraded {
            mode: status.low_space_mode,
            count: status.pending_low_space_path_count,
            sample_paths: status.low_space_paths.iter().take(3).cloned().collect(),
        });
    }
    if status.recovered_pending_copy_count > 0 {
        reasons.push(MountSafetyReason::RecoveryCopiesPresent {
            count: status.recovered_pending_copy_count,
            sample_paths: status
                .recovered_pending_copy_paths
                .iter()
                .take(3)
                .cloned()
                .collect(),
        });
    }

    reasons
}

fn format_mount_safety_reason(mountpoint: &Path, reason: &MountSafetyReason) -> String {
    match reason {
        MountSafetyReason::PendingWriteback {
            count,
            oldest_age_ms,
            sample_paths,
            last_error,
        } => {
            let mut reason = format!(
                "{count} pending encrypted commit(s) still need to finish before the newest local changes are protected. Oldest pending commit age: {}s.",
                oldest_age_ms / 1000
            );
            if let Some(example) = sample_paths.first() {
                reason.push_str(&format!(" Example: {example}"));
            }
            if let Some(error) = last_error
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                reason.push_str(&format!(" Last error: {error}"));
            }
            reason
        }
        MountSafetyReason::PendingRefresh { count } => format!(
            "{count} pending plaintext refresh(es) are still rebuilding the local mount state."
        ),
        MountSafetyReason::Conflict {
            count,
            edited_count,
            sample_paths,
        } => {
            let example = sample_paths
                .first()
                .cloned()
                .unwrap_or_else(|| mountpoint.display().to_string());
            let mut reason = format!(
                "{count} unresolved conflict file(s) remain local-only until they are resolved or merged back. Example: {example}"
            );
            if *edited_count > 0 {
                reason.push_str(&format!(
                    " {edited_count} conflict file(s) were edited locally and are still not protected by encrypted sync."
                ));
            }
            reason
        }
        MountSafetyReason::DeletedOpen {
            count,
            sample_paths,
        } => {
            let example = sample_paths
                .first()
                .cloned()
                .unwrap_or_else(|| mountpoint.display().to_string());
            format!("{count} deleted-open path(s) are still active. Example: {example}")
        }
        MountSafetyReason::TransactionalBlocked {
            count,
            sample_paths,
        } => {
            let example = sample_paths
                .first()
                .cloned()
                .unwrap_or_else(|| mountpoint.display().to_string());
            format!(
                "{count} transactional path(s) are blocked because sync mount does not provide atomic-set guarantees for databases, packages, or bundle-style formats. Example: {example}"
            )
        }
        MountSafetyReason::HardLinkBlocked {
            count,
            sample_paths,
        } => {
            let example = sample_paths
                .first()
                .cloned()
                .unwrap_or_else(|| mountpoint.display().to_string());
            format!(
                "{count} hard-linked file(s) are blocked because sync mount does not preserve hard-link semantics. Example: {example} Break the hard link or replace it with an independent copy to resume protected sync."
            )
        }
        MountSafetyReason::LowSpaceDegraded {
            mode,
            count,
            sample_paths,
        } => {
            let mut reason = if *count > 0 {
                format!("low-space degraded mode ({mode:?}) is active for {count} path(s)")
            } else {
                format!("low-space degraded mode ({mode:?}) is active")
            };
            if let Some(example) = sample_paths.first() {
                reason.push_str(&format!(". Example: {example}"));
            } else {
                reason.push('.');
            }
            reason
        }
        MountSafetyReason::RecoveryCopiesPresent {
            count,
            sample_paths,
        } => {
            let example = sample_paths
                .first()
                .cloned()
                .unwrap_or_else(|| mountpoint.display().to_string());
            format!(
                "{count} recovered pending-work copy/copies are present as local-only read-only files after an unclean restart. Example: {example}"
            )
        }
    }
}

fn status_has_only_auto_drainable_reasons(
    mountpoint: &Path,
    status: &MountSyncRuntimeStatus,
) -> bool {
    let reasons = mount_sync_unsafe_reasons(mountpoint, status);
    !reasons.is_empty() && reasons.iter().all(MountSafetyReason::is_auto_drainable)
}

fn unsafe_unmount_block_message(
    root_id: Uuid,
    mountpoint: &Path,
    status: &MountSyncRuntimeStatus,
) -> Option<String> {
    if status.safe_to_unmount {
        return None;
    }

    let mut reasons = mount_sync_unsafe_reasons(mountpoint, status)
        .iter()
        .map(|reason| format_mount_safety_reason(mountpoint, reason))
        .collect::<Vec<_>>();
    if reasons.is_empty() {
        let mut extra_warnings = status
            .preflight_warnings
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>();
        reasons.append(&mut extra_warnings);
    }

    if reasons.is_empty() {
        reasons.push(
            "HybridCipher still reports background sync or recovery work that is unsafe to interrupt."
                .to_string(),
        );
    }

    let detail = reasons
        .into_iter()
        .map(|reason| format!("- {}", reason))
        .collect::<Vec<_>>()
        .join("\n");
    let unsafe_reasons = mount_sync_unsafe_reasons(mountpoint, status);
    let mut guidance = Vec::new();
    if unsafe_reasons
        .iter()
        .any(|reason| matches!(reason, MountSafetyReason::Conflict { .. }))
    {
        guidance.push(format!(
            "Resolve conflicts with `hybridcipher conflict list --root-id {}` when conflicts are the blocker.",
            root_id
        ));
    }
    if unsafe_reasons
        .iter()
        .any(|reason| matches!(reason, MountSafetyReason::RecoveryCopiesPresent { .. }))
    {
        guidance.push(format!(
            "Resolve recovery copies with `hybridcipher mount-recovery list --root-id {}` when recovery copies are the blocker.",
            root_id
        ));
    }
    let guidance = if guidance.is_empty() {
        String::new()
    } else {
        format!("\n{}", guidance.join("\n"))
    };
    Some(format!(
        "Refusing to unmount {} because it is not safe to unmount and may cause file loss.\n{}{}\nRe-run with --force to override.",
        mountpoint.display(),
        detail,
        guidance
    ))
}

async fn wait_for_safe_unmount_status(
    session_manager: &SessionManager,
    root_id: Uuid,
    mountpoint: &Path,
) -> Result<Option<MountSyncRuntimeStatus>, CliError> {
    let status_path = mount_sync_status_path(session_manager, root_id)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let poll_interval = Duration::from_millis(500);

    loop {
        let Some(status) = read_mount_sync_status(&status_path)? else {
            return Ok(None);
        };
        if status.safe_to_unmount {
            return Ok(Some(status));
        }

        let only_auto_drainable = status_has_only_auto_drainable_reasons(mountpoint, &status);
        if !only_auto_drainable || Instant::now() >= deadline {
            return Ok(Some(status));
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Read mount state for a specific root_id
fn read_runtime_state_by_root_id(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<Option<MountRuntimeState>, CliError> {
    let path = mount_state_path(session_manager, root_id)?;
    read_runtime_state(&path)
}

pub(crate) async fn root_mount_status(
    session_manager: &SessionManager,
    root_id: Uuid,
) -> Result<RootMountStatus, CliError> {
    let Some(state) = read_runtime_state_by_root_id(session_manager, root_id)? else {
        return Ok(RootMountStatus::inactive());
    };

    if state.requested_unmount {
        return Ok(RootMountStatus::inactive());
    }

    let fuse_mounted = mountpoint_has_fuse_mount(&state.mountpoint).await;
    Ok(RootMountStatus {
        active: true,
        fuse_mounted,
        mountpoint: Some(state.mountpoint),
    })
}

/// List all active mount states
fn list_all_mount_states(
    session_manager: &SessionManager,
) -> Result<Vec<MountRuntimeState>, CliError> {
    let state_dir = mount_state_dir(session_manager)?;
    let mut states = Vec::new();

    if !state_dir.exists() {
        return Ok(states);
    }

    let entries = fs::read_dir(&state_dir).map_err(|e| {
        CliError::configuration(format!(
            "Failed to read mount state directory {}: {}",
            state_dir.display(),
            e
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            CliError::configuration(format!("Failed to read directory entry: {}", e))
        })?;
        let path = entry.path();

        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(Some(state)) = read_runtime_state(&path) {
                if !state.requested_unmount {
                    states.push(state);
                }
            }
        }
    }

    // Also check for legacy single mount state file and migrate if found
    let legacy_path = mount_state_path_legacy(session_manager)?;
    if let Ok(Some(legacy_state)) = read_runtime_state(&legacy_path) {
        if !legacy_state.requested_unmount {
            // Migrate legacy state to new format
            let new_path = mount_state_path(session_manager, legacy_state.root_id)?;
            write_runtime_state(&new_path, &legacy_state)?;
            // Remove legacy file after migration
            let _ = fs::remove_file(&legacy_path);
            states.push(legacy_state);
        }
    }

    Ok(states)
}

fn clear_runtime_state(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| {
            CliError::configuration(format!(
                "Failed to remove mount state {}: {}",
                path.display(),
                e
            ))
        })?;
    }
    Ok(())
}

fn clear_mount_sync_status(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| {
            CliError::configuration(format!(
                "Failed to remove mount sync status {}: {}",
                path.display(),
                e
            ))
        })?;
    }
    Ok(())
}

fn mark_unmount_requested(path: &Path) -> Result<(), CliError> {
    if let Some(mut state) = read_runtime_state(path)? {
        if !state.requested_unmount {
            state.requested_unmount = true;
            write_runtime_state(path, &state)?;
        }
    }
    Ok(())
}

fn runtime_state_requested_unmount(path: &Path) -> Result<bool, CliError> {
    Ok(read_runtime_state(path)?
        .map(|s| s.requested_unmount)
        .unwrap_or(false))
}

fn default_encrypted_candidate() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".hybridcipher").join("encrypted"))
}

fn default_enrolled_index(
    enrolled_roots: &[PathBuf],
    last_encrypted_dir: Option<&PathBuf>,
) -> Option<usize> {
    if enrolled_roots.is_empty() {
        return None;
    }

    if let Some(last) = last_encrypted_dir {
        if let Some(idx) = find_enrolled_index(enrolled_roots, last) {
            return Some(idx);
        }
    }

    Some(0)
}

fn find_enrolled_index(enrolled_roots: &[PathBuf], target: &Path) -> Option<usize> {
    let target_canonical = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    enrolled_roots.iter().enumerate().find_map(|(idx, root)| {
        let root_canonical = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        if root_canonical == target_canonical {
            Some(idx)
        } else {
            None
        }
    })
}

fn determine_mountpoint(encrypted_dir: &Path, root_id: Uuid) -> Result<PathBuf, CliError> {
    let encrypted_name = encrypted_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("encrypted");
    let sanitized = sanitize_mount_name(encrypted_name);

    let home = dirs::home_dir().ok_or_else(|| {
        CliError::configuration("Unable to resolve home directory for mount allocation")
    })?;
    let base = home.join(".hybridcipher");
    fs::create_dir_all(&base).map_err(|e| {
        CliError::configuration(format!(
            "Failed to prepare base mount directory {}: {}",
            base.display(),
            e
        ))
    })?;

    let legacy_mount_dir = base.join(format!("{}_mount", sanitized));
    let scoped_mount_dir = base.join(format!("{}_{}_mount", sanitized, root_id));

    if scoped_mount_dir.exists() {
        prepare_mountpoint(&scoped_mount_dir)?;
        return Ok(scoped_mount_dir);
    }

    if legacy_mount_dir.exists() {
        match fs::rename(&legacy_mount_dir, &scoped_mount_dir) {
            Ok(()) => {
                info!(
                    "Migrated legacy mountpoint {} to root-scoped path {}",
                    legacy_mount_dir.display(),
                    scoped_mount_dir.display()
                );
                prepare_mountpoint(&scoped_mount_dir)?;
                return Ok(scoped_mount_dir);
            }
            Err(err) => {
                warn!(
                    "Could not migrate legacy mountpoint {} to {}: {}. Reusing legacy path for this run.",
                    legacy_mount_dir.display(),
                    scoped_mount_dir.display(),
                    err
                );
                prepare_mountpoint(&legacy_mount_dir)?;
                return Ok(legacy_mount_dir);
            }
        }
    }

    prepare_mountpoint(&scoped_mount_dir)?;
    Ok(scoped_mount_dir)
}

fn derive_mount_label(encrypted_dir: &Path, root_id: Uuid) -> String {
    let encrypted_name = encrypted_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("encrypted");
    let sanitized = sanitize_mount_name(encrypted_name);
    let root_short = root_id.simple().to_string();
    let suffix = &root_short[..8];
    format!("{}-{}-mount", sanitized, suffix)
}

fn sanitize_mount_name(input: &str) -> String {
    let mut sanitized: String = input
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            _ => '_',
        })
        .collect();

    if sanitized.trim_matches('_').is_empty() {
        sanitized = "encrypted".to_string();
    }

    sanitized
}

fn expand_path(input: &str) -> Result<PathBuf, CliError> {
    if let Some(stripped) = input.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(stripped));
        } else {
            return Err(CliError::configuration(
                "Unable to resolve home directory for '~' expansion",
            ));
        }
    }
    if let Some(stripped) = input.strip_prefix("~\\") {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(stripped));
        } else {
            return Err(CliError::configuration(
                "Unable to resolve home directory for '~' expansion",
            ));
        }
    }
    if input == "~" {
        if let Some(home) = dirs::home_dir() {
            return Ok(home);
        } else {
            return Err(CliError::configuration(
                "Unable to resolve home directory for '~' expansion",
            ));
        }
    }
    Ok(PathBuf::from(input))
}

fn prepare_mountpoint(path: &Path) -> Result<(), CliError> {
    // Don't try to remove if it exists - this could be a FUSE mount or in use.
    // We'll handle cleanup after unmounting if needed.
    // Just ensure the directory can be created if it doesn't exist.
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| {
            CliError::storage(format!(
                "Failed to create mount directory {}: {}",
                path.display(),
                e
            ))
        })?;
    }

    Ok(())
}

fn prepare_mountpoint_for_strategy(path: &Path, strategy: MountStrategy) -> Result<(), CliError> {
    let _ = strategy;
    prepare_mountpoint(path)
}

// Helper function to check if a directory is empty
fn is_directory_empty(path: &Path) -> Result<bool, CliError> {
    if !path.exists() || !path.is_dir() {
        return Ok(true);
    }

    let mut entries = fs::read_dir(path).map_err(|e| {
        CliError::storage(format!(
            "Failed to read directory {}: {}",
            path.display(),
            e
        ))
    })?;

    Ok(entries.next().is_none())
}

// Helper function to clean up mountpoint after unmounting
// CRITICAL: Only deletes empty directories to prevent data loss
// CRITICAL: Never deletes encrypted_dir - only mountpoint directories
fn clean_and_prepare_mountpoint(path: &Path) -> Result<(), CliError> {
    // Safety check: ensure this is a mountpoint directory, not an encrypted source
    // Mountpoints should be under ~/.hybridcipher/*_mount
    let home = dirs::home_dir().ok_or_else(|| {
        CliError::configuration("Unable to resolve home directory for safety check")
    })?;
    let hybridcipher_base = home.join(".hybridcipher");

    // Ensure path is under .hybridcipher and ends with _mount
    if !path.starts_with(&hybridcipher_base) {
        return Err(CliError::mount(format!(
            "CRITICAL: Refusing to clean path {} - not a mountpoint directory (not under ~/.hybridcipher)",
            path.display()
        )));
    }

    // Additional safety: check if path looks like a mountpoint (contains _mount)
    let path_str = path.to_string_lossy();
    if !path_str.contains("_mount") && !path_str.ends_with("mount") {
        warn!(
            "WARNING: Path {} does not look like a mountpoint directory. Skipping cleanup to prevent data loss.",
            path.display()
        );
        // Don't fail, just skip cleanup
        return Ok(());
    }

    if path.exists() {
        // Check if directory is empty before attempting deletion
        match is_directory_empty(path) {
            Ok(true) => {
                // Directory is empty, safe to remove
                fs::remove_dir_all(path).map_err(|e| {
                    CliError::storage(format!(
                        "Failed to remove existing mount directory {}: {}",
                        path.display(),
                        e
                    ))
                })?;
            }
            Ok(false) => {
                // Directory contains files - DO NOT DELETE
                // This prevents data loss if unmount didn't complete properly
                warn!(
                    "Mountpoint {} contains files, skipping deletion to prevent data loss",
                    path.display()
                );
                return Err(CliError::mount(format!(
                    "Mountpoint {} still contains files. Please manually verify and clean up before remounting.",
                    path.display()
                )));
            }
            Err(e) => {
                // Error checking directory - err on the side of caution
                warn!(
                    "Failed to check if mountpoint {} is empty: {}. Skipping deletion to prevent data loss.",
                    path.display(),
                    e
                );
                return Err(CliError::mount(format!(
                    "Cannot safely clean mountpoint {}. Please verify it's empty before remounting.",
                    path.display()
                )));
            }
        }
    }

    fs::create_dir_all(path).map_err(|e| {
        CliError::storage(format!(
            "Failed to create mount directory {}: {}",
            path.display(),
            e
        ))
    })
}

/// Safe cleanup: only removes mountpoint if it's empty
/// CRITICAL: Never deletes encrypted_dir - only mountpoint directories
fn cleanup_mountpoint_safe(path: &Path) -> Result<(), CliError> {
    if !path.exists() {
        return Ok(());
    }

    // Safety check: ensure this is a mountpoint directory, not an encrypted source
    let home = dirs::home_dir().ok_or_else(|| {
        CliError::configuration("Unable to resolve home directory for safety check")
    })?;
    let hybridcipher_base = home.join(".hybridcipher");

    // Ensure path is under .hybridcipher and ends with _mount
    if !path.starts_with(&hybridcipher_base) {
        warn!(
            "CRITICAL: Refusing to clean path {} - not a mountpoint directory (not under ~/.hybridcipher). Skipping to prevent data loss.",
            path.display()
        );
        return Ok(());
    }

    // Additional safety: check if path looks like a mountpoint (contains _mount)
    let path_str = path.to_string_lossy();
    if !path_str.contains("_mount") && !path_str.ends_with("mount") {
        warn!(
            "WARNING: Path {} does not look like a mountpoint directory. Skipping cleanup to prevent data loss.",
            path.display()
        );
        return Ok(());
    }

    // CRITICAL: Only delete if directory is empty to prevent data loss
    match is_directory_empty(path) {
        Ok(true) => {
            // Directory is empty, safe to remove
            fs::remove_dir_all(path).map_err(|e| {
                CliError::storage(format!(
                    "Failed to remove mount directory {}: {}",
                    path.display(),
                    e
                ))
            })
        }
        Ok(false) => {
            // Directory contains files - DO NOT DELETE
            warn!(
                "Mountpoint {} contains files, skipping deletion to prevent data loss",
                path.display()
            );
            Ok(()) // Return Ok to not fail unmount, but don't delete
        }
        Err(e) => {
            // Error checking directory - err on the side of caution
            warn!(
                "Failed to check if mountpoint {} is empty: {}. Skipping deletion to prevent data loss.",
                path.display(),
                e
            );
            Ok(()) // Return Ok to not fail unmount, but don't delete
        }
    }
}

fn cleanup_mountpoint_tree_for_safe_sync_remount(path: &Path) -> Result<(), CliError> {
    ensure_mountpoint_cleanup_target(path)?;

    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| {
            CliError::storage(format!(
                "Failed to recreate mount directory {}: {}",
                path.display(),
                e
            ))
        })?;
        return Ok(());
    }

    fs::remove_dir_all(path).map_err(|e| {
        CliError::storage(format!(
            "Failed to remove stale decrypted mount view {}: {}",
            path.display(),
            e
        ))
    })?;
    fs::create_dir_all(path).map_err(|e| {
        CliError::storage(format!(
            "Failed to recreate mount directory {}: {}",
            path.display(),
            e
        ))
    })
}

fn ensure_mountpoint_cleanup_target(path: &Path) -> Result<(), CliError> {
    let home = dirs::home_dir().ok_or_else(|| {
        CliError::configuration("Unable to resolve home directory for safety check")
    })?;
    let hybridcipher_base = home.join(".hybridcipher");

    if !mountpoint_is_under_hybridcipher_base(path, &hybridcipher_base) {
        return Err(CliError::mount(format!(
            "Refusing to clean {} because it is not under ~/.hybridcipher",
            path.display()
        )));
    }

    let path_str = path.to_string_lossy();
    if !path_str.contains("_mount") && !path_str.ends_with("mount") {
        return Err(CliError::mount(format!(
            "Refusing to clean {} because it does not look like a HybridCipher mountpoint",
            path.display()
        )));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn mountpoint_is_under_hybridcipher_base(path: &Path, hybridcipher_base: &Path) -> bool {
    fn comparable(path: &Path) -> String {
        normalize_canonical_path(path.to_path_buf())
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    }

    let path = comparable(path);
    let base = comparable(hybridcipher_base);
    path == base || path.starts_with(&format!("{}\\", base))
}

#[cfg(not(target_os = "windows"))]
fn mountpoint_is_under_hybridcipher_base(path: &Path, hybridcipher_base: &Path) -> bool {
    path.starts_with(hybridcipher_base)
}

struct MountDirGuard {
    path: PathBuf,
}

impl MountDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for MountDirGuard {
    fn drop(&mut self) {
        if let Err(err) = cleanup_mountpoint_safe(&self.path) {
            warn!(
                "Preserving non-empty mount directory {} on drop: {}",
                self.path.display(),
                err
            );
        } else {
            debug!(
                "Successfully cleaned mount directory {}",
                self.path.display()
            );
        }
    }
}

fn ensure_directory(path: &Path) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::mount(format!(
            "Directory {} does not exist",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(CliError::mount(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    Ok(())
}

fn canonicalize_existing(path: PathBuf) -> Result<PathBuf, CliError> {
    match fs::canonicalize(&path) {
        Ok(canonical) => Ok(normalize_canonical_path(canonical)),
        Err(e) => Err(CliError::mount(format!(
            "Failed to canonicalize {}: {}",
            path.display(),
            e
        ))),
    }
}

#[cfg(target_os = "windows")]
fn normalize_canonical_path(path: PathBuf) -> PathBuf {
    let path_str = path.as_os_str().to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("\\\\?\\UNC\\") {
        PathBuf::from(format!("\\\\{}", stripped))
    } else if let Some(stripped) = path_str.strip_prefix("\\\\?\\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

#[cfg(not(target_os = "windows"))]
fn normalize_canonical_path(path: PathBuf) -> PathBuf {
    path
}

fn path_to_string(path: &PathBuf) -> Result<String, CliError> {
    path.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| CliError::mount("Path contains invalid UTF-8 characters"))
}

// run_fuse_mount, run_sync_mount, initialize_sync_migration_reporting,
// drive_sync_migration_reporting, and log_sync_migration_error are now
// imported from hybridcipher-mount-sync::mount_runner

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn expand_home_paths() {
        let path = expand_path("/tmp").expect("/tmp");
        assert_eq!(path, PathBuf::from("/tmp"));
    }

    #[test]
    fn preferences_roundtrip() {
        let prefs = MountPreferences {
            last_encrypted_dir: Some(PathBuf::from("/encrypted")),
        };
        let serialized = serde_json::to_string(&prefs).expect("serialize");
        let parsed: MountPreferences = serde_json::from_str(&serialized).expect("parse");
        assert_eq!(
            parsed.last_encrypted_dir.unwrap(),
            PathBuf::from("/encrypted")
        );
    }

    #[test]
    fn runtime_state_flag() {
        let temp_dir = TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");
        let state = MountRuntimeState {
            root_id: Uuid::new_v4(),
            mountpoint: PathBuf::from("/tmp/mount"),
            encrypted_dir: PathBuf::from("/tmp/encrypted"),
            platform: "linux".into(),
            backend: Some(MountBackend::Sync),
            host_pid: Some(1234),
            fallback_reason: None,
            ready: true,
            requested_unmount: false,
        };
        write_runtime_state(&state_path, &state).expect("write");
        assert!(!runtime_state_requested_unmount(&state_path).unwrap());
        mark_unmount_requested(&state_path).unwrap();
        assert!(runtime_state_requested_unmount(&state_path).unwrap());
    }

    #[test]
    fn runtime_state_backward_compatibility_defaults_new_fields() {
        let temp_dir = TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");
        fs::write(
            &state_path,
            r#"{
  "root_id":"12345678-90ab-cdef-1234-567890abcdef",
  "mountpoint":"/tmp/mount",
  "encrypted_dir":"/tmp/encrypted",
  "platform":"windows",
  "requested_unmount":false
}"#,
        )
        .unwrap();

        let state = read_runtime_state(&state_path)
            .unwrap()
            .expect("runtime state should deserialize");
        assert_eq!(state.backend(), MountBackend::Sync);
        assert_eq!(state.host_pid, None);
        assert_eq!(state.fallback_reason, None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_auto_uses_cloud_files_when_ready() {
        let (strategy, fallback_reason) =
            resolve_windows_mount_strategy(MountStrategyArg::Auto, Ok(())).unwrap();
        assert_eq!(strategy, MountStrategy::CloudFiles);
        assert_eq!(fallback_reason, None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_auto_falls_back_to_sync_when_cloud_files_not_ready() {
        let (strategy, fallback_reason) = resolve_windows_mount_strategy(
            MountStrategyArg::Auto,
            Err("Cloud Files not ready".to_string()),
        )
        .unwrap();
        assert_eq!(strategy, MountStrategy::Sync);
        assert_eq!(
            fallback_reason,
            Some("Cloud Files unavailable: Cloud Files not ready".to_string())
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_explicit_sync_stays_sync() {
        let (strategy, fallback_reason) = resolve_windows_mount_strategy(
            MountStrategyArg::Sync,
            Err("ignored cloud failure".to_string()),
        )
        .unwrap();
        assert_eq!(strategy, MountStrategy::Sync);
        assert_eq!(fallback_reason, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_auto_uses_file_provider_when_ready() {
        let (strategy, fallback_reason) =
            resolve_macos_mount_strategy(MountStrategyArg::Auto, Ok(())).unwrap();
        assert_eq!(strategy, MountStrategy::MacOsFileProvider);
        assert_eq!(fallback_reason, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_auto_falls_back_to_sync_when_file_provider_not_ready() {
        let (strategy, fallback_reason) = resolve_macos_mount_strategy(
            MountStrategyArg::Auto,
            Err("extension not registered".to_string()),
        )
        .unwrap();
        assert_eq!(strategy, MountStrategy::Sync);
        assert_eq!(
            fallback_reason,
            Some("macOS File Provider unavailable: extension not registered".to_string())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_explicit_file_provider_does_not_fallback() {
        let err = resolve_macos_mount_strategy(
            MountStrategyArg::FileProvider,
            Err("extension not registered".to_string()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("extension not registered"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_explicit_sync_stays_sync() {
        let (strategy, fallback_reason) = resolve_macos_mount_strategy(
            MountStrategyArg::Sync,
            Err("ignored provider failure".to_string()),
        )
        .unwrap();
        assert_eq!(strategy, MountStrategy::Sync);
        assert_eq!(fallback_reason, None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_verbatim_mountpoint_paths_are_normalized() {
        let normalized =
            normalize_canonical_path(PathBuf::from(r"\\?\C:\Mounts\.hybridcipher\root_mount"));
        assert_eq!(
            normalized,
            PathBuf::from(r"C:\Mounts\.hybridcipher\root_mount")
        );

        let normalized_unc = normalize_canonical_path(PathBuf::from(
            r"\\?\UNC\server\share\.hybridcipher\root_mount",
        ));
        assert_eq!(
            normalized_unc,
            PathBuf::from(r"\\server\share\.hybridcipher\root_mount")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_verbatim_mountpoint_passes_hybridcipher_base_check() {
        let base = PathBuf::from(r"C:\Users\Example\.hybridcipher");
        let mountpoint = PathBuf::from(r"\\?\C:\Users\Example\.hybridcipher\root_mount");

        assert!(mountpoint_is_under_hybridcipher_base(&mountpoint, &base));
    }

    #[test]
    fn picks_last_enrolled_when_present() {
        let roots = vec![PathBuf::from("/one"), PathBuf::from("/two")];
        let idx = default_enrolled_index(&roots, Some(&PathBuf::from("/two")));
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn defaults_to_first_enrolled_when_missing_previous_choice() {
        let roots = vec![PathBuf::from("/one"), PathBuf::from("/two")];
        let idx = default_enrolled_index(&roots, Some(&PathBuf::from("/other")));
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn returns_none_when_no_enrolled_roots() {
        let idx = default_enrolled_index(&[], Some(&PathBuf::from("/other")));
        assert_eq!(idx, None);
    }

    #[test]
    fn mount_label_includes_root_id_suffix() {
        let root_id = Uuid::parse_str("12345678-90ab-cdef-1234-567890abcdef").expect("valid uuid");
        let label = derive_mount_label(Path::new("/tmp/example"), root_id);
        assert!(label.starts_with("example-12345678-mount"));
    }

    #[test]
    fn unsafe_status_blocks_unmount_without_force() {
        let status = MountSyncRuntimeStatus {
            pending_conflict_count: 2,
            edited_conflict_count: 1,
            conflict_paths: vec!["/tmp/mount/document.txt.conflict-20260313_120000".to_string()],
            edited_conflict_paths: vec![
                "/tmp/mount/document.txt.conflict-20260313_120000".to_string()
            ],
            pending_writeback_count: 1,
            pending_low_space_path_count: 1,
            low_space_mode: LowSpaceMode::WritebackDegraded,
            low_space_paths: vec!["/tmp/mount/document.txt".to_string()],
            ..MountSyncRuntimeStatus::default()
        };

        let root_id = Uuid::new_v4();
        let message =
            unsafe_unmount_block_message(root_id, Path::new("/tmp/mount"), &status).unwrap();
        assert!(message.contains("not safe to unmount"));
        assert!(message.contains("may cause file loss"));
        assert!(message.contains("unresolved conflict file(s)"));
        assert!(message.contains("pending encrypted commit(s)"));
        assert!(message.contains("low-space degraded mode"));
        assert!(message.contains("/tmp/mount/document.txt"));
        assert!(message.contains(&format!("hybridcipher conflict list --root-id {}", root_id)));
        assert!(message.contains("--force"));
    }

    #[test]
    fn deleted_open_status_blocks_unmount_without_force() {
        let status = MountSyncRuntimeStatus {
            pending_open_unlinked_count: 2,
            open_unlinked_paths: vec!["/tmp/mount/document.txt".to_string()],
            ..MountSyncRuntimeStatus::default()
        };

        let message =
            unsafe_unmount_block_message(Uuid::new_v4(), Path::new("/tmp/mount"), &status).unwrap();
        assert!(message.contains("deleted-open path(s)"));
        assert!(message.contains("/tmp/mount/document.txt"));
    }

    #[test]
    fn healthy_status_does_not_block_unmount() {
        let status = MountSyncRuntimeStatus {
            safe_to_unmount: true,
            ..MountSyncRuntimeStatus::default()
        };
        assert!(
            unsafe_unmount_block_message(Uuid::new_v4(), Path::new("/tmp/mount"), &status)
                .is_none()
        );
    }

    #[test]
    fn auto_drainable_reason_detection_only_allows_pending_commit_and_refresh() {
        let drainable = MountSyncRuntimeStatus {
            pending_writeback_count: 1,
            pending_writeback_oldest_age_ms: Some(350),
            pending_refresh_count: 1,
            unsafe_reasons: vec![
                MountSafetyReason::PendingWriteback {
                    count: 1,
                    oldest_age_ms: 350,
                    sample_paths: Vec::new(),
                    last_error: None,
                },
                MountSafetyReason::PendingRefresh { count: 1 },
            ],
            ..MountSyncRuntimeStatus::default()
        };
        assert!(status_has_only_auto_drainable_reasons(
            Path::new("/tmp/mount"),
            &drainable
        ));

        let blocked = MountSyncRuntimeStatus {
            unsafe_reasons: vec![
                MountSafetyReason::PendingWriteback {
                    count: 1,
                    oldest_age_ms: 350,
                    sample_paths: Vec::new(),
                    last_error: None,
                },
                MountSafetyReason::Conflict {
                    count: 1,
                    edited_count: 0,
                    sample_paths: vec!["/tmp/mount/document.txt.conflict-20260313_120000".into()],
                },
            ],
            ..MountSyncRuntimeStatus::default()
        };
        assert!(!status_has_only_auto_drainable_reasons(
            Path::new("/tmp/mount"),
            &blocked
        ));
    }

    #[test]
    fn structured_unsafe_reasons_drive_cli_message() {
        let status = MountSyncRuntimeStatus {
            unsafe_reasons: vec![
                MountSafetyReason::RecoveryCopiesPresent {
                    count: 1,
                    sample_paths: vec![
                        "/tmp/mount/document.txt.recovered-pending-20260313_120000".into()
                    ],
                },
                MountSafetyReason::PendingWriteback {
                    count: 2,
                    oldest_age_ms: 900,
                    sample_paths: vec!["/tmp/mount/document.txt".into()],
                    last_error: Some("unstable file changed during read".into()),
                },
            ],
            ..MountSyncRuntimeStatus::default()
        };

        let root_id = Uuid::new_v4();
        let message =
            unsafe_unmount_block_message(root_id, Path::new("/tmp/mount"), &status).unwrap();
        assert!(message.contains("recovered pending-work copy/copies"));
        assert!(message.contains("pending encrypted commit(s)"));
        assert!(message.contains(&format!(
            "hybridcipher mount-recovery list --root-id {}",
            root_id
        )));
    }

    #[test]
    fn hard_link_reason_is_rendered_in_cli_unmount_message() {
        let status = MountSyncRuntimeStatus {
            unsafe_reasons: vec![MountSafetyReason::HardLinkBlocked {
                count: 1,
                sample_paths: vec!["/tmp/mount/document.txt".into()],
            }],
            ..MountSyncRuntimeStatus::default()
        };

        let message =
            unsafe_unmount_block_message(Uuid::new_v4(), Path::new("/tmp/mount"), &status).unwrap();
        assert!(message.contains("hard-linked file(s)"));
        assert!(message.contains("does not preserve hard-link semantics"));
        assert!(message.contains("Break the hard link or replace it with an independent copy"));
        assert!(message.contains("/tmp/mount/document.txt"));
    }
}
