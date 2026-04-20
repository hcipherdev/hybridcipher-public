use crate::local_client::LocalClientProvider;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tauri::async_runtime::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

async fn run_cli_unmount_command(
    cli_binary: &Path,
    args: &[String],
    force: bool,
    timeout: Duration,
) -> Result<(), String> {
    let mut cmd = tokio::process::Command::new(cli_binary);
    cmd.arg("unmount");
    for arg in args {
        cmd.arg(arg);
    }
    if force {
        cmd.arg("--force");
    }

    match tokio::time::timeout(timeout, cmd.output()).await {
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.is_empty() {
                Err(format!("unmount exited with status {}", output.status))
            } else {
                Err(stderr)
            }
        }
        Ok(Err(err)) => Err(format!("failed to run unmount command: {}", err)),
        Err(_) => Err("unmount command timed out".to_string()),
    }
}

/// Simplified mount manager that delegates mount operations to CLI
/// and only handles unmount and scope management
pub struct MountManager {
    base_dir: PathBuf,
    manifest_scope: Mutex<Option<String>>,
}

impl MountManager {
    pub fn new(_client_provider: Arc<LocalClientProvider>) -> Result<Self, String> {
        let home = dirs::home_dir().ok_or("Unable to locate home directory")?;
        let base_dir = home.join(".hybridcipher");
        std::fs::create_dir_all(&base_dir).map_err(|e| {
            format!(
                "Failed to prepare HybridCipher root directory {}: {}",
                base_dir.display(),
                e
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700));
        }

        Ok(Self {
            base_dir,
            manifest_scope: Mutex::new(None),
        })
    }

    pub async fn activate_manifest_scope(&self, identifier: &str) -> Result<(), String> {
        let mut scope = self.manifest_scope.lock().await;
        *scope = Some(identifier.to_string());
        Ok(())
    }

    pub async fn clear_manifest_scope(&self) {
        let mut scope = self.manifest_scope.lock().await;
        *scope = None;
    }

    /// Unmount all mounts using CLI unmount command
    pub async fn unmount_all(&self, force: bool) -> Result<(), String> {
        info!("Unmounting all mounts via CLI");

        // Use CLI unmount command
        let cli_binary = crate::cli_utils::locate_cli_binary()
            .map_err(|e| format!("Failed to locate CLI binary: {}", e))?;

        // Best-effort: enumerate active mount states and unmount each explicitly.
        // This avoids relying on the CLI default of a single "active" mount.
        let mounts = self.discover_active_mounts();
        let mut failures: Vec<String> = Vec::new();

        for (root_id, mountpoint) in mounts {
            let args = vec!["--root-id".to_string(), root_id.clone()];
            match run_cli_unmount_command(&cli_binary.0, &args, force, Duration::from_secs(20))
                .await
            {
                Ok(()) => {
                    // Poll briefly to ensure the mountpoint goes away
                    if let Err(e) = self
                        .wait_for_unmount(&mountpoint, Duration::from_secs(5))
                        .await
                    {
                        warn!(
                            "Unmounted root_id {} but mountpoint still present: {}",
                            root_id, e
                        );
                    }
                }
                Err(err) => {
                    warn!("Unmount failed for root_id {}: {}", root_id, err);
                    failures.push(format!("root {}: {}", root_id, err));
                }
            }
        }

        // Final sweep: ask CLI to unmount all mounts (covers any we didn't detect)
        let final_args = vec!["--all".to_string()];
        if let Err(err) =
            run_cli_unmount_command(&cli_binary.0, &final_args, force, Duration::from_secs(15))
                .await
        {
            warn!("Final --all unmount failed: {}", err);
            failures.push(format!("final --all unmount: {}", err));
        }

        if failures.is_empty() {
            info!("Successfully unmounted all mounts");
            Ok(())
        } else {
            Err(format!(
                "Unmount encountered issues: {}",
                failures.join("; ")
            ))
        }
    }

    /// Unmount a specific mount by root_id using CLI unmount command
    pub async fn unmount_by_root_id(&self, root_id: &str, force: bool) -> Result<(), String> {
        info!("Unmounting mount with root_id {} via CLI", root_id);

        // Use CLI unmount command with --root-id
        let cli_binary = crate::cli_utils::locate_cli_binary()
            .map_err(|e| format!("Failed to locate CLI binary: {}", e))?;

        let args = vec!["--root-id".to_string(), root_id.to_string()];

        match run_cli_unmount_command(&cli_binary.0, &args, force, Duration::from_secs(20)).await {
            Ok(()) => {
                info!("Successfully unmounted mount with root_id {}", root_id);
                Ok(())
            }
            Err(err) => Err(format!("Unmount failed: {}", err)),
        }
    }

    /// Check if a path is within the HybridCipher base directory
    pub fn is_within_mounts(&self, path: &PathBuf) -> bool {
        path.starts_with(&self.base_dir)
    }

    /// Prioritize folder decrypt (no-op since CLI handles this)
    pub async fn prioritize_folder(&self, _folder_path: &str) -> Result<(), String> {
        // CLI mount handles prioritization internally
        Ok(())
    }

    /// Walk ~/.hybridcipher/users/*/mount_states to find active mounts
    fn discover_active_mounts(&self) -> Vec<(String, PathBuf)> {
        #[derive(Deserialize)]
        struct MountRuntimeState {
            root_id: String,
            mountpoint: PathBuf,
            requested_unmount: bool,
        }

        let mut mounts = Vec::new();
        let users_dir = self.base_dir.join("users");
        if let Ok(entries) = std::fs::read_dir(&users_dir) {
            for user_entry in entries.flatten() {
                let mount_states_dir = user_entry.path().join("mount_states");
                if !mount_states_dir.exists() {
                    continue;
                }
                if let Ok(states) = std::fs::read_dir(&mount_states_dir) {
                    for state_file in states.flatten() {
                        let path = state_file.path();
                        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if path.extension().and_then(|e| e.to_str()) != Some("json")
                            || !file_name.starts_with("mount_state_")
                        {
                            continue;
                        }
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if let Ok(state) = serde_json::from_str::<MountRuntimeState>(&content) {
                                if !state.requested_unmount && state.mountpoint.exists() {
                                    mounts.push((state.root_id, state.mountpoint));
                                }
                            }
                        }
                    }
                }
            }
        }
        mounts
    }

    /// Poll briefly to ensure a mountpoint disappears after unmount
    async fn wait_for_unmount(
        &self,
        mountpoint: &PathBuf,
        timeout: Duration,
    ) -> Result<(), String> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if !mountpoint.exists() {
                return Ok(());
            }
            sleep(Duration::from_millis(300)).await;
        }
        Err(format!(
            "Mountpoint {} still exists after unmount",
            mountpoint.display()
        ))
    }

    /// Mark mount state files as needing cleanup on next launch.
    /// This is synchronous and only touches state files, not data.
    /// The recovery system will handle orphaned mountpoints on next launch.
    pub fn cleanup_state_files_on_exit(&self) {
        let users_dir = self.base_dir.join("users");
        if let Ok(entries) = std::fs::read_dir(&users_dir) {
            for user_entry in entries.flatten() {
                let mount_states_dir = user_entry.path().join("mount_states");
                if !mount_states_dir.exists() {
                    continue;
                }
                if let Ok(states) = std::fs::read_dir(&mount_states_dir) {
                    for state_file in states.flatten() {
                        let path = state_file.path();
                        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if path.extension().and_then(|e| e.to_str()) == Some("json")
                            && file_name.starts_with("mount_state_")
                        {
                            // Mark as requested_unmount so recovery knows it was interrupted
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if let Ok(mut state) =
                                    serde_json::from_str::<serde_json::Value>(&content)
                                {
                                    if let Some(obj) = state.as_object_mut() {
                                        obj.insert(
                                            "requested_unmount".to_string(),
                                            serde_json::Value::Bool(true),
                                        );
                                        if let Ok(updated) = serde_json::to_string_pretty(&state) {
                                            let _ = std::fs::write(&path, updated);
                                            info!(
                                                "Marked mount state for recovery: {}",
                                                path.display()
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
