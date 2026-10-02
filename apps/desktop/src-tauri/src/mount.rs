use crate::local_client::LocalClientProvider;
use crate::process_utils::{configure_background_std_command, configure_background_tokio_command};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tauri::async_runtime::Mutex;
use tokio::time::{sleep, Duration};
use tracing::info;

#[derive(Debug, Clone)]
struct CliMountRecord {
    root_id: String,
    state_path: PathBuf,
    host_pid: Option<u32>,
    mountpoint: Option<PathBuf>,
}

impl CliMountRecord {
    fn is_active(&self) -> bool {
        self.host_pid
            .map(process_is_running)
            .unwrap_or_else(|| self.mountpoint.as_ref().is_some_and(|path| path.exists()))
    }
}

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

    configure_background_tokio_command(&mut cmd);
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
        let base_dir = home.join(hybridcipher_client::config_loader::account_data_location());
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
        let users_dir = self.base_dir.join("users");
        if !users_dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&users_dir)
            .map_err(|err| format!("Failed to inspect account mounts: {err}"))?
        {
            let entry = entry.map_err(|err| format!("Failed to inspect account mounts: {err}"))?;
            if entry.path().is_dir() {
                self.unmount_account(&entry.path(), force).await?;
            }
        }
        Ok(())
    }

    /// Stop only CLI mounts belonging to one account. A temporary desktop login
    /// uses this before deleting that account's saved CLI credentials.
    pub async fn unmount_account(&self, user_dir: &Path, force: bool) -> Result<(), String> {
        let mounts = Self::discover_cli_mounts_in(user_dir)?;
        if mounts.is_empty() {
            return Ok(());
        }
        let cli_binary = crate::cli_utils::locate_cli_binary()
            .map_err(|err| format!("Failed to locate CLI binary: {err}"))?;
        let mut failures = Vec::new();
        for mount in &mounts {
            let args = vec!["--root-id".to_string(), mount.root_id.clone()];
            if let Err(err) =
                run_cli_unmount_command(&cli_binary.0, &args, force, Duration::from_secs(45)).await
            {
                failures.push(format!("root {}: {err}", mount.root_id));
            } else if let Err(err) =
                Self::wait_for_cli_unmount(mount, Duration::from_secs(10)).await
            {
                failures.push(format!("root {}: {err}", mount.root_id));
            }
        }
        for mount in Self::discover_cli_mounts_in(user_dir)? {
            if mount.is_active() {
                failures.push(format!(
                    "root {} remains active at {}",
                    mount.root_id,
                    mount.state_path.display()
                ));
            }
        }
        if failures.is_empty() {
            info!("CLI mounts stopped for {}", user_dir.display());
            Ok(())
        } else {
            Err(format!(
                "CLI mounts could not be stopped safely: {}",
                failures.join("; ")
            ))
        }
    }

    /// Unmount a specific mount by root_id using CLI unmount command
    pub async fn unmount_by_root_id(&self, root_id: &str, force: bool) -> Result<(), String> {
        info!("Unmounting mount with root_id {} via CLI", root_id);

        let mut record = None;
        let users_dir = self.base_dir.join("users");
        if users_dir.exists() {
            for entry in std::fs::read_dir(&users_dir)
                .map_err(|err| format!("Failed to inspect account mounts: {err}"))?
            {
                let entry =
                    entry.map_err(|err| format!("Failed to inspect account mounts: {err}"))?;
                if entry.path().is_dir() {
                    record = Self::discover_cli_mounts_in(&entry.path())?
                        .into_iter()
                        .find(|mount| mount.root_id == root_id);
                    if record.is_some() {
                        break;
                    }
                }
            }
        }

        // Use CLI unmount command with --root-id
        let cli_binary = crate::cli_utils::locate_cli_binary()
            .map_err(|e| format!("Failed to locate CLI binary: {}", e))?;

        let args = vec!["--root-id".to_string(), root_id.to_string()];

        match run_cli_unmount_command(&cli_binary.0, &args, force, Duration::from_secs(20)).await {
            Ok(()) => {
                if let Some(record) = record.as_ref() {
                    Self::wait_for_cli_unmount(record, Duration::from_secs(10)).await?;
                    if record.state_path.exists() && record.is_active() {
                        return Err(format!("Root {} remains active after CLI unmount", root_id));
                    }
                }
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

    fn discover_cli_mounts_in(user_dir: &Path) -> Result<Vec<CliMountRecord>, String> {
        #[derive(Deserialize)]
        struct MountRuntimeState {
            root_id: String,
            #[serde(default)]
            backend: Option<String>,
            #[serde(default)]
            host_pid: Option<u32>,
            #[serde(default)]
            mountpoint: Option<PathBuf>,
        }
        let mut paths = Vec::new();
        let states_dir = user_dir.join("mount_states");
        if states_dir.exists() {
            for entry in std::fs::read_dir(&states_dir)
                .map_err(|err| format!("Failed to inspect {}: {err}", states_dir.display()))?
            {
                let entry = entry.map_err(|err| format!("Failed to inspect mount state: {err}"))?;
                let path = entry.path();
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                if name.starts_with("mount_state_")
                    && path.extension().is_some_and(|ext| ext == "json")
                {
                    paths.push(path);
                }
            }
        }
        let legacy = user_dir.join("mount_state.json");
        if legacy.exists() {
            paths.push(legacy);
        }
        let mut mounts = Vec::new();
        for path in paths {
            let contents = std::fs::read_to_string(&path)
                .map_err(|err| format!("Failed to read {}: {err}", path.display()))?;
            let mount: MountRuntimeState = serde_json::from_str(&contents)
                .map_err(|err| format!("Invalid mount state {}: {err}", path.display()))?;
            if matches!(
                mount.backend.as_deref(),
                Some("windows-cloud-files" | "macos-file-provider")
            ) {
                continue;
            }
            if mounts
                .iter()
                .any(|known: &CliMountRecord| known.root_id == mount.root_id)
            {
                continue;
            }
            let record = CliMountRecord {
                root_id: mount.root_id,
                state_path: path,
                host_pid: mount.host_pid,
                mountpoint: mount.mountpoint,
            };
            if record.is_active() {
                mounts.push(record);
            }
        }
        Ok(mounts)
    }

    async fn wait_for_cli_unmount(mount: &CliMountRecord, timeout: Duration) -> Result<(), String> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            let host_stopped = mount
                .host_pid
                .map(|pid| !process_is_running(pid))
                .unwrap_or(true);
            if host_stopped && (!mount.state_path.exists() || mount.host_pid.is_some()) {
                return Ok(());
            }
            sleep(Duration::from_millis(250)).await;
        }
        Err(format!(
            "Mount state or host remains active at {}",
            mount.state_path.display()
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

#[cfg(test)]
mod safe_stop_tests {
    use super::*;

    #[tokio::test]
    async fn account_discovery_ignores_native_roots_and_keeps_cli_roots() {
        let temp = tempfile::tempdir().unwrap();
        let states = temp.path().join("mount_states");
        std::fs::create_dir_all(&states).unwrap();
        for (root, backend) in [("cli", "sync"), ("native", "windows-cloud-files")] {
            std::fs::write(
                states.join(format!("mount_state_{root}.json")),
                serde_json::json!({
                    "root_id": root,
                    "backend": backend,
                    "host_pid": null,
                    "mountpoint": temp.path()
                })
                .to_string(),
            )
            .unwrap();
        }
        let found = MountManager::discover_cli_mounts_in(temp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root_id, "cli");
    }

    #[tokio::test]
    async fn mount_state_remaining_after_cli_response_fails_postcondition() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mount_state_cli.json");
        std::fs::write(&path, "{}").unwrap();
        let record = CliMountRecord {
            root_id: "cli".into(),
            state_path: path,
            host_pid: None,
            mountpoint: Some(temp.path().to_path_buf()),
        };
        assert!(
            MountManager::wait_for_cli_unmount(&record, Duration::from_millis(1))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cli_unmount_launch_failure_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        let result = run_cli_unmount_command(
            &temp.path().join("missing-cli"),
            &["--root-id".into(), "some-root".into()],
            false,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());
    }
}

#[cfg(target_os = "windows")]
fn process_is_running(pid: u32) -> bool {
    let filter = format!("PID eq {}", pid);
    let mut command = std::process::Command::new("tasklist");
    command.args(["/FI", &filter, "/FO", "CSV", "/NH"]);
    configure_background_std_command(&mut command);
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
    let mut command = std::process::Command::new("kill");
    command.arg("-0").arg(pid.to_string());
    configure_background_std_command(&mut command);
    command
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn process_is_running(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{}", pid)).exists()
}
