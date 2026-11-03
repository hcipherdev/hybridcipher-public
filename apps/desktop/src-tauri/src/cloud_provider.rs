use crate::local_client::LocalClient;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tauri::async_runtime::Mutex;
use tauri::Emitter;
use uuid::Uuid;

/// Event telling the app which mounts left by the last run were reconnected.
pub(crate) const MOUNTS_RECONNECTED_EVENT: &str = "mounts_reconnected";

/// A mount the last run left registered with Windows or macOS that this run
/// connected again.
#[derive(Debug, Clone)]
pub struct ReconnectedRoot {
    pub root_id: Uuid,
    /// The folder shown in File Explorer or Finder.
    pub mountpoint: PathBuf,
    pub encrypted_root: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconnectFailure {
    pub root_id: String,
    pub name: String,
    pub error: String,
}

/// What reconnecting the mounts left by the last run did.
#[derive(Debug, Clone, Default)]
pub struct ReconnectReport {
    pub reconnected: Vec<ReconnectedRoot>,
    pub failed: Vec<ReconnectFailure>,
}

impl ReconnectReport {
    #[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
    fn fail(&mut self, root_id: Uuid, encrypted_root: &Path, error: String) {
        self.failed.push(ReconnectFailure {
            root_id: root_id.to_string(),
            name: encrypted_root
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
                .unwrap_or_else(|| root_id.to_string()),
            error,
        });
    }
}

#[cfg(any(test, target_os = "windows"))]
fn cloud_provider_health_ready(
    registered: bool,
    running: bool,
    heartbeat_fresh: bool,
    durable_state_readable: bool,
) -> bool {
    registered && running && heartbeat_fresh && durable_state_readable
}

#[cfg(any(test, target_os = "windows"))]
fn cloud_provider_supervisor_requires_recovery(
    lifecycle_healthy: bool,
    heartbeat_fresh: bool,
    operational_healthy: bool,
) -> bool {
    !(lifecycle_healthy && heartbeat_fresh && operational_healthy)
}

#[cfg(target_os = "windows")]
struct RunningCloudRoot {
    host: hybridcipher_windows_cloud_provider::CloudProviderHost,
    bridge: Arc<dyn hybridcipher_windows_cloud_provider::ProviderBridge>,
    operation_lock: Arc<Mutex<()>>,
    owner_token: Uuid,
    recovery_exhausted: Arc<AtomicBool>,
}

#[cfg(target_os = "macos")]
struct RunningMacFileProviderRoot {
    host: hybridcipher_macos_file_provider::MacFileProviderHost,
    registration: hybridcipher_macos_file_provider::FileProviderDomainRegistration,
    compatibility: Arc<hybridcipher_macos_file_provider::VaultCompatibility>,
}

#[cfg(target_os = "macos")]
trait MacFileProviderSystemDomainRegistrar {
    fn register_system_domain(
        &self,
        registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
    ) -> Result<(), String>;

    fn unregister_system_domain(
        &self,
        registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
    ) -> Result<(), String>;
}

#[cfg(target_os = "macos")]
struct NativeMacFileProviderSystemDomainRegistrar;

#[cfg(target_os = "macos")]
impl MacFileProviderSystemDomainRegistrar for NativeMacFileProviderSystemDomainRegistrar {
    fn register_system_domain(
        &self,
        registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
    ) -> Result<(), String> {
        crate::macos_file_provider_native::register_domain(registration)
    }

    fn unregister_system_domain(
        &self,
        registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
    ) -> Result<(), String> {
        crate::macos_file_provider_native::unregister_domain(registration)
    }
}

/// How long an unmount waits for Finder to hand over edits it still holds.
#[cfg(target_os = "macos")]
const MACOS_PENDING_CHANGES_WAIT_SECS: u32 = 30;

/// Saves the registration, starts the bridge, and only then adds the domain
/// to macOS. macOS asks a new domain for its contents at once; a bridge not
/// yet listening answers "server unreachable", and macOS then backs the
/// domain off for longer after each such failure, past the mount's wait.
#[cfg(target_os = "macos")]
async fn start_macos_root_with<R, F>(
    host: &hybridcipher_macos_file_provider::MacFileProviderHost,
    registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
    registrar: &R,
    start_bridge: F,
) -> Result<(), String>
where
    R: MacFileProviderSystemDomainRegistrar,
    F: std::future::Future<Output = Result<(), String>>,
{
    host.register_domain(registration)
        .map_err(|err| err.to_string())?;
    if let Err(err) = start_bridge.await {
        let _ = registrar.unregister_system_domain(registration);
        let _ = host.unregister_domain_state(registration.root_id);
        return Err(err);
    }
    if let Err(err) = registrar.register_system_domain(registration) {
        let _ = host.stop_root(registration.root_id);
        let _ = host.unregister_domain_state(registration.root_id);
        return Err(err);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn unregister_macos_domain_for_desktop<R: MacFileProviderSystemDomainRegistrar>(
    host: &hybridcipher_macos_file_provider::MacFileProviderHost,
    registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
    registrar: &R,
) -> Result<(), String> {
    registrar.unregister_system_domain(registration)?;
    host.unregister_domain_state(registration.root_id)
        .map_err(|err| err.to_string())
}

pub struct DesktopCloudProviderManager {
    #[cfg(target_os = "windows")]
    running: Mutex<HashMap<Uuid, RunningCloudRoot>>,
    #[cfg(target_os = "windows")]
    supervisor_started: AtomicBool,
    #[cfg(target_os = "macos")]
    running: Mutex<HashMap<Uuid, RunningMacFileProviderRoot>>,
    /// Roots whose first sync is underway; a second start of one waits its turn.
    #[cfg(target_os = "macos")]
    starting: std::sync::Mutex<HashSet<Uuid>>,
    /// Restarting kept roots after sign-in, run in the background so sign-in
    /// does not wait for a large folder's first sync.
    #[cfg(target_os = "macos")]
    reconcile_task: std::sync::Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// Set once the app is built, for events that don't answer a command.
    app: std::sync::OnceLock<tauri::AppHandle>,
}

/// A root claimed for starting, released when dropped (also when cancelled).
#[cfg(target_os = "macos")]
struct StartingRoot<'a> {
    starting: &'a std::sync::Mutex<HashSet<Uuid>>,
    root_id: Uuid,
}

#[cfg(target_os = "macos")]
impl Drop for StartingRoot<'_> {
    fn drop(&mut self) {
        if let Ok(mut starting) = self.starting.lock() {
            starting.remove(&self.root_id);
        }
    }
}

impl DesktopCloudProviderManager {
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        crate::macos_file_provider_native::install_domain_signal_handler();

        Self {
            #[cfg(target_os = "windows")]
            running: Mutex::new(HashMap::new()),
            #[cfg(target_os = "windows")]
            supervisor_started: AtomicBool::new(false),
            #[cfg(target_os = "macos")]
            running: Mutex::new(HashMap::new()),
            #[cfg(target_os = "macos")]
            starting: std::sync::Mutex::new(HashSet::new()),
            #[cfg(target_os = "macos")]
            reconcile_task: std::sync::Mutex::new(None),
            app: std::sync::OnceLock::new(),
        }
    }

    pub fn attach_app(&self, app: tauri::AppHandle) {
        let _ = self.app.set(app);
    }

    /// Tell the app which mounts left by the last run were reconnected, so it
    /// shows them as mounted and reports any it could not bring back.
    #[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
    pub(crate) fn emit_mounts_reconnected(&self, report: &ReconnectReport) {
        if report.reconnected.is_empty() && report.failed.is_empty() {
            return;
        }
        let Some(app) = self.app.get() else {
            return;
        };
        let payload = serde_json::json!({
            "reconnected": report
                .reconnected
                .iter()
                .map(|root| root.root_id.to_string())
                .collect::<Vec<_>>(),
            "failed": report.failed,
        });
        if let Err(err) = app.emit(MOUNTS_RECONNECTED_EVENT, payload) {
            tracing::warn!("Could not report reconnected mounts to the app: {}", err);
        }
    }

    /// Whether a start of `root_id` (such as the one after sign-in) is underway.
    #[cfg(target_os = "macos")]
    pub fn is_root_starting(&self, root_id: Uuid) -> bool {
        self.starting
            .lock()
            .map(|starting| starting.contains(&root_id))
            .unwrap_or(false)
    }

    /// Claim `root_id` for starting, or `None` while another start of it runs.
    #[cfg(target_os = "macos")]
    fn claim_start(&self, root_id: Uuid) -> Option<StartingRoot<'_>> {
        let mut starting = self.starting.lock().ok()?;
        starting.insert(root_id).then_some(StartingRoot {
            starting: &self.starting,
            root_id,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn cloud_files_available() -> bool {
        let host = hybridcipher_windows_cloud_provider::CloudProviderHost::new(
            hybridcipher_windows_cloud_provider::ProviderHostConfig {
                user_config_dir: PathBuf::new(),
                pipe_name: None,
            },
        );
        let status = host.status();
        status.available && status.native_callbacks_ready
    }

    #[cfg(not(target_os = "windows"))]
    pub fn cloud_files_available() -> bool {
        false
    }

    #[cfg(target_os = "macos")]
    pub fn file_provider_available(user_config_dir: PathBuf) -> Result<(), String> {
        let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
            hybridcipher_macos_file_provider::ProviderHostConfig {
                user_config_dir,
                socket_path: None,
                provider_identifier: Some(
                    "com.hybridcipher.app.HybridCipherFileProvider".to_string(),
                ),
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
    pub async fn start_root(
        &self,
        user_config_dir: PathBuf,
        root_id: Uuid,
        sync_root_path: PathBuf,
        encrypted_root: PathBuf,
        display_name: String,
        client: Arc<LocalClient>,
    ) -> Result<(), String> {
        {
            let running = self.running.lock().await;
            if let Some(root) = running.get(&root_id) {
                if root.recovery_exhausted.load(Ordering::Acquire) {
                    return Err(format!(
                        "Cloud Files recovery for root {root_id} exhausted its 3-attempt budget; stop and remount the root to retry"
                    ));
                }
                return Ok(());
            }
        }

        let compatibility = Arc::new(
            hybridcipher_windows_cloud_provider::VaultCompatibility::load(
                &user_config_dir,
                root_id,
            )
            .map_err(|e| e.to_string())?,
        );
        let bridge =
            hybridcipher_windows_cloud_provider::local_provider_bridge_for_root_with_compatibility(
                client.clone(),
                root_id,
                compatibility,
            )
            .await
            .map_err(|err| err.to_string())?;
        let host = hybridcipher_windows_cloud_provider::CloudProviderHost::with_provider_bridge(
            hybridcipher_windows_cloud_provider::ProviderHostConfig {
                user_config_dir,
                pipe_name: None,
            },
            bridge.clone(),
        );
        let status = host.status();
        if !status.native_callbacks_ready {
            return Err(status.message.unwrap_or_else(|| {
                "Windows Cloud Files provider native callbacks are unavailable.".to_string()
            }));
        }

        let base_display_name = format!("HybridCipher — {display_name}");
        let display_name = if host
            .load_registrations()
            .map_err(|err| err.to_string())?
            .iter()
            .any(|existing| {
                existing.root_id != root_id && existing.display_name == base_display_name
            }) {
            let short = root_id.simple().to_string();
            format!("{base_display_name} ({})", &short[..8])
        } else {
            base_display_name
        };
        let registration =
            hybridcipher_windows_cloud_provider::CloudRootRegistration::shell_integrated(
                root_id,
                sync_root_path,
                encrypted_root,
                display_name,
            )
            .map_err(|err| err.to_string())?;
        let registration_preexisted = host
            .registration_exists(root_id)
            .map_err(|err| err.to_string())?;
        host.register_root(&registration)
            .map_err(|err| err.to_string())?;
        let start_result = host.start_root_with_bridge(root_id, bridge.clone()).await;
        if let Err(err) = start_result {
            return Err(host
                .cleanup_failed_root_start_after_error(
                    root_id,
                    registration_preexisted,
                    err.cleanup_disposition(),
                    format!("Cloud Files startup failed: {err}"),
                )
                .await);
        }
        let health = match host.check_root_health(root_id) {
            Ok(health) => health,
            Err(error) => {
                return Err(host
                    .cleanup_failed_root_readiness_after_error(
                        root_id,
                        registration_preexisted,
                        format!("Cloud Files startup health check failed: {error}"),
                    )
                    .await);
            }
        };
        let running = health.operational.as_ref().is_some_and(|operational| {
            operational.lifecycle
                == hybridcipher_windows_cloud_provider::CloudRootConnectionState::Running
        });
        if !cloud_provider_health_ready(
            health.registered,
            running,
            health.heartbeat_fresh,
            health.durable_state_readable,
        ) {
            let detail = if health.unhealthy_evidence.is_empty() {
                "Cloud Files root did not publish complete startup health".to_string()
            } else {
                health.unhealthy_evidence.join("; ")
            };
            return Err(host
                .cleanup_failed_root_readiness_after_error(
                    root_id,
                    registration_preexisted,
                    format!("Cloud Files startup readiness failed: {detail}"),
                )
                .await);
        }

        if let Err(error) = host.probe_root(root_id).await {
            return Err(host
                .cleanup_failed_root_readiness_after_error(
                    root_id,
                    registration_preexisted,
                    format!("Cloud Files active startup probe failed: {error}"),
                )
                .await);
        }

        let mut running = self.running.lock().await;
        running.insert(
            root_id,
            RunningCloudRoot {
                host,
                bridge,
                operation_lock: Arc::new(Mutex::new(())),
                owner_token: Uuid::new_v4(),
                recovery_exhausted: Arc::new(AtomicBool::new(false)),
            },
        );
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn start_windows_health_supervisor(self: &Arc<Self>) {
        if self
            .supervisor_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let manager = Arc::downgrade(self);
        tauri::async_runtime::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(manager) = manager.upgrade() else {
                    return;
                };
                manager.supervise_windows_cloud_roots_once().await;
            }
        });
    }

    #[cfg(target_os = "windows")]
    async fn supervise_windows_cloud_roots_once(&self) {
        let targets = {
            let running = self.running.lock().await;
            running
                .iter()
                .map(|(root_id, root)| {
                    (
                        *root_id,
                        root.host.clone(),
                        root.bridge.clone(),
                        root.operation_lock.clone(),
                        root.owner_token,
                        root.recovery_exhausted.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        for (root_id, host, bridge, operation_lock, owner_token, recovery_exhausted) in targets {
            if recovery_exhausted.load(Ordering::Acquire) {
                continue;
            }
            let _operation = operation_lock.lock().await;
            let still_managed = self
                .running
                .lock()
                .await
                .get(&root_id)
                .is_some_and(|root| root.owner_token == owner_token);
            if !still_managed {
                continue;
            }

            let health_is_good = host.check_root_health(root_id).is_ok_and(|health| {
                !cloud_provider_supervisor_requires_recovery(
                    health.lifecycle_healthy,
                    health.heartbeat_fresh,
                    health
                        .operational
                        .as_ref()
                        .is_some_and(|operational| operational.healthy),
                )
            });
            let probe = if health_is_good {
                host.probe_root(root_id).await.map(|_| ())
            } else {
                Err(
                    hybridcipher_windows_cloud_provider::CloudProviderError::Callback(
                        "Cloud Files lifecycle, heartbeat, or callback health is unhealthy".into(),
                    ),
                )
            };
            if probe.is_ok() {
                continue;
            }

            let mut failures = Vec::new();
            let mut recovered = false;
            for attempt in 1..=3u32 {
                if host.is_root_running(root_id) {
                    if let Err(error) = host.stop_root_for_restart(root_id).await {
                        failures.push(format!("attempt {attempt} stop failed: {error}"));
                        tokio::time::sleep(std::time::Duration::from_millis(
                            250 * u64::from(attempt),
                        ))
                        .await;
                        continue;
                    }
                }
                match host.start_root_with_bridge(root_id, bridge.clone()).await {
                    Ok(()) => match host.probe_root(root_id).await {
                        Ok(_) => {
                            recovered = true;
                            break;
                        }
                        Err(error) => {
                            failures.push(format!("attempt {attempt} active probe failed: {error}"))
                        }
                    },
                    Err(error) => failures.push(format!("attempt {attempt} start failed: {error}")),
                }
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(250 * u64::from(attempt)))
                        .await;
                }
            }
            if recovered {
                tracing::info!(root_id = %root_id, "Cloud Files health supervisor recovered the root");
            } else {
                tracing::error!(
                    root_id = %root_id,
                    "Cloud Files health supervisor exhausted this recovery cycle; retrying on the next health check: {}",
                    failures.join("; ")
                );
            }
        }
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    pub async fn is_root_active(&self, root_id: Uuid) -> bool {
        self.running.lock().await.contains_key(&root_id)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    pub async fn is_root_active(&self, _root_id: Uuid) -> bool {
        false
    }

    #[cfg(target_os = "windows")]
    pub async fn recheck_cloud_files_conflicts(&self, root_id: Uuid) -> Result<(), String> {
        let host = {
            let running = self.running.lock().await;
            running
                .get(&root_id)
                .ok_or_else(|| format!("Cloud Files root {root_id} is not running"))?
                .host
                .clone()
        };
        host.recheck_conflicts(root_id)
            .await
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "windows")]
    pub async fn check_root_health(
        &self,
        root_id: Uuid,
    ) -> Result<hybridcipher_windows_cloud_provider::CloudRootHealthResponse, String> {
        let running = self.running.lock().await;
        let root = running
            .get(&root_id)
            .ok_or_else(|| format!("Cloud Files root {root_id} is not managed by this process"))?;
        let exhausted = root.recovery_exhausted.load(Ordering::Acquire);
        let mut health = root
            .host
            .check_root_health(root_id)
            .map_err(|error| error.to_string())?;
        if exhausted {
            let evidence = "Cloud Files automatic recovery exhausted its 3-attempt budget; stop and remount the root to retry".to_string();
            health.unhealthy_evidence.push(evidence.clone());
            if let Some(operational) = health.operational.as_mut() {
                operational.healthy = false;
                operational.unhealthy_evidence.push(evidence);
            }
        }
        Ok(health)
    }

    #[cfg(target_os = "windows")]
    pub async fn vault_compatibility(
        &self,
        root_id: Uuid,
        enabled: Option<bool>,
    ) -> Result<Option<hybridcipher_windows_cloud_provider::VaultCompatibilityStatus>, String> {
        let (host, lock) = {
            let running = self.running.lock().await;
            let root = running
                .get(&root_id)
                .ok_or("Mount the folder to manage legacy compatibility")?;
            (root.host.clone(), root.operation_lock.clone())
        };
        let _operation = lock.lock().await;
        match enabled {
            Some(enabled) => host
                .set_legacy_compatibility(root_id, enabled)
                .await
                .map(Some)
                .map_err(|e| e.to_string()),
            None => host
                .compatibility_status(root_id)
                .map_err(|e| e.to_string()),
        }
    }

    #[cfg(target_os = "windows")]
    pub async fn legacy_files(
        &self,
        root_id: Uuid,
    ) -> Result<Vec<hybridcipher_windows_cloud_provider::LegacyFileSummary>, String> {
        let (host, lock) = {
            let running = self.running.lock().await;
            let root = running
                .get(&root_id)
                .ok_or("Mount the folder to review older files")?;
            (root.host.clone(), root.operation_lock.clone())
        };
        let _operation = lock.lock().await;
        host.legacy_files(root_id).await.map_err(|e| e.to_string())
    }

    #[cfg(target_os = "windows")]
    pub async fn upgrade_legacy_files(
        &self,
        root_id: Uuid,
        relative_paths: Option<Vec<String>>,
    ) -> Result<hybridcipher_windows_cloud_provider::LegacyUpgradeReport, String> {
        let (host, lock) = {
            let running = self.running.lock().await;
            let root = running
                .get(&root_id)
                .ok_or("Mount the folder to upgrade older files")?;
            (root.host.clone(), root.operation_lock.clone())
        };
        let _operation = lock.lock().await;
        host.upgrade_legacy_files(root_id, relative_paths)
            .await
            .map_err(|e| e.to_string())
    }

    #[cfg(target_os = "windows")]
    pub async fn list_pending_operations(
        &self,
        root_id: Uuid,
    ) -> Result<serde_json::Value, String> {
        let running = self.running.lock().await;
        let root = running
            .get(&root_id)
            .ok_or("Mount the folder to view pending operations")?;
        let status = root
            .host
            .read_runtime_status(root_id)
            .map_err(|e| e.to_string())?;
        serde_json::to_value(status.pending_operations).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "windows")]
    pub async fn resolve_pending_operation(
        &self,
        root_id: Uuid,
        operation_id: Uuid,
        action: hybridcipher_windows_cloud_provider::PendingOperationResolution,
    ) -> Result<(), String> {
        let (host, lock) = {
            let running = self.running.lock().await;
            let root = running
                .get(&root_id)
                .ok_or("Mount the folder to resolve pending work")?;
            (root.host.clone(), root.operation_lock.clone())
        };
        let _operation = lock.lock().await;
        host.resolve_pending_operation(root_id, operation_id, action)
            .await
            .map_err(|e| e.to_string())
    }

    #[cfg(target_os = "macos")]
    pub async fn start_root(
        &self,
        user_config_dir: PathBuf,
        root_id: Uuid,
        provider_url: PathBuf,
        encrypted_root: PathBuf,
        display_name: String,
        client: Arc<LocalClient>,
    ) -> Result<(), String> {
        {
            let running = self.running.lock().await;
            if running.contains_key(&root_id) {
                return Ok(());
            }
        }
        let Some(_starting) = self.claim_start(root_id) else {
            return Err(
                "This folder is still being prepared after sign-in. Try again when it finishes."
                    .to_string(),
            );
        };

        let compatibility = Arc::new(
            hybridcipher_macos_file_provider::VaultCompatibility::load(&user_config_dir, root_id)
                .map_err(|error| error.to_string())?,
        );
        let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
            hybridcipher_macos_file_provider::ProviderHostConfig {
                user_config_dir: user_config_dir.clone(),
                socket_path: None,
                provider_identifier: Some(
                    "com.hybridcipher.app.HybridCipherFileProvider".to_string(),
                ),
            },
        );
        let status = host.status();
        if !(status.available && status.extension_ready) {
            return Err(status
                .message
                .unwrap_or_else(|| "macOS File Provider extension is not ready.".to_string()));
        }

        let registration = hybridcipher_macos_file_provider::FileProviderDomainRegistration {
            root_id,
            domain_identifier: format!("com.hybridcipher.root.{root_id}"),
            display_name,
            encrypted_root,
            user_visible_url: Some(provider_url),
        };
        let start_bridge = async {
            let excluded_patterns = client.excluded_file_patterns();
            let crypto = Arc::new(
                hybridcipher_macos_file_provider::ClientMountCrypto::for_root_with_compatibility(
                    client,
                    root_id,
                    compatibility.clone(),
                )
                .await
                .map_err(|err| err.to_string())?,
            );
            host.start_root_with_compatibility(
                root_id,
                crypto,
                excluded_patterns,
                compatibility.clone(),
            )
            .await
            .map_err(|err| err.to_string())
        };
        start_macos_root_with(
            &host,
            &registration,
            &NativeMacFileProviderSystemDomainRegistrar,
            start_bridge,
        )
        .await?;

        let mut running = self.running.lock().await;
        running.insert(
            root_id,
            RunningMacFileProviderRoot {
                host,
                registration,
                compatibility,
            },
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub async fn vault_compatibility(
        &self,
        root_id: Uuid,
        enabled: Option<bool>,
    ) -> Result<Option<hybridcipher_macos_file_provider::VaultCompatibilityStatus>, String> {
        let (host, compatibility) = {
            let running = self.running.lock().await;
            let root = running
                .get(&root_id)
                .ok_or("Mount the folder to manage legacy compatibility")?;
            (root.host.clone(), root.compatibility.clone())
        };
        if let Some(enabled) = enabled {
            compatibility
                .set_enabled(enabled)
                .map_err(|error| error.to_string())?;
            host.refresh_root(root_id)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(Some(compatibility.status()))
    }

    #[cfg(target_os = "macos")]
    pub async fn legacy_files(
        &self,
        root_id: Uuid,
    ) -> Result<Vec<hybridcipher_macos_file_provider::LegacyFileSummary>, String> {
        let host = self.running_macos_host(root_id).await?;
        host.legacy_files(root_id)
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "macos")]
    pub async fn upgrade_legacy_files(
        &self,
        root_id: Uuid,
        relative_paths: Option<Vec<String>>,
    ) -> Result<hybridcipher_macos_file_provider::LegacyUpgradeReport, String> {
        let host = self.running_macos_host(root_id).await?;
        host.upgrade_legacy_files(root_id, relative_paths)
            .await
            .map_err(|error| error.to_string())
    }

    /// Returns the conflict registry and the cache directory its relative paths
    /// resolve against.
    #[cfg(target_os = "macos")]
    pub async fn macos_conflict_location(
        &self,
        root_id: Uuid,
    ) -> Result<(PathBuf, PathBuf), String> {
        let host = self.running_macos_host(root_id).await?;
        let registry_path = host
            .conflict_registry_path(root_id)
            .map_err(|error| error.to_string())?;
        let cache_dir = host
            .runtime_paths(root_id)
            .map_err(|error| error.to_string())?
            .cache_dir;
        Ok((registry_path, cache_dir))
    }

    #[cfg(target_os = "macos")]
    pub async fn resolve_macos_conflict(
        &self,
        root_id: Uuid,
        request: hybridcipher_mount_sync::ConflictResolutionRequest,
    ) -> Result<hybridcipher_mount_sync::ConflictResolutionResult, String> {
        let host = self.running_macos_host(root_id).await?;
        host.resolve_conflict(root_id, request)
            .await
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "macos")]
    async fn running_macos_host(
        &self,
        root_id: Uuid,
    ) -> Result<hybridcipher_macos_file_provider::MacFileProviderHost, String> {
        let running = self.running.lock().await;
        let root = running
            .get(&root_id)
            .ok_or("Mount the folder to review conflicts")?;
        Ok(root.host.clone())
    }

    /// Run `reconcile_file_provider_roots` in the background, replacing any run
    /// still going. `stop_all` cancels it.
    #[cfg(target_os = "macos")]
    pub fn spawn_file_provider_reconcile(
        self: &Arc<Self>,
        user_config_dir: PathBuf,
        client: Arc<LocalClient>,
    ) {
        let manager = Arc::clone(self);
        let task = tauri::async_runtime::spawn(async move {
            match manager
                .reconcile_file_provider_roots(user_config_dir.clone(), client)
                .await
            {
                Ok(report) => {
                    crate::commands::record_reconnected_mounts(&user_config_dir, &report).await;
                    manager.emit_mounts_reconnected(&report);
                }
                Err(err) => {
                    tracing::warn!("macOS File Provider reconciliation failed: {}", err);
                }
            }
        });
        let previous = self
            .reconcile_task
            .lock()
            .ok()
            .and_then(|mut slot| slot.replace(task));
        if let Some(previous) = previous {
            previous.abort();
        }
    }

    #[cfg(target_os = "macos")]
    pub async fn reconcile_file_provider_roots(
        &self,
        user_config_dir: PathBuf,
        client: Arc<LocalClient>,
    ) -> Result<ReconnectReport, String> {
        let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
            hybridcipher_macos_file_provider::ProviderHostConfig {
                user_config_dir: user_config_dir.clone(),
                socket_path: None,
                provider_identifier: Some(
                    "com.hybridcipher.app.HybridCipherFileProvider".to_string(),
                ),
            },
        );
        let registrations = host
            .load_registrations()
            .map_err(|err| format!("Failed to load macOS File Provider registrations: {err}"))?;
        let mut report = ReconnectReport::default();
        if registrations.is_empty() {
            return Ok(report);
        }

        let status = host.status();
        if !(status.available && status.extension_ready) {
            let reason = status
                .message
                .unwrap_or_else(|| "macOS File Provider extension is not ready".to_string());
            let registrar = NativeMacFileProviderSystemDomainRegistrar;
            for registration in registrations {
                tracing::warn!(
                    "Unregistering macOS File Provider root {} because extension is not restartable: {}",
                    registration.root_id,
                    reason
                );
                let _ = registrar.unregister_system_domain(&registration);
                let _ = host.unregister_domain_state(registration.root_id);
                report.fail(
                    registration.root_id,
                    &registration.encrypted_root,
                    format!("Unmounted because {reason}"),
                );
            }
            return Ok(report);
        }

        let registrar = NativeMacFileProviderSystemDomainRegistrar;
        for registration in registrations {
            {
                let running = self.running.lock().await;
                if running.contains_key(&registration.root_id) {
                    continue;
                }
            }
            // A mount the user started meanwhile owns this root.
            let Some(_starting) = self.claim_start(registration.root_id) else {
                continue;
            };

            let health = host.check_runtime_health(registration.root_id);
            if matches!(
                health.as_ref(),
                Ok(health) if health.registration_present && health.socket_reachable
            ) {
                tracing::info!(
                    "macOS File Provider root {} already has a healthy bridge socket",
                    registration.root_id
                );
                continue;
            }

            let excluded_patterns = client.excluded_file_patterns();
            let compatibility = Arc::new(
                hybridcipher_macos_file_provider::VaultCompatibility::load(
                    &user_config_dir,
                    registration.root_id,
                )
                .map_err(|error| error.to_string())?,
            );
            let crypto = Arc::new(
                hybridcipher_macos_file_provider::ClientMountCrypto::for_root_with_compatibility(
                    client.clone(),
                    registration.root_id,
                    compatibility.clone(),
                )
                .await
                .map_err(|err| err.to_string())?,
            );
            let restart_result = host
                .start_root_with_compatibility(
                    registration.root_id,
                    crypto,
                    excluded_patterns,
                    compatibility.clone(),
                )
                .await
                .map_err(|err| err.to_string())
                .and_then(|_| {
                    host.check_runtime_health(registration.root_id)
                        .map_err(|err| err.to_string())
                });

            match restart_result {
                Ok(health) if health.registration_present && health.socket_reachable => {
                    // macOS restarted this kept domain before the bridge existed and
                    // may have backed it off; lift that now the bridge answers.
                    let domain_identifier = registration.domain_identifier.clone();
                    let root_id = registration.root_id;
                    if let Ok(Err(err)) = tokio::task::spawn_blocking(move || {
                        crate::macos_file_provider_native::wake_domain(&domain_identifier)
                    })
                    .await
                    {
                        tracing::warn!(
                            "Could not wake the restored File Provider root {}: {}",
                            root_id,
                            err
                        );
                    }
                    report.reconnected.push(ReconnectedRoot {
                        root_id: registration.root_id,
                        mountpoint: registration
                            .user_visible_url
                            .clone()
                            .or_else(|| {
                                dirs::home_dir().map(|home| {
                                    home.join("Library").join("CloudStorage").join(format!(
                                        "HybridCipher-{}",
                                        registration.display_name
                                    ))
                                })
                            })
                            .unwrap_or_default(),
                        encrypted_root: registration.encrypted_root.clone(),
                    });
                    let mut running = self.running.lock().await;
                    running.insert(
                        registration.root_id,
                        RunningMacFileProviderRoot {
                            host: host.clone(),
                            registration,
                            compatibility,
                        },
                    );
                }
                Ok(health) => {
                    let reason = health.latest_error.unwrap_or_else(|| {
                        "registration or provider socket health check failed".to_string()
                    });
                    tracing::warn!(
                        "Unregistering stale macOS File Provider root {} after failed bridge restart: {}",
                        registration.root_id,
                        reason
                    );
                    let _ = registrar.unregister_system_domain(&registration);
                    let _ = host.unregister_domain_state(registration.root_id);
                    report.fail(
                        registration.root_id,
                        &registration.encrypted_root,
                        format!("Unmounted because it could not be reconnected: {reason}"),
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        "Unregistering stale macOS File Provider root {} after failed bridge restart: {}",
                        registration.root_id,
                        err
                    );
                    let _ = registrar.unregister_system_domain(&registration);
                    let _ = host.unregister_domain_state(registration.root_id);
                    report.fail(
                        registration.root_id,
                        &registration.encrypted_root,
                        format!("Unmounted because it could not be reconnected: {err}"),
                    );
                }
            }
        }

        Ok(report)
    }

    #[cfg(target_os = "windows")]
    pub async fn reconcile_windows_cloud_roots(
        &self,
        user_config_dir: PathBuf,
        client: Arc<LocalClient>,
    ) -> Result<ReconnectReport, String> {
        let host = hybridcipher_windows_cloud_provider::CloudProviderHost::new(
            hybridcipher_windows_cloud_provider::ProviderHostConfig {
                user_config_dir: user_config_dir.clone(),
                pipe_name: None,
            },
        );
        let registrations = host
            .load_registrations()
            .map_err(|err| format!("Failed to load Windows Cloud Files registrations: {err}"))?;
        let mut report = ReconnectReport::default();
        for registration in registrations {
            if self
                .running
                .lock()
                .await
                .contains_key(&registration.root_id)
            {
                continue;
            }
            let mut last_error = None;
            for attempt in 1..=3u32 {
                match self
                    .start_root(
                        user_config_dir.clone(),
                        registration.root_id,
                        registration.sync_root_path.clone(),
                        registration.encrypted_root.clone(),
                        registration.display_name.clone(),
                        client.clone(),
                    )
                    .await
                {
                    Ok(()) => {
                        last_error = None;
                        break;
                    }
                    Err(error) => {
                        last_error = Some(format!("attempt {attempt}: {error}"));
                        if attempt < 3 {
                            tokio::time::sleep(std::time::Duration::from_millis(
                                250 * u64::from(attempt),
                            ))
                            .await;
                        }
                    }
                }
            }
            match last_error {
                Some(error) => report.fail(registration.root_id, &registration.encrypted_root, error),
                None => report.reconnected.push(ReconnectedRoot {
                    root_id: registration.root_id,
                    mountpoint: registration.sync_root_path,
                    encrypted_root: registration.encrypted_root,
                }),
            }
        }
        Ok(report)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    pub async fn start_root(
        &self,
        _user_config_dir: PathBuf,
        _root_id: Uuid,
        _sync_root_path: PathBuf,
        _encrypted_root: PathBuf,
        _display_name: String,
        _client: Arc<LocalClient>,
    ) -> Result<(), String> {
        Err("Desktop cloud provider mounts are only available on Windows and macOS.".to_string())
    }

    #[cfg(target_os = "windows")]
    pub async fn stop_root(
        &self,
        root_id: Uuid,
        dehydrate: bool,
        force: bool,
    ) -> Result<(), String> {
        let (host, operation_lock, owner_token, recovery_exhausted) = {
            let roots = self.running.lock().await;
            let Some(running) = roots.get(&root_id) else {
                return Ok(());
            };
            (
                running.host.clone(),
                running.operation_lock.clone(),
                running.owner_token,
                running.recovery_exhausted.clone(),
            )
        };
        let _operation = operation_lock.lock().await;
        if !self
            .running
            .lock()
            .await
            .get(&root_id)
            .is_some_and(|root| root.owner_token == owner_token)
        {
            return Ok(());
        }
        if !force {
            let status = host
                .read_runtime_status(root_id)
                .map_err(|err| err.to_string())?;
            if !status.safe_to_unmount {
                let detail = status
                    .last_error
                    .unwrap_or_else(|| "pending Cloud Files mutation work remains".to_string());
                return Err(format!(
                    "Cloud Files root {} is not safe to unmount: {}",
                    root_id, detail
                ));
            }
        }
        let recovery_preserved_reason = if force {
            if host.is_root_running(root_id) {
                host.stop_root(root_id)
                    .await
                    .map_err(|err| err.to_string())?;
            }
            None
        } else if dehydrate {
            match host
                .unmount_root_safely(root_id)
                .await
                .map_err(|err| err.to_string())?
            {
                hybridcipher_windows_cloud_provider::SafeRootStopOutcome::Cleaned => None,
                hybridcipher_windows_cloud_provider::SafeRootStopOutcome::RecoveryPreserved {
                    reason,
                } => Some(reason),
            }
        } else {
            match host
                .stop_root_safely(root_id, false)
                .await
                .map_err(|err| err.to_string())?
            {
                hybridcipher_windows_cloud_provider::SafeRootStopOutcome::Cleaned => None,
                hybridcipher_windows_cloud_provider::SafeRootStopOutcome::RecoveryPreserved {
                    reason,
                } => Some(reason),
            }
        };
        if let Some(reason) = recovery_preserved_reason {
            recovery_exhausted.store(true, Ordering::Release);
            return Err(format!(
                "Cloud Files root {root_id} stopped, but cleanup was skipped to preserve recovery state: {reason}"
            ));
        }
        self.running.lock().await.remove(&root_id);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub async fn stop_root(
        &self,
        root_id: Uuid,
        _dehydrate: bool,
        force: bool,
    ) -> Result<(), String> {
        let running = {
            let mut running = self.running.lock().await;
            running.remove(&root_id)
        };
        let Some(running) = running else {
            return Ok(());
        };

        if !force {
            // Let macOS hand over edits it has not given the extension yet, while
            // the bridge still runs; removing the domain first sets them aside.
            let domain_identifier = running.registration.domain_identifier.clone();
            match tokio::task::spawn_blocking(move || {
                crate::macos_file_provider_native::wait_for_pending_changes(
                    &domain_identifier,
                    MACOS_PENDING_CHANGES_WAIT_SECS,
                )
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => tracing::warn!(
                    "macOS File Provider root {} still had edits Finder had not handed over: {}",
                    root_id,
                    err
                ),
                Err(err) => tracing::warn!(
                    "Waiting for macOS File Provider edits of root {} failed: {}",
                    root_id,
                    err
                ),
            }
            let status = running
                .host
                .read_runtime_status(root_id)
                .map_err(|err| err.to_string())?;
            if !status.safe_to_unmount {
                let detail = status
                    .last_error
                    .unwrap_or_else(|| "pending File Provider mutation work remains".to_string());
                let mut guard = self.running.lock().await;
                guard.insert(root_id, running);
                return Err(format!(
                    "macOS File Provider root {} is not safe to unmount: {}",
                    root_id, detail
                ));
            }
        }

        running
            .host
            .stop_root(root_id)
            .map_err(|err| err.to_string())?;
        unregister_macos_domain_for_desktop(
            &running.host,
            &running.registration,
            &NativeMacFileProviderSystemDomainRegistrar,
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    pub async fn stop_root(
        &self,
        _root_id: Uuid,
        _dehydrate: bool,
        _force: bool,
    ) -> Result<(), String> {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub async fn stop_all(&self, dehydrate: bool, force: bool) -> Result<(), String> {
        let root_ids = {
            let running = self.running.lock().await;
            running.keys().copied().collect::<Vec<_>>()
        };
        let mut failures = Vec::new();
        for root_id in root_ids {
            if let Err(err) = self.stop_root(root_id, dehydrate, force).await {
                failures.push(format!("{}: {}", root_id, err));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    #[cfg(target_os = "macos")]
    pub async fn stop_all(&self, dehydrate: bool, force: bool) -> Result<(), String> {
        // Stop restarting roots first, so none starts after this sweep or keeps
        // decrypting for an account that is signing out.
        let reconcile = self.reconcile_task.lock().ok().and_then(|mut task| task.take());
        if let Some(task) = reconcile {
            task.abort();
            let _ = task.await;
        }
        let root_ids = {
            let running = self.running.lock().await;
            running.keys().copied().collect::<Vec<_>>()
        };
        let mut failures = Vec::new();
        for root_id in root_ids {
            if let Err(err) = self.stop_root(root_id, dehydrate, force).await {
                failures.push(format!("{}: {}", root_id, err));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    pub async fn stop_all(&self, _dehydrate: bool, _force: bool) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;

    #[test]
    fn cloud_provider_health_readiness_requires_cross_process_durable_truth() {
        assert!(cloud_provider_health_ready(true, true, true, true));
        assert!(!cloud_provider_health_ready(false, true, true, true));
        assert!(!cloud_provider_health_ready(true, false, true, true));
        assert!(!cloud_provider_health_ready(true, true, false, true));
        assert!(!cloud_provider_health_ready(true, true, true, false));
    }

    #[test]
    fn cloud_provider_supervisor_recovers_only_unhealthy_roots() {
        assert!(!cloud_provider_supervisor_requires_recovery(
            true, true, true
        ));
        assert!(cloud_provider_supervisor_requires_recovery(
            false, true, true
        ));
        assert!(cloud_provider_supervisor_requires_recovery(
            true, false, true
        ));
        assert!(cloud_provider_supervisor_requires_recovery(
            true, true, false
        ));
    }
}

impl Default for DesktopCloudProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    type EventLog = Arc<StdMutex<Vec<&'static str>>>;

    #[derive(Default)]
    struct RecordingMacRegistrar {
        registered: Arc<StdMutex<Vec<String>>>,
        unregistered: Arc<StdMutex<Vec<String>>>,
        /// Shared with a test's bridge start, to record the order of steps.
        events: EventLog,
        fail_register: bool,
    }

    impl MacFileProviderSystemDomainRegistrar for RecordingMacRegistrar {
        fn register_system_domain(
            &self,
            registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
        ) -> Result<(), String> {
            self.events.lock().unwrap().push("system");
            if self.fail_register {
                return Err("addDomain refused".to_string());
            }
            self.registered
                .lock()
                .unwrap()
                .push(registration.domain_identifier.clone());
            Ok(())
        }

        fn unregister_system_domain(
            &self,
            registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
        ) -> Result<(), String> {
            self.unregistered
                .lock()
                .unwrap()
                .push(registration.domain_identifier.clone());
            Ok(())
        }
    }

    fn test_host_and_registration(
        temp: &tempfile::TempDir,
    ) -> (
        hybridcipher_macos_file_provider::MacFileProviderHost,
        hybridcipher_macos_file_provider::FileProviderDomainRegistration,
        std::path::PathBuf,
    ) {
        let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
            hybridcipher_macos_file_provider::ProviderHostConfig {
                user_config_dir: temp.path().to_path_buf(),
                socket_path: None,
                provider_identifier: None,
            },
        );
        let registration = hybridcipher_macos_file_provider::FileProviderDomainRegistration {
            root_id: Uuid::new_v4(),
            domain_identifier: "com.hybridcipher.root.test".to_string(),
            display_name: "HybridCipher Test".to_string(),
            encrypted_root: temp.path().join("encrypted"),
            user_visible_url: None,
        };
        let state_path = temp
            .path()
            .join("macos-file-provider")
            .join("domains")
            .join(format!("{}.json", registration.root_id));
        (host, registration, state_path)
    }

    #[tokio::test]
    async fn the_bridge_starts_before_macos_learns_of_the_domain() {
        let temp = tempfile::tempdir().unwrap();
        let (host, registration, state_path) = test_host_and_registration(&temp);
        let registrar = RecordingMacRegistrar::default();
        let events = registrar.events.clone();

        start_macos_root_with(&host, &registration, &registrar, async {
            assert!(
                state_path.is_file(),
                "the bridge needs the saved registration"
            );
            events.lock().unwrap().push("bridge");
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(
            registrar.events.lock().unwrap().as_slice(),
            ["bridge", "system"]
        );
        assert_eq!(
            registrar.registered.lock().unwrap().as_slice(),
            ["com.hybridcipher.root.test"]
        );
        assert!(state_path.is_file());
    }

    #[tokio::test]
    async fn a_bridge_that_fails_to_start_never_reaches_macos() {
        let temp = tempfile::tempdir().unwrap();
        let (host, registration, state_path) = test_host_and_registration(&temp);
        let registrar = RecordingMacRegistrar::default();

        let result = start_macos_root_with(&host, &registration, &registrar, async {
            Err("crypto unavailable".to_string())
        })
        .await;

        assert_eq!(result.unwrap_err(), "crypto unavailable");
        assert!(registrar.registered.lock().unwrap().is_empty());
        assert!(!state_path.exists(), "the saved registration is removed");
    }

    #[tokio::test]
    async fn a_domain_macos_refuses_undoes_the_saved_registration() {
        let temp = tempfile::tempdir().unwrap();
        let (host, registration, state_path) = test_host_and_registration(&temp);
        let registrar = RecordingMacRegistrar {
            fail_register: true,
            ..Default::default()
        };

        let result =
            start_macos_root_with(&host, &registration, &registrar, async { Ok(()) }).await;

        assert_eq!(result.unwrap_err(), "addDomain refused");
        assert!(!state_path.exists());
    }

    #[test]
    fn desktop_macos_unregister_uses_in_app_registrar_and_removes_state() {
        let temp = tempfile::tempdir().unwrap();
        let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
            hybridcipher_macos_file_provider::ProviderHostConfig {
                user_config_dir: temp.path().to_path_buf(),
                socket_path: None,
                provider_identifier: None,
            },
        );
        let registration = hybridcipher_macos_file_provider::FileProviderDomainRegistration {
            root_id: Uuid::new_v4(),
            domain_identifier: "com.hybridcipher.root.test".to_string(),
            display_name: "HybridCipher Test".to_string(),
            encrypted_root: temp.path().join("encrypted"),
            user_visible_url: None,
        };
        host.register_domain(&registration).unwrap();
        let state_path = temp
            .path()
            .join("macos-file-provider")
            .join("domains")
            .join(format!("{}.json", registration.root_id));
        assert!(state_path.is_file());
        let registrar = RecordingMacRegistrar::default();

        unregister_macos_domain_for_desktop(&host, &registration, &registrar).unwrap();

        assert_eq!(
            registrar.unregistered.lock().unwrap().as_slice(),
            ["com.hybridcipher.root.test"]
        );
        assert!(!state_path.exists());
    }
}
