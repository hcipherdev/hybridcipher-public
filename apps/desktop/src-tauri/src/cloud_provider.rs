use crate::local_client::LocalClient;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tauri::async_runtime::Mutex;
use uuid::Uuid;

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

#[cfg(target_os = "macos")]
fn register_macos_domain_for_desktop<R: MacFileProviderSystemDomainRegistrar>(
    host: &hybridcipher_macos_file_provider::MacFileProviderHost,
    registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
    registrar: &R,
) -> Result<(), String> {
    host.register_domain(registration)
        .map_err(|err| err.to_string())?;
    if let Err(err) = registrar.register_system_domain(registration) {
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
        }
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
        _display_name: String,
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
        let bridge = hybridcipher_windows_cloud_provider::local_provider_bridge_with_compatibility(
            client.clone(),
            compatibility,
        );
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

        let vault_name = encrypted_root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("Vault");
        let base_display_name = format!("HybridCipher — {vault_name}");
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
        register_macos_domain_for_desktop(
            &host,
            &registration,
            &NativeMacFileProviderSystemDomainRegistrar,
        )?;
        let excluded_patterns = client.excluded_file_patterns();
        let crypto = Arc::new(hybridcipher_macos_file_provider::ClientMountCrypto::new(
            client,
        ));
        if let Err(err) = host
            .start_root_with_crypto_and_exclusions(root_id, crypto, excluded_patterns)
            .await
        {
            let registrar = NativeMacFileProviderSystemDomainRegistrar;
            let _ = registrar.unregister_system_domain(&registration);
            let _ = host.unregister_domain_state(root_id);
            return Err(err.to_string());
        }

        let mut running = self.running.lock().await;
        running.insert(root_id, RunningMacFileProviderRoot { host, registration });
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub async fn reconcile_file_provider_roots(
        &self,
        user_config_dir: PathBuf,
        client: Arc<LocalClient>,
    ) -> Result<(), String> {
        let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
            hybridcipher_macos_file_provider::ProviderHostConfig {
                user_config_dir,
                socket_path: None,
                provider_identifier: Some(
                    "com.hybridcipher.app.HybridCipherFileProvider".to_string(),
                ),
            },
        );
        let registrations = host
            .load_registrations()
            .map_err(|err| format!("Failed to load macOS File Provider registrations: {err}"))?;
        if registrations.is_empty() {
            return Ok(());
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
            }
            return Ok(());
        }

        let registrar = NativeMacFileProviderSystemDomainRegistrar;
        for registration in registrations {
            {
                let running = self.running.lock().await;
                if running.contains_key(&registration.root_id) {
                    continue;
                }
            }

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
            let crypto = Arc::new(hybridcipher_macos_file_provider::ClientMountCrypto::new(
                client.clone(),
            ));
            let restart_result = host
                .start_root_with_crypto_and_exclusions(
                    registration.root_id,
                    crypto,
                    excluded_patterns,
                )
                .await
                .map_err(|err| err.to_string())
                .and_then(|_| {
                    host.check_runtime_health(registration.root_id)
                        .map_err(|err| err.to_string())
                });

            match restart_result {
                Ok(health) if health.registration_present && health.socket_reachable => {
                    let mut running = self.running.lock().await;
                    running.insert(
                        registration.root_id,
                        RunningMacFileProviderRoot {
                            host: host.clone(),
                            registration,
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
                }
                Err(err) => {
                    tracing::warn!(
                        "Unregistering stale macOS File Provider root {} after failed bridge restart: {}",
                        registration.root_id,
                        err
                    );
                    let _ = registrar.unregister_system_domain(&registration);
                    let _ = host.unregister_domain_state(registration.root_id);
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub async fn reconcile_windows_cloud_roots(
        &self,
        user_config_dir: PathBuf,
        client: Arc<LocalClient>,
    ) -> Result<(), String> {
        let host = hybridcipher_windows_cloud_provider::CloudProviderHost::new(
            hybridcipher_windows_cloud_provider::ProviderHostConfig {
                user_config_dir: user_config_dir.clone(),
                pipe_name: None,
            },
        );
        let registrations = host
            .load_registrations()
            .map_err(|err| format!("Failed to load Windows Cloud Files registrations: {err}"))?;
        let mut failures = Vec::new();
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
            if let Some(error) = last_error {
                failures.push(format!("{}: {}", registration.root_id, error));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
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

    #[derive(Default)]
    struct RecordingMacRegistrar {
        registered: Arc<StdMutex<Vec<String>>>,
        unregistered: Arc<StdMutex<Vec<String>>>,
    }

    impl MacFileProviderSystemDomainRegistrar for RecordingMacRegistrar {
        fn register_system_domain(
            &self,
            registration: &hybridcipher_macos_file_provider::FileProviderDomainRegistration,
        ) -> Result<(), String> {
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

    #[test]
    fn desktop_macos_registration_uses_in_app_registrar() {
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
        let registrar = RecordingMacRegistrar::default();

        register_macos_domain_for_desktop(&host, &registration, &registrar).unwrap();

        assert_eq!(
            registrar.registered.lock().unwrap().as_slice(),
            ["com.hybridcipher.root.test"]
        );
        assert!(temp
            .path()
            .join("macos-file-provider")
            .join("domains")
            .join(format!("{}.json", registration.root_id))
            .is_file());
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
