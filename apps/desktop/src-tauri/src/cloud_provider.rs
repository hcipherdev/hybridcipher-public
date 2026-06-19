use crate::local_client::LocalClient;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tauri::async_runtime::Mutex;
use uuid::Uuid;

#[cfg(target_os = "windows")]
struct RunningCloudRoot {
    host: hybridcipher_windows_cloud_provider::CloudProviderHost,
    registration: hybridcipher_windows_cloud_provider::CloudRootRegistration,
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
        display_name: String,
        client: Arc<LocalClient>,
    ) -> Result<(), String> {
        {
            let running = self.running.lock().await;
            if running.contains_key(&root_id) {
                return Ok(());
            }
        }

        let host = hybridcipher_windows_cloud_provider::CloudProviderHost::new(
            hybridcipher_windows_cloud_provider::ProviderHostConfig {
                user_config_dir,
                pipe_name: None,
            },
        );
        let status = host.status();
        if !status.native_callbacks_ready {
            return Err(status.message.unwrap_or_else(|| {
                "Windows Cloud Files provider native callbacks are unavailable.".to_string()
            }));
        }

        let registration = hybridcipher_windows_cloud_provider::CloudRootRegistration {
            root_id,
            sync_root_path,
            encrypted_root,
            display_name,
        };
        host.register_root(&registration)
            .map_err(|err| err.to_string())?;
        host.sync_placeholders(&registration)
            .map_err(|err| err.to_string())?;
        host.start_root_with_bridge(
            root_id,
            hybridcipher_windows_cloud_provider::local_provider_bridge(client),
        )
        .await
        .map_err(|err| err.to_string())?;

        let mut running = self.running.lock().await;
        running.insert(root_id, RunningCloudRoot { host, registration });
        Ok(())
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
                    .unwrap_or_else(|| "pending Cloud Files mutation work remains".to_string());
                let mut guard = self.running.lock().await;
                guard.insert(root_id, running);
                return Err(format!(
                    "Cloud Files root {} is not safe to unmount: {}",
                    root_id, detail
                ));
            }
        }

        if dehydrate && !force {
            running
                .host
                .dehydrate_root_path(&running.registration.sync_root_path)
                .map_err(|err| err.to_string())?;
        }
        running
            .host
            .stop_root(root_id)
            .map_err(|err| err.to_string())
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
