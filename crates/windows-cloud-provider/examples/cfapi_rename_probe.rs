#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("the CFAPI rename probe is only available on Windows");
}

#[cfg(target_os = "windows")]
mod windows_probe {
    use async_trait::async_trait;
    use chrono::Utc;
    use hybridcipher_provider_core::{
        FileIdentityV1, ProviderBridge, ProviderEntry, Result as ProviderResult,
    };
    use hybridcipher_windows_cloud_provider::{
        CloudCallbackKind, CloudProviderHost, CloudRootRegistration, ProviderHostConfig,
        SafeRootStopOutcome,
    };
    use std::{
        collections::HashMap,
        error::Error,
        fs,
        path::{Path, PathBuf},
        process::Command,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::{Duration, Instant},
    };
    use uuid::Uuid;

    #[derive(Clone)]
    struct ProbeEntry {
        entry: ProviderEntry,
        bytes: Vec<u8>,
    }

    #[derive(Default)]
    struct ProbeBridge {
        entries: Mutex<HashMap<String, ProbeEntry>>,
        delay_next_write: AtomicBool,
        delayed_write_started: AtomicBool,
    }

    impl ProbeBridge {
        fn insert_directory(&self, root_id: Uuid, encrypted_root: &Path, relative_path: &str) {
            let entry = ProviderEntry::cache_directory(
                root_id,
                relative_path,
                encrypted_root.join(relative_path),
                Utc::now(),
            );
            self.entries.lock().expect("probe bridge lock").insert(
                relative_path.to_string(),
                ProbeEntry {
                    entry,
                    bytes: Vec::new(),
                },
            );
        }

        fn contains(&self, relative_path: &str) -> bool {
            self.entries
                .lock()
                .expect("probe bridge lock")
                .contains_key(relative_path)
        }

        fn file_id(&self, relative_path: &str) -> Option<String> {
            self.entries
                .lock()
                .expect("probe bridge lock")
                .get(relative_path)
                .and_then(|entry| entry.entry.identity.file_id.clone())
        }

        fn content_matches(&self, relative_path: &str, expected: &[u8]) -> bool {
            self.entries
                .lock()
                .expect("probe bridge lock")
                .get(relative_path)
                .is_some_and(|entry| entry.bytes == expected)
        }

        fn write_plaintext(
            &self,
            root_id: Uuid,
            encrypted_root: &Path,
            relative_path: &str,
            plaintext_path: &Path,
            existing_identity: Option<&FileIdentityV1>,
        ) -> ProviderResult<ProviderEntry> {
            let bytes = fs::read(plaintext_path)?;
            let file_id = existing_identity
                .and_then(|identity| identity.file_id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            let epoch_id = existing_identity
                .and_then(|identity| identity.epoch_id)
                .or(Some(1));
            let entry = ProviderEntry::cache_file_with_identity(
                root_id,
                relative_path,
                encrypted_root.join(format!("{}.probe", relative_path.replace('/', "_"))),
                bytes.len() as u64,
                bytes.len() as u64,
                Utc::now(),
                None,
                Some(file_id),
                epoch_id,
            );
            let mut entries = self.entries.lock().expect("probe bridge lock");
            if let Some(identity) = existing_identity {
                entries.remove(&identity.relative_path);
            }
            entries.insert(
                relative_path.to_string(),
                ProbeEntry {
                    entry: entry.clone(),
                    bytes,
                },
            );
            Ok(entry)
        }
    }

    #[async_trait]
    impl ProviderBridge for ProbeBridge {
        async fn inventory(
            &self,
            _root_id: Uuid,
            _encrypted_root: &Path,
        ) -> ProviderResult<Vec<ProviderEntry>> {
            Ok(self
                .entries
                .lock()
                .expect("probe bridge lock")
                .values()
                .map(|entry| entry.entry.clone())
                .collect())
        }

        async fn hydrate_file(&self, entry: &ProviderEntry) -> ProviderResult<Vec<u8>> {
            Ok(self
                .entries
                .lock()
                .expect("probe bridge lock")
                .get(&entry.relative_path)
                .map(|entry| entry.bytes.clone())
                .unwrap_or_default())
        }

        async fn writeback_file(
            &self,
            root_id: Uuid,
            encrypted_root: &Path,
            relative_path: &str,
            plaintext_path: &Path,
            existing_identity: Option<&FileIdentityV1>,
        ) -> ProviderResult<ProviderEntry> {
            if self.delay_next_write.swap(false, Ordering::SeqCst) {
                self.delayed_write_started.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            self.write_plaintext(
                root_id,
                encrypted_root,
                relative_path,
                plaintext_path,
                existing_identity,
            )
        }

        async fn delete_entry(
            &self,
            _encrypted_root: &Path,
            identity: &FileIdentityV1,
        ) -> ProviderResult<()> {
            self.entries
                .lock()
                .expect("probe bridge lock")
                .remove(&identity.relative_path);
            Ok(())
        }

        async fn rename_entry(
            &self,
            root_id: Uuid,
            encrypted_root: &Path,
            source_identity: &FileIdentityV1,
            target_relative_path: &str,
            target_plaintext_path: Option<&Path>,
        ) -> ProviderResult<Option<ProviderEntry>> {
            let Some(plaintext_path) = target_plaintext_path else {
                return Ok(None);
            };
            self.write_plaintext(
                root_id,
                encrypted_root,
                target_relative_path,
                plaintext_path,
                Some(source_identity),
            )
            .map(Some)
        }
    }

    async fn wait_for(
        label: &str,
        timeout: Duration,
        condition: impl Fn() -> bool,
    ) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!("timed out waiting for {label}").into())
    }

    fn rename_in_child_process(source: &Path, target: &Path) -> Result<(), Box<dyn Error>> {
        let status = Command::new(std::env::current_exe()?)
            .arg("--rename-child")
            .arg(source)
            .arg(target)
            .status()?;
        if !status.success() {
            return Err(format!("external rename process exited with {status}").into());
        }
        Ok(())
    }

    fn run_child() -> Result<bool, Box<dyn Error>> {
        let mut args = std::env::args_os();
        let _program = args.next();
        let mode = args.next();
        if mode.as_deref() == Some(std::ffi::OsStr::new("--edit-child")) {
            let path = PathBuf::from(args.next().ok_or("missing child edit path")?);
            fs::write(path, b"edited during provider recovery\n")?;
            return Ok(true);
        }
        if mode.as_deref() != Some(std::ffi::OsStr::new("--rename-child")) {
            return Ok(false);
        }
        let source = PathBuf::from(args.next().ok_or("missing child source path")?);
        let target = PathBuf::from(args.next().ok_or("missing child target path")?);
        fs::rename(source, target)?;
        Ok(true)
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        if run_child()? {
            return Ok(());
        }

        let root_id = Uuid::new_v4();
        let base = std::env::current_dir()?
            .join("target")
            .join("cfapi-rename-probe")
            .join(root_id.to_string());
        let sync_root_path = base
            .join(".hybridcipher")
            .join(format!("probe_{root_id}_mount"));
        let encrypted_root = base.join("encrypted");
        let user_config_dir = base.join(".hybridcipher");
        fs::create_dir_all(&sync_root_path)?;
        fs::create_dir_all(&encrypted_root)?;
        fs::create_dir_all(&user_config_dir)?;

        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir,
            pipe_name: None,
        });
        let registration = CloudRootRegistration::legacy_cfapi(
            root_id,
            sync_root_path.clone(),
            encrypted_root.clone(),
            format!("HybridCipher CFAPI Rename Probe {root_id}"),
        );
        let bridge = Arc::new(ProbeBridge::default());
        bridge.insert_directory(root_id, &encrypted_root, "nested");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let result = (|| -> Result<(), Box<dyn Error>> {
            host.register_root(&registration)?;
            runtime.block_on(async {
                host.start_root_with_bridge(root_id, bridge.clone()).await?;
                host.probe_root(root_id).await?;
                let source = sync_root_path.join("nested").join("untitled.md");
                let target = sync_root_path.join("nested").join("renamed.md");
                fs::write(&source, b"cfapi external rename probe\n")?;
                wait_for("new-file writeback", Duration::from_secs(15), || {
                    bridge.contains("nested/untitled.md")
                })
                .await?;
                let original_file_id = bridge.file_id("nested/untitled.md");

                rename_in_child_process(&source, &target)?;
                wait_for("rename writeback", Duration::from_secs(15), || {
                    !source.exists()
                        && target.exists()
                        && !bridge.contains("nested/untitled.md")
                        && bridge.contains("nested/renamed.md")
                })
                .await?;
                if original_file_id != bridge.file_id("nested/renamed.md") {
                    return Err("stable file identity changed during rename".into());
                }
                println!(
                    "rename probe passed: {} -> {}",
                    source.display(),
                    target.display()
                );

                // Exercise a real Close callback while restarting. A provider-owned
                // file open cannot test this because self-hydration is blocked.
                bridge.delay_next_write.store(true, Ordering::SeqCst);
                let edit_path = target.clone();
                let executable = std::env::current_exe()?;
                let editor = tokio::task::spawn_blocking(move || {
                    Command::new(executable).arg("--edit-child").arg(edit_path).status()
                });
                wait_for("delayed edit writeback", Duration::from_secs(15), || {
                    bridge.delayed_write_started.load(Ordering::SeqCst)
                        && host.check_root_health(root_id).ok()
                            .and_then(|health| health.operational)
                            .is_some_and(|health| health.callback_health.iter().any(|callback| {
                                callback.kind == CloudCallbackKind::Close && callback.in_flight_count > 0
                            }))
                }).await?;
                host.stop_root_for_restart(root_id).await?;
                if !editor.await??.success() {
                    return Err("external editor failed".into());
                }
                if host.read_runtime_status(root_id)?.safe_to_unmount {
                    return Err("disconnected root incorrectly reported safe".into());
                }
                let offline = sync_root_path.join("nested").join("offline-created.md");
                fs::write(&offline, b"created while disconnected\n")?;
                host.start_root_with_bridge(root_id, bridge.clone()).await?;
                host.probe_root(root_id).await?;
                wait_for("recovered edits and offline new file", Duration::from_secs(15), || {
                    bridge.content_matches("nested/renamed.md", b"edited during provider recovery\n")
                        && bridge.content_matches("nested/offline-created.md", b"created while disconnected\n")
                }).await?;
                let after_restart = sync_root_path.join("nested").join("after-restart.md");
                fs::write(&after_restart, b"new file after restart\n")?;
                wait_for("new-file writeback after restart", Duration::from_secs(15), || {
                    bridge.content_matches("nested/after-restart.md", b"new file after restart\n")
                }).await?;
                println!("recovery probe passed: delayed edit, offline creation, and post-restart creation");
                Ok(())
            })
        })();

        let cleanup_complete = runtime.block_on(async {
            for path in [
                sync_root_path.join("nested").join("untitled.md"),
                sync_root_path.join("nested").join("renamed.md"),
                sync_root_path.join("nested").join("offline-created.md"),
                sync_root_path.join("nested").join("after-restart.md"),
            ] {
                if path.exists() {
                    let _ = fs::remove_file(path);
                }
            }
            let _ = wait_for("probe delete writeback", Duration::from_secs(10), || {
                !bridge.contains("nested/untitled.md")
                    && !bridge.contains("nested/renamed.md")
                    && !bridge.contains("nested/offline-created.md")
                    && !bridge.contains("nested/after-restart.md")
                    && host
                        .read_runtime_status(root_id)
                        .map(|status| status.safe_to_unmount)
                        .unwrap_or(false)
            })
            .await;
            match host.unmount_root_safely(root_id).await {
                Ok(SafeRootStopOutcome::Cleaned) => true,
                Ok(SafeRootStopOutcome::RecoveryPreserved { reason }) => {
                    eprintln!("probe cleanup preserved recovery state: {reason}");
                    false
                }
                Err(error) => {
                    eprintln!("probe cleanup failed: {error}");
                    false
                }
            }
        });
        if cleanup_complete {
            let _ = fs::remove_dir_all(base);
        }
        if !cleanup_complete && result.is_ok() {
            return Err(
                "rename passed, but the disposable CFAPI root could not be cleaned up".into(),
            );
        }
        result
    }
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows_probe::run()
}
