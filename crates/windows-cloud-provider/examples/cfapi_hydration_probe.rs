#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("the CFAPI hydration probe is only available on Windows");
}

#[cfg(target_os = "windows")]
mod windows_probe {
    use async_trait::async_trait;
    use chrono::Utc;
    use hybridcipher_mount_sync::MountSyncError;
    use hybridcipher_provider_core::{
        ProviderBridge, ProviderCoreError, ProviderEntry, Result as ProviderResult,
    };
    use hybridcipher_windows_cloud_provider::{
        CloudCallbackKind, CloudProviderHost, CloudRootRegistration, ProviderHostConfig,
        SafeRootStopOutcome,
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashMap,
        error::Error,
        fs::{self, File},
        io::{Read, Seek, SeekFrom},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use uuid::Uuid;
    use windows::{
        core::{HRESULT, PCWSTR},
        Win32::{
            Foundation::{
                CloseHandle, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, GENERIC_READ, HANDLE,
            },
            Storage::FileSystem::{
                CreateFileW, ReadFile, FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, OPEN_EXISTING,
            },
            System::{
                Threading::CreateEventW,
                IO::{CancelIo, GetOverlappedResult, OVERLAPPED},
            },
        },
    };
    use zeroize::Zeroizing;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ProbeFormat {
        Current,
        Legacy,
        Sparse,
    }

    #[derive(Clone)]
    struct ProbeFile {
        entry: ProviderEntry,
        bytes: Arc<Vec<u8>>,
        format: ProbeFormat,
        delay: Duration,
    }

    #[derive(Default)]
    struct ProbeBridge {
        files: Mutex<HashMap<String, ProbeFile>>,
    }

    impl ProbeBridge {
        fn insert(
            &self,
            root_id: Uuid,
            encrypted_root: &Path,
            relative_path: &str,
            bytes: Vec<u8>,
            format: ProbeFormat,
            delay: Duration,
        ) {
            let entry = ProviderEntry::cache_file_with_identity(
                root_id,
                relative_path,
                encrypted_root.join(format!("{}.probe", relative_path.replace('/', "_"))),
                bytes.len() as u64,
                bytes.len() as u64,
                Utc::now(),
                None,
                Some(Uuid::new_v4().to_string()),
                Some(1),
            );
            self.files.lock().expect("probe files lock").insert(
                relative_path.to_string(),
                ProbeFile {
                    entry,
                    bytes: Arc::new(bytes),
                    format,
                    delay,
                },
            );
        }

        fn lookup(&self, entry: &ProviderEntry) -> ProviderResult<ProbeFile> {
            self.files
                .lock()
                .expect("probe files lock")
                .get(&entry.relative_path)
                .cloned()
                .ok_or_else(|| {
                    ProviderCoreError::InvalidIdentity(
                        "hydration probe entry is not present".to_string(),
                    )
                })
        }
    }

    #[async_trait]
    impl ProviderBridge for ProbeBridge {
        async fn inventory(
            &self,
            _root_id: Uuid,
            _encrypted_root: &Path,
        ) -> ProviderResult<Vec<ProviderEntry>> {
            let mut entries = self
                .files
                .lock()
                .expect("probe files lock")
                .values()
                .map(|file| file.entry.clone())
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
            Ok(entries)
        }

        async fn hydrate_file(&self, entry: &ProviderEntry) -> ProviderResult<Vec<u8>> {
            Ok(self.lookup(entry)?.bytes.as_ref().clone())
        }

        async fn hydrate_file_range(
            &self,
            entry: &ProviderEntry,
            offset: u64,
            length: usize,
        ) -> ProviderResult<Zeroizing<Vec<u8>>> {
            let file = self.lookup(entry)?;
            if file.format != ProbeFormat::Current {
                let reason = match file.format {
                    ProbeFormat::Legacy => "legacy probe format",
                    ProbeFormat::Sparse => "sparse probe format",
                    ProbeFormat::Current => unreachable!(),
                };
                return Err(ProviderCoreError::Crypto(MountSyncError::RangeUnsupported(
                    reason.to_string(),
                )));
            }
            if !file.delay.is_zero() {
                tokio::time::sleep(file.delay).await;
            }
            let start = usize::try_from(offset).map_err(|_| {
                ProviderCoreError::InvalidIdentity("probe range offset is too large".into())
            })?;
            let end = start
                .checked_add(length)
                .ok_or_else(|| ProviderCoreError::InvalidIdentity("probe range overflow".into()))?;
            let range = file.bytes.get(start..end).ok_or_else(|| {
                ProviderCoreError::InvalidIdentity("probe range exceeds content".into())
            })?;
            Ok(Zeroizing::new(range.to_vec()))
        }
    }

    fn bytes_for(label: &str, length: usize) -> Vec<u8> {
        let seed = Sha256::digest(label.as_bytes());
        (0..length)
            .map(|index| seed[index % seed.len()] ^ (index as u8).wrapping_mul(31))
            .collect()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn issue_and_cancel_overlapped_read(path: &Path) -> Result<(), Box<dyn Error>> {
        use std::os::windows::ffi::OsStrExt;

        struct OwnedHandle(HANDLE);
        impl Drop for OwnedHandle {
            fn drop(&mut self) {
                if !self.0.is_invalid() {
                    let _ = unsafe { CloseHandle(self.0) };
                }
            }
        }

        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = OwnedHandle(unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )?
        });
        let event = OwnedHandle(unsafe { CreateEventW(None, true, false, PCWSTR::null())? });
        let mut overlapped = Box::new(OVERLAPPED {
            hEvent: event.0,
            ..OVERLAPPED::default()
        });
        let mut bytes = vec![0u8; 64 * 1024];
        match unsafe { ReadFile(handle.0, Some(&mut bytes), None, Some(&mut *overlapped)) } {
            Ok(()) => return Err("cancellation read completed before cancellation".into()),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {}
            Err(error) => return Err(format!("cancellation read failed: {error}").into()),
        }
        unsafe { CancelIo(handle.0)? };
        let mut transferred = 0u32;
        match unsafe { GetOverlappedResult(handle.0, &*overlapped, &mut transferred, true) } {
            Err(error) if error.code() == HRESULT::from_win32(ERROR_OPERATION_ABORTED.0) => Ok(()),
            Err(error) => {
                Err(format!("cancelled read completed with an unexpected error: {error}").into())
            }
            Ok(()) => {
                eprintln!("hydration probe: cancellation request raced with a completed read");
                Ok(())
            }
        }
    }

    fn read_child() -> Result<bool, Box<dyn Error>> {
        let mut args = std::env::args_os();
        let _program = args.next();
        let Some(mode) = args.next() else {
            return Ok(false);
        };
        if mode == "--read-hash-child" {
            let path = PathBuf::from(args.next().ok_or("missing read path")?);
            let expected = args.next().ok_or("missing expected hash")?;
            let bytes = fs::read(path)?;
            if sha256_hex(&bytes) != expected.to_string_lossy() {
                return Err("hydrated plaintext hash mismatch".into());
            }
            return Ok(true);
        }
        if mode == "--read-range-child" {
            let path = PathBuf::from(args.next().ok_or("missing range path")?);
            let offset = args
                .next()
                .ok_or("missing range offset")?
                .to_string_lossy()
                .parse::<u64>()?;
            let length = args
                .next()
                .ok_or("missing range length")?
                .to_string_lossy()
                .parse::<usize>()?;
            let expected = args.next().ok_or("missing range hash")?;
            let mut file = File::open(path)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut bytes = vec![0u8; length];
            file.read_exact(&mut bytes)?;
            if sha256_hex(&bytes) != expected.to_string_lossy() {
                return Err("random-seek plaintext hash mismatch".into());
            }
            return Ok(true);
        }
        if mode == "--cancel-read-child" {
            let path = PathBuf::from(args.next().ok_or("missing cancellation path")?);
            issue_and_cancel_overlapped_read(&path)?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn wait_for_child(
        mut child: Child,
        label: &str,
        timeout: Duration,
    ) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                if status.success() {
                    return Ok(());
                }
                return Err(format!("{label} exited with {status}").into());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{label} did not finish before its timeout").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn run_reader(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        let child = Command::new(std::env::current_exe()?)
            .arg("--read-hash-child")
            .arg(path)
            .arg(sha256_hex(bytes))
            .spawn()?;
        wait_for_child(child, "reader process", Duration::from_secs(60)).await
    }

    fn spawn_reader(path: &Path, bytes: &[u8]) -> Result<Child, Box<dyn Error>> {
        Ok(Command::new(std::env::current_exe()?)
            .arg("--read-hash-child")
            .arg(path)
            .arg(sha256_hex(bytes))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?)
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
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(format!("timed out waiting for {label}").into())
    }

    fn assert_cache_empty(cache_dir: &Path) -> Result<(), Box<dyn Error>> {
        if cache_dir.exists() && fs::read_dir(cache_dir)?.next().transpose()?.is_some() {
            return Err(format!(
                "provider plaintext temporary directory is not empty: {}",
                cache_dir.display()
            )
            .into());
        }
        Ok(())
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        if read_child()? {
            return Ok(());
        }

        let root_id = Uuid::new_v4();
        let base = std::env::temp_dir()
            .join("hybridcipher-cfapi-hydration-probe")
            .join(root_id.to_string());
        let hybridcipher_base = base.join(".hybridcipher");
        let sync_root_path = hybridcipher_base.join(format!("{root_id}_mount"));
        let encrypted_root = base.join("encrypted");
        let user_config_dir = hybridcipher_base.join("users").join("probe");
        let cache_dir = user_config_dir
            .join("mount_states")
            .join(format!("cloud_cache_{root_id}"));
        fs::create_dir_all(&sync_root_path)?;
        fs::create_dir_all(&encrypted_root)?;
        fs::create_dir_all(&user_config_dir)?;

        let bridge = Arc::new(ProbeBridge::default());
        let mut fixtures = Vec::new();
        for (name, size) in [
            ("empty.bin", 0usize),
            ("one.bin", 1),
            ("4095.bin", 4095),
            ("4096.bin", 4096),
            ("4097.bin", 4097),
            ("four-mib-boundary.bin", 4 * 1024 * 1024 + 1),
            ("over-16-mib.bin", 16 * 1024 * 1024 + 4097),
            ("random-seek.bin", 8 * 1024 * 1024 + 8192),
            ("restart.bin", 128 * 1024),
        ] {
            let bytes = bytes_for(name, size);
            bridge.insert(
                root_id,
                &encrypted_root,
                name,
                bytes.clone(),
                ProbeFormat::Current,
                Duration::ZERO,
            );
            fixtures.push((name.to_string(), bytes));
        }
        for name in ["concurrent-a.bin", "concurrent-b.bin", "concurrent-c.bin"] {
            let bytes = bytes_for(name, 2 * 1024 * 1024);
            bridge.insert(
                root_id,
                &encrypted_root,
                name,
                bytes.clone(),
                ProbeFormat::Current,
                Duration::from_millis(300),
            );
            fixtures.push((name.to_string(), bytes));
        }
        let legacy = bytes_for("legacy.bin", 64 * 1024);
        bridge.insert(
            root_id,
            &encrypted_root,
            "legacy.bin",
            legacy.clone(),
            ProbeFormat::Legacy,
            Duration::ZERO,
        );
        let sparse = bytes_for("sparse.bin", 96 * 1024);
        bridge.insert(
            root_id,
            &encrypted_root,
            "sparse.bin",
            sparse.clone(),
            ProbeFormat::Sparse,
            Duration::ZERO,
        );
        let cancel = bytes_for("cancel.bin", 4 * 1024 * 1024);
        bridge.insert(
            root_id,
            &encrypted_root,
            "cancel.bin",
            cancel,
            ProbeFormat::Current,
            Duration::from_secs(5),
        );

        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir,
            pipe_name: None,
        });
        let registration = CloudRootRegistration::legacy_cfapi(
            root_id,
            sync_root_path.clone(),
            encrypted_root,
            format!("HybridCipher CFAPI Hydration Probe {root_id}"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let result = (|| -> Result<(), Box<dyn Error>> {
            host.register_root(&registration)?;
            runtime.block_on(async {
                host.start_root_with_bridge(root_id, bridge.clone()).await?;

                println!("hydration probe: cancellation");
                let fetch_attempts_before = host
                    .check_root_health(root_id)?
                    .operational
                    .as_ref()
                    .and_then(|health| health.callback(CloudCallbackKind::FetchData))
                    .map(|callback| callback.attempt_count)
                    .unwrap_or(0);
                let dehydration = host.dehydrate_root_path(&sync_root_path)?;
                if dehydration.failed_count != 0 {
                    return Err(format!(
                        "could not prepare cancellation fixture: {} of {} placeholders failed to dehydrate",
                        dehydration.failed_count, dehydration.attempted_count
                    )
                    .into());
                }
                let cancelled_reader = Command::new(std::env::current_exe()?)
                    .arg("--cancel-read-child")
                    .arg(sync_root_path.join("cancel.bin"))
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()?;
                wait_for_child(
                    cancelled_reader,
                    "cancellation reader",
                    Duration::from_secs(10),
                )
                .await?;
                wait_for(
                    "cancelled read callback completion",
                    Duration::from_secs(15),
                    || {
                        host.check_root_health(root_id)
                            .ok()
                            .and_then(|health| health.operational)
                            .and_then(|health| {
                                health.callback(CloudCallbackKind::FetchData).map(|callback| {
                                    callback.attempt_count > fetch_attempts_before
                                        && callback.in_flight_count == 0
                                })
                            })
                            .unwrap_or(false)
                    },
                )
                .await?;
                let cancellation_health = host
                    .check_root_health(root_id)?
                    .operational
                    .ok_or("missing cancellation health telemetry")?;
                if cancellation_health.hydration_failure.is_some() {
                    return Err("caller cancellation degraded hydration health".into());
                }
                let cancellation_observed = cancellation_health
                    .last_hydration_transfer
                    .as_ref()
                    .is_some_and(|transfer| transfer.cancellation_observed)
                    || cancellation_health
                        .callback(CloudCallbackKind::CancelFetchData)
                        .is_some_and(|callback| callback.attempt_count > 0);
                if cancellation_observed {
                    println!("hydration probe: provider cancellation callback observed");
                } else {
                    eprintln!(
                        "hydration probe: caller cancellation was requested; this Windows build did not emit the optional provider cancellation callback"
                    );
                }
                assert_cache_empty(&cache_dir)?;

                for (name, bytes) in fixtures
                    .iter()
                    .filter(|(name, _)| {
                        !name.starts_with("concurrent-")
                            && name != "restart.bin"
                            && name != "random-seek.bin"
                    })
                {
                    println!("hydration probe: {name}");
                    run_reader(&sync_root_path.join(name), bytes)
                        .await
                        .map_err(|error| format!("{name}: {error}"))?;
                    assert_cache_empty(&cache_dir)?;
                }

                let random = fixtures
                    .iter()
                    .find(|(name, _)| name == "random-seek.bin")
                    .expect("random seek fixture");
                let offset = 4 * 1024 * 1024 - 2048;
                let length = 8192;
                println!("hydration probe: random seek");
                let random_reader = Command::new(std::env::current_exe()?)
                    .arg("--read-range-child")
                    .arg(sync_root_path.join(&random.0))
                    .arg(offset.to_string())
                    .arg(length.to_string())
                    .arg(sha256_hex(&random.1[offset..offset + length]))
                    .spawn()?;
                wait_for_child(random_reader, "random-seek reader", Duration::from_secs(60))
                    .await?;
                assert_cache_empty(&cache_dir)?;

                println!("hydration probe: three concurrent readers");
                let mut readers = fixtures
                    .iter()
                    .filter(|(name, _)| name.starts_with("concurrent-"))
                    .map(|(name, bytes)| spawn_reader(&sync_root_path.join(name), bytes))
                    .collect::<Result<Vec<_>, _>>()?;
                for (index, reader) in readers.drain(..).enumerate() {
                    wait_for_child(
                        reader,
                        &format!("concurrent reader {}", index + 1),
                        Duration::from_secs(60),
                    )
                    .await?;
                }
                assert_cache_empty(&cache_dir)?;

                println!("hydration probe: legacy fallback");
                run_reader(&sync_root_path.join("legacy.bin"), &legacy).await?;
                assert_cache_empty(&cache_dir)?;
                println!("hydration probe: sparse fallback");
                run_reader(&sync_root_path.join("sparse.bin"), &sparse).await?;
                assert_cache_empty(&cache_dir)?;

                host.stop_root_for_restart(root_id).await?;
                host.start_root_with_bridge(root_id, bridge.clone()).await?;
                let restart = fixtures
                    .iter()
                    .find(|(name, _)| name == "restart.bin")
                    .expect("restart fixture");
                println!("hydration probe: provider restart");
                run_reader(&sync_root_path.join(&restart.0), &restart.1).await?;
                assert_cache_empty(&cache_dir)?;

                let health = host.check_root_health(root_id)?;
                let operational = health.operational.ok_or("missing operational health")?;
                if !operational.hydration_success_observed {
                    return Err("no successful hydration callback was observed".into());
                }
                println!(
                    "hydration probe passed: exact hashes, ranges, concurrency, caller cancellation request, restart, legacy and sparse fallback"
                );
                Ok(())
            })
        })();

        let cleaned = runtime.block_on(async {
            match host.unmount_root_safely(root_id).await {
                Ok(SafeRootStopOutcome::Cleaned) => true,
                Ok(SafeRootStopOutcome::RecoveryPreserved { reason }) => {
                    eprintln!("hydration probe preserved recovery state: {reason}");
                    false
                }
                Err(error) => {
                    if host.unregister_root_path(&sync_root_path).is_ok() {
                        eprintln!(
                            "hydration probe did not reach durable registration; its disposable root was unregistered: {error}"
                        );
                        true
                    } else {
                        eprintln!("hydration probe cleanup failed: {error}");
                        false
                    }
                }
            }
        });
        if cleaned {
            let _ = fs::remove_dir_all(&base);
        }
        if !cleaned && result.is_ok() {
            return Err("probe passed but its disposable sync root could not be removed".into());
        }
        result
    }
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows_probe::run()
}
