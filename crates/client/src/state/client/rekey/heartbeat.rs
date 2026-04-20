use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    // ========== REKEY OPERATIONS ==========

    pub(in super::super) async fn ensure_rekey_heartbeat_worker(&self) {
        if !self.config.migration_automation_enabled {
            return;
        }
        let has_active = {
            let state = self.state.read().await;
            state.active_rekey.is_some()
        };

        if !has_active {
            return;
        }

        let mut worker = self.heartbeat_worker.lock().await;

        if worker.running {
            return;
        }

        worker.running = true;

        let client = self.clone();
        let control = self.heartbeat_worker.clone();
        tokio::spawn(async move {
            Self::run_rekey_heartbeat_loop(client, control).await;
        });
    }

    /// Schedule a rekey heartbeat (respects migration_automation_enabled flag)
    pub async fn schedule_rekey_heartbeat(&self) {
        if !self.config.migration_automation_enabled {
            return;
        }
        self.schedule_rekey_heartbeat_internal().await;
    }

    /// Force a rekey heartbeat (bypasses migration_automation_enabled flag)
    /// Used for final heartbeats after migration completion to ensure server has aggregate counts
    pub async fn force_rekey_heartbeat(&self) {
        self.schedule_rekey_heartbeat_internal().await;
    }

    /// Internal method to schedule heartbeat without checking automation flag
    pub(in super::super) async fn schedule_rekey_heartbeat_internal(&self) {
        let has_active = {
            let mut state = self.state.write().await;
            let active_rekey = state.active_rekey.clone();
            let Some(active_rekey) = active_rekey else {
                return;
            };
            let entry = state
                .rekey_heartbeats
                .entry(active_rekey.rekey_id)
                .or_insert_with(RekeyHeartbeatState::default);
            entry.pending_emit = true;
            true
        };

        if has_active {
            self.ensure_rekey_heartbeat_worker().await;
        }
    }

    pub(in super::super) async fn run_rekey_heartbeat_loop(
        self,
        control: Arc<Mutex<HeartbeatWorkerState>>,
    ) {
        let mut consecutive_errors: u32 = 0;

        loop {
            let maybe_operation = {
                let state = self.state.read().await;
                state.active_rekey.clone()
            };

            let Some(operation) = maybe_operation else {
                break;
            };

            if matches!(
                operation.status,
                RekeyStatus::Completed | RekeyStatus::Cancelled | RekeyStatus::Failed
            ) {
                break;
            }

            let min_interval_secs = self.config.migration_heartbeat_min_interval_secs.max(1);
            let max_interval_secs = HEARTBEAT_MAX_INTERVAL_SECS.max(min_interval_secs);
            let has_pending = {
                let state = self.state.read().await;
                state
                    .rekey_heartbeats
                    .get(&operation.rekey_id)
                    .map(|entry| entry.pending_emit)
                    .unwrap_or(true)
            };

            if !has_pending {
                sleep(std::time::Duration::from_secs(min_interval_secs)).await;
                continue;
            }

            if let Some(delay) = self.reserve_rekey_heartbeat_slot(&operation).await {
                sleep(delay).await;
                continue;
            }

            match self.emit_rekey_heartbeat().await {
                Ok(op) => {
                    consecutive_errors = 0;
                    if matches!(
                        op.status,
                        RekeyStatus::Completed | RekeyStatus::Cancelled | RekeyStatus::Failed
                    ) {
                        // Clear stale migration state when rekey finishes
                        let mut state = self.state.write().await;
                        state.migration = None;
                        drop(state);
                        break;
                    }
                }
                Err(err) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Rekey heartbeat attempt failed: {err}"),
                        None,
                    );

                    if matches!(err, ClientError::InvalidState(_)) {
                        break;
                    }
                }
            }

            let mut wait_secs = if consecutive_errors == 0 {
                min_interval_secs
            } else {
                min_interval_secs.saturating_mul(1u64 << consecutive_errors.min(4))
            }
            .min(max_interval_secs);
            let jitter = if HEARTBEAT_JITTER_SECS > 0 {
                thread_rng().gen_range(0..=HEARTBEAT_JITTER_SECS)
            } else {
                0
            };
            wait_secs = wait_secs.saturating_add(jitter).min(max_interval_secs);

            sleep(std::time::Duration::from_secs(wait_secs)).await;
        }

        let mut worker = control.lock().await;
        worker.running = false;
    }

    pub(in super::super) async fn reserve_rekey_heartbeat_slot(
        &self,
        operation: &ActiveRekeyOperation,
    ) -> Option<std::time::Duration> {
        let mut state = self.state.write().await;
        let heartbeat_state = state
            .rekey_heartbeats
            .entry(operation.rekey_id)
            .or_insert_with(RekeyHeartbeatState::default);

        let now = Utc::now();
        let min_interval_secs = self.config.migration_heartbeat_min_interval_secs.max(1) as f64;

        if let Some(last_emitted_at) = heartbeat_state.last_emitted_at {
            let elapsed_secs = (now - last_emitted_at).num_milliseconds().max(0) as f64 / 1000.0;
            if elapsed_secs < min_interval_secs {
                let remaining = (min_interval_secs - elapsed_secs).clamp(0.5, min_interval_secs);
                return Some(std::time::Duration::from_secs_f64(remaining));
            }
        }
        heartbeat_state.bucket_last_refill = Some(now);
        None
    }

    pub(in super::super) async fn ensure_idle_crawler(&self) {
        if !self.config.migration_automation_enabled {
            return;
        }
        let mut worker = self.idle_crawler.lock().await;
        if worker.running {
            return;
        }
        worker.abort = false;

        let has_pending = {
            let state = self.state.read().await;
            !state.pending_rewraps.is_empty()
        };

        if !has_pending {
            if rekey_debug_enabled() {
                eprintln!("DEBUG idle_crawler: No pending rewrap tasks to process");
            }
            return;
        }

        worker.running = true;
        let client = self.clone();
        let control = self.idle_crawler.clone();
        tokio::spawn(async move {
            client.run_idle_crawler_loop(control).await;
        });
    }

    pub(in super::super) async fn cancel_idle_crawler(&self) {
        // Set abort flag
        {
            let mut worker = self.idle_crawler.lock().await;
            if worker.running {
                worker.abort = true;
                if rekey_debug_enabled() {
                    eprintln!(
                        "DEBUG cancel_idle_crawler: Set abort=true, waiting for crawler to stop"
                    );
                }
            } else {
                if rekey_debug_enabled() {
                    eprintln!("DEBUG cancel_idle_crawler: Crawler not running, nothing to cancel");
                }
                return; // Not running, nothing to cancel
            }
        }

        // Wait for crawler to actually stop (with timeout)
        let timeout = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let mut worker = self.idle_crawler.lock().await;
            if !worker.running {
                // Ensure clean state for next crawler
                worker.abort = false;
                if rekey_debug_enabled() {
                    eprintln!("DEBUG cancel_idle_crawler: Crawler stopped, state reset");
                }
                break;
            }
            if start.elapsed() > timeout {
                if rekey_debug_enabled() {
                    eprintln!("DEBUG cancel_idle_crawler: Timeout waiting for crawler to stop, forcing state reset");
                }
                // Force reset on timeout to prevent deadlock
                worker.running = false;
                worker.abort = false;
                break;
            }
        }
    }

    /// Public method to trigger idle crawler after state reloads
    /// This is useful for mount daemons that need to detect externally-started rekeys
    pub async fn trigger_rewrap_processing(&self) {
        if !self.config.migration_automation_enabled {
            return;
        }
        self.ensure_idle_crawler().await;
    }

    pub(in super::super) async fn run_idle_crawler_loop(
        self,
        control: Arc<Mutex<IdleCrawlerState>>,
    ) {
        let mut processed_count = 0u64;
        let mut processed_since_save = 0u64;
        let mut last_state_save_at = Instant::now();
        let save_batch_size = self.config.migration_state_save_batch_size;
        let save_max_interval = self.config.migration_state_save_max_interval_secs;
        let heartbeat_batch_size = self.config.migration_state_save_batch_size;
        let heartbeat_min_interval = self.config.migration_heartbeat_min_interval_secs.max(1);
        let mut processed_since_heartbeat = 0u64;
        let mut last_heartbeat_at = Instant::now();

        loop {
            {
                let mut worker = control.lock().await;
                if worker.abort {
                    worker.running = false;
                    worker.abort = false;
                    break;
                }
            }

            let task = {
                let mut state = self.state.write().await;
                state.pending_rewraps.pop_front()
            };

            let Some(mut pending) = task else { break };

            {
                let mut worker = control.lock().await;
                if worker.abort {
                    worker.running = false;
                    worker.abort = false;
                    break;
                }
            }

            let result = self.rewrap_pending_entry(&pending).await;

            // Check abort flag immediately after rewrap completes
            {
                let mut worker = control.lock().await;
                if worker.abort {
                    worker.running = false;
                    worker.abort = false;
                    if rekey_debug_enabled() {
                        eprintln!(
                            "DEBUG idle_crawler: Abort detected after rewrap, stopping immediately"
                        );
                    }
                    break;
                }
            }

            match result {
                Ok(()) => {
                    let _ = self.update_file_pending_flag(&pending.path, false).await;
                    processed_since_save = processed_since_save.saturating_add(1);
                    let batch_due = save_batch_size > 0 && processed_since_save >= save_batch_size;
                    let time_due = save_max_interval > 0
                        && last_state_save_at.elapsed()
                            >= std::time::Duration::from_secs(save_max_interval);
                    if batch_due || time_due {
                        let _ = self.save_client_state().await;
                        processed_since_save = 0;
                        last_state_save_at = Instant::now();
                    }
                    processed_count = processed_count.saturating_add(1);
                    processed_since_heartbeat = processed_since_heartbeat.saturating_add(1);

                    // Schedule heartbeats by batch size or time (whichever comes first).
                    let heartbeat_batch_due = heartbeat_batch_size > 0
                        && processed_since_heartbeat >= heartbeat_batch_size;
                    let heartbeat_time_due = last_heartbeat_at.elapsed()
                        >= std::time::Duration::from_secs(heartbeat_min_interval);
                    if heartbeat_batch_due || heartbeat_time_due {
                        self.schedule_rekey_heartbeat().await;
                        processed_since_heartbeat = 0;
                        last_heartbeat_at = Instant::now();
                    }
                }
                Err(err) => {
                    pending.attempts = pending.attempts.saturating_add(1);
                    pending.last_attempt = Some(Utc::now());
                    // Check if file was already rewrapped to target epoch (e.g., by another process or previous success)
                    // This prevents infinite retry loops on files that are already at the target epoch
                    let already_at_target = if let Some(header) =
                        Self::parse_encrypted_file_metadata(&PathBuf::from(&pending.path))
                    {
                        header.epoch_id == pending.to_epoch
                    } else {
                        false
                    };

                    if already_at_target {
                        if rekey_debug_enabled() {
                            eprintln!(
                                "DEBUG idle_crawler: File {} already at target epoch {}, skipping retry",
                                pending.path, pending.to_epoch
                            );
                        }
                        self.logger.log(
                            crate::logging::LogLevel::Info,
                            &format!(
                                "Idle crawler skipped retry for {} - file already at epoch {}",
                                pending.path, pending.to_epoch
                            ),
                            Some("idle_crawler_skip_rewrapped"),
                        );
                        let _ = self.update_file_pending_flag(&pending.path, false).await;
                        continue;
                    }

                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Idle crawler failed to rewrap {} (attempt {}): {}",
                            pending.path, pending.attempts, err
                        ),
                        Some("idle_crawler_retry"),
                    );

                    if pending.attempts < 5 {
                        let mut state = self.state.write().await;
                        state.pending_rewraps.push_back(pending);
                        drop(state);
                        processed_since_save = processed_since_save.saturating_add(1);
                        let batch_due =
                            save_batch_size > 0 && processed_since_save >= save_batch_size;
                        let time_due = save_max_interval > 0
                            && last_state_save_at.elapsed()
                                >= std::time::Duration::from_secs(save_max_interval);
                        if batch_due || time_due {
                            let _ = self.save_client_state().await;
                            processed_since_save = 0;
                            last_state_save_at = Instant::now();
                        }
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }
        }

        if processed_since_save > 0 {
            let _ = self.save_client_state().await;
        }

        // Final progress report when migration completes
        if processed_count > 0 {
            // Always send final heartbeat after migration completes, regardless of automation setting
            // This ensures the server has aggregate counts for cutover operations
            self.force_rekey_heartbeat().await;
            if let Some(progress_pct) = self.compute_rekey_progress_percentage().await {
                let _ = self
                    .report_rekey_progress(
                        Some(RekeyProgressState::Confirmed),
                        Some(progress_pct.clamp(0, 100) as u8),
                    )
                    .await;
            }
        }

        let mut worker = control.lock().await;
        worker.running = false;
        worker.abort = false;
    }

    pub(in super::super) async fn compute_rekey_progress_percentage(&self) -> Option<u64> {
        let state = self.state.read().await;
        state.migration.as_ref().and_then(|m| {
            if m.total_files == 0 {
                Some(100)
            } else {
                let percentage =
                    (m.migrated_files.len() as f64 / m.total_files as f64 * 100.0) as u64;
                Some(percentage)
            }
        })
    }

    /// Emit an automatic heartbeat with local coverage metrics for the active rekey operation.
    pub async fn emit_rekey_heartbeat(&self) -> Result<ActiveRekeyOperation, ClientError> {
        self.ensure_state_loaded().await?;

        let session = self.get_session_info().await?;
        let token = session.token.clone();
        let device_id_str = session.device_id.clone().ok_or_else(|| {
            ClientError::InvalidState(
                "Authenticated session does not include a device identifier".to_string(),
            )
        })?;

        // Use device_id as-is (string format: "device_<id>")
        let device_id = device_id_str;

        let server_base = Self::resolve_server_base_url(session.server_url.clone());
        let group_id = self
            .require_active_group("emitting rekey heartbeat")
            .await?;

        let observed_at = Utc::now();

        let root_ids: HashSet<Uuid> = self
            .active_group_roots_map()
            .await
            .map(|(_, _, roots)| roots.keys().copied().collect())
            .unwrap_or_default();

        let (tracked_files, tracked_bytes) = self.tracked_file_stats(&root_ids).await?;

        let (
            operation_id,
            epoch_uuid,
            protected_hint,
            migrated_hint,
            coverage_counts,
            descriptor_commitment,
            should_rescan,
        ) = {
            let mut state = self.state.write().await;
            let active_rekey = state.active_rekey.as_ref().ok_or_else(|| {
                ClientError::InvalidState(
                    "No active rekey operation is available for heartbeat emission".to_string(),
                )
            })?;

            let epoch_uuid = active_rekey.new_epoch_id.ok_or_else(|| {
                ClientError::InvalidState(
                    "Active rekey operation is missing the target epoch identifier".to_string(),
                )
            })?;

            let rekey_id = active_rekey.rekey_id;
            let descriptor_commitment = active_rekey.descriptor_commitment.clone();
            let total_files = active_rekey.progress.total_files;
            let migrated_files = active_rekey.progress.migrated_files;

            let target_epoch = state
                .migration
                .as_ref()
                .map(|migration| migration.to_epoch)
                .unwrap_or(state.current_epoch);

            let counts = state
                .coverage_ledgers
                .get(&group_id)
                .map(|l| l.log.counts_for_epoch(target_epoch))
                .unwrap_or_default();

            // Check for stuck tracked_files count (indicates stale file_index)
            let heartbeat_state = state
                .rekey_heartbeats
                .entry(rekey_id)
                .or_insert_with(RekeyHeartbeatState::default);

            let should_rescan =
                if tracked_files == heartbeat_state.last_tracked_files && tracked_files > 0 {
                    heartbeat_state.stuck_tracked_files_count += 1;
                    heartbeat_state.stuck_tracked_files_count >= 5
                } else {
                    heartbeat_state.last_tracked_files = tracked_files;
                    heartbeat_state.stuck_tracked_files_count = 0;
                    false
                };

            if rekey_debug_enabled() {
                eprintln!(
                    "DEBUG emit_heartbeat: target_epoch={}, tracked_files={}, tracked_bytes={}",
                    target_epoch, tracked_files, tracked_bytes
                );
                eprintln!(
                    "DEBUG emit_heartbeat: coverage_log counts - total={}, rewrapped={}",
                    counts.total_items, counts.rewrapped_items
                );
                if should_rescan {
                    eprintln!(
                        "DEBUG emit_heartbeat: tracked_files stuck at {} for 5 iterations, triggering coverage scan",
                        tracked_files
                    );
                }
            }

            (
                rekey_id,
                epoch_uuid,
                total_files,
                migrated_files,
                counts,
                descriptor_commitment,
                should_rescan,
            )
        };

        // Trigger coverage scan if tracked_files count is stuck
        let (mut tracked_files, mut tracked_bytes) = (tracked_files, tracked_bytes);
        if should_rescan {
            if rekey_debug_enabled() {
                eprintln!("DEBUG emit_heartbeat: Running coverage scan to refresh file index...");
            }

            // Execute the hybridcipher coverage scan command as a subprocess
            // This ensures identical behavior to manual execution with fresh client state
            use std::process::Command;

            match Command::new("hybridcipher")
                .arg("coverage")
                .arg("scan")
                .env("HYBRIDCIPHER_DEBUG_REKEY", "1")
                .output()
            {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);

                    if rekey_debug_enabled() {
                        eprintln!("DEBUG emit_heartbeat: Coverage scan subprocess output:");
                        if !stdout.is_empty() {
                            eprintln!("{}", stdout);
                        }
                        if !stderr.is_empty() {
                            eprintln!("{}", stderr);
                        }
                    }

                    if output.status.success() {
                        // Reload state from disk after scan completes
                        if let Err(err) = self.load_client_state().await {
                            if rekey_debug_enabled() {
                                eprintln!("DEBUG emit_heartbeat: Failed to reload client state after scan: {}", err);
                            }
                        }

                        // Re-read the updated tracked_files count
                        let (new_tracked_files, new_tracked_bytes) =
                            self.tracked_file_stats(&root_ids).await?;

                        if rekey_debug_enabled() {
                            eprintln!(
                                "DEBUG emit_heartbeat: Updated tracked_files: {} -> {}",
                                tracked_files, new_tracked_files
                            );
                        }

                        tracked_files = new_tracked_files;
                        tracked_bytes = new_tracked_bytes;
                    } else {
                        if rekey_debug_enabled() {
                            eprintln!("DEBUG emit_heartbeat: Coverage scan command failed with status: {:?}", output.status);
                        }
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Auto coverage scan subprocess failed: exit code {:?}",
                                output.status.code()
                            ),
                            Some("heartbeat_coverage_scan_error"),
                        );
                    }
                }
                Err(err) => {
                    if rekey_debug_enabled() {
                        eprintln!(
                            "DEBUG emit_heartbeat: Failed to spawn coverage scan subprocess: {}",
                            err
                        );
                    }
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Failed to spawn coverage scan subprocess: {}", err),
                        Some("heartbeat_coverage_scan_spawn_error"),
                    );
                }
            }

            // Reset the stuck counter after attempting rescan
            let mut state = self.state.write().await;
            if let Some(heartbeat_state) = state.rekey_heartbeats.get_mut(&operation_id) {
                heartbeat_state.stuck_tracked_files_count = 0;
                heartbeat_state.last_tracked_files = tracked_files;
            }
        }

        let (protected_items, coverage_items) = if tracked_files > 0 {
            (
                tracked_files,
                coverage_counts.rewrapped_items.min(tracked_files),
            )
        } else if coverage_counts.total_items > 0 {
            (
                coverage_counts.total_items,
                coverage_counts
                    .rewrapped_items
                    .min(coverage_counts.total_items),
            )
        } else {
            (protected_hint, migrated_hint.min(protected_hint))
        };

        let protected_bytes = if tracked_bytes > 0 {
            tracked_bytes
        } else {
            protected_items
        };
        let coverage_bytes = coverage_items.min(protected_bytes);

        let (
            sequence_value,
            descriptor_for_payload,
            protected_bytes,
            protected_items,
            coverage_bytes,
            coverage_items,
            coverage_clamped,
        ) = {
            let mut state = self.state.write().await;
            let heartbeat_state = state
                .rekey_heartbeats
                .entry(operation_id)
                .or_insert_with(RekeyHeartbeatState::default);

            heartbeat_state.sequence = heartbeat_state.sequence.saturating_add(1);
            heartbeat_state.last_observed_at = Some(observed_at);

            let descriptor_to_use = descriptor_commitment
                .clone()
                .or_else(|| heartbeat_state.last_descriptor_commitment.clone());

            let descriptor_changed = match (
                heartbeat_state.last_descriptor_commitment.as_ref(),
                descriptor_to_use.as_ref(),
            ) {
                (Some(prev), Some(curr)) => prev != curr,
                _ => false,
            };

            if descriptor_changed {
                heartbeat_state.last_coverage_bytes = 0;
                heartbeat_state.last_coverage_items = 0;
                heartbeat_state.last_protected_bytes = 0;
                heartbeat_state.last_protected_items = 0;
            }

            let mut adjusted_protected_bytes = protected_bytes;
            if adjusted_protected_bytes < heartbeat_state.last_protected_bytes {
                adjusted_protected_bytes = heartbeat_state.last_protected_bytes;
            }

            let mut adjusted_protected_items = protected_items;
            if adjusted_protected_items < heartbeat_state.last_protected_items {
                adjusted_protected_items = heartbeat_state.last_protected_items;
            }

            let mut adjusted_coverage_bytes = coverage_bytes.min(adjusted_protected_bytes);
            let mut adjusted_coverage_items = coverage_items.min(adjusted_protected_items);
            let mut clamped = false;

            if !descriptor_changed {
                if adjusted_coverage_bytes < heartbeat_state.last_coverage_bytes {
                    adjusted_coverage_bytes = heartbeat_state.last_coverage_bytes;
                    clamped = true;
                }
                if adjusted_coverage_items < heartbeat_state.last_coverage_items {
                    adjusted_coverage_items = heartbeat_state.last_coverage_items;
                    clamped = true;
                }
            }

            heartbeat_state.last_descriptor_commitment = descriptor_to_use.clone();
            heartbeat_state.last_protected_bytes = adjusted_protected_bytes;
            heartbeat_state.last_protected_items = adjusted_protected_items;
            heartbeat_state.last_coverage_bytes = adjusted_coverage_bytes;
            heartbeat_state.last_coverage_items = adjusted_coverage_items;

            (
                heartbeat_state.sequence,
                descriptor_to_use,
                adjusted_protected_bytes,
                adjusted_protected_items,
                adjusted_coverage_bytes,
                adjusted_coverage_items,
                clamped,
            )
        };

        if coverage_clamped {
            self.logger.log(
                crate::logging::LogLevel::Info,
                "Clamped rekey heartbeat coverage regression to maintain monotonicity",
                None,
            );
        }

        let root_kpis = match self.collect_heartbeat_root_kpis().await {
            Ok(kpis) => kpis,
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Failed to compute per-root coverage KPIs for heartbeat: {}",
                        err
                    ),
                    Some("heartbeat_root_kpi_error"),
                );
                Vec::new()
            }
        };

        let payload = RekeyHeartbeatRequestPayload {
            operation_id,
            device_id,
            epoch_id: epoch_uuid,
            descriptor_commitment: descriptor_for_payload,
            coverage_bytes,
            protected_bytes,
            coverage_items,
            protected_items,
            sequence: sequence_value,
            observed_at,
            signature: None,
            root_kpis,
        };

        let url = format!("{}/api/v1/groups/{}/rekey/heartbeat", server_base, group_id);

        // Info logging before network call (always visible)
        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("emit_rekey_heartbeat: Preparing POST request to {}", url),
            None,
        );
        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "emit_rekey_heartbeat: operation_id={}, epoch_id={}, sequence={}",
                operation_id, epoch_uuid, sequence_value
            ),
            None,
        );

        let client = reqwest::Client::new();
        self.rekey_request_throttle.wait_for_slot().await;
        let response = match client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                self.rekey_request_throttle.register_failure(None).await;
                // Enhanced error logging with detailed context
                let error_type = if e.is_timeout() {
                    "timeout"
                } else if e.is_connect() {
                    "connection_failed"
                } else if e.is_request() {
                    "request_error"
                } else if e.is_body() {
                    "body_error"
                } else if e.is_decode() {
                    "decode_error"
                } else {
                    "unknown"
                };

                let detailed_msg = format!(
                    "Failed to submit rekey heartbeat - Error type: {}, URL: {}, Details: {:?}",
                    error_type, url, e
                );

                self.logger
                    .log(crate::logging::LogLevel::Error, &detailed_msg, None);

                // Log source error if available
                if let Some(source) = e.source() {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!("emit_rekey_heartbeat: Root cause: {:?}", source),
                        None,
                    );
                }

                return Err(ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    detailed_msg,
                    "emit_rekey_heartbeat".to_string(),
                    0,
                    error_type.to_string(),
                ));
            }
        };

        let status = response.status();
        if should_backoff(status) {
            let retry_after = retry_after_delay(response.headers());
            self.rekey_request_throttle
                .register_failure(retry_after)
                .await;
        } else {
            self.rekey_request_throttle.register_success().await;
        }

        if let Some(retention_err) = self
            .handle_retention_status(status, response.headers(), "emit_rekey_heartbeat")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while emitting rekey heartbeat".to_string(),
                "emit_rekey_heartbeat".to_string(),
                0,
                "unauthorized".to_string(),
            ));
        }

        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to submit rekey heartbeat ({}): {}", status, body),
                "emit_rekey_heartbeat".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        let payload: RekeyStatusPayload = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to parse rekey heartbeat response: {}", e),
                "emit_rekey_heartbeat".to_string(),
                0,
                "decode".to_string(),
            )
        })?;

        let (mut operation, _) = {
            let mut state = self.state.write().await;
            let mut current = state
                .active_rekey
                .clone()
                .unwrap_or_else(|| ActiveRekeyOperation::from_status(&payload));
            current.update_from_status(&payload);

            let completed = matches!(
                current.status,
                RekeyStatus::Completed | RekeyStatus::Cancelled | RekeyStatus::Failed
            );

            if completed {
                state.active_rekey = None;
                state.rekey_heartbeats.remove(&payload.rekey_id);
            } else {
                let heartbeat_entry = state
                    .rekey_heartbeats
                    .entry(payload.rekey_id)
                    .or_insert_with(RekeyHeartbeatState::default);
                heartbeat_entry.last_emitted_at = Some(observed_at);
                heartbeat_entry.pending_emit = false;
                state.active_rekey = Some(current.clone());
            }

            (current, !completed)
        };

        self.save_client_state().await?;

        let should_autoconfirm = if coverage_counts.total_items == 0
            || coverage_counts.rewrapped_items >= coverage_counts.total_items
        {
            let mut state = self.state.write().await;
            match state.rekey_heartbeats.get_mut(&operation.rekey_id) {
                Some(entry) if !entry.confirmed_reported => {
                    entry.confirmed_reported = true;
                    true
                }
                _ => false,
            }
        } else {
            false
        };

        if should_autoconfirm {
            match self
                .report_rekey_progress_impl(Some(RekeyProgressState::Confirmed), Some(100))
                .await
            {
                Ok((updated_operation, _)) => {
                    operation = updated_operation;
                    self.logger.log(
                        crate::logging::LogLevel::Info,
                        "Reported rekey progress as confirmed for this device",
                        Some(&operation.rekey_id.to_string()),
                    );
                }
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Automatic rekey confirmation failed (will retry on next heartbeat): {}",
                            err
                        ),
                        Some(&operation.rekey_id.to_string()),
                    );

                    let mut state = self.state.write().await;
                    if let Some(entry) = state.rekey_heartbeats.get_mut(&operation.rekey_id) {
                        entry.confirmed_reported = false;
                    }
                }
            }
        }

        Ok(operation)
    }

    /// Report local migration progress for the active rekey operation.
    pub async fn report_rekey_progress(
        &self,
        status: Option<RekeyProgressState>,
        progress: Option<u8>,
    ) -> Result<ActiveRekeyOperation, ClientError> {
        let (operation, operation_active) =
            self.report_rekey_progress_impl(status, progress).await?;

        if operation_active {
            self.ensure_rekey_heartbeat_worker().await;
        }

        Ok(operation)
    }

    pub(in super::super) async fn report_rekey_progress_impl(
        &self,
        status: Option<RekeyProgressState>,
        progress: Option<u8>,
    ) -> Result<(ActiveRekeyOperation, bool), ClientError> {
        self.ensure_state_loaded().await?;

        let session = self.get_session_info().await?;
        let token = session.token.clone();
        let device_id = session.device_id.clone();
        let server_base = Self::resolve_server_base_url(session.server_url.clone());
        let group_id = self
            .require_active_group("reporting rekey progress")
            .await?;

        let operation_id = {
            let state = self.state.read().await;
            state.active_rekey.as_ref().map(|op| op.rekey_id)
        };

        let operation_id = match operation_id {
            Some(id) => id,
            None => {
                // Some CLI flows (e.g. first Welcome sync after initiating rekey)
                // attempt to report progress before the cached rekey status
                // has been hydrated. Refresh once before failing so we can
                // self-heal missing client state without requiring a manual
                // background heartbeat.
                let (maybe_operation, _) = self.refresh_rekey_status_from_server().await?;
                match maybe_operation {
                    Some(operation) => operation.rekey_id,
                    None => {
                        return Err(ClientError::InvalidState(
                            "No active rekey operation to report progress for".to_string(),
                        ))
                    }
                }
            }
        };

        let payload = RekeyProgressUpdateRequest {
            operation_id,
            device_id,
            status,
            progress,
        };

        let url = format!("{}/api/v1/groups/{}/rekey/progress", server_base, group_id);
        let client = reqwest::Client::new();
        self.rekey_request_throttle.wait_for_slot().await;
        let response = match client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                self.rekey_request_throttle.register_failure(None).await;
                return Err(ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to submit rekey progress: {}", e),
                    "report_rekey_progress".to_string(),
                    0,
                    "request_failed".to_string(),
                ));
            }
        };

        let status = response.status();
        if should_backoff(status) {
            let retry_after = retry_after_delay(response.headers());
            self.rekey_request_throttle
                .register_failure(retry_after)
                .await;
        } else {
            self.rekey_request_throttle.register_success().await;
        }

        if let Some(retention_err) = self
            .handle_retention_status(status, response.headers(), "report_rekey_progress")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while reporting rekey progress".to_string(),
                "report_rekey_progress".to_string(),
                0,
                "unauthorized".to_string(),
            ));
        }

        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to submit rekey progress ({}): {}", status, body),
                "report_rekey_progress".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        let payload: RekeyStatusPayload = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to parse rekey progress response: {}", e),
                "report_rekey_progress".to_string(),
                0,
                "decode".to_string(),
            )
        })?;

        let (operation, operation_active) = {
            let mut state = self.state.write().await;
            let mut current = state
                .active_rekey
                .clone()
                .unwrap_or_else(|| ActiveRekeyOperation::from_status(&payload));
            current.update_from_status(&payload);

            let completed = matches!(
                current.status,
                RekeyStatus::Completed | RekeyStatus::Cancelled | RekeyStatus::Failed
            );

            if completed {
                state.active_rekey = None;
                state.rekey_heartbeats.remove(&payload.rekey_id);
            } else {
                state
                    .rekey_heartbeats
                    .entry(payload.rekey_id)
                    .or_insert_with(RekeyHeartbeatState::default);
                state.active_rekey = Some(current.clone());
            }

            (current, !completed)
        };

        self.save_client_state().await?;

        Ok((operation, operation_active))
    }
}
