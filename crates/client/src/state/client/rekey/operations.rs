use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// Initiate the server-managed two-phase rekey pipeline for the active group.
    pub async fn initiate_rekey(
        &self,
        options: RekeyInitiationOptions,
    ) -> Result<ActiveRekeyOperation, ClientError> {
        self.ensure_state_loaded().await?;

        let session = self.get_session_info().await?;
        let token = session.token.clone();
        let server_base = Self::resolve_server_base_url(session.server_url.clone());
        let group_id = self.require_active_group("initiating a rekey").await?;

        let request = RekeyInitiateRequest {
            reason: options.reason,
            config: options.config,
            member_updates: options.member_updates,
            welcome_messages: options.welcome_messages,
            emergency: options.emergency,
            client_epoch_id: options.client_epoch_id,
        };

        let url = format!("{}/api/v1/groups/{}/rekey", server_base, group_id);
        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to initiate rekey: {}", e),
                    "initiate_rekey".to_string(),
                    0,
                    "request_failed".to_string(),
                )
            })?;

        let status = response.status();

        if let Some(retention_err) = self
            .handle_retention_status(status, response.headers(), "initiate_rekey")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while initiating rekey".to_string(),
                "initiate_rekey".to_string(),
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
                format!("Rekey initiation failed with status {}: {}", status, body),
                "initiate_rekey".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        let payload: RekeyResponsePayload = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to parse rekey response: {}", e),
                "initiate_rekey".to_string(),
                0,
                "decode".to_string(),
            )
        })?;

        let operation = ActiveRekeyOperation::from_initiation(payload);

        {
            let mut state = self.state.write().await;
            state
                .rekey_heartbeats
                .insert(operation.rekey_id, RekeyHeartbeatState::default());
            state.active_rekey = Some(operation.clone());
        }

        self.synchronize_new_epoch(&operation).await?;

        self.save_client_state().await?;

        if self.config.migration_automation_enabled {
            self.ensure_rekey_heartbeat_worker().await;

            // Populate pending_rewraps with all enrolled files that need migration
            self.populate_migration_queue().await?;
        }

        Ok(operation)
    }

    /// Scan all enrolled folders and enqueue files for background migration
    pub async fn populate_migration_queue(&self) -> Result<(), ClientError> {
        if !self.config.migration_automation_enabled {
            self.logger.log(
                crate::logging::LogLevel::Debug,
                "Skipping migration queue population (automation disabled)",
                Some("populate_migration_queue"),
            );
            return Ok(());
        }
        let migration = {
            let state = self.state.read().await;
            state.migration.clone()
        };

        let Some(migration) = migration else {
            if std::env::var("HYBRIDCIPHER_DEBUG_REKEY").is_ok() {
                eprintln!("DEBUG populate_migration_queue: No migration state, returning early");
            }
            return Ok(());
        };

        if std::env::var("HYBRIDCIPHER_DEBUG_REKEY").is_ok() {
            eprintln!(
                "DEBUG populate_migration_queue: Starting - from_epoch={}, to_epoch={}",
                migration.from_epoch, migration.to_epoch
            );
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Scanning enrolled files from epoch {} to {} (migration via mount access)",
                migration.from_epoch, migration.to_epoch
            ),
            Some("populate_migration_queue"),
        );

        // Clean up any duplicate coverage log entries before reconciliation
        if let Err(err) = self.deduplicate_coverage_log().await {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Coverage deduplication skipped: {}", err),
                Some("coverage_dedup"),
            );
        }

        // Ensure the coverage log reflects all tracked files before reporting counts.
        if let Err(err) = self.reconcile_coverage_log_from_index().await {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Coverage reconcile skipped: {}", err),
                Some("coverage_reconcile"),
            );
        }

        // Build the list of files we should migrate in the background (tracked + wrong-epoch orphans)
        let files_to_migrate = {
            let (_, _, roots) = self.active_group_roots_map().await?;
            let coverage_root_count = roots.len();

            let mut tracked_candidates = 0usize;
            let mut orphan_candidates = 0usize;
            let mut total_entries = 0usize;
            let mut files = Vec::new();

            for (root_id, root) in roots.iter() {
                if root.state != CoverageRootState::Active {
                    continue;
                }
                let entries = self.list_file_index_entries_for_root(*root_id).await?;
                total_entries = total_entries.saturating_add(entries.len());

                for entry in entries {
                    let is_tracked = matches!(entry.state, FileCoverageState::Tracked);
                    let is_orphan_wrong_epoch = entry.state == FileCoverageState::Orphaned
                        && entry.orphan_kind == Some(FileOrphanKind::WrongEpoch);
                    // Encrypted by another device, so this one has no local record of it; its
                    // header's key (recorded at scan) still has to move with the rotation.
                    let is_from_other_device = entry.state == FileCoverageState::Orphaned
                        && entry.orphan_kind == Some(FileOrphanKind::MissingMetadata)
                        && entry.last_epoch > 0;

                    let needs_migration = (is_tracked || is_orphan_wrong_epoch || is_from_other_device)
                        && entry.last_epoch != migration.to_epoch;

                    if std::env::var("HYBRIDCIPHER_DEBUG_REKEY").is_ok() {
                        eprintln!(
                            "DEBUG populate_migration_queue: File {} - tracked={}, orphan_wrong_epoch={}, last_epoch={}, needs_migration={}",
                            entry.relative_path, is_tracked, is_orphan_wrong_epoch, entry.last_epoch, needs_migration
                        );
                    }

                    if !needs_migration {
                        continue;
                    }

                    let absolute_path = root.path.join(&entry.relative_path);

                    let mut source_epoch = entry.last_epoch;
                    if source_epoch == 0 {
                        if let Some(header) = Self::parse_encrypted_file_metadata(&absolute_path) {
                            if header.epoch_id > 0 {
                                source_epoch = header.epoch_id;
                                self.logger.log(
                                    crate::logging::LogLevel::Debug,
                                    &format!(
                                        "Derived source epoch {} from ciphertext header for {}",
                                        source_epoch,
                                        absolute_path.display()
                                    ),
                                    Some("populate_migration_queue"),
                                );
                            }
                        }
                    }
                    if source_epoch == 0 {
                        // Fallback to current migration source epoch when metadata is missing
                        source_epoch = migration.from_epoch;
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Missing source epoch for {}; defaulting to migration from_epoch {}",
                                entry.relative_path, source_epoch
                            ),
                            Some("populate_migration_queue"),
                        );
                    }

                    if is_tracked {
                        tracked_candidates += 1;
                    } else {
                        orphan_candidates += 1;
                    }
                    files.push((absolute_path, source_epoch));
                }
            }

            if std::env::var("HYBRIDCIPHER_DEBUG_REKEY").is_ok() {
                eprintln!(
                    "DEBUG populate_migration_queue: Scanning file_index with {} entries (active roots for group: {})",
                    total_entries,
                    coverage_root_count
                );
            }

            if tracked_candidates > 0 || orphan_candidates > 0 {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Migration candidates identified (tracked={}, orphan_wrong_epoch={})",
                        tracked_candidates, orphan_candidates
                    ),
                    Some("populate_migration_queue"),
                );
            }

            files
        };

        let count = files_to_migrate.len();
        if count == 0 {
            self.logger.log(
                crate::logging::LogLevel::Info,
                "No files need migration (already at target epoch or no eligible entries)",
                Some("populate_migration_queue"),
            );
            if std::env::var("HYBRIDCIPHER_DEBUG_REKEY").is_ok() {
                eprintln!("DEBUG populate_migration_queue: No eligible files to enqueue");
            }
            return Ok(());
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Enqueueing {} files for background migration to epoch {}",
                count, migration.to_epoch
            ),
            Some("populate_migration_queue"),
        );
        if std::env::var("HYBRIDCIPHER_DEBUG_REKEY").is_ok() {
            eprintln!(
                "DEBUG populate_migration_queue: Enqueueing {} files to {}",
                count, migration.to_epoch
            );
        }

        // Enqueue files in batches to avoid holding write lock too long
        const BATCH_SIZE: usize = 100;
        for (i, chunk) in files_to_migrate.chunks(BATCH_SIZE).enumerate() {
            let mut state = self.state.write().await;
            let group_id = state
                .active_group_id
                .ok_or_else(|| ClientError::InvalidState("No active group selected".into()))?;

            for (path, from_epoch) in chunk {
                let normalized = Self::normalize_storage_path(&path.to_string_lossy());
                let already_pending = state
                    .pending_rewraps
                    .iter()
                    .any(|entry| entry.path == normalized && entry.to_epoch == migration.to_epoch);

                if !already_pending {
                    state.pending_rewraps.push_back(PendingRewrap {
                        path: normalized,
                        from_epoch: *from_epoch,
                        to_epoch: migration.to_epoch,
                        group_id,
                        attempts: 0,
                        last_attempt: None,
                    });
                }
            }
            drop(state);

            if (i + 1) % 10 == 0 {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Enqueued {}/{} files for migration",
                        ((i + 1) * BATCH_SIZE).min(count),
                        count
                    ),
                    Some("populate_migration_queue"),
                );
            }
        }

        self.save_client_state().await?;
        self.ensure_idle_crawler().await;

        // Schedule initial heartbeat to report file counts before migration starts.
        self.schedule_rekey_heartbeat().await;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Migration queue populated with {} files, idle crawler started",
                count
            ),
            Some("populate_migration_queue"),
        );
        if std::env::var("HYBRIDCIPHER_DEBUG_REKEY").is_ok() {
            eprintln!(
                "DEBUG populate_migration_queue: Queue size now {}, idle crawler requested",
                count
            );
        }

        Ok(())
    }

    /// Fetch the latest rekey status from the server.
    pub async fn rekey_status(&self) -> Result<Option<ActiveRekeyOperation>, ClientError> {
        let (mut operation, operation_active) = self.refresh_rekey_status_from_server().await?;

        if rekey_debug_enabled() {
            eprintln!(
                "DEBUG rekey_status: operation.is_some()={}, operation_active={}",
                operation.is_some(),
                operation_active
            );
        }

        if operation_active && self.config.migration_automation_enabled {
            self.ensure_rekey_heartbeat_worker().await;
        }

        // Only populate migration queue if operation is still active (not cancelled/failed/completed)
        // This prevents re-triggering forward migration after a fallback
        if let Some(ref op) = operation {
            let is_active_operation = !matches!(
                op.status,
                RekeyStatus::Completed | RekeyStatus::Cancelled | RekeyStatus::Failed
            );

            if is_active_operation && self.config.migration_automation_enabled {
                let (has_migration, file_count, pending_count) = {
                    let (active_group, _, roots) = self.active_group_roots_map().await?;
                    let state = self.state.read().await;
                    let pending = state
                        .pending_rewraps
                        .iter()
                        .filter(|p| p.group_id == active_group)
                        .count();
                    let has_migration = state.migration.is_some();
                    drop(state);

                    let mut tracked_files = 0usize;
                    for root_id in roots.keys().copied() {
                        let entries = self.list_file_index_entries_for_root(root_id).await?;
                        tracked_files += entries.len();
                    }
                    Ok::<_, ClientError>((has_migration, tracked_files, pending))
                }?;

                if rekey_debug_enabled() {
                    eprintln!(
                        "DEBUG rekey_status: has_migration={}, file_count={}, pending_count={}",
                        has_migration, file_count, pending_count
                    );
                }

                let needs_population = has_migration && file_count > 0 && pending_count == 0;

                if needs_population {
                    if rekey_debug_enabled() {
                        eprintln!("DEBUG rekey_status: Calling populate_migration_queue()");
                    }
                    self.logger.log(
                        crate::logging::LogLevel::Info,
                        "Migration state active with unmigrated files, populating migration queue",
                        Some("rekey_status"),
                    );
                    let _ = self.populate_migration_queue().await;
                } else if has_migration && pending_count > 0 {
                    // Ensure idle crawler is running to process pending rewraps
                    if rekey_debug_enabled() {
                        eprintln!("DEBUG rekey_status: Ensuring idle_crawler is running for {} pending rewraps", pending_count);
                    }
                    self.ensure_idle_crawler().await;
                }
            } else if rekey_debug_enabled() {
                eprintln!(
                    "DEBUG rekey_status: Skipping migration queue population - operation status is {:?}",
                    op.status
                );
            }
        }

        // Refresh local migration progress from coverage/file_index to avoid stale migrated counts.
        // Skip the first status after a new rekey so we don't carry over stale 100% snapshots.
        if let Some(op) = operation.as_mut() {
            if op.suppress_local_override {
                op.suppress_local_override = false;
                let mut state = self.state.write().await;
                if let Some(active) = state.active_rekey.as_mut() {
                    if active.rekey_id == op.rekey_id {
                        active.suppress_local_override = false;
                    }
                }
                drop(state);
                self.save_client_state().await?;
            } else if let Ok((total, migrated)) = self.local_migration_progress().await {
                op.progress.total_files = total;
                op.progress.migrated_files = migrated.min(total);
            }
        }

        Ok(operation)
    }

    pub(in super::super) async fn refresh_rekey_status_from_server(
        &self,
    ) -> Result<(Option<ActiveRekeyOperation>, bool), ClientError> {
        self.ensure_state_loaded().await?;

        let session = self.get_session_info().await?;
        let token = session.token.clone();
        let server_base = Self::resolve_server_base_url(session.server_url.clone());
        let group_id = self.require_active_group("fetching rekey status").await?;

        let url = format!("{}/api/v1/groups/{}/rekey/status", server_base, group_id);

        // Build HTTP client with longer timeout to handle slow connections
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to build HTTP client: {}", e),
                    "rekey_status".to_string(),
                    0,
                    "client_build_failed".to_string(),
                )
            })?;

        self.rekey_request_throttle.wait_for_slot().await;

        let response = match client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                self.rekey_request_throttle.register_failure(None).await;
                // Log more details about the network error
                eprintln!("DEBUG: rekey_status network error: {:?}", e);
                eprintln!("DEBUG: URL was: {}", url);
                eprintln!("DEBUG: Is timeout: {}", e.is_timeout());
                eprintln!("DEBUG: Is connect: {}", e.is_connect());
                return Err(ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to query rekey status: {}", e),
                    "rekey_status".to_string(),
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
            .handle_retention_status(status, response.headers(), "rekey_status")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::NOT_FOUND {
            let previous_rekey = {
                let state = self.state.read().await;
                state.active_rekey.as_ref().map(|op| op.rekey_id)
            };
            let _ = self
                .reset_rekey_progress_state_async(group_id, previous_rekey)
                .await;
            {
                let mut state = self.state.write().await;
                state.active_rekey = None;
            }
            self.save_client_state().await?;
            return Ok((None, false));
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while fetching rekey status".to_string(),
                "rekey_status".to_string(),
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
                format!("Failed to fetch rekey status ({}): {}", status, body),
                "rekey_status".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        let payload: RekeyStatusPayload = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to parse rekey status response: {}", e),
                "rekey_status".to_string(),
                0,
                "decode".to_string(),
            )
        })?;

        let mut needs_reset = false;
        let mut reset_on_terminal = false;
        #[allow(unused_assignments)]
        let mut previous_rekey: Option<Uuid> = None;
        let (operation, operation_active) = {
            let mut state = self.state.write().await;

            // Check if this is a NEW rekey operation (different rekey_id)
            let is_new_rekey = state
                .active_rekey
                .as_ref()
                .map(|existing| existing.rekey_id != payload.rekey_id)
                .unwrap_or(true);
            previous_rekey = state.active_rekey.as_ref().map(|op| op.rekey_id);
            if is_new_rekey {
                needs_reset = true;
            }

            if rekey_debug_enabled() {
                eprintln!(
                    "DEBUG refresh_rekey_status: is_new_rekey={}, payload.rekey_id={}, payload.status={:?}",
                    is_new_rekey,
                    payload.rekey_id,
                    payload.status
                );
            }

            // If this is a new rekey operation, create fresh from payload instead of updating stale state
            let current = if is_new_rekey {
                let mut op = ActiveRekeyOperation::from_status(&payload);
                op.suppress_local_override = true;
                op
            } else {
                let mut existing = state.active_rekey.clone().unwrap();
                existing.update_from_status(&payload);
                existing
            };

            if rekey_debug_enabled() {
                eprintln!(
                    "DEBUG refresh_rekey_status: current.status={:?}, current.rekey_id={}",
                    current.status, current.rekey_id
                );
            }

            let completed = matches!(
                current.status,
                RekeyStatus::Completed | RekeyStatus::Cancelled | RekeyStatus::Failed
            );
            let _affected_group = current.group_id;

            if completed {
                if matches!(current.status, RekeyStatus::Cancelled | RekeyStatus::Failed) {
                    // Fallback/failed rekey: clear coverage/heartbeat state so subsequent scans
                    // don't report stale migration coverage.
                    reset_on_terminal = true;
                }
                state.active_rekey = None;
                state.rekey_heartbeats.remove(&payload.rekey_id);
                // Preserve pending_rewraps so lazy migration can continue after cutover.
            } else {
                state
                    .rekey_heartbeats
                    .entry(payload.rekey_id)
                    .or_insert_with(RekeyHeartbeatState::default);
                state.active_rekey = Some(current.clone());
            }
            (current, !completed)
        };

        // If a new rekey was detected, clear any stale coverage/heartbeat state before proceeding.
        if needs_reset {
            let _ = self
                .reset_rekey_progress_state_async(group_id, previous_rekey)
                .await;
        } else if reset_on_terminal {
            let _ = self
                .reset_rekey_progress_state_async(group_id, Some(operation.rekey_id))
                .await;
        }

        self.synchronize_new_epoch(&operation).await?;

        self.save_client_state().await?;

        Ok((Some(operation), operation_active))
    }
}
