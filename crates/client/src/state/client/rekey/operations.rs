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

                    let needs_migration = (is_tracked || is_orphan_wrong_epoch)
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
                    } else if is_orphan_wrong_epoch {
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

    /// Cancel the active rekey operation and revert local state.
    pub async fn fallback_rekey(
        &self,
        reason: Option<String>,
    ) -> Result<RekeyFallbackSummary, ClientError> {
        self.ensure_state_loaded().await?;

        let session = self.get_session_info().await?;
        let token = session.token.clone();
        let server_base = Self::resolve_server_base_url(session.server_url.clone());
        let group_id = self
            .require_active_group("requesting rekey fallback")
            .await?;

        let active_rekey_id = {
            let state = self.state.read().await;
            state
                .active_rekey
                .as_ref()
                .map(|op| op.rekey_id)
                .ok_or_else(|| {
                    ClientError::InvalidState("No active rekey operation to cancel".to_string())
                })?
        };

        let normalized_reason = reason
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string());

        let request_payload = RekeyFallbackRequestPayload {
            reason: normalized_reason.clone(),
        };

        let url = format!("{}/api/v1/groups/{}/rekey/fallback", server_base, group_id);
        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request_payload)
            .send()
            .await
            .map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to request rekey fallback: {}", e),
                    "fallback_rekey".to_string(),
                    0,
                    "request_failed".to_string(),
                )
            })?;

        let status = response.status();

        if let Some(retention_err) = self
            .handle_retention_status(status, response.headers(), "fallback_rekey")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while cancelling rekey".to_string(),
                "fallback_rekey".to_string(),
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
                format!("Failed to cancel rekey ({}): {}", status, body),
                "fallback_rekey".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        let payload: RekeyFallbackResponsePayload = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to parse rekey fallback response: {}", e),
                "fallback_rekey".to_string(),
                0,
                "decode".to_string(),
            )
        })?;

        if payload.rekey_id != active_rekey_id {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                "Fallback response refers to a different rekey operation than expected",
                Some(&payload.rekey_id.to_string()),
            );
        }

        self.apply_rekey_fallback_state(group_id, &payload).await?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Rekey operation cancelled via fallback command",
            Some(&payload.rekey_id.to_string()),
        );

        let server_reason = payload.reason.clone();
        Ok(RekeyFallbackSummary {
            rekey_id: payload.rekey_id,
            group_id: payload.group_id,
            cancelled_at: payload.cancelled_at,
            reason: server_reason.or(normalized_reason),
            new_epoch_id: payload.new_epoch_id,
            new_epoch_number: payload.new_epoch_number,
            previous_epoch_id: payload.previous_epoch_id,
            previous_epoch_number: payload.previous_epoch_number,
        })
    }

    pub(in super::super) async fn collect_epoch_rewrap_candidates(
        &self,
        group_id: Uuid,
        epoch: u64,
    ) -> Result<Vec<String>, ClientError> {
        let (active_group, _, roots) = self.active_group_roots_map().await?;
        if active_group != group_id {
            if rekey_debug_enabled() {
                eprintln!(
                    "DEBUG collect_epoch_rewrap_candidates: active_group={} != group_id={}, returning empty",
                    active_group, group_id
                );
            }
            return Ok(Vec::new());
        }

        let mut candidates = Vec::new();
        let mut index_matches = 0u64;
        let mut header_matches = 0u64;

        for (root_id, root) in roots.iter() {
            if root.state != CoverageRootState::Active {
                continue;
            }

            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                let absolute_path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };

                // Fast path: check file_index.last_epoch
                if entry.last_epoch == epoch {
                    index_matches += 1;
                    candidates.push(Self::normalize_storage_path(
                        &absolute_path.to_string_lossy(),
                    ));
                    continue;
                }

                // Fallback: check actual file header for epoch (handles stale index)
                // This is critical for rollback scenarios where the index may not have been updated
                if let Some(header) = Self::parse_encrypted_file_metadata(&absolute_path) {
                    if header.epoch_id == epoch {
                        header_matches += 1;
                        candidates.push(Self::normalize_storage_path(
                            &absolute_path.to_string_lossy(),
                        ));
                    }
                }
            }
        }

        if rekey_debug_enabled() {
            eprintln!(
                "DEBUG collect_epoch_rewrap_candidates: epoch={}, index_matches={}, header_matches={}, total_candidates={}",
                epoch, index_matches, header_matches, candidates.len()
            );
        }

        candidates.sort();
        candidates.dedup();
        Ok(candidates)
    }

    pub(in super::super) async fn apply_rekey_fallback_state(
        &self,
        group_id: Uuid,
        response: &RekeyFallbackResponsePayload,
    ) -> Result<(), ClientError> {
        self.cancel_idle_crawler().await;

        let new_epoch_number = response.new_epoch_number;
        let previous_epoch_number = response.previous_epoch_number;

        if rekey_debug_enabled() {
            eprintln!(
                "DEBUG apply_rekey_fallback_state: new_epoch={:?}, previous_epoch={:?}",
                new_epoch_number, previous_epoch_number
            );
        }

        let rollback_epochs = match (new_epoch_number, previous_epoch_number) {
            (Some(from_epoch), Some(to_epoch)) if from_epoch != to_epoch => {
                Some((from_epoch, to_epoch))
            }
            _ => None,
        };

        if rekey_debug_enabled() {
            eprintln!(
                "DEBUG apply_rekey_fallback_state: rollback_epochs={:?}",
                rollback_epochs
            );
        }

        // collect_epoch_rewrap_candidates now checks both file_index AND actual file headers,
        // so we don't need the unreliable migration.migrated_files fallback anymore
        let rollback_candidates = if let Some((from_epoch, _)) = rollback_epochs {
            let candidates = self
                .collect_epoch_rewrap_candidates(group_id, from_epoch)
                .await?;
            if rekey_debug_enabled() {
                eprintln!(
                    "DEBUG apply_rekey_fallback_state: Found {} rollback candidates for epoch {}",
                    candidates.len(),
                    from_epoch
                );
            }
            candidates
        } else {
            if rekey_debug_enabled() {
                eprintln!("DEBUG apply_rekey_fallback_state: No rollback_epochs, skipping candidate collection");
            }
            Vec::new()
        };

        {
            let mut state = self.state.write().await;

            if let Some(active) = state.active_rekey.as_ref() {
                if active.rekey_id == response.rekey_id {
                    state.active_rekey = None;
                }
            }

            state.rekey_heartbeats.remove(&response.rekey_id);

            state
                .pending_rewraps
                .retain(|task| task.group_id != group_id);

            // Instead of removing the epoch immediately, mark it for deferred removal.
            // The epoch key is still needed to decrypt files during rollback rewrap.
            // It will be removed after 100% coverage is reached and 24 hours have passed.
            if let Some(epoch_number) = new_epoch_number {
                if let Some(entries) = state.epochs.get_mut(&epoch_number) {
                    for epoch in entries.iter_mut().filter(|e| e.group_id == Some(group_id)) {
                        epoch.is_active = false;
                        epoch.marked_for_removal = true;
                        // removal_eligible_at will be set when 100% coverage is reached
                    }
                }
            }

            if let Some(previous_epoch) = previous_epoch_number {
                if let Some(membership) = state.group_memberships.get_mut(&group_id) {
                    membership.current_epoch_id = Some(previous_epoch);
                }

                if let Some(entries) = state.epochs.get_mut(&previous_epoch) {
                    for epoch in entries.iter_mut().filter(|e| e.group_id == Some(group_id)) {
                        epoch.is_active = true;
                    }
                }

                if let Some(target_epoch) = new_epoch_number {
                    if let Some(entries) = state.epochs.get_mut(&target_epoch) {
                        for epoch in entries.iter_mut().filter(|e| e.group_id == Some(group_id)) {
                            epoch.is_active = false;
                        }
                    }
                }

                if state.active_group_id == Some(group_id) {
                    state.current_epoch = previous_epoch;
                }
            }

            if let Some((from_epoch, to_epoch)) = rollback_epochs {
                if !rollback_candidates.is_empty() {
                    for path in rollback_candidates.iter() {
                        if !state
                            .pending_rewraps
                            .iter()
                            .any(|task| task.path == *path && task.to_epoch == to_epoch)
                        {
                            state.pending_rewraps.push_back(PendingRewrap {
                                path: path.clone(),
                                from_epoch,
                                to_epoch,
                                group_id,
                                attempts: 0,
                                last_attempt: None,
                            });
                        }
                    }

                    state.migration = Some(MigrationState {
                        from_epoch,
                        to_epoch,
                        phase: MigrationPhase::Rollback,
                        migrated_files: Vec::new(),
                        migrated_files_set: HashSet::new(),
                        failed_files: Vec::new(),
                        total_files: rollback_candidates.len() as u64,
                        started_at: Utc::now(),
                        estimated_completion: None,
                    });
                } else {
                    state.migration = None;
                }
            } else {
                state.migration = None;
            }

            state.last_sync = Utc::now();
        }

        self.save_client_state().await?;

        if rekey_debug_enabled() {
            let pending_count = {
                let state = self.state.read().await;
                state.pending_rewraps.len()
            };
            eprintln!(
                "DEBUG apply_rekey_fallback_state: After save, pending_rewraps count = {}, starting idle_crawler = {}",
                pending_count,
                rollback_epochs.is_some() && !rollback_candidates.is_empty()
            );
        }

        if rollback_epochs.is_some() && !rollback_candidates.is_empty() {
            self.ensure_idle_crawler().await;
        }

        Ok(())
    }

    /// Trigger cutover for the active rekey operation once migration is complete.
    pub async fn cutover_rekey(
        &self,
        force: bool,
        immediate_cleanup: bool,
    ) -> Result<CutoverSummary, ClientError> {
        self.ensure_state_loaded().await?;

        let session = self.get_session_info().await?;
        let token = session.token.clone();
        let server_base = Self::resolve_server_base_url(session.server_url.clone());
        let group_id = self.require_active_group("executing cutover").await?;

        let operation_id = {
            let state = self.state.read().await;
            state
                .active_rekey
                .as_ref()
                .map(|op| op.rekey_id)
                .ok_or_else(|| {
                    ClientError::InvalidState(
                        "No active rekey operation is available for cutover".to_string(),
                    )
                })?
        };

        let client = reqwest::Client::new();

        let (signature, signature_algorithm) = if force {
            let commitment = self
                .fetch_rekey_descriptor_commitment(
                    &client,
                    &server_base,
                    &token,
                    group_id,
                    operation_id,
                )
                .await
                .map_err(Self::map_descriptor_fetch_error)?;
            let message = cutover_commit_message(operation_id, &commitment);
            let signature_bytes = self.device_identity.sign(&message);
            (
                Some(general_purpose::STANDARD.encode(signature_bytes)),
                Some("ed25519".to_string()),
            )
        } else {
            (None, None)
        };

        let request = CutoverRequest {
            rekey_id: operation_id,
            force,
            immediate_cleanup,
            signature,
            signature_algorithm,
        };

        let url = format!("{}/api/v1/groups/{}/cutover", server_base, group_id);
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to initiate cutover: {}", e),
                    "cutover_rekey".to_string(),
                    0,
                    "request_failed".to_string(),
                )
            })?;

        let status = response.status();

        if let Some(retention_err) = self
            .handle_retention_status(status, response.headers(), "cutover_rekey")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while finalizing cutover".to_string(),
                "cutover_rekey".to_string(),
                0,
                "unauthorized".to_string(),
            ));
        }

        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            let mut message = format!("Cutover failed with status {}: {}", status, body);
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(error_msg) = parsed.get("error").and_then(|value| value.as_str()) {
                    if error_msg.contains("Migration not ready for cutover") {
                        message =
                            "Migration not ready for cutover. Run hybridcipher rekey status to see details."
                                .to_string();
                    }
                }
            }
            return Err(ClientError::network_error(
                ErrorCode::NetworkProtocol,
                message,
                "cutover_rekey".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        let payload: CutoverResponsePayload = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to parse cutover response: {}", e),
                "cutover_rekey".to_string(),
                0,
                "decode".to_string(),
            )
        })?;

        {
            let mut state = self.state.write().await;
            state.active_rekey = None;
            Self::clear_migration_state_for_group(&mut state, group_id);
        }

        self.save_client_state().await?;

        Ok(CutoverSummary {
            cutover_id: payload.cutover_id,
            group_id: payload.group_id,
            new_epoch_id: payload.new_epoch_id,
            old_epoch_id: payload.old_epoch_id,
            completed_at: payload.completed_at,
            cleanup_status: payload.cleanup_status,
        })
    }

    pub(in super::super) async fn fetch_rekey_descriptor_commitment(
        &self,
        client: &reqwest::Client,
        server_base: &str,
        token: &str,
        group_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Vec<u8>, ClientError> {
        let url = format!(
            "{}/api/v1/admin/groups/{}/rekey/descriptors",
            server_base, group_id
        );
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to fetch rekey descriptors: {}", e),
                    "fetch_rekey_descriptors".to_string(),
                    0,
                    "request_failed".to_string(),
                )
            })?;

        let status = response.status();

        if let Some(retention_err) = self
            .handle_retention_status(status, response.headers(), "fetch_rekey_descriptors")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while fetching rekey descriptors".to_string(),
                "fetch_rekey_descriptors".to_string(),
                0,
                "unauthorized".to_string(),
            ));
        }

        if status == StatusCode::FORBIDDEN {
            return Err(ClientError::network_error(
                ErrorCode::SecurityUnauthorized,
                "Insufficient permissions to inspect rekey descriptors".to_string(),
                "fetch_rekey_descriptors".to_string(),
                0,
                "forbidden".to_string(),
            ));
        }

        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to fetch rekey descriptors ({}): {}", status, body),
                "fetch_rekey_descriptors".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        let payload: RekeyDescriptorList = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to decode descriptor list: {}", e),
                "fetch_rekey_descriptors".to_string(),
                0,
                "decode".to_string(),
            )
        })?;

        let descriptor = payload
            .descriptors
            .into_iter()
            .find(|d: &RekeyDescriptorSummary| d.operation_id == operation_id)
            .ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Descriptor for rekey operation {} not found in admin listing",
                    operation_id
                ))
            })?;

        let commitment = descriptor.commitment.trim();
        let bytes = hex::decode(commitment).map_err(|e| {
            ClientError::InvalidState(format!(
                "Descriptor commitment '{}' could not be decoded: {}",
                commitment, e
            ))
        })?;

        if bytes.len() != 32 {
            return Err(ClientError::InvalidState(format!(
                "Descriptor commitment for operation {} has invalid length {} (expected 32)",
                operation_id,
                bytes.len()
            )));
        }

        Ok(bytes)
    }

    pub(in super::super) fn map_descriptor_fetch_error(err: ClientError) -> ClientError {
        match err {
            ClientError::NetworkError { context, .. }
                if context.operation == "fetch_rekey_descriptors"
                    && context.code == ErrorCode::SecurityUnauthorized =>
            {
                ClientError::Auth(
                    "Forced cutover requires audit privileges to read the pending descriptor. \
                     Re-authenticate as a group owner/admin or ask an operator to grant the \
                     necessary access before retrying."
                        .to_string(),
                )
            }
            ClientError::NetworkError { context, .. }
                if context.operation == "fetch_rekey_descriptors"
                    && context.code == ErrorCode::NetworkAuthentication =>
            {
                ClientError::Auth(
                    "Authentication expired while fetching the rekey descriptor. Refresh your \
                     session and retry the forced cutover."
                        .to_string(),
                )
            }
            other => other,
        }
    }
}
