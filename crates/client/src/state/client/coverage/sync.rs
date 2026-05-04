use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    pub(in super::super) async fn collect_heartbeat_root_kpis(
        &self,
    ) -> Result<Vec<RootCoverageKpiPayload>, ClientError> {
        let summaries = self.coverage_root_stats().await?;
        let mut kpis = Vec::with_capacity(summaries.len());

        for summary in summaries {
            let coverage_ratio = (summary.coverage_ratio * 100.0).clamp(0.0, 100.0);
            kpis.push(RootCoverageKpiPayload {
                root_id: summary.root.root_id,
                coverage_ratio,
                tracked_files: summary.tracked_files as u64,
                orphaned_files: summary.orphaned_files as u64,
                unmanaged_files: summary.unmanaged_files as u64,
                tracked_bytes: summary.tracked_bytes,
                orphaned_bytes: summary.orphaned_bytes,
                unmanaged_bytes: summary.unmanaged_bytes,
            });
        }

        Ok(kpis)
    }

    /// Return a batch of coverage log deltas for replication to the server.
    pub async fn coverage_replication_batch(
        &self,
        since_sequence: u64,
        limit: usize,
    ) -> Result<Vec<CoverageLogDeltaData>, ClientError> {
        self.ensure_state_loaded().await?;
        let group_id = self.require_active_group("replicating coverage").await?;
        let mut deltas = self
            .storage
            .load_coverage_log_deltas(group_id, since_sequence)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageRead,
                    format!("Failed to load coverage deltas: {}", e),
                    "coverage_replication_batch".to_string(),
                    None,
                    true,
                )
            })?;
        deltas.sort_by_key(|delta| delta.sequence);
        if limit > 0 && deltas.len() > limit {
            deltas.truncate(limit);
        }
        Ok(deltas)
    }

    /// Download (without applying) the latest server-side coverage snapshot.
    pub async fn download_coverage_snapshot_artifact(
        &self,
    ) -> Result<CoverageSnapshotArtifact, ClientError> {
        self.ensure_state_loaded().await?;
        let page_size = 5_000usize;
        let mut payload = self
            .fetch_coverage_snapshot_response_page(Some(0), Some(page_size as u64), true)
            .await?;
        let mut entries = std::mem::take(&mut payload.entries);
        let mut total_entries = payload
            .entries_total
            .or_else(|| Some(payload.total_files))
            .unwrap_or(0) as usize;
        total_entries = total_entries.max(entries.len());
        let mut offset = entries.len();

        while offset < total_entries {
            let page = self
                .fetch_coverage_snapshot_response_page(
                    Some(offset as u64),
                    Some(page_size as u64),
                    true,
                )
                .await?;
            if page.entries.is_empty() {
                break;
            }
            entries.extend(page.entries);
            offset = entries.len();
        }

        payload.entries = entries;
        Self::snapshot_response_to_artifact(payload)
    }

    pub(in super::super) async fn fetch_coverage_snapshot_response_page(
        &self,
        entries_offset: Option<u64>,
        entries_limit: Option<u64>,
        include_entries: bool,
    ) -> Result<CoverageSnapshotDownloadResponse, ClientError> {
        let session = self.get_session_info().await?;
        let group_id = self
            .require_active_group("restoring coverage snapshot")
            .await?;
        let token = session.token.clone();
        let server_base = Self::resolve_server_base_url(session.server_url.clone());
        let mut url = format!(
            "{}/api/v1/groups/{}/coverage/snapshot",
            server_base, group_id
        );
        let mut params = Vec::new();
        if let Some(offset) = entries_offset {
            params.push(format!("entries_offset={}", offset));
        }
        if let Some(limit) = entries_limit {
            params.push(format!("entries_limit={}", limit));
        }
        if !include_entries {
            params.push("include_entries=false".to_string());
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|err| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to fetch coverage snapshot: {}", err),
                    "coverage_snapshot_download".to_string(),
                    0,
                    "request_failed".to_string(),
                )
            })?;

        let status = response.status();
        if let Some(retention_err) = self
            .handle_retention_status(status, response.headers(), "coverage_snapshot_download")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::NOT_FOUND {
            return Err(ClientError::InvalidState(
                "Server has no coverage snapshot for this group yet".to_string(),
            ));
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while fetching coverage snapshot".to_string(),
                "coverage_snapshot_download".to_string(),
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
                format!("Failed to fetch coverage snapshot ({}): {}", status, body),
                "coverage_snapshot_download".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        response.json().await.map_err(|err| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to decode coverage snapshot response: {}", err),
                "coverage_snapshot_download".to_string(),
                0,
                "decode_failed".to_string(),
            )
        })
    }

    pub(in super::super) fn snapshot_response_to_artifact(
        payload: CoverageSnapshotDownloadResponse,
    ) -> Result<CoverageSnapshotArtifact, ClientError> {
        let merkle_root_vec = hex::decode(payload.merkle_root_hex).map_err(|err| {
            ClientError::InvalidState(format!("Failed to decode coverage snapshot root: {}", err))
        })?;
        if merkle_root_vec.len() != 32 {
            return Err(ClientError::InvalidState(format!(
                "Coverage snapshot root must be 32 bytes (got {})",
                merkle_root_vec.len()
            )));
        }
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&merkle_root_vec);

        let verifying_key_vec = general_purpose::STANDARD
            .decode(payload.verifying_key_base64)
            .map_err(|err| {
                ClientError::InvalidState(format!(
                    "Failed to decode coverage verifying key: {}",
                    err
                ))
            })?;
        if verifying_key_vec.len() != VERIFYING_KEY_LEN {
            return Err(ClientError::InvalidState(format!(
                "Coverage verifying key must be {} bytes (got {})",
                VERIFYING_KEY_LEN,
                verifying_key_vec.len()
            )));
        }
        let mut verifying_key = [0u8; VERIFYING_KEY_LEN];
        verifying_key.copy_from_slice(&verifying_key_vec);

        let signature = general_purpose::STANDARD
            .decode(payload.signature_base64)
            .map_err(|err| {
                ClientError::InvalidState(format!(
                    "Failed to decode coverage snapshot signature: {}",
                    err
                ))
            })?;

        let entries = payload
            .entries
            .into_iter()
            .map(|entry| CoverageSnapshotEntry {
                file_id: entry.file_id,
                epoch_number: entry.epoch_number,
            })
            .collect();

        Ok(CoverageSnapshotArtifact {
            snapshot_id: payload.snapshot_id,
            group_id: payload.group_id,
            epoch_id: payload.epoch_id,
            merkle_root,
            signature,
            verifying_key,
            signing_key_id: payload.signing_key_id,
            total_files: payload.total_files,
            generated_at: payload.coverage_generated_at,
            transparency_metadata: payload.transparency_metadata,
            entries,
        })
    }

    /// Download an inclusion proof for a single file ID.
    pub async fn download_coverage_file_proof(
        &self,
        file_id: &str,
    ) -> Result<CoverageProofArtifact, ClientError> {
        self.ensure_state_loaded().await?;
        let session = self.get_session_info().await?;
        let group_id = self
            .require_active_group("downloading coverage proof")
            .await?;
        let token = session.token.clone();
        let server_base = Self::resolve_server_base_url(session.server_url.clone());
        let mut url = format!("{}/api/v1/groups/{}/coverage/proof", server_base, group_id);
        url.push_str(&format!("?file_id={}", urlencoding::encode(file_id)));

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|err| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to fetch coverage proof: {}", err),
                    "coverage_proof_download".to_string(),
                    0,
                    "request_failed".to_string(),
                )
            })?;

        let status = response.status();
        if let Some(retention_err) = self
            .handle_retention_status(status, response.headers(), "coverage_proof_download")
            .await
        {
            return Err(retention_err);
        }

        if status == StatusCode::NOT_FOUND {
            return Err(ClientError::InvalidState(
                "Coverage proof not available for this file".to_string(),
            ));
        }

        if status == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication rejected while fetching coverage proof".to_string(),
                "coverage_proof_download".to_string(),
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
                format!("Failed to fetch coverage proof ({}): {}", status, body),
                "coverage_proof_download".to_string(),
                0,
                "error_response".to_string(),
            ));
        }

        let payload: CoverageProofResponse = response.json().await.map_err(|err| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to decode coverage proof response: {}", err),
                "coverage_proof_download".to_string(),
                0,
                "decode_failed".to_string(),
            )
        })?;

        let merkle_root_vec = hex::decode(payload.merkle_root_hex).map_err(|err| {
            ClientError::InvalidState(format!("Failed to decode coverage snapshot root: {}", err))
        })?;
        if merkle_root_vec.len() != 32 {
            return Err(ClientError::InvalidState(format!(
                "Coverage snapshot root must be 32 bytes (got {})",
                merkle_root_vec.len()
            )));
        }
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&merkle_root_vec);

        let verifying_key_vec = general_purpose::STANDARD
            .decode(payload.verifying_key_base64)
            .map_err(|err| {
                ClientError::InvalidState(format!(
                    "Failed to decode coverage verifying key: {}",
                    err
                ))
            })?;
        if verifying_key_vec.len() != VERIFYING_KEY_LEN {
            return Err(ClientError::InvalidState(format!(
                "Coverage verifying key must be {} bytes (got {})",
                VERIFYING_KEY_LEN,
                verifying_key_vec.len()
            )));
        }
        let mut verifying_key = [0u8; VERIFYING_KEY_LEN];
        verifying_key.copy_from_slice(&verifying_key_vec);

        let signature = general_purpose::STANDARD
            .decode(payload.signature_base64)
            .map_err(|err| {
                ClientError::InvalidState(format!(
                    "Failed to decode coverage snapshot signature: {}",
                    err
                ))
            })?;

        Ok(CoverageProofArtifact {
            snapshot_id: payload.snapshot_id,
            group_id: payload.group_id,
            epoch_id: payload.epoch_id,
            merkle_root,
            signature,
            verifying_key,
            signing_key_id: payload.signing_key_id,
            total_files: payload.total_files,
            generated_at: payload.coverage_generated_at,
            file_id: payload.file_id,
            file_epoch: payload.file_epoch,
            proof: payload.proof,
        })
    }

    /// Re-scan enrolled coverage roots and refresh the file index.
    pub async fn coverage_rescan(
        &self,
        filter: Option<PathBuf>,
    ) -> Result<CoverageScanSummary, ClientError> {
        self.coverage_rescan_with_progress(filter, None).await
    }

    /// Re-scan enrolled coverage roots with optional progress reporting.
    pub async fn coverage_rescan_with_progress(
        &self,
        filter: Option<PathBuf>,
        progress: Option<CoverageScanProgress>,
    ) -> Result<CoverageScanSummary, ClientError> {
        self.ensure_state_loaded().await?;

        let (_, _, root_map) = self.active_group_roots_map().await?;

        let mut summary = CoverageScanSummary::default();

        let canonical_filter = if let Some(path) = filter {
            if !path.exists() {
                summary.missing_roots.push(path);
                return Ok(summary);
            }
            Some(canonicalize_existing_path(path).await?)
        } else {
            None
        };

        let locked_roots = self.coverage_enrollment_roots_snapshot().await;
        let roots_to_scan: Vec<CoverageRoot> = root_map
            .values()
            .filter(|root| {
                canonical_filter
                    .as_ref()
                    .map_or(true, |target| &root.path == target)
            })
            .filter(|root| !locked_roots.contains(&root.root_id))
            .cloned()
            .collect();

        if roots_to_scan.is_empty() {
            return Ok(CoverageScanSummary::default());
        }

        let mut missing_roots = Vec::new();

        for root in roots_to_scan {
            let pending_entries = match self
                .build_index_entries_from_filesystem(&root, progress.as_ref())
                .await
            {
                Ok(entries) => entries,
                Err(err) => {
                    if let ClientError::FileError { context, .. } = &err {
                        if matches!(
                            context.code,
                            ErrorCode::FileNotFound | ErrorCode::FilePathInvalid
                        ) {
                            missing_roots.push(root.path.clone());
                            continue;
                        }
                    }
                    return Err(err);
                }
            };
            let stats = self
                .persist_index_entries_for_root(root.clone(), pending_entries)
                .await?;
            summary.roots_scanned += 1;
            summary.files_indexed += stats.tracked;
            summary.orphaned_files += stats.orphaned;
            summary.unmanaged_files += stats.unmanaged;
        }

        summary.missing_roots = missing_roots;

        // Check if we've reached 100% coverage and can schedule deferred epoch removal
        self.check_deferred_epoch_removal().await?;

        Ok(summary)
    }

    /// Sync local coverage state to the server by uploading the current file index.
    pub async fn coverage_sync(
        &self,
        filter: Option<PathBuf>,
    ) -> Result<CoverageSyncSummary, ClientError> {
        self.coverage_sync_with_progress(filter, None, None).await
    }

    /// Sync local coverage state to the server with optional progress reporting.
    pub async fn coverage_sync_with_progress(
        &self,
        filter: Option<PathBuf>,
        scan_progress: Option<CoverageSyncProgress>,
        upload_progress: Option<CoverageUploadProgress>,
    ) -> Result<CoverageSyncSummary, ClientError> {
        self.ensure_state_loaded().await?;
        self.ensure_coverage_log_loaded().await?;

        let _bulk_guard = self.begin_coverage_bulk_operation().await;
        let (group_id, _, root_map) = self.active_group_roots_map().await?;

        let canonical_filter = if let Some(path) = filter {
            Some(canonicalize_existing_path(path).await?)
        } else {
            None
        };

        let target_roots: Vec<CoverageRoot> = root_map
            .values()
            .filter(|root| {
                canonical_filter
                    .as_ref()
                    .map_or(true, |target| &root.path == target)
            })
            .cloned()
            .collect();

        if canonical_filter.is_some() && target_roots.is_empty() {
            return Err(ClientError::InvalidInput(
                "No enrolled coverage root matched the provided path".to_string(),
            ));
        }

        let default_epoch = {
            let state = self.state.read().await;
            state
                .migration
                .as_ref()
                .map(|m| m.to_epoch.max(1))
                .unwrap_or_else(|| state.current_epoch.max(1))
        };

        let mut entries_considered = 0usize;
        let mut skipped_entries = 0usize;
        let mut canonical_entries: HashMap<String, u64> = HashMap::new();
        let mut file_id_updates = Vec::new();

        let mut entries_by_root = Vec::with_capacity(target_roots.len());
        let mut total_entries = 0usize;
        for root in target_roots.iter() {
            let entries = self.list_file_index_entries_for_root(root.root_id).await?;
            total_entries = total_entries.saturating_add(entries.len());
            entries_by_root.push((root.clone(), entries));
        }

        if let Some(cb) = scan_progress.as_ref() {
            cb(0, total_entries);
        }

        let mut processed = 0usize;
        let progress_tick = 200usize;

        for (root, entries) in entries_by_root {
            for mut entry in entries {
                processed = processed.saturating_add(1);
                if let Some(cb) = scan_progress.as_ref() {
                    if processed % progress_tick == 0 || processed == total_entries {
                        cb(processed, total_entries);
                    }
                }

                match entry.state {
                    FileCoverageState::Unmanaged | FileCoverageState::Tombstoned => continue,
                    FileCoverageState::Orphaned => {
                        if entry.orphan_kind == Some(FileOrphanKind::Outcast) {
                            continue;
                        }
                        if entry.orphan_kind == Some(FileOrphanKind::MissingMetadata) {
                            skipped_entries = skipped_entries.saturating_add(1);
                            continue;
                        }
                    }
                    _ => {}
                }

                entries_considered = entries_considered.saturating_add(1);

                let path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };

                let mut epoch_id = entry.last_epoch;
                let mut file_id = entry.file_id.clone();

                let should_parse_header =
                    Self::path_has_encrypted_suffix(&path) && (epoch_id == 0 || file_id.is_none());
                let header = if should_parse_header {
                    Self::parse_encrypted_file_metadata(&path)
                } else {
                    None
                };

                if epoch_id == 0 {
                    if let Some(header) = header.as_ref() {
                        if header.epoch_id > 0 {
                            epoch_id = header.epoch_id;
                        }
                    }
                }
                if epoch_id == 0 {
                    epoch_id = default_epoch;
                }

                if file_id.is_none() {
                    if let Some(metadata) = self.load_metadata_for_canonical(&path).await? {
                        file_id = metadata.file_id.clone();
                    }
                }

                if file_id.is_none() {
                    if let Some(header) = header {
                        if !header.file_id.is_empty() {
                            file_id = Some(header.file_id);
                        }
                    }
                }

                if file_id.is_none() {
                    match self
                        .resolve_file_id_for_path(&path.to_string_lossy(), epoch_id)
                        .await
                    {
                        Ok(resolved) => {
                            file_id = Some(resolved);
                        }
                        Err(err) => {
                            skipped_entries = skipped_entries.saturating_add(1);
                            self.logger.log(
                                crate::logging::LogLevel::Warn,
                                &format!(
                                    "Skipping coverage sync entry {}: {}",
                                    path.display(),
                                    err
                                ),
                                Some("coverage_sync_skip"),
                            );
                            continue;
                        }
                    }
                }

                let Some(file_id) = file_id else {
                    skipped_entries = skipped_entries.saturating_add(1);
                    continue;
                };

                if entry.file_id.as_ref() != Some(&file_id) {
                    entry.file_id = Some(file_id.clone());
                    file_id_updates.push(entry);
                }

                canonical_entries
                    .entry(file_id)
                    .and_modify(|existing| {
                        if epoch_id > *existing {
                            *existing = epoch_id;
                        }
                    })
                    .or_insert(epoch_id);
            }
        }

        if !file_id_updates.is_empty() {
            self.store_file_index_entries(&file_id_updates).await?;
        }

        let allow_removals = canonical_filter.is_none();
        let mut removals = Vec::new();

        if allow_removals {
            let state = self.state.read().await;
            if let Some(ledger) = state.coverage_ledgers.get(&group_id) {
                for file_id in ledger.log.get_all_file_ids() {
                    if !canonical_entries.contains_key(&file_id) {
                        let epoch_id = ledger.log.get_entry(&file_id).unwrap_or(default_epoch);
                        removals.push((file_id, epoch_id));
                    }
                }
            }
        }

        let mut upsert_entries: Vec<(String, u64)> = Vec::new();
        {
            let state = self.state.read().await;
            let existing_log = state.coverage_ledgers.get(&group_id).map(|l| &l.log);
            for (file_id, epoch_id) in canonical_entries.iter() {
                let needs_upsert = match existing_log {
                    Some(log) => log
                        .get_entry(file_id)
                        .map_or(true, |existing| existing != *epoch_id),
                    None => true,
                };
                if needs_upsert {
                    upsert_entries.push((file_id.clone(), *epoch_id));
                }
            }
        }

        upsert_entries.sort_by(|a, b| a.0.cmp(&b.0));
        removals.sort_by(|a, b| a.0.cmp(&b.0));

        let upserts_prepared = upsert_entries.len();
        let removals_prepared = removals.len();

        let total_deltas = upserts_prepared.saturating_add(removals_prepared);

        let final_sequence = if total_deltas > 0 {
            let now = Utc::now();
            let mut deltas = Vec::with_capacity(total_deltas);

            let (snapshot_log, final_sequence) = {
                let mut state = self.state.write().await;
                let ledger = state.coverage_ledgers.entry(group_id).or_default();
                ledger.loaded = true;

                let mut sequence = ledger.sequence;

                for (file_id, epoch_id) in upsert_entries.iter() {
                    let entry = make_placeholder_file_epoch_entry(file_id.clone(), *epoch_id);
                    ledger.log.add_entry(entry);
                    sequence = sequence.saturating_add(1);
                    deltas.push(CoverageLogDeltaData {
                        sequence,
                        file_id: file_id.clone(),
                        epoch_id: *epoch_id,
                        from_epoch: None,
                        updated_at: now,
                        rewrap_timestamp: None,
                        action: crate::storage::CoverageDeltaAction::Upsert,
                    });
                }

                for (file_id, epoch_id) in removals.iter() {
                    ledger.log.remove_entry(file_id);
                    sequence = sequence.saturating_add(1);
                    deltas.push(CoverageLogDeltaData {
                        sequence,
                        file_id: file_id.clone(),
                        epoch_id: *epoch_id,
                        from_epoch: None,
                        updated_at: now,
                        rewrap_timestamp: None,
                        action: crate::storage::CoverageDeltaAction::Remove,
                    });
                }

                ledger.sequence = sequence;

                let snapshot_log = if sequence.saturating_sub(ledger.snapshot_sequence)
                    >= COVERAGE_LOG_SNAPSHOT_INTERVAL
                {
                    Some(ledger.log.clone())
                } else {
                    None
                };

                (snapshot_log, sequence)
            };

            for delta in deltas {
                self.append_coverage_log_delta(group_id, delta).await?;
            }

            if let Some(log) = snapshot_log {
                self.persist_coverage_log_snapshot(group_id, log, final_sequence)
                    .await?;
                let mut state = self.state.write().await;
                if let Some(ledger) = state.coverage_ledgers.get_mut(&group_id) {
                    ledger.snapshot_sequence = final_sequence;
                }
            }

            self.request_coverage_compaction(group_id, true).await;
            self.save_client_state().await?;

            final_sequence
        } else {
            let state = self.state.read().await;
            state
                .coverage_ledgers
                .get(&group_id)
                .map(|ledger| ledger.sequence)
                .unwrap_or(0)
        };

        let pending_total = {
            let state = self.state.read().await;
            state
                .active_group_id
                .and_then(|gid| state.coverage_ledgers.get(&gid))
                .map(|ledger| ledger.sequence.saturating_sub(ledger.ack_sequence) as usize)
                .unwrap_or(0)
        };

        let use_baseline = allow_removals
            && self.config.coverage_baseline_threshold > 0
            && pending_total >= self.config.coverage_baseline_threshold;

        if use_baseline {
            let mut baseline_entries: Vec<(String, u64)> = canonical_entries
                .iter()
                .map(|(file_id, epoch_id)| (file_id.clone(), *epoch_id))
                .collect();
            baseline_entries.sort_by(|a, b| a.0.cmp(&b.0));
            let baseline_total = baseline_entries.len();

            let _response = self
                .upload_coverage_baseline(group_id, &baseline_entries, final_sequence)
                .await?;

            self.update_coverage_ack_sequence(group_id, final_sequence)
                .await;

            if let Err(err) = self.save_client_state().await {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Failed to persist coverage baseline progress: {}", err),
                    Some("coverage_baseline_save"),
                );
            }

            if let Err(err) = self
                .compact_coverage_log_deltas(group_id, final_sequence)
                .await
            {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Failed to compact coverage log after baseline: {}", err),
                    Some("coverage_baseline_compact"),
                );
            }

            return Ok(CoverageSyncSummary {
                roots_synced: target_roots.len(),
                entries_considered,
                upserts_prepared,
                removals_prepared,
                skipped_entries,
                uploaded_deltas: 0,
                uploaded_batches: 0,
                baseline_entries: baseline_total,
            });
        }

        if pending_total == 0 {
            return Ok(CoverageSyncSummary {
                roots_synced: target_roots.len(),
                entries_considered,
                upserts_prepared,
                removals_prepared,
                skipped_entries,
                uploaded_deltas: 0,
                uploaded_batches: 0,
                baseline_entries: 0,
            });
        }

        let (uploaded_deltas, uploaded_batches) = self
            .upload_coverage_sync_deltas(pending_total, upload_progress)
            .await?;

        Ok(CoverageSyncSummary {
            roots_synced: target_roots.len(),
            entries_considered,
            upserts_prepared,
            removals_prepared,
            skipped_entries,
            uploaded_deltas,
            uploaded_batches,
            baseline_entries: 0,
        })
    }

    pub(in super::super) async fn upload_coverage_sync_deltas(
        &self,
        total_pending: usize,
        progress: Option<CoverageUploadProgress>,
    ) -> Result<(usize, usize), ClientError> {
        let http_client = reqwest::Client::new();
        let throttle = CoverageUploadThrottle::new(&self.config);
        let mut uploaded_deltas = 0usize;
        let mut uploaded_batches = 0usize;
        let mut failures = 0usize;
        let max_failures = 5usize;
        let mut last_reported = 0usize;

        if let Some(cb) = progress.as_ref() {
            cb(0, total_pending);
        }

        loop {
            let (needs_work, group_id, ack_sequence) = {
                let state = self.state.read().await;
                let gid = state.active_group_id;
                let (needs, ack_seq) = gid
                    .and_then(|g| state.coverage_ledgers.get(&g))
                    .map(|ledger| {
                        (
                            ledger.loaded
                                && !ledger.permanently_disabled
                                && ledger.sequence > ledger.ack_sequence,
                            ledger.ack_sequence,
                        )
                    })
                    .unwrap_or((false, 0));
                (needs, gid, ack_seq)
            };

            if !needs_work {
                break;
            }

            if failures >= max_failures {
                return Err(ClientError::InvalidState(
                    "Coverage sync aborted after repeated upload failures".to_string(),
                ));
            }

            let Some(group_id) = group_id else {
                break;
            };

            let session = self.get_session_info().await.map_err(|err| {
                ClientError::network_error(
                    ErrorCode::NetworkAuthentication,
                    format!("Coverage sync failed to load session info: {}", err),
                    "coverage_sync_session".to_string(),
                    failures as u32,
                    "missing_session".to_string(),
                )
            })?;

            let Some(device_id) = session.device_id.clone() else {
                return Err(ClientError::network_error(
                    ErrorCode::NetworkAuthentication,
                    "Coverage sync aborted: session missing device identifier".to_string(),
                    "coverage_sync_session".to_string(),
                    failures as u32,
                    "missing_device".to_string(),
                ));
            };

            let token = session.token.clone();
            let server_base = Self::resolve_server_base_url(session.server_url.clone());
            let url = format!("{}/api/v1/groups/{}/coverage/log", server_base, group_id);

            let batch_size = self.config.coverage_batch_size;
            let deltas = self
                .coverage_replication_batch(ack_sequence, batch_size)
                .await?;

            if deltas.is_empty() {
                break;
            }

            let payload = CoverageDeltaUploadRequest {
                device_id: device_id.clone(),
                deltas: deltas
                    .iter()
                    .map(|delta| CoverageDeltaUploadEntry {
                        sequence: delta.sequence,
                        file_id: delta.file_id.clone(),
                        epoch_id: delta.epoch_id,
                        updated_at: delta.updated_at,
                        action: delta.action.clone(),
                    })
                    .collect(),
            };

            throttle.wait_for_slot().await;

            let response = match http_client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(err) => {
                    failures = failures.saturating_add(1);
                    throttle.register_failure(None).await;
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Coverage sync upload failed: {}", err),
                        Some("coverage_sync_upload"),
                    );
                    continue;
                }
            };

            let status = response.status();
            let retry_after = if should_backoff(status) {
                retry_after_delay(response.headers())
            } else {
                None
            };

            if let Some(retention_err) = self
                .handle_retention_status(status, response.headers(), "coverage_sync_upload")
                .await
            {
                return Err(retention_err);
            }

            if status == StatusCode::UNAUTHORIZED {
                if let Err(err) = self.cleanup_conflicting_auth_state().await {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Failed to clean up auth state after 401: {}", err),
                        Some("coverage_sync_auth"),
                    );
                }
                return Err(ClientError::network_error(
                    ErrorCode::NetworkAuthentication,
                    "Coverage sync rejected with 401 Unauthorized".to_string(),
                    "coverage_sync_upload".to_string(),
                    failures as u32,
                    "unauthorized".to_string(),
                ));
            }

            if !status.is_success() {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                failures = failures.saturating_add(1);
                throttle.register_failure(retry_after).await;
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Coverage sync upload received {} from server: {}",
                        status, body
                    ),
                    Some("coverage_sync_response"),
                );
                continue;
            }

            let ack: CoverageDeltaUploadResponse = match response.json().await {
                Ok(value) => value,
                Err(err) => {
                    failures = failures.saturating_add(1);
                    throttle.register_failure(None).await;
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Coverage sync failed to decode response: {}", err),
                        Some("coverage_sync_decode"),
                    );
                    continue;
                }
            };

            self.update_coverage_ack_sequence(group_id, ack.acknowledged_sequence)
                .await;

            if let Err(err) = self.save_client_state().await {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Failed to persist coverage sync progress: {}", err),
                    Some("coverage_sync_save"),
                );
            }

            uploaded_deltas = uploaded_deltas.saturating_add(deltas.len());
            uploaded_batches = uploaded_batches.saturating_add(1);
            failures = 0;
            throttle.register_success().await;

            if let Some(cb) = progress.as_ref() {
                if uploaded_deltas != last_reported {
                    last_reported = uploaded_deltas;
                    cb(uploaded_deltas, total_pending);
                }
            }
        }

        Ok((uploaded_deltas, uploaded_batches))
    }

    pub(in super::super) async fn upload_coverage_baseline(
        &self,
        group_id: Uuid,
        entries: &[(String, u64)],
        last_sequence: u64,
    ) -> Result<CoverageBaselineResponse, ClientError> {
        let http_client = reqwest::Client::new();
        let throttle = CoverageUploadThrottle::new(&self.config);
        let mut failures = 0usize;
        let max_failures = 3usize;

        loop {
            if failures >= max_failures {
                return Err(ClientError::InvalidState(
                    "Coverage baseline aborted after repeated upload failures".to_string(),
                ));
            }

            let session = self.get_session_info().await.map_err(|err| {
                ClientError::network_error(
                    ErrorCode::NetworkAuthentication,
                    format!("Coverage baseline failed to load session info: {}", err),
                    "coverage_baseline_session".to_string(),
                    failures as u32,
                    "missing_session".to_string(),
                )
            })?;

            let Some(device_id) = session.device_id.clone() else {
                return Err(ClientError::network_error(
                    ErrorCode::NetworkAuthentication,
                    "Coverage baseline aborted: session missing device identifier".to_string(),
                    "coverage_baseline_session".to_string(),
                    failures as u32,
                    "missing_device".to_string(),
                ));
            };

            let token = session.token.clone();
            let server_base = Self::resolve_server_base_url(session.server_url.clone());
            let url = format!(
                "{}/api/v1/groups/{}/coverage/baseline",
                server_base, group_id
            );

            let payload = CoverageBaselineRequest {
                device_id: device_id.clone(),
                last_sequence,
                entries: entries
                    .iter()
                    .map(|(file_id, epoch_id)| CoverageBaselineEntry {
                        file_id: file_id.clone(),
                        epoch_id: *epoch_id,
                    })
                    .collect(),
            };

            throttle.wait_for_slot().await;

            let response = match http_client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(err) => {
                    failures = failures.saturating_add(1);
                    throttle.register_failure(None).await;
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Coverage baseline upload failed: {}", err),
                        Some("coverage_baseline_upload"),
                    );
                    continue;
                }
            };

            let status = response.status();
            let retry_after = if should_backoff(status) {
                retry_after_delay(response.headers())
            } else {
                None
            };

            if let Some(retention_err) = self
                .handle_retention_status(status, response.headers(), "coverage_baseline_upload")
                .await
            {
                return Err(retention_err);
            }

            if status == StatusCode::UNAUTHORIZED {
                if let Err(err) = self.cleanup_conflicting_auth_state().await {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Failed to clean up auth state after 401: {}", err),
                        Some("coverage_baseline_auth"),
                    );
                }
                return Err(ClientError::network_error(
                    ErrorCode::NetworkAuthentication,
                    "Coverage baseline rejected with 401 Unauthorized".to_string(),
                    "coverage_baseline_upload".to_string(),
                    failures as u32,
                    "unauthorized".to_string(),
                ));
            }

            if !status.is_success() {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                failures = failures.saturating_add(1);
                throttle.register_failure(retry_after).await;
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Coverage baseline received {} from server: {}",
                        status, body
                    ),
                    Some("coverage_baseline_response"),
                );
                continue;
            }

            let ack: CoverageBaselineResponse = match response.json().await {
                Ok(value) => value,
                Err(err) => {
                    failures = failures.saturating_add(1);
                    throttle.register_failure(None).await;
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Coverage baseline failed to decode response: {}", err),
                        Some("coverage_baseline_decode"),
                    );
                    continue;
                }
            };

            throttle.register_success().await;
            return Ok(ack);
        }
    }

    /// Return the current file index entries for the specified root (or all roots if None).
    pub async fn coverage_file_records(
        &self,
        filter: Option<PathBuf>,
    ) -> Result<Vec<CoverageFileRecord>, ClientError> {
        self.ensure_state_loaded().await?;

        let (_, _, root_map) = self.active_group_roots_map().await?;

        let canonical_filter = if let Some(path) = filter {
            if !path.exists() {
                return Ok(vec![]);
            }
            Some(canonicalize_existing_path(path).await?)
        } else {
            None
        };

        let target_roots: HashMap<Uuid, CoverageRoot> = root_map
            .iter()
            .filter_map(|(id, root)| {
                if canonical_filter
                    .as_ref()
                    .map_or(true, |target| root.path == *target)
                {
                    Some((*id, root.clone()))
                } else {
                    None
                }
            })
            .collect();

        if target_roots.is_empty() {
            return Ok(vec![]);
        }

        let mut records = Vec::new();
        for (root_id, root) in target_roots.iter() {
            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                records.push(CoverageFileRecord {
                    root: root.clone(),
                    entry,
                });
            }
        }

        records.sort_by(|a, b| {
            a.root
                .path
                .cmp(&b.root.path)
                .then_with(|| a.entry.relative_path.cmp(&b.entry.relative_path))
        });

        Ok(records)
    }
}
