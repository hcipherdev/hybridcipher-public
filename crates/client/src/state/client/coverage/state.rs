use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    pub(in super::super) async fn ensure_coverage_log_loaded(&self) -> Result<(), ClientError> {
        let group_id = self.require_active_group("loading coverage log").await?;
        {
            let state = self.state.read().await;
            if state
                .coverage_ledgers
                .get(&group_id)
                .map(|l| l.loaded)
                .unwrap_or(false)
            {
                return Ok(());
            }
        }

        let data = self
            .storage
            .load_coverage_log(group_id)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageRead,
                    format!("Failed to load coverage log: {}", e),
                    "coverage_log_load".to_string(),
                    None,
                    true,
                )
            })?;

        let mut log = coverage_log_from_data(&data)?;
        let mut sequence = data.sequence;

        let deltas = self
            .storage
            .load_coverage_log_deltas(group_id, sequence)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageRead,
                    format!("Failed to load coverage log deltas: {}", e),
                    "coverage_log_load_deltas".to_string(),
                    None,
                    true,
                )
            })?;

        for delta in deltas {
            match delta.action {
                crate::storage::CoverageDeltaAction::Remove => {
                    log.remove_entry(&delta.file_id);
                }
                crate::storage::CoverageDeltaAction::Upsert => {
                    log.add_entry(make_placeholder_file_epoch_entry(
                        delta.file_id.clone(),
                        delta.epoch_id,
                    ));
                }
            }
            sequence = sequence.max(delta.sequence);
        }

        let mut state = self.state.write().await;
        let cached_meta = state.coverage_ledgers_meta.get(&group_id).cloned();
        let needs_replication;
        let meta_snapshot;
        {
            let ledger = state.coverage_ledgers.entry(group_id).or_default();
            let preserve_skip = ledger.skip_seed_once;
            ledger.log = log;
            ledger.loaded = true;
            ledger.snapshot_sequence = data.sequence;
            ledger.sequence = sequence;
            ledger.skip_seed_once = preserve_skip;
            if let Some(meta) = cached_meta.as_ref() {
                ledger.apply_meta(meta);
            }
            needs_replication =
                ledger.sequence > ledger.ack_sequence && !ledger.permanently_disabled;
            meta_snapshot = ledger.to_meta();
        }
        state.coverage_ledgers_meta.insert(group_id, meta_snapshot);
        drop(state);

        // Seed ledger from file index if this group's log is empty.
        self.seed_coverage_log_from_index(group_id).await?;

        if needs_replication {
            self.ensure_coverage_replication_worker();
        }
        Ok(())
    }

    pub(in super::super) async fn seed_coverage_log_from_index(
        &self,
        group_id: Uuid,
    ) -> Result<(), ClientError> {
        let roots = {
            let state = self.state.read().await;
            let ledger = state.coverage_ledgers.get(&group_id);
            if let Some(ledger) = ledger {
                if ledger.sequence > 0 || ledger.log.latest_snapshot().is_some() {
                    return Ok(());
                }
            }

            state
                .coverage_roots
                .values()
                .filter(|root| {
                    root.state == CoverageRootState::Active && root.group_id == Some(group_id)
                })
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut candidates = Vec::new();
        for root in roots {
            let entries = self.list_file_index_entries_for_root(root.root_id).await?;
            for entry in entries {
                let path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };
                candidates.push((path.to_string_lossy().to_string(), entry.last_epoch.max(1)));
            }
        }

        if candidates.is_empty() {
            return Ok(());
        }

        let mut resolved_entries = Vec::with_capacity(candidates.len());
        for (path, epoch_id) in candidates {
            let file_id = self.resolve_file_id_for_path(&path, epoch_id).await?;
            resolved_entries.push((file_id, epoch_id));
        }

        let (log_to_persist, sequence) = {
            let mut state = self.state.write().await;
            let ledger = state.coverage_ledgers.entry(group_id).or_default();
            if ledger.skip_seed_once {
                ledger.skip_seed_once = false;
                // Preserve empty ledger; do not seed.
                return Ok(());
            }
            for (file_id, epoch_id) in resolved_entries.iter() {
                ledger.log.add_entry(make_placeholder_file_epoch_entry(
                    file_id.clone(),
                    *epoch_id,
                ));
            }
            ledger.loaded = true;
            ledger.sequence = ledger
                .sequence
                .saturating_add(resolved_entries.len() as u64);
            ledger.snapshot_sequence = ledger.sequence;
            (ledger.log.clone(), ledger.sequence)
        };

        self.persist_coverage_log_snapshot(group_id, log_to_persist, sequence)
            .await
    }

    /// Backfill missing coverage log entries from the file index so heartbeats
    /// report accurate totals even when the ledger was seeded partially.
    pub(in super::super) async fn reconcile_coverage_log_from_index(
        &self,
    ) -> Result<usize, ClientError> {
        self.ensure_state_loaded().await?;
        let (group_id, _, roots) = self.active_group_roots_map().await?;
        self.ensure_coverage_log_loaded().await?;

        let default_epoch = {
            let state = self.state.read().await;
            state
                .migration
                .as_ref()
                .map(|m| m.to_epoch.max(1))
                .unwrap_or_else(|| state.current_epoch.max(1))
        };

        // Build list of (path, current_epoch_in_index) for all tracked files
        let migrated = {
            let state = self.state.read().await;
            state.migration.clone()
        };

        let mut candidates = Vec::new();
        for (root_id, root) in roots.iter() {
            if root.state != CoverageRootState::Active {
                continue;
            }
            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                let path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };

                let mut epoch_id = entry.last_epoch;
                if epoch_id == 0 {
                    if let Some(header) = Self::parse_encrypted_file_metadata(&path) {
                        if header.epoch_id > 0 {
                            epoch_id = header.epoch_id;
                        }
                    }
                }
                if epoch_id == 0 {
                    epoch_id = default_epoch;
                }

                candidates.push((path.to_string_lossy().to_string(), epoch_id));
            }
        }

        if let Some(migration) = migrated {
            for path in migration.migrated_files.iter() {
                candidates.push((path.clone(), migration.to_epoch));
            }
        }

        if candidates.is_empty() {
            return Ok(0);
        }

        let mut added = 0usize;
        let mut replaced = 0usize;

        for (path, current_epoch) in candidates {
            let current_file_id = self.resolve_file_id_for_path(&path, current_epoch).await?;

            let existing_epoch = {
                let state = self.state.read().await;
                state
                    .coverage_ledgers
                    .get(&group_id)
                    .and_then(|l| l.log.get_entry(&current_file_id))
            };

            if let Some(existing_epoch) = existing_epoch {
                if existing_epoch != current_epoch {
                    match self
                        .replace_coverage_for_file(
                            &current_file_id,
                            &current_file_id,
                            current_epoch,
                            Some(existing_epoch),
                            None,
                        )
                        .await
                    {
                        Ok(_) => {
                            replaced = replaced.saturating_add(1);
                        }
                        Err(err) => {
                            self.logger.log(
                                crate::logging::LogLevel::Warn,
                                &format!(
                                    "Failed to update coverage entry for {} (existing epoch {}, new epoch {}): {}",
                                    current_file_id, existing_epoch, current_epoch, err
                                ),
                                Some("coverage_reconcile"),
                            );
                        }
                    }
                }
                continue;
            }

            match self
                .update_coverage_for_file(&current_file_id, current_epoch)
                .await
            {
                Ok(_) => {
                    added = added.saturating_add(1);
                }
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Failed to backfill coverage entry for {} (epoch {}): {}",
                            current_file_id, current_epoch, err
                        ),
                        Some("coverage_reconcile"),
                    );
                }
            }
        }

        if added > 0 || replaced > 0 {
            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!(
                    "Reconciled coverage log with file index; added {} new entries, replaced {} stale entries",
                    added, replaced
                ),
                Some("coverage_reconcile"),
            );
        }

        Ok(added.saturating_add(replaced))
    }

    /// Rebuild the coverage log from file_index, discarding all stale entries.
    /// This is the same logic that runs on remount to clean up bloated ledgers.
    #[allow(dead_code)]
    pub(in super::super) async fn rebuild_coverage_log_from_index(
        &self,
    ) -> Result<usize, ClientError> {
        self.ensure_state_loaded().await?;
        let (group_id, _, roots) = self.active_group_roots_map().await?;

        let default_epoch = {
            let state = self.state.read().await;
            state
                .migration
                .as_ref()
                .map(|m| m.to_epoch.max(1))
                .unwrap_or_else(|| state.current_epoch.max(1))
        };

        // Build the canonical set of file_ids from file_index
        let mut candidate_paths = Vec::new();
        for (root_id, root) in roots.iter() {
            if root.state != CoverageRootState::Active {
                continue;
            }
            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                let path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };

                let mut epoch_id = entry.last_epoch;
                if epoch_id == 0 {
                    epoch_id = default_epoch;
                }

                candidate_paths.push((path.to_string_lossy().to_string(), epoch_id));
            }
        }

        let mut canonical_entries = Vec::with_capacity(candidate_paths.len());
        for (path, epoch_id) in candidate_paths {
            let file_id = self.resolve_file_id_for_path(&path, epoch_id).await?;
            canonical_entries.push((file_id, epoch_id));
        }

        // Count entries before rebuild
        let entries_before = {
            let state = self.state.read().await;
            state
                .coverage_ledgers
                .get(&group_id)
                .map(|l| l.log.get_all_file_ids().len())
                .unwrap_or(0)
        };

        // Rebuild the coverage log with only canonical entries
        {
            let mut state = self.state.write().await;
            let Some(ledger) = state.coverage_ledgers.get_mut(&group_id) else {
                return Ok(0);
            };

            // Clear the existing log
            ledger.log = CoverageLog::new();

            // Re-add only the canonical entries
            for (file_id, epoch_id) in canonical_entries {
                let entry = make_placeholder_file_epoch_entry(file_id, epoch_id);
                ledger.log.add_entry(entry);
            }

            ledger.sequence = ledger.sequence.saturating_add(1);
        }

        let entries_after = {
            let state = self.state.read().await;
            state
                .coverage_ledgers
                .get(&group_id)
                .map(|l| l.log.get_all_file_ids().len())
                .unwrap_or(0)
        };

        let removed = entries_before.saturating_sub(entries_after);

        if removed > 0 {
            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!(
                    "Rebuilt coverage log from file_index; removed {} stale entries ({} -> {})",
                    removed, entries_before, entries_after
                ),
                Some("coverage_rebuild"),
            );
        }

        // Persist the rebuilt log
        let (log_to_persist, sequence) = {
            let state = self.state.read().await;
            let ledger = state.coverage_ledgers.get(&group_id).unwrap();
            (ledger.log.clone(), ledger.sequence)
        };

        self.persist_coverage_log_snapshot(group_id, log_to_persist, sequence)
            .await?;

        // Clear the journal since we just wrote a full snapshot
        self.compact_coverage_log_deltas(group_id, sequence).await?;

        Ok(removed)
    }

    /// Remove duplicate coverage log entries, keeping only the highest epoch for each file path.
    /// This cleans up duplicates that may have accumulated from previous bugs.
    pub(in super::super) async fn deduplicate_coverage_log(&self) -> Result<usize, ClientError> {
        self.ensure_state_loaded().await?;
        let group_id = self.require_active_group("deduplicating coverage").await?;
        let (_, _, roots) = self.active_group_roots_map().await?;

        // Build a set of canonical file_ids (one per path, at the current epoch from file_index)
        let mut candidate_paths = Vec::new();
        for (root_id, root) in roots.iter() {
            if root.state != CoverageRootState::Active {
                continue;
            }
            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                let path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };
                let path_str = path.to_string_lossy().to_string();

                let epoch = entry.last_epoch.max(1);
                candidate_paths.push((path_str, epoch));
            }
        }

        let mut canonical_file_ids: HashSet<String> = HashSet::with_capacity(candidate_paths.len());
        for (path, epoch) in candidate_paths {
            let file_id = self.resolve_file_id_for_path(&path, epoch).await?;
            canonical_file_ids.insert(file_id);
        }

        // Find all file_ids in the coverage log that aren't in the canonical set
        let entries_to_remove: Vec<String> = {
            let state = self.state.read().await;
            let Some(ledger) = state.coverage_ledgers.get(&group_id) else {
                return Ok(0);
            };

            let all_file_ids = ledger.log.get_all_file_ids();

            // Keep only file_ids that are NOT in the canonical set
            // (These are stale entries from old epochs or other anomalies)
            all_file_ids
                .into_iter()
                .filter(|file_id| !canonical_file_ids.contains(file_id))
                .collect()
        };

        if entries_to_remove.is_empty() {
            return Ok(0);
        }

        let removed_count = entries_to_remove.len();

        // Remove the stale entries
        {
            let mut state = self.state.write().await;
            let Some(ledger) = state.coverage_ledgers.get_mut(&group_id) else {
                return Ok(0);
            };

            for file_id in &entries_to_remove {
                ledger.log.remove_entry(file_id);
            }

            ledger.sequence = ledger.sequence.saturating_add(1);
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Removed {} stale duplicate entries from coverage log",
                removed_count
            ),
            Some("coverage_dedup"),
        );

        // Persist the cleaned log
        let (log_to_persist, sequence) = {
            let state = self.state.read().await;
            let ledger = state.coverage_ledgers.get(&group_id).unwrap();
            (ledger.log.clone(), ledger.sequence)
        };

        self.persist_coverage_log_snapshot(group_id, log_to_persist, sequence)
            .await?;

        // Clear the journal since we just wrote a full snapshot
        self.compact_coverage_log_deltas(group_id, sequence).await?;

        Ok(removed_count)
    }

    pub(in super::super) async fn persist_coverage_log_snapshot(
        &self,
        group_id: Uuid,
        log: CoverageLog,
        sequence: u64,
    ) -> Result<(), ClientError> {
        let data = coverage_log_to_data(&log, sequence)?;
        self.storage
            .store_coverage_log(group_id, &data)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageWrite,
                    format!("Failed to store coverage log: {}", e),
                    "coverage_log_store".to_string(),
                    None,
                    false,
                )
            })
    }

    pub(in super::super) async fn append_coverage_log_delta(
        &self,
        group_id: Uuid,
        delta: CoverageLogDeltaData,
    ) -> Result<(), ClientError> {
        self.storage
            .append_coverage_log_delta(group_id, &delta)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageWrite,
                    format!("Failed to append coverage delta: {}", e),
                    "coverage_log_delta_append".to_string(),
                    None,
                    false,
                )
            })
    }

    pub(in super::super) async fn compact_coverage_log_deltas(
        &self,
        group_id: Uuid,
        up_to_sequence: u64,
    ) -> Result<(), ClientError> {
        self.storage
            .compact_coverage_log_deltas(group_id, up_to_sequence)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageWrite,
                    format!("Failed to compact coverage journal: {}", e),
                    "coverage_log_delta_compact".to_string(),
                    None,
                    false,
                )
            })
    }

    pub(in super::super) async fn load_root_registry(
        &self,
    ) -> Result<CoverageRootRegistry, ClientError> {
        match self.storage.load_config(COVERAGE_ROOT_REGISTRY_KEY).await {
            Ok(Some(json)) => match serde_json::from_str(&json) {
                Ok(registry) => Ok(registry),
                Err(err) => {
                    log::warn!(
                        "Failed to parse coverage root registry ({}); using empty registry",
                        err
                    );
                    Ok(CoverageRootRegistry::default())
                }
            },
            Ok(None) => Ok(CoverageRootRegistry::default()),
            Err(e) => Err(ClientError::storage_error(
                ErrorCode::StorageRead,
                format!("Failed to load coverage root registry: {}", e),
                "coverage_root_registry_load".to_string(),
                None,
                true,
            )),
        }
    }

    pub(in super::super) async fn save_root_registry(
        &self,
        registry: &CoverageRootRegistry,
    ) -> Result<(), ClientError> {
        let payload = serde_json::to_string(registry).map_err(|err| {
            ClientError::SerializationError(format!(
                "Failed to serialize coverage root registry: {}",
                err
            ))
        })?;

        self.storage
            .store_config(COVERAGE_ROOT_REGISTRY_KEY, &payload)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageWrite,
                    format!("Failed to store coverage root registry: {}", e),
                    "coverage_root_registry_store".to_string(),
                    None,
                    false,
                )
            })
    }

    pub(in super::super) async fn assert_no_cross_group_conflict(
        &self,
        canonical: &Path,
        group_id: Uuid,
    ) -> Result<(), ClientError> {
        let registry = self.load_root_registry().await?;
        for (registered_path, entry) in registry.entries.iter() {
            if entry.group_id == group_id {
                continue;
            }

            let registered_path = Path::new(registered_path);
            if paths_overlap(registered_path, canonical) {
                return Err(ClientError::InvalidInput(format!(
                    "Cannot enroll '{}': overlaps with coverage root '{}' owned by group {}. Choose a different folder to avoid disrupting another group's coverage.",
                    canonical.display(),
                    registered_path.display(),
                    entry.group_id
                )));
            }
        }

        Ok(())
    }

    pub(in super::super) async fn upsert_root_registry_entry(
        &self,
        canonical: &Path,
        group_id: Uuid,
        root_id: Uuid,
    ) -> Result<(), ClientError> {
        let mut registry = self.load_root_registry().await?;
        registry.entries.insert(
            canonical.to_string_lossy().to_string(),
            CoverageRootRegistryEntry {
                group_id,
                root_id: Some(root_id),
            },
        );
        self.save_root_registry(&registry).await
    }

    pub(in super::super) async fn remove_root_registry_entry(
        &self,
        canonical: &Path,
    ) -> Result<(), ClientError> {
        let mut registry = self.load_root_registry().await?;
        let key = canonical.to_string_lossy().to_string();
        if registry.entries.remove(&key).is_some() {
            self.save_root_registry(&registry).await?;
        }
        Ok(())
    }

    pub(in super::super) fn registry_entry_for_path<'a>(
        registry: &'a CoverageRootRegistry,
        path: &Path,
    ) -> Option<&'a CoverageRootRegistryEntry> {
        registry.entries.get(&path.to_string_lossy().to_string())
    }

    pub(in super::super) fn root_for_group(
        root: &CoverageRoot,
        active_group: Uuid,
        registry: &CoverageRootRegistry,
    ) -> Option<CoverageRoot> {
        if let Some(root_group) = root.group_id {
            if root_group == active_group && root.state == CoverageRootState::Active {
                return Some(root.clone());
            }
            return None;
        }

        if let Some(entry) = Self::registry_entry_for_path(registry, &root.path) {
            if entry.group_id == active_group && root.state == CoverageRootState::Active {
                let mut cloned = root.clone();
                cloned.group_id = Some(entry.group_id);
                return Some(cloned);
            }
        }

        None
    }
}
