use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    pub(in super::super) async fn active_group_required(&self) -> Result<Uuid, ClientError> {
        let state = self.state.read().await;
        state.active_group_id.ok_or_else(|| {
            ClientError::InvalidState(
                "No active group selected. Run 'hybridcipher switch-group <group-id>' and retry."
                    .to_string(),
            )
        })
    }

    pub(in super::super) async fn active_group_roots_map(
        &self,
    ) -> Result<(Uuid, CoverageRootRegistry, HashMap<Uuid, CoverageRoot>), ClientError> {
        let active_group = self.active_group_required().await?;
        let registry = self.load_root_registry().await?;
        let state = self.state.read().await;
        let roots: HashMap<Uuid, CoverageRoot> = state
            .coverage_roots
            .values()
            .filter_map(|root| Self::root_for_group(root, active_group, &registry))
            .map(|root| (root.root_id, root))
            .collect();

        Ok((active_group, registry, roots))
    }

    /// Update coverage log for file encryption
    pub(in super::super) async fn update_coverage_for_file(
        &self,
        file_id: &str,
        epoch_id: u64,
    ) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;
        let group_id = self.require_active_group("updating coverage").await?;

        let entry = make_placeholder_file_epoch_entry(file_id.to_string(), epoch_id);

        {
            let state = self.state.read().await;
            if !state.epochs.contains_key(&epoch_id) {
                return Err(ClientError::InvalidState(format!(
                    "Cannot update coverage for invalid epoch {}",
                    epoch_id
                )));
            }
        }

        let (sequence, snapshot_due, snapshot_log) = {
            let mut state = self.state.write().await;
            let ledger = state.coverage_ledgers.entry(group_id).or_default();

            ledger.log.add_entry(entry);
            ledger.loaded = true;
            ledger.sequence = ledger.sequence.saturating_add(1);
            let sequence = ledger.sequence;
            let snapshot_due =
                sequence.saturating_sub(ledger.snapshot_sequence) >= COVERAGE_LOG_SNAPSHOT_INTERVAL;
            let snapshot_log = if snapshot_due {
                Some(ledger.log.clone())
            } else {
                None
            };
            (sequence, snapshot_due, snapshot_log)
        };

        let delta = CoverageLogDeltaData {
            sequence,
            file_id: file_id.to_string(),
            epoch_id,
            from_epoch: None,
            updated_at: Utc::now(),
            rewrap_timestamp: None,
            action: crate::storage::CoverageDeltaAction::Upsert,
        };

        self.append_coverage_log_delta(group_id, delta).await?;

        if snapshot_due {
            if let Some(log) = snapshot_log {
                self.persist_coverage_log_snapshot(group_id, log, sequence)
                    .await?;
            }
            let mut state = self.state.write().await;
            if let Some(ledger) = state.coverage_ledgers.get_mut(&group_id) {
                ledger.snapshot_sequence = sequence;
            }
        }

        self.request_coverage_compaction(group_id, true).await;
        // Don't start replication worker here - it will be started explicitly after scan completes
        // This prevents blocking during coverage updates

        Ok(())
    }

    /// Replace a coverage entry when a file is rewrapped to a new epoch.
    pub(in super::super) async fn replace_coverage_for_file(
        &self,
        old_file_id: &str,
        new_file_id: &str,
        epoch_id: u64,
        from_epoch: Option<u64>,
        rewrap_timestamp: Option<DateTime<Utc>>,
    ) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;
        let group_id = self.require_active_group("updating coverage").await?;

        let entry = make_placeholder_file_epoch_entry(new_file_id.to_string(), epoch_id);

        {
            let state = self.state.read().await;
            if !state.epochs.contains_key(&epoch_id) {
                return Err(ClientError::InvalidState(format!(
                    "Cannot update coverage for invalid epoch {}",
                    epoch_id
                )));
            }
        }

        let (sequence, snapshot_due, snapshot_log) = {
            let mut state = self.state.write().await;
            let ledger = state.coverage_ledgers.entry(group_id).or_default();

            ledger.log.replace_entry(old_file_id, entry);
            ledger.loaded = true;

            ledger.sequence = ledger.sequence.saturating_add(1);
            let sequence = ledger.sequence;
            let snapshot_due =
                sequence.saturating_sub(ledger.snapshot_sequence) >= COVERAGE_LOG_SNAPSHOT_INTERVAL;
            let snapshot_log = if snapshot_due {
                Some(ledger.log.clone())
            } else {
                None
            };
            (sequence, snapshot_due, snapshot_log)
        };

        let delta = CoverageLogDeltaData {
            sequence,
            file_id: new_file_id.to_string(),
            epoch_id,
            from_epoch,
            updated_at: Utc::now(),
            rewrap_timestamp,
            action: crate::storage::CoverageDeltaAction::Upsert,
        };

        self.append_coverage_log_delta(group_id, delta).await?;

        if snapshot_due {
            if let Some(log) = snapshot_log {
                self.persist_coverage_log_snapshot(group_id, log, sequence)
                    .await?;
            }
            let mut state = self.state.write().await;
            if let Some(ledger) = state.coverage_ledgers.get_mut(&group_id) {
                ledger.snapshot_sequence = sequence;
            }
        }

        self.request_coverage_compaction(group_id, true).await;
        // Don't start replication worker here - it will be started explicitly after scan completes
        // This prevents blocking during coverage updates

        Ok(())
    }

    pub async fn pending_coverage_files(&self) -> Result<Vec<CoveragePendingFile>, ClientError> {
        self.ensure_state_loaded().await?;

        let (migration, pending_map) = {
            let state = self.state.read().await;
            let migration = state.migration.clone();
            let pending = state
                .pending_rewraps
                .iter()
                .cloned()
                .map(|entry| (entry.path.clone(), entry))
                .collect::<HashMap<_, _>>();
            (migration, pending)
        };

        let Some(migration) = migration else {
            return Ok(Vec::new());
        };

        let target_epoch = migration.to_epoch;

        let file_paths = self
            .storage
            .list_files(None)
            .await
            .map_err(ClientError::from)?;

        let mut pending_files = Vec::new();

        for path in file_paths {
            let normalized = Self::normalize_storage_path(&path);
            let candidates = if normalized == path {
                vec![normalized.clone()]
            } else {
                vec![path.clone(), normalized.clone()]
            };

            let mut metadata: Option<crate::storage::FileMetadataData> = None;
            for candidate in candidates {
                metadata = self
                    .storage
                    .load_file_metadata(&candidate)
                    .await
                    .map_err(ClientError::from)?;
                if metadata.is_some() {
                    break;
                }
            }

            let metadata = match metadata {
                Some(meta) => meta,
                None => continue,
            };

            let current_epoch = metadata.epoch_id;
            if current_epoch >= target_epoch {
                continue;
            }

            let canonical_path = Self::normalize_storage_path(&metadata.file_path);
            let pending_entry = pending_map.get(&canonical_path);

            pending_files.push(CoveragePendingFile {
                path: canonical_path,
                current_epoch,
                target_epoch,
                file_size: metadata.file_size,
                last_modified: metadata.modified_at,
                attempts: pending_entry.map(|entry| entry.attempts).unwrap_or(0),
                last_attempt: pending_entry.and_then(|entry| entry.last_attempt),
            });
        }

        pending_files.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(pending_files)
    }

    /// Determine whether the local coverage log already contains entries.
    pub async fn has_coverage_entries(&self) -> Result<bool, ClientError> {
        self.ensure_state_loaded().await?;
        let group_id = self
            .require_active_group("checking coverage entries")
            .await?;
        let state = self.state.read().await;
        let counts = state
            .coverage_ledgers
            .get(&group_id)
            .map(|l| l.log.counts_for_epoch(state.current_epoch))
            .unwrap_or_default();
        Ok(counts.total_items > 0)
    }

    /// Return all enrolled coverage roots, sorted by absolute path.
    pub async fn coverage_roots(&self) -> Result<Vec<CoverageRoot>, ClientError> {
        self.ensure_state_loaded().await?;
        self.ensure_coverage_watcher().await;

        let mut roots = {
            let state = self.state.read().await;
            state.coverage_roots.values().cloned().collect::<Vec<_>>()
        };

        roots.sort_by(|a, b| a.path.to_string_lossy().cmp(&b.path.to_string_lossy()));

        Ok(roots)
    }

    /// Return the raw registry entries for all enrolled roots (across groups).
    pub async fn coverage_root_registry_entries(
        &self,
    ) -> Result<Vec<CoverageRegistryEntry>, ClientError> {
        self.ensure_state_loaded().await?;
        let registry = self.load_root_registry().await?;
        Ok(registry
            .entries
            .iter()
            .map(|(path, entry)| CoverageRegistryEntry {
                path: path.clone(),
                group_id: entry.group_id,
                root_id: entry.root_id,
            })
            .collect())
    }

    /// Import and persist a registry snapshot (overwrites existing entries).
    pub async fn coverage_import_registry_entries(
        &self,
        entries: Vec<CoverageRegistryEntry>,
    ) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;
        let mut registry = CoverageRootRegistry::default();
        for entry in entries {
            registry.entries.insert(
                entry.path.clone(),
                CoverageRootRegistryEntry {
                    group_id: entry.group_id,
                    root_id: entry.root_id,
                },
            );
        }
        self.save_root_registry(&registry).await
    }

    /// Discover marker files and auto-enroll matching roots for the active group.
    pub async fn coverage_recover_from_markers(
        &self,
        search_roots: Vec<PathBuf>,
        max_depth: usize,
        show_progress: bool,
    ) -> Result<CoverageMarkerRecoveryResult, ClientError> {
        self.ensure_state_loaded().await?;
        if max_depth == 0 {
            return Err(ClientError::InvalidInput(
                "max_depth must be greater than zero".to_string(),
            ));
        }

        let active_group = self
            .require_active_group("recovering coverage markers")
            .await?;
        let mut result = CoverageMarkerRecoveryResult::default();
        let mut seen_root_ids: HashSet<Uuid> = HashSet::new();

        let mut existing_ids: HashSet<Uuid> = {
            let state = self.state.read().await;
            state.coverage_roots.keys().copied().collect()
        };

        let total_roots = search_roots.len();
        for (root_index, root) in search_roots.into_iter().enumerate() {
            if !root.exists() {
                continue;
            }
            if show_progress {
                log::info!(
                    "Marker scan {}/{}: {} (max depth {})",
                    root_index + 1,
                    total_roots,
                    root.display(),
                    max_depth
                );
            }
            for entry in WalkDir::new(&root)
                .max_depth(max_depth)
                .into_iter()
                .filter_map(|res| {
                    if let Err(err) = &res {
                        log::debug!(
                            "marker scan skipped entry under {}: {}",
                            root.display(),
                            err
                        );
                    }
                    res.ok()
                })
                .enumerate()
            {
                let (i, entry) = entry;
                if show_progress && i % 500 == 0 {
                    log::debug!(
                        "Marker scan progress ({}): processed {} entries",
                        root.display(),
                        i
                    );
                }
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !name.starts_with(COVERAGE_MARKER_PREFIX)
                    || !name.ends_with(COVERAGE_MARKER_SUFFIX)
                {
                    continue;
                }

                result.scanned += 1;
                let marker: CoverageMarkerFile = match std::fs::read_to_string(path)
                    .ok()
                    .and_then(|raw| serde_json::from_str(&raw).ok())
                {
                    Some(m) => m,
                    None => continue,
                };

                let Some(candidate_path) = marker_path_from_marker(path, &marker) else {
                    continue;
                };

                let marker_info = ScannedMarkerInfo {
                    marker_path: path.to_path_buf(),
                    root_id: marker.root_id,
                    root_path: candidate_path.clone(),
                    kind: marker.kind,
                };
                result.scanned_markers.push(marker_info.clone());

                if marker.group_id != active_group {
                    result.group_mismatch += 1;
                    result.group_mismatch_markers.push(marker_info);
                    continue;
                }

                if !seen_root_ids.insert(marker.root_id) {
                    continue;
                }

                if !candidate_path.exists() {
                    result.missing_paths.push(candidate_path);
                    continue;
                }

                if existing_ids.contains(&marker.root_id) {
                    result.already_enrolled += 1;
                    result.already_enrolled_markers.push(marker_info);
                    continue;
                }

                result.eligible += 1;
                result.eligible_markers.push(marker_info);
                match self.coverage_enroll_root(&candidate_path).await {
                    Ok(root) => {
                        result.enrolled.push(root.path.clone());
                        existing_ids.insert(root.root_id);
                    }
                    Err(err) => {
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Failed to enroll {} from marker {}: {}",
                                candidate_path.display(),
                                path.display(),
                                err
                            ),
                            Some("coverage_marker_recover"),
                        );
                    }
                }
            }
        }

        Ok(result)
    }

    /// Return aggregated per-root coverage statistics for UX surfaces.
    pub async fn coverage_root_stats(&self) -> Result<Vec<CoverageRootStats>, ClientError> {
        self.ensure_state_loaded().await?;
        self.ensure_coverage_watcher().await;

        let (_, _, root_map) = self.active_group_roots_map().await?;
        if root_map.is_empty() {
            return Ok(Vec::new());
        }

        let mut summaries = Vec::new();
        for root in root_map.values() {
            let mut tracked = 0usize;
            let mut tracked_bytes = 0u64;
            let mut orphaned = 0usize;
            let mut orphaned_bytes = 0u64;
            let mut orphan_wrong_epoch = 0usize;
            let mut orphan_missing_file = 0usize;
            let mut orphan_missing_metadata = 0usize;
            let mut orphan_outcast = 0usize;
            let mut unmanaged = 0usize;
            let mut unmanaged_bytes = 0u64;
            let mut orphan_samples = Vec::new();
            let mut unmanaged_samples = Vec::new();

            let entries = self.list_file_index_entries_for_root(root.root_id).await?;
            for entry in entries {
                match entry.state {
                    FileCoverageState::Tracked => {
                        tracked += 1;
                        tracked_bytes = tracked_bytes.saturating_add(entry.size);
                    }
                    FileCoverageState::Orphaned => {
                        orphaned += 1;
                        orphaned_bytes = orphaned_bytes.saturating_add(entry.size);
                        match entry.orphan_kind {
                            Some(FileOrphanKind::WrongEpoch) => orphan_wrong_epoch += 1,
                            Some(FileOrphanKind::MissingFile) => orphan_missing_file += 1,
                            Some(FileOrphanKind::MissingMetadata) => orphan_missing_metadata += 1,
                            Some(FileOrphanKind::Outcast) => orphan_outcast += 1,
                            None => orphan_missing_file += 1,
                        }
                        orphan_samples.push(CoverageOrphanSample {
                            relative_path: entry.relative_path.clone(),
                            size: entry.size,
                            last_seen: entry.last_seen,
                            state: entry.state.clone(),
                            orphan_kind: entry.orphan_kind.clone(),
                        });
                    }
                    FileCoverageState::Unmanaged => {
                        unmanaged += 1;
                        unmanaged_bytes = unmanaged_bytes.saturating_add(entry.size);
                        unmanaged_samples.push(CoverageOrphanSample {
                            relative_path: entry.relative_path.clone(),
                            size: entry.size,
                            last_seen: entry.last_seen,
                            state: entry.state.clone(),
                            orphan_kind: None,
                        });
                    }
                    _ => {}
                }
            }

            orphan_samples.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
            unmanaged_samples.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
            orphan_samples.truncate(3);
            unmanaged_samples.truncate(3);

            let total_files = tracked + orphaned + unmanaged;
            let coverage_ratio = if total_files == 0 {
                1.0
            } else {
                tracked as f64 / total_files as f64
            };

            summaries.push(CoverageRootStats {
                root: root.clone(),
                tracked_files: tracked,
                tracked_bytes,
                orphaned_files: orphaned,
                orphaned_bytes,
                orphan_wrong_epoch,
                orphan_missing_file,
                orphan_missing_metadata,
                orphan_outcast,
                unmanaged_files: unmanaged,
                unmanaged_bytes,
                coverage_ratio,
                recent_orphans: orphan_samples,
                recent_unmanaged: unmanaged_samples,
            });
        }

        summaries.sort_by(|a, b| {
            a.root
                .path
                .to_string_lossy()
                .cmp(&b.root.path.to_string_lossy())
        });
        Ok(summaries)
    }

    /// Get total count of enrolled files across all active coverage roots
    pub async fn get_enrolled_file_count(&self) -> Result<usize, ClientError> {
        self.ensure_state_loaded().await?;

        let (_, _, roots) = self.active_group_roots_map().await?;
        let mut count = 0usize;
        for root_id in roots.keys().copied() {
            let entries = self.list_file_index_entries_for_root(root_id).await?;
            count += entries
                .iter()
                .filter(|entry| matches!(entry.state, FileCoverageState::Tracked))
                .count();
        }

        Ok(count)
    }

    /// Remove orphaned entries whose files no longer exist on disk.
    pub async fn coverage_prune_orphans(
        &self,
        filter: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError> {
        self.ensure_state_loaded().await?;

        let canonical_filter = if let Some(path) = filter {
            Some(canonicalize_existing_path(path).await?)
        } else {
            None
        };

        if canonical_filter.is_none() && !all {
            return Err(ClientError::InvalidInput(
                "Refusing to prune across all enrolled roots without --all".to_string(),
            ));
        }

        let (_, _, root_snapshot) = self.active_group_roots_map().await?;

        if root_snapshot.is_empty() {
            return Ok(0);
        }

        let mut filtered_ids = HashSet::new();
        for (root_id, root) in root_snapshot.iter() {
            if canonical_filter
                .as_ref()
                .map_or(true, |candidate| &root.path == candidate)
            {
                filtered_ids.insert(*root_id);
            }
        }

        if canonical_filter.is_some() && filtered_ids.is_empty() {
            return Err(ClientError::InvalidInput(
                "No enrolled coverage root matched the provided path".to_string(),
            ));
        }

        let target_root_ids = if canonical_filter.is_some() {
            filtered_ids
        } else {
            root_snapshot.keys().copied().collect()
        };

        if target_root_ids.is_empty() {
            return Ok(0);
        }

        let mut removal_candidates = Vec::new();
        for root_id in target_root_ids.iter().copied() {
            let Some(root) = root_snapshot.get(&root_id) else {
                continue;
            };
            let entries = self.list_file_index_entries_for_root(root_id).await?;
            for entry in entries {
                if entry.state != FileCoverageState::Orphaned {
                    continue;
                }

                if Self::is_directory_metadata_sidecar_relative(&entry.relative_path) {
                    removal_candidates.push((root_id, entry.file_uuid));
                    continue;
                }

                let plain_path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };
                if self.is_path_excluded(&plain_path) {
                    continue;
                }

                let encrypted_path = Self::encrypted_path_for_entry(root, &entry.relative_path);

                let should_remove = {
                    // If either variant exists on disk, do not prune.
                    if std::fs::metadata(&encrypted_path).is_ok()
                        || std::fs::metadata(&plain_path).is_ok()
                    {
                        false
                    } else {
                        matches!(entry.orphan_kind, Some(FileOrphanKind::MissingFile) | None)
                    }
                };

                if should_remove {
                    removal_candidates.push((root_id, entry.file_uuid));
                }
            }
        }

        if removal_candidates.is_empty() {
            return Ok(0);
        }

        for (root_id, file_uuid) in &removal_candidates {
            self.remove_file_index_entry_for_root(*root_id, *file_uuid)
                .await?;
        }

        self.save_client_state().await?;
        Ok(removal_candidates.len())
    }

    /// Remove a specific orphaned entry identified by its absolute path.
    pub async fn coverage_prune_orphan_file(&self, path: PathBuf) -> Result<bool, ClientError> {
        self.ensure_state_loaded().await?;

        let absolute = if path.is_absolute() {
            path
        } else {
            env::current_dir()
                .map_err(|err| {
                    ClientError::file_error(
                        ErrorCode::FilePathInvalid,
                        format!("Cannot resolve current directory: {}", err),
                        "coverage_prune_resolve_path".to_string(),
                        "".to_string(),
                        None,
                    )
                })?
                .join(path)
        };

        if self.is_path_excluded(&absolute) {
            return Ok(false);
        }

        let (_, _, root_snapshot) = self.active_group_roots_map().await?;

        if root_snapshot.is_empty() {
            return Ok(false);
        }

        let mut target_entry: Option<(Uuid, FileIndexEntry, CoverageRoot, PathBuf)> = None;

        for (root_id, root) in root_snapshot.iter() {
            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                if entry.state != FileCoverageState::Orphaned {
                    continue;
                }
                let file_path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };
                if file_path == absolute {
                    target_entry = Some((*root_id, entry, root.clone(), file_path));
                    break;
                }
            }
            if target_entry.is_some() {
                break;
            }
        }

        let Some((root_id, entry, root, entry_path)) = target_entry else {
            return Ok(false);
        };

        if entry.orphan_kind != Some(FileOrphanKind::MissingFile) && entry.orphan_kind.is_some() {
            return Err(ClientError::InvalidInput(
                "Only missing-file orphans can be pruned; migrate or adopt other entries instead."
                    .to_string(),
            ));
        }

        if Self::entry_exists_on_disk(&root, &entry) {
            return Err(ClientError::InvalidInput(format!(
                "The file at {} still exists; adopt it instead of pruning.",
                entry_path.display()
            )));
        }

        self.remove_file_index_entry_for_root(root_id, entry.file_uuid)
            .await?;
        self.save_client_state().await?;
        Ok(true)
    }

    /// Purge orphaned entries that belong to a different group ([outcast]).
    pub async fn coverage_purge_outcasts(
        &self,
        file: Option<PathBuf>,
        filter: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError> {
        self.ensure_state_loaded().await?;

        if file.is_none() && filter.is_none() && !all {
            return Err(ClientError::InvalidInput(
                "Refusing to purge across all enrolled roots without --all".to_string(),
            ));
        }

        let canonical_filter = if let Some(path) = filter {
            Some(canonicalize_existing_path(path).await?)
        } else {
            None
        };

        if let Some(path) = file {
            let absolute = canonicalize_existing_path(path).await?;
            if self.is_path_excluded(&absolute) {
                return Ok(0);
            }
            let (_, _, root_snapshot) = self.active_group_roots_map().await?;

            for (root_id, root) in root_snapshot.iter() {
                let entries = self.list_file_index_entries_for_root(*root_id).await?;
                for entry in entries {
                    if entry.state != FileCoverageState::Orphaned
                        || entry.orphan_kind != Some(FileOrphanKind::Outcast)
                    {
                        continue;
                    }
                    let file_path = match root.kind {
                        CoverageRootKind::SingleFile => root.path.clone(),
                        CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                    };
                    if self.is_path_excluded(&file_path) {
                        continue;
                    }
                    if file_path == absolute {
                        self.remove_file_index_entry_for_root(*root_id, entry.file_uuid)
                            .await?;
                        self.save_client_state().await?;
                        return Ok(1);
                    }
                }
            }
            return Ok(0);
        }

        let (_, _, root_snapshot) = self.active_group_roots_map().await?;
        let target_root_ids: HashSet<Uuid> = root_snapshot
            .iter()
            .filter(|(_, root)| {
                canonical_filter
                    .as_ref()
                    .map_or(true, |candidate| root.path == *candidate)
            })
            .map(|(id, _)| *id)
            .collect();

        if target_root_ids.is_empty() {
            return Ok(0);
        }

        let mut removal = Vec::new();
        for root_id in target_root_ids.iter().copied() {
            let Some(root) = root_snapshot.get(&root_id) else {
                continue;
            };
            let entries = self.list_file_index_entries_for_root(root_id).await?;
            for entry in entries {
                if entry.state != FileCoverageState::Orphaned {
                    continue;
                }
                if entry.orphan_kind != Some(FileOrphanKind::Outcast) {
                    continue;
                }

                let file_path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };
                if self.is_path_excluded(&file_path) {
                    continue;
                }

                removal.push((root_id, entry.file_uuid));
            }
        }

        if removal.is_empty() {
            return Ok(0);
        }

        for (root_id, file_uuid) in &removal {
            self.remove_file_index_entry_for_root(*root_id, *file_uuid)
                .await?;
        }
        self.save_client_state().await?;
        Ok(removal.len())
    }

    /// Enqueue migration/rewrap tasks for orphaned entries stuck on the wrong epoch.
    pub async fn coverage_migrate_orphans(
        &self,
        file: Option<PathBuf>,
        filter: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError> {
        let progress = self
            .coverage_migrate_orphans_with_progress(file, filter, all, |_| {})
            .await?;
        Ok(progress.migrated_files)
    }

    /// Enqueue migration/rewrap tasks for orphaned entries with progress callbacks.
    pub async fn coverage_migrate_orphans_with_progress<F>(
        &self,
        file: Option<PathBuf>,
        filter: Option<PathBuf>,
        all: bool,
        mut on_progress: F,
    ) -> Result<CoverageMigrationProgress, ClientError>
    where
        F: FnMut(CoverageMigrationProgress),
    {
        self.ensure_state_loaded().await?;

        // Enter bulk mode to defer compaction until migration completes
        let _bulk_guard = self.begin_coverage_bulk_operation().await;

        let canonical_filter = if let Some(path) = filter {
            Some(canonicalize_existing_path(path).await?)
        } else {
            None
        };
        let canonical_file = if let Some(path) = file {
            let canonical = canonicalize_existing_path(path).await?;
            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!(
                    "Looking for orphaned file to migrate: {}",
                    canonical.display()
                ),
                Some("coverage_migrate_target"),
            );
            Some(canonical)
        } else {
            None
        };

        if canonical_filter.is_none() && canonical_file.is_none() && !all {
            return Err(ClientError::InvalidInput(
                "Refusing to migrate across all enrolled roots without --all".to_string(),
            ));
        }

        // Target the active migration epoch when present; otherwise rewrap straight to the
        // current epoch so leftover old-epoch files can be modernized even outside a formal
        // migration window.
        let (active_group, _, roots) = self.active_group_roots_map().await?;
        let (migration_to, has_active_migration) = {
            let state = self.state.read().await;
            (
                state
                    .migration
                    .as_ref()
                    .map(|m| m.to_epoch)
                    .unwrap_or(state.current_epoch),
                state.migration.is_some(),
            )
        };

        let group_id = active_group;

        // During active migration, include tracked files that need migration
        // Outside migration, only process orphaned wrong-epoch files
        let mut files_to_migrate: Vec<(CoverageRoot, FileIndexEntry)> = Vec::new();
        for (root_id, root) in roots.iter() {
            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                let is_orphaned_wrong_epoch = entry.state == FileCoverageState::Orphaned
                    && entry.orphan_kind == Some(FileOrphanKind::WrongEpoch);
                let is_tracked_old_epoch = has_active_migration
                    && entry.state == FileCoverageState::Tracked
                    && entry.last_epoch != migration_to;

                if is_orphaned_wrong_epoch || is_tracked_old_epoch {
                    files_to_migrate.push((root.clone(), entry));
                }
            }
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Found {} files to migrate (orphaned + tracked old-epoch)",
                files_to_migrate.len()
            ),
            Some("coverage_migrate_scan"),
        );

        let mut targets: Vec<(FileIndexEntry, PathBuf, u64, Option<u64>)> = Vec::new();
        let mut skipped_missing_epoch = 0usize;

        for (root, entry) in files_to_migrate.into_iter() {
            if let Some(candidate) = canonical_filter.as_ref() {
                if &root.path != candidate {
                    continue;
                }
            }

            let raw_path = match root.kind {
                CoverageRootKind::SingleFile => root.path.clone(),
                CoverageRootKind::Folder => root.path.join(&entry.relative_path),
            };

            let canonical_path =
                std::fs::canonicalize(&raw_path).unwrap_or_else(|_| raw_path.clone());

            if self.is_path_excluded(&canonical_path) {
                continue;
            }

            if let Some(target_file) = canonical_file.as_ref() {
                self.logger.log(
                    crate::logging::LogLevel::Debug,
                    &format!(
                        "Comparing paths: canonical={}, target={}",
                        canonical_path.display(),
                        target_file.display()
                    ),
                    Some("coverage_migrate_compare"),
                );
                if &canonical_path != target_file {
                    continue;
                }
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!("Found matching orphaned file: {}", canonical_path.display()),
                    Some("coverage_migrate_match"),
                );
            }

            // Always prefer the actual epoch from the ciphertext header (ground truth),
            // then fall back to metadata, then file index as last resort.
            // This ensures we use the correct epoch even if the index is stale.
            let metadata = self.load_metadata_for_canonical(&canonical_path).await?;
            let header = Self::parse_encrypted_file_metadata(&canonical_path);

            let mut from_epoch = 0u64;

            // Priority 1: Ciphertext header (most authoritative - what's actually on disk)
            if let Some(header) = header.as_ref() {
                if header.epoch_id > 0 {
                    from_epoch = header.epoch_id;
                    self.logger.log(
                        crate::logging::LogLevel::Debug,
                        &format!(
                            "Using epoch {} from ciphertext header for {}",
                            from_epoch,
                            canonical_path.display()
                        ),
                        Some("coverage_migrate_epoch_source"),
                    );
                }
            }

            // Priority 2: Metadata epoch (if header didn't have epoch)
            if from_epoch == 0 {
                if let Some(meta) = metadata.as_ref() {
                    from_epoch = meta.epoch_id;
                    self.logger.log(
                        crate::logging::LogLevel::Debug,
                        &format!(
                            "Using epoch {} from metadata for {}",
                            from_epoch,
                            canonical_path.display()
                        ),
                        Some("coverage_migrate_epoch_source"),
                    );
                }
            }

            // Priority 3: File index last_epoch (fallback for edge cases)
            if from_epoch == 0 {
                from_epoch = entry.last_epoch;
                if from_epoch > 0 {
                    self.logger.log(
                        crate::logging::LogLevel::Debug,
                        &format!(
                            "Using epoch {} from file index for {}",
                            from_epoch,
                            canonical_path.display()
                        ),
                        Some("coverage_migrate_epoch_source"),
                    );
                }
            }

            if from_epoch == 0 {
                skipped_missing_epoch += 1;
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Skipping migrate for {}: missing source epoch in metadata/header",
                        canonical_path.display()
                    ),
                    Some("coverage_migrate_skip"),
                );
                continue;
            }

            targets.push((
                entry,
                canonical_path,
                from_epoch,
                metadata.as_ref().map(|meta| meta.file_size),
            ));
        }

        if skipped_missing_epoch > 0 {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Skipped {} file(s) missing source epoch metadata",
                    skipped_missing_epoch
                ),
                Some("coverage_migrate_skip"),
            );
        }

        let heartbeat_batch_size = self.config.migration_state_save_batch_size;
        let heartbeat_min_interval = self.config.migration_heartbeat_min_interval_secs.max(1);
        let mut migrated_since_heartbeat = 0usize;
        let mut last_heartbeat_at = Instant::now();
        let mut processed_since_progress = 0usize;
        let mut last_progress_at = Instant::now();
        let progress_batch_size = if heartbeat_batch_size == 0 {
            None
        } else {
            Some(heartbeat_batch_size as usize)
        };

        let mut progress = CoverageMigrationProgress {
            total_files: targets.len(),
            migrated_files: 0,
            failed_files: 0,
        };
        on_progress(progress);

        const FILE_INDEX_BATCH_SIZE: usize = 1000;

        let mut save_required = false;
        let mut pending_index_updates: Vec<FileIndexEntry> =
            Vec::with_capacity(FILE_INDEX_BATCH_SIZE);

        for (mut entry, canonical_path, from_epoch, size_hint) in targets {
            // Always use rewrap_orphaned_file for files on disk (it handles the full HybridCipher format)
            // rewrap_file_internal is only for storage-backend files without headers
            match self
                .rewrap_orphaned_file(&canonical_path, from_epoch, migration_to, group_id)
                .await
            {
                Ok((_, _, _)) => {
                    progress.migrated_files += 1;
                    entry.state = FileCoverageState::Tracked;
                    entry.orphan_kind = None;
                    entry.last_epoch = migration_to;
                    if let Some(size) = size_hint {
                        entry.size = size;
                    }
                    entry.last_seen = Utc::now();
                    pending_index_updates.push(entry);
                    if pending_index_updates.len() >= FILE_INDEX_BATCH_SIZE {
                        self.store_file_index_entries(&pending_index_updates)
                            .await?;
                        pending_index_updates.clear();
                    }
                    save_required = true;

                    migrated_since_heartbeat = migrated_since_heartbeat.saturating_add(1);
                }
                Err(err) => {
                    progress.failed_files += 1;
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Failed to migrate {} from epoch {} to {}: {}",
                            canonical_path.display(),
                            from_epoch,
                            migration_to,
                            err
                        ),
                        Some("coverage_migrate_failure"),
                    );
                }
            }

            processed_since_progress = processed_since_progress.saturating_add(1);

            if let Some(batch) = progress_batch_size {
                if processed_since_progress >= batch {
                    on_progress(progress);
                    processed_since_progress = 0;
                    last_progress_at = Instant::now();
                }
            } else if last_progress_at.elapsed()
                >= std::time::Duration::from_secs(heartbeat_min_interval)
            {
                on_progress(progress);
                processed_since_progress = 0;
                last_progress_at = Instant::now();
            }

            if self.config.migration_automation_enabled && migrated_since_heartbeat > 0 {
                let batch_due = heartbeat_batch_size > 0
                    && migrated_since_heartbeat >= heartbeat_batch_size as usize;
                let time_due = last_heartbeat_at.elapsed()
                    >= std::time::Duration::from_secs(heartbeat_min_interval);

                if batch_due || time_due {
                    self.schedule_rekey_heartbeat().await;
                    migrated_since_heartbeat = 0;
                    last_heartbeat_at = Instant::now();
                }
            }
        }

        if processed_since_progress > 0 {
            on_progress(progress);
        }

        if !pending_index_updates.is_empty() {
            self.store_file_index_entries(&pending_index_updates)
                .await?;
        }

        // Always send final heartbeat after migration completes, regardless of automation setting
        // This ensures the server has aggregate counts for cutover operations
        if migrated_since_heartbeat > 0 {
            self.force_rekey_heartbeat().await;
        }

        if save_required {
            self.save_client_state().await?;
        }

        Ok(progress)
    }

    /// Apply remediation for all orphaned files under the provided scope.
    pub async fn coverage_guard(
        &self,
        filter: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, ClientError> {
        self.ensure_state_loaded().await?;

        let canonical_filter = if let Some(path) = filter {
            Some(canonicalize_existing_path(path).await?)
        } else {
            None
        };

        if canonical_filter.is_none() && !all {
            return Err(ClientError::InvalidInput(
                "Refusing to run guard across all enrolled roots without --all".to_string(),
            ));
        }

        let mut summary = CoverageGuardSummary::default();

        // First, migrate wrong-epoch orphans (requires active migration).
        match self
            .coverage_migrate_orphans(None, canonical_filter.clone(), true)
            .await
        {
            Ok(count) => summary.migrated = count,
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Guard: migrate step skipped: {}", err),
                    Some("coverage_guard_migrate"),
                );
            }
        }

        // Prune missing files.
        summary.pruned = self
            .coverage_prune_orphans(canonical_filter.clone(), canonical_filter.is_none())
            .await?;

        // Purge outcast files.
        summary.purged_outcast = self
            .coverage_purge_outcasts(None, canonical_filter.clone(), canonical_filter.is_none())
            .await?;

        // Attempt adoption for ciphertexts without metadata.
        let (_, _, roots) = self.active_group_roots_map().await?;
        let mut adoption_targets = Vec::new();
        for (root_id, root) in roots.iter() {
            if let Some(candidate) = canonical_filter.as_ref() {
                if &root.path != candidate {
                    continue;
                }
            }
            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                if entry.state != FileCoverageState::Orphaned {
                    continue;
                }
                if entry.orphan_kind != Some(FileOrphanKind::MissingMetadata) {
                    continue;
                }
                let path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };
                if self.is_path_excluded(&path) {
                    continue;
                }
                adoption_targets.push(path);
            }
        }

        for path in adoption_targets {
            match self.coverage_adopt_path(&path).await {
                Ok(_) => summary.adopted += 1,
                Err(err) => {
                    summary
                        .adopt_failures
                        .push(format!("{}: {}", path.display(), err));
                }
            }
        }

        Ok(summary)
    }

    /// Check whether a path should be excluded from encryption/coverage flows.
    pub fn is_path_excluded<P: AsRef<Path>>(&self, path: P) -> bool {
        self.file_exclusions.matches(path.as_ref())
    }

    /// Determine whether HybridCipher already has metadata for a canonical path.
    pub async fn coverage_has_metadata_for_path<P>(&self, path: P) -> Result<bool, ClientError>
    where
        P: AsRef<Path> + Send,
    {
        self.ensure_state_loaded().await?;
        let canonical = canonicalize_existing_path(path.as_ref().to_path_buf()).await?;
        let metadata = self.load_metadata_for_canonical(&canonical).await?;
        Ok(metadata.is_some())
    }

    /// Store file metadata so coverage scans can treat the path as tracked.
    pub async fn coverage_store_file_metadata(
        &self,
        metadata: FileMetadataData,
    ) -> Result<(), ClientError> {
        self.storage
            .store_file_metadata(&metadata.file_path, &metadata)
            .await
            .map_err(ClientError::from)
    }

    /// Enrolls a folder (or single file) so it participates in coverage tracking.
    pub async fn coverage_enroll_root<P>(&self, path: P) -> Result<CoverageRoot, ClientError>
    where
        P: AsRef<Path> + Send,
    {
        self.ensure_state_loaded().await?;

        let group_id = {
            let state = self.state.read().await;
            state.active_group_id.ok_or_else(|| {
                ClientError::InvalidState(
                    "Cannot enroll coverage root without an active group. Run 'hybridcipher switch-group <group-id>' first."
                        .to_string(),
                )
            })?
        };

        let canonical = canonicalize_existing_path(path.as_ref().to_path_buf()).await?;
        if self.is_path_excluded(&canonical) {
            return Err(ClientError::InvalidInput(format!(
                "Coverage root '{}' is excluded by configuration",
                canonical.display()
            )));
        }
        let metadata = fs::metadata(&canonical).await.map_err(|err| {
            ClientError::file_error(
                ErrorCode::FileNotFound,
                format!(
                    "Coverage root '{}' could not be accessed: {}",
                    canonical.display(),
                    err
                ),
                "coverage_enroll_metadata".to_string(),
                canonical.display().to_string(),
                None,
            )
        })?;

        let kind = if metadata.is_dir() {
            CoverageRootKind::Folder
        } else if metadata.is_file() {
            CoverageRootKind::SingleFile
        } else {
            return Err(ClientError::InvalidInput(format!(
                "Coverage roots must reference a file or directory (got '{}')",
                canonical.display()
            )));
        };

        self.assert_no_cross_group_conflict(&canonical, group_id)
            .await?;

        let display_path = canonical.display().to_string();
        let mut reactivated: Option<CoverageRoot> = None;
        let marker_hint = find_marker_for_path(&canonical, kind, group_id);

        // Second layer: If marker exists for this group but not in state, it indicates
        // the registry was lost. Check against existing roots by marker's root_id.
        if let Some(ref marker) = marker_hint {
            let state = self.state.read().await;
            if let Some(existing) = state.coverage_roots.get(&marker.root_id) {
                if let Some(existing_group) = existing.group_id {
                    if existing_group != group_id {
                        return Err(ClientError::InvalidInput(format!(
                            "Coverage root '{}' belongs to group {}. Run 'hybridcipher switch-group {}' to manage it.",
                            display_path, existing_group, existing_group
                        )));
                    }
                }

                if existing.state == CoverageRootState::Active {
                    return Err(ClientError::InvalidInput(format!(
                        "Coverage root '{}' is already enrolled",
                        display_path
                    )));
                }
            }
        }

        {
            let mut state = self.state.write().await;
            if let Some(existing) = state
                .coverage_roots
                .values_mut()
                .find(|root| root.path == canonical)
            {
                if let Some(existing_group) = existing.group_id {
                    if existing_group != group_id {
                        return Err(ClientError::InvalidInput(format!(
                            "Coverage root '{}' belongs to group {}. Run 'hybridcipher switch-group {}' to manage it.",
                            display_path, existing_group, existing_group
                        )));
                    }
                }

                if existing.state == CoverageRootState::Active {
                    return Err(ClientError::InvalidInput(format!(
                        "Coverage root '{}' is already enrolled",
                        display_path
                    )));
                }

                existing.group_id = Some(group_id);
                existing.state = CoverageRootState::Active;
                existing.updated_at = Utc::now();
                reactivated = Some(existing.clone());
            }
        }

        if let Some(root) = reactivated {
            self.upsert_root_registry_entry(&root.path, group_id, root.root_id)
                .await?;
            self.save_client_state().await?;
            if let Err(err) = write_marker_for_root(&root, group_id).await {
                log::warn!(
                    "Failed to write coverage marker for {}: {}",
                    root.path.display(),
                    err
                );
            }
            return Ok(root);
        }

        let root = {
            let mut state = self.state.write().await;
            let now = Utc::now();
            let root = CoverageRoot {
                root_id: marker_hint
                    .as_ref()
                    .map(|m| m.root_id)
                    .unwrap_or_else(Uuid::new_v4),
                path: canonical.clone(),
                group_id: Some(group_id),
                kind,
                state: CoverageRootState::Active,
                created_at: now,
                updated_at: now,
                last_scan: None,
            };
            state.coverage_roots.insert(root.root_id, root.clone());
            root
        };

        self.upsert_root_registry_entry(&canonical, group_id, root.root_id)
            .await?;
        self.save_client_state().await?;
        if let Err(err) = write_marker_for_root(&root, group_id).await {
            log::warn!(
                "Failed to write coverage marker for {}: {}",
                root.path.display(),
                err
            );
        }
        Ok(root)
    }

    /// Adopt a specific file into coverage (creating a single-file root if needed).
    pub async fn coverage_adopt_path<P>(&self, path: P) -> Result<CoverageAdoptResult, ClientError>
    where
        P: AsRef<Path> + Send,
    {
        self.ensure_state_loaded().await?;

        let canonical = canonicalize_existing_path(path.as_ref().to_path_buf()).await?;
        if self.is_path_excluded(&canonical) {
            return Err(ClientError::InvalidInput(format!(
                "Path '{}' is excluded from coverage operations",
                canonical.display()
            )));
        }

        // Try to load existing metadata, or create it from the encrypted file header
        let metadata = if let Some(meta) = self.load_metadata_for_canonical(&canonical).await? {
            meta
        } else {
            // No metadata found - parse the encrypted file header to create metadata
            let parsed = Self::parse_encrypted_file_metadata(&canonical).ok_or_else(|| {
                ClientError::file_error(
                    ErrorCode::FileNotFound,
                    format!(
                        "Cannot adopt '{}': file is not a valid encrypted file (no header found)",
                        canonical.display()
                    ),
                    "coverage_adopt_parse_header".to_string(),
                    canonical.display().to_string(),
                    None,
                )
            })?;

            // Create metadata from the parsed header
            let new_metadata = FileMetadataData {
                file_path: canonical.display().to_string(),
                file_id: Some(parsed.file_id.clone()),
                group_id: parsed.group_id,
                epoch_id: parsed.epoch_id,
                header_version: parsed.header_version,
                wrapped_file_key: parsed.wrapped_file_key.clone(),
                key_wrap_nonce: parsed.key_wrap_nonce.clone(),
                key_wrap_aad_hash: parsed.key_wrap_aad_hash.clone(),
                content_nonce: parsed.content_nonce.clone(),
                content_chunk_size: parsed.content_chunk_size,
                algorithm: "ChaCha20-Poly1305".to_string(),
                file_size: parsed.content_size,
                modified_at: Utc::now(),
                integrity_hash: [0u8; 32], // Will be updated on next scan
                permissions: AccessControlData {
                    readers: vec![],
                    writers: vec![],
                    is_public: true,
                },
                version: 1,
                chunks: vec![],
                encrypted_size: parsed.encrypted_size,
                encrypted_at: parsed.created_at,
            };

            // Store the metadata
            self.storage
                .store_file_metadata(&canonical.display().to_string(), &new_metadata)
                .await
                .map_err(ClientError::from)?;

            new_metadata
        };

        let root = if let Some(root) = self.active_root_for_path(&canonical).await? {
            root
        } else {
            self.coverage_enroll_root(&canonical).await?
        };

        let relative_path = Self::relative_path_for_root(&root.path, root.kind, &canonical).ok_or(
            ClientError::InvalidInput(format!(
                "File '{}' does not sit under the enrolled coverage root '{}'",
                canonical.display(),
                root.path.display()
            )),
        )?;

        let file_uuid = self
            .find_file_index_entry_for_root_path(root.root_id, &relative_path)
            .await?
            .map(|entry| entry.file_uuid)
            .unwrap_or_else(|| Uuid::new_v5(&root.root_id, relative_path.as_bytes()));

        let entry = FileIndexEntry {
            file_uuid,
            file_id: metadata.file_id.clone(),
            root_id: root.root_id,
            relative_path: relative_path.clone(),
            size: metadata.file_size,
            last_epoch: metadata.epoch_id,
            checksum_hint: Some(hex::encode(metadata.integrity_hash)),
            last_seen: metadata.modified_at,
            state: FileCoverageState::Tracked,
            orphan_kind: None,
        };

        self.store_file_index_entry(&entry).await?;
        let scanned_at = Utc::now();
        let updated_root = {
            let mut state = self.state.write().await;
            if let Some(root_entry) = state.coverage_roots.get_mut(&root.root_id) {
                root_entry.last_scan = Some(scanned_at);
                root_entry.updated_at = scanned_at;
            }
            state
                .coverage_roots
                .get(&root.root_id)
                .cloned()
                .unwrap_or(root)
        };

        self.save_client_state().await?;
        self.ensure_coverage_watcher().await;

        Ok(CoverageAdoptResult {
            root: updated_root,
            entry,
        })
    }

    /// Adopt all ciphertext-without-metadata orphans under the provided scope.
    pub async fn coverage_adopt_missing_metadata(
        &self,
        filter: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, ClientError> {
        self.ensure_state_loaded().await?;

        let canonical_filter = if let Some(path) = filter {
            Some(canonicalize_existing_path(path).await?)
        } else {
            None
        };

        if canonical_filter.is_none() && !all {
            return Err(ClientError::InvalidInput(
                "Refusing to adopt across all enrolled roots without --all".to_string(),
            ));
        }

        let mut summary = CoverageGuardSummary::default();

        let (_, _, roots) = self.active_group_roots_map().await?;
        let mut adoption_targets = Vec::new();
        for (root_id, root) in roots.iter() {
            if let Some(candidate) = canonical_filter.as_ref() {
                if &root.path != candidate {
                    continue;
                }
            }
            let entries = self.list_file_index_entries_for_root(*root_id).await?;
            for entry in entries {
                if entry.state != FileCoverageState::Orphaned {
                    continue;
                }
                if entry.orphan_kind != Some(FileOrphanKind::MissingMetadata) {
                    continue;
                }
                let path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };
                if self.is_path_excluded(&path) {
                    continue;
                }
                adoption_targets.push(path);
            }
        }

        for path in adoption_targets {
            match self.coverage_adopt_path(&path).await {
                Ok(_) => summary.adopted += 1,
                Err(err) => summary
                    .adopt_failures
                    .push(format!("{}: {}", path.display(), err)),
            }
        }

        Ok(summary)
    }

    /// Unenrolls an existing coverage root referenced by path.
    /// Note: Decryption of files should be handled by the caller (e.g., CLI layer).
    pub async fn coverage_unenroll_root<P>(&self, path: P) -> Result<CoverageRoot, ClientError>
    where
        P: AsRef<Path> + Send,
    {
        self.ensure_state_loaded().await?;

        let active_group = {
            let state = self.state.read().await;
            state.active_group_id.ok_or_else(|| {
                ClientError::InvalidState(
                    "Cannot unenroll coverage root without an active group. Run 'hybridcipher switch-group <group-id>' first."
                        .to_string(),
                )
            })?
        };

        let provided_path = path.as_ref();
        let absolute_candidate = if provided_path.is_absolute() {
            provided_path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(provided_path)
        };

        let canonical = match canonicalize_existing_path(absolute_candidate.clone()).await {
            Ok(canonical) => Some(canonical),
            Err(err) => {
                // Allow unenroll even if the path no longer exists; fall back to string matching.
                if let ClientError::FileError { context, .. } = &err {
                    if matches!(context.code, ErrorCode::FilePathInvalid) {
                        None
                    } else {
                        return Err(err);
                    }
                } else {
                    return Err(err);
                }
            }
        };
        let display_path = canonical
            .as_ref()
            .unwrap_or(&absolute_candidate)
            .display()
            .to_string();

        // Roots are bound to the group that enrolled them; block unenroll from the wrong group.
        if let Some(registry_entry) = self.load_root_registry().await?.entries.get(&display_path) {
            if registry_entry.group_id != active_group {
                return Err(ClientError::InvalidState(format!(
                    "Coverage root belongs to group {}, but the active group is {}. Run 'hybridcipher switch-group {}' and retry.",
                    registry_entry.group_id, active_group, registry_entry.group_id
                )));
            }
        }

        let root = {
            let state = self.state.read().await;
            let maybe_root = state.coverage_roots.values().find(|root| {
                if let Some(ref canonical) = canonical {
                    root.path == *canonical
                } else {
                    root.path == absolute_candidate
                }
            });

            let root = maybe_root.ok_or_else(|| {
                ClientError::InvalidInput(format!(
                    "No enrolled coverage root matches '{}'",
                    display_path
                ))
            })?;

            if root.state == CoverageRootState::Unenrolled {
                return Err(ClientError::InvalidInput(format!(
                    "Coverage root '{}' is already unenrolled",
                    display_path
                )));
            }

            root.clone()
        };

        let entries = self.list_file_index_entries_for_root(root.root_id).await?;
        let removals = self.collect_unenroll_removals(&root, &entries).await?;
        let removal_ids: HashSet<String> =
            removals.into_iter().map(|(file_id, _)| file_id).collect();

        let mut updated_root = None;

        {
            let mut state = self.state.write().await;
            if let Some(root_entry) = state.coverage_roots.get_mut(&root.root_id) {
                root_entry.state = CoverageRootState::Unenrolled;
                root_entry.updated_at = Utc::now();
                updated_root = Some(root_entry.clone());
            }

            if let Some(root_entry) = updated_root.as_ref() {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!("Unenrolled {}", root_entry.path.display()),
                    Some("coverage_unenroll"),
                );
            }
        }

        let root = updated_root.expect("coverage root should exist");
        for entry in &entries {
            let path = match root.kind {
                CoverageRootKind::SingleFile => root.path.clone(),
                CoverageRootKind::Folder => root.path.join(&entry.relative_path),
            };
            let path_str = path.to_string_lossy().to_string();
            let _ = self.storage.delete_file(&path_str).await;
            let normalized = Self::normalize_storage_path(&path_str);
            if normalized != path_str {
                let _ = self.storage.delete_file(&normalized).await;
            }
        }
        self.replace_file_index_entries_for_root(root.root_id, &[])
            .await?;
        self.remove_root_registry_entry(&root.path).await?;
        self.save_client_state().await?;

        let clear_pending = !self.has_active_roots().await;
        if clear_pending || !removal_ids.is_empty() {
            let (snapshot_log, sequence) = {
                let mut state = self.state.write().await;
                let ledger = state.coverage_ledgers.entry(active_group).or_default();
                ledger.loaded = true;
                if clear_pending {
                    ledger.log = CoverageLog::new();
                    ledger.ack_sequence = ledger.sequence;
                    ledger.delta_ack_sequence = ledger.sequence;
                    ledger.snapshot_sequence = ledger.sequence;
                } else {
                    for file_id in &removal_ids {
                        ledger.log.remove_entry(file_id);
                    }
                    ledger.snapshot_sequence = ledger.sequence;
                }
                (ledger.log.clone(), ledger.sequence)
            };

            self.persist_coverage_log_snapshot(active_group, snapshot_log, sequence)
                .await?;
            if clear_pending {
                self.compact_coverage_log_deltas(active_group, sequence)
                    .await?;
            }
        }
        if let Err(err) = remove_marker_for_root(&root).await {
            log::warn!(
                "Failed to remove coverage marker for {}: {}",
                root.path.display(),
                err
            );
        }
        Ok(root)
    }

    pub(in super::super) async fn collect_unenroll_removals(
        &self,
        root: &CoverageRoot,
        entries: &[FileIndexEntry],
    ) -> Result<Vec<(String, u64)>, ClientError> {
        let mut removals = Vec::new();
        for entry in entries {
            let path = match root.kind {
                CoverageRootKind::SingleFile => root.path.clone(),
                CoverageRootKind::Folder => root.path.join(&entry.relative_path),
            };

            let mut file_id = None;
            let mut epoch_id = entry.last_epoch;

            if let Some(metadata) = self.load_metadata_for_canonical(&path).await? {
                file_id = metadata.file_id.clone();
                epoch_id = metadata.epoch_id;
            } else if path.exists() && Self::detect_hybridcipher_header(&path) {
                if let Some(header) = Self::parse_encrypted_file_metadata(&path) {
                    file_id = Some(header.file_id);
                    epoch_id = header.epoch_id;
                }
            }

            if let Some(file_id) = file_id {
                removals.push((file_id, epoch_id));
            }
        }

        Ok(removals)
    }

    /// Verify file exists in coverage log and return its epoch
    pub(in super::super) async fn verify_file_coverage(
        &self,
        _file_id: &str,
    ) -> Result<u64, ClientError> {
        // This is a simplified implementation
        // In practice, this would query the coverage manager

        // For now, extract epoch from file_id (which includes epoch in generation)
        // This is a temporary solution until full coverage integration

        let state = self.state.read().await;
        let current_epoch = state.current_epoch;

        // Check if we're in migration and support dual-epoch lookup
        if let Some(migration) = &state.migration {
            // During migration, try new epoch first, then old epoch
            if state.epochs.contains_key(&migration.to_epoch) {
                return Ok(migration.to_epoch);
            }
            if state.epochs.contains_key(&migration.from_epoch) {
                return Ok(migration.from_epoch);
            }
        }

        // Default to current epoch
        if state.epochs.contains_key(&current_epoch) {
            Ok(current_epoch)
        } else {
            Err(ClientError::InvalidState(
                "No valid epoch available for file".to_string(),
            ))
        }
    }

    #[cfg(feature = "mount-fs")]
    pub async fn coverage_overview(&self) -> Result<CoverageOverview, ClientError> {
        self.ensure_state_loaded().await?;
        let state = self.state.read().await;

        let mut epoch_ids: Vec<u64> = state.epochs.keys().cloned().collect();
        if let Some(migration) = &state.migration {
            if !epoch_ids.contains(&migration.from_epoch) {
                epoch_ids.push(migration.from_epoch);
            }
            if !epoch_ids.contains(&migration.to_epoch) {
                epoch_ids.push(migration.to_epoch);
            }
        }
        epoch_ids.sort_unstable();
        epoch_ids.dedup();

        let mut epochs = Vec::with_capacity(epoch_ids.len());
        let mut total_tracked_files = 0u64;

        for epoch_id in epoch_ids {
            let counts: CoverageCounts = state
                .coverage_ledgers
                .get(&state.active_group_id.unwrap_or_default())
                .map(|l| l.log.counts_for_epoch(epoch_id))
                .unwrap_or_default();
            if total_tracked_files == 0 {
                total_tracked_files = counts.total_items;
            }

            let coverage_ratio = if counts.total_items == 0 {
                0.0
            } else {
                counts.rewrapped_items as f64 / counts.total_items as f64
            };

            let is_active = epoch_id == state.current_epoch;
            let is_migration_target = state
                .migration
                .as_ref()
                .map(|migration| migration.to_epoch == epoch_id)
                .unwrap_or(false);

            epochs.push(CoverageEpochSummary {
                epoch_id,
                total_files: counts.total_items,
                rewrapped_files: counts.rewrapped_items,
                coverage_ratio,
                is_active,
                is_migration_target,
            });
        }

        if epochs.is_empty() {
            let counts = state
                .coverage_ledgers
                .get(&state.active_group_id.unwrap_or_default())
                .map(|l| l.log.counts_for_epoch(state.current_epoch))
                .unwrap_or_default();
            total_tracked_files = counts.total_items;
        }

        let latest_snapshot = state
            .active_group_id
            .and_then(|gid| state.coverage_ledgers.get(&gid))
            .and_then(|ledger| ledger.log.latest_snapshot())
            .map(|snapshot: CoverageRootSnapshot| CoverageSnapshotInfo {
                merkle_root_hex: hex::encode(snapshot.merkle_root),
                verifying_key_base64: general_purpose::STANDARD.encode(snapshot.verifying_key),
                signing_key_id: snapshot.signing_key_id.clone(),
                signature_base64: Some(general_purpose::STANDARD.encode(snapshot.signature)),
            });

        Ok(CoverageOverview {
            generated_at: Utc::now(),
            current_epoch: state.current_epoch,
            migration_target_epoch: state.migration.as_ref().map(|migration| migration.to_epoch),
            total_tracked_files,
            epochs,
            latest_snapshot,
        })
    }
}
