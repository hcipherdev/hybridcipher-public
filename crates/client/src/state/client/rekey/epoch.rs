use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// Initialize genesis epoch from server-provided group parameters
    ///
    /// This method creates the first epoch for a group using server-distributed
    /// parameters instead of client-side fixed seeds.
    ///
    /// # Arguments
    /// * `group_id` - Group identifier
    /// * `genesis_key` - Server-provided genesis epoch key
    /// * `group_members` - Initial group member list
    ///
    /// # Returns
    /// The genesis epoch ID (always 0)
    pub async fn initialize_genesis_epoch(
        &self,
        group_id: uuid::Uuid,
        genesis_key: [u8; 32],
        group_members: Vec<crate::welcome_manager::GroupMember>,
    ) -> Result<u64, ClientError> {
        let mut state = self.state.write().await;

        let members = Self::hydrate_group_members(&group_members)?;

        // Create genesis epoch with server-provided key
        let genesis_epoch = EpochState {
            group_id: Some(group_id),
            epoch_id: 0,
            encryption_key: genesis_key,
            key_source: EpochKeySource::Welcome,
            members,
            created_at: chrono::Utc::now(),
            is_active: true,
            file_count: 0,
            marked_for_removal: false,
            removal_eligible_at: None,
        };

        Self::upsert_epoch_state(&mut state, group_id, genesis_epoch);
        state.current_epoch = 0;
        if let Some(membership) = state.group_memberships.get_mut(&group_id) {
            membership.current_epoch_id = Some(0);
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Initialized genesis epoch for group {}", group_id),
            Some(&format!(
                "group_id: {}, member_count: {}",
                group_id,
                group_members.len()
            )),
        );

        Ok(0)
    }

    /// Check if the client has any epochs established
    ///
    /// # Returns
    /// True if at least one epoch is available for operations
    pub async fn has_epochs(&self) -> bool {
        if let Err(err) = self.ensure_state_loaded().await {
            log::warn!("Failed to load client state while checking epochs: {}", err);
            return false;
        }

        let state = self.state.read().await;
        !state.epochs.is_empty()
    }

    /// Get the current epoch ID
    ///
    /// # Returns
    /// Current epoch ID, or None if no epochs are established
    pub async fn current_epoch_id(&self) -> Option<u64> {
        if let Err(err) = self.ensure_state_loaded().await {
            log::warn!(
                "Failed to load client state while determining current epoch: {}",
                err
            );
            return None;
        }

        let state = self.state.read().await;
        if state.epochs.is_empty() {
            None
        } else {
            Some(state.current_epoch)
        }
    }

    /// Snapshot the in-memory migration state (if any).
    pub async fn migration_snapshot(&self) -> Option<MigrationState> {
        if self.ensure_state_loaded().await.is_err() {
            return None;
        }

        let state = self.state.read().await;
        state.migration.clone()
    }

    /// Check if any epochs marked for removal are now eligible for cleanup.
    /// This is called after coverage scan to handle the 24-hour deferred removal window.
    pub(in super::super) async fn check_deferred_epoch_removal(&self) -> Result<(), ClientError> {
        let group_id = match self.active_group_required().await {
            Ok(gid) => gid,
            Err(_) => return Ok(()), // No active group, nothing to do
        };

        // First, get the list of epochs marked for removal
        let marked_epochs: Vec<u64> = {
            let state = self.state.read().await;
            state
                .epochs
                .iter()
                .flat_map(|(epoch_id, entries)| {
                    entries
                        .iter()
                        .filter(|e| e.group_id == Some(group_id) && e.marked_for_removal)
                        .map(move |_| *epoch_id)
                })
                .collect()
        };

        if marked_epochs.is_empty() {
            return Ok(()); // No epochs marked for removal
        }

        // Check if there are files still encrypted with the marked epochs
        // We need to check both file_index AND actual file headers
        let (active_root_ids, has_pending_rewraps) = {
            let state = self.state.read().await;

            // Get root IDs for active group
            let registry_json = self
                .storage
                .load_config(COVERAGE_ROOT_REGISTRY_KEY)
                .await
                .map_err(ClientError::from)?
                .unwrap_or_else(|| "{}".to_string());
            let registry: CoverageRootRegistry =
                serde_json::from_str(&registry_json).unwrap_or_default();

            let active_root_ids: HashSet<Uuid> = state
                .coverage_roots
                .values()
                .filter(|root| {
                    root.state == CoverageRootState::Active
                        && registry
                            .entries
                            .get(&root.path.to_string_lossy().to_string())
                            .map(|e| e.group_id == group_id)
                            .unwrap_or(false)
                })
                .map(|r| r.root_id)
                .collect();

            let pending = state.pending_rewraps.iter().any(|p| p.group_id == group_id);

            (active_root_ids, pending)
        };

        let mut files_at_marked_epoch = 0usize;
        for root_id in active_root_ids.iter().copied() {
            let entries = self.list_file_index_entries_for_root(root_id).await?;
            for entry in entries {
                if marked_epochs.contains(&entry.last_epoch) {
                    files_at_marked_epoch += 1;
                }
            }
        }

        if rekey_debug_enabled() {
            eprintln!(
                "DEBUG check_deferred_epoch_removal: files_at_marked_epoch={}, pending_rewraps={}",
                files_at_marked_epoch, has_pending_rewraps
            );
        }

        let has_files_at_marked_epoch = files_at_marked_epoch > 0;

        let now = Utc::now();
        let mut epochs_to_remove: Vec<u64> = Vec::new();

        {
            let mut state = self.state.write().await;

            // Iterate through all epochs for this group
            for (epoch_id, entries) in state.epochs.iter_mut() {
                for epoch in entries.iter_mut().filter(|e| e.group_id == Some(group_id)) {
                    if !epoch.marked_for_removal {
                        continue;
                    }

                    // Only set removal timer if:
                    // 1. No files are still encrypted with any marked epoch
                    // 2. No pending rewraps for this group
                    if !has_files_at_marked_epoch && !has_pending_rewraps {
                        if epoch.removal_eligible_at.is_none() {
                            let eligible_at = now + Duration::hours(24);
                            epoch.removal_eligible_at = Some(eligible_at);

                            if rekey_debug_enabled() {
                                eprintln!(
                                    "DEBUG check_deferred_epoch_removal: Epoch {} scheduled for removal at {}",
                                    epoch_id, eligible_at
                                );
                            }
                        }
                    } else {
                        // Reset the timer if conditions are no longer met
                        if epoch.removal_eligible_at.is_some() {
                            epoch.removal_eligible_at = None;

                            if rekey_debug_enabled() {
                                eprintln!(
                                    "DEBUG check_deferred_epoch_removal: Epoch {} removal timer reset (files_at_epoch={}, pending_rewraps={})",
                                    epoch_id, has_files_at_marked_epoch, has_pending_rewraps
                                );
                            }
                        }
                    }

                    // Check if removal timer has expired
                    if let Some(eligible_at) = epoch.removal_eligible_at {
                        if now >= eligible_at {
                            epochs_to_remove.push(*epoch_id);

                            if rekey_debug_enabled() {
                                eprintln!(
                                    "DEBUG check_deferred_epoch_removal: Epoch {} is now eligible for removal",
                                    epoch_id
                                );
                            }
                        }
                    }
                }
            }
        }

        // Actually remove the eligible epochs
        if !epochs_to_remove.is_empty() {
            let mut state = self.state.write().await;
            for epoch_id in epochs_to_remove {
                Self::remove_epoch_state(&mut state, group_id, epoch_id);

                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Removed deferred epoch {} after 24-hour grace period",
                        epoch_id
                    ),
                    Some("deferred_epoch_removal"),
                );
            }
            drop(state);
            self.save_client_state().await?;
        }

        Ok(())
    }

    /// Get the current active epoch ID
    pub async fn current_epoch(&self) -> u64 {
        let state = self.state.read().await;
        state.current_epoch
    }

    /// Check if a migration is currently in progress
    pub async fn is_migrating(&self) -> bool {
        let state = self.state.read().await;
        state.migration.is_some()
    }

    /// Check if background migration automation is enabled.
    pub fn migration_automation_enabled(&self) -> bool {
        self.config.migration_automation_enabled
    }

    #[cfg(feature = "mount-fs")]
    pub async fn migration_state_snapshot(&self) -> Option<MigrationState> {
        // Ensure state is loaded so cached data is available
        if self.ensure_state_loaded().await.is_err() {
            return None;
        }

        let state = self.state.read().await;
        state.migration.clone()
    }

    #[cfg(feature = "mount-fs")]
    pub async fn rekey_overlay_state(&self) -> Result<RekeyOverlayState, ClientError> {
        self.ensure_state_loaded().await?;

        let state = self.state.read().await;

        let heartbeats = state
            .rekey_heartbeats
            .iter()
            .map(|(rekey_id, heartbeat)| RekeyHeartbeatSummary {
                rekey_id: *rekey_id,
                sequence: heartbeat.sequence,
                last_emitted_at: heartbeat.last_emitted_at,
                last_observed_at: heartbeat.last_observed_at,
                descriptor_commitment: heartbeat.last_descriptor_commitment.clone(),
                last_coverage_bytes: heartbeat.last_coverage_bytes,
                last_coverage_items: heartbeat.last_coverage_items,
                last_protected_bytes: heartbeat.last_protected_bytes,
                last_protected_items: heartbeat.last_protected_items,
                confirmed_reported: heartbeat.confirmed_reported,
            })
            .collect();

        let pending_rewraps = state
            .pending_rewraps
            .iter()
            .map(|entry| PendingRewrapSummary {
                path: entry.path.clone(),
                from_epoch: entry.from_epoch,
                to_epoch: entry.to_epoch,
                group_id: entry.group_id,
                attempts: entry.attempts,
                last_attempt: entry.last_attempt,
            })
            .collect();

        Ok(RekeyOverlayState {
            generated_at: Utc::now(),
            active_operation: state.active_rekey.clone(),
            migration: state.migration.clone(),
            heartbeats,
            pending_rewraps,
        })
    }

    /// Get current migration progress (0.0 to 1.0)
    pub async fn migration_progress(&self) -> Option<f64> {
        let state = self.state.read().await;
        state.migration.as_ref().map(|migration| {
            if migration.total_files == 0 {
                0.0
            } else {
                migration.migrated_files.len() as f64 / migration.total_files as f64
            }
        })
    }

    /// Lightweight local rewrap progress snapshot (no network I/O).
    pub async fn rewrap_queue_snapshot(&self) -> Result<LocalRewrapSnapshot, ClientError> {
        self.ensure_state_loaded().await?;
        let state = self.state.read().await;

        let (total_files, migrated_files, pending_rewraps) =
            if let Some(migration) = state.migration.as_ref() {
                let target_epoch = migration.to_epoch;
                let pending_rewraps = state.pending_rewraps.len() as u64;

                // Prefer coverage ledger counts to avoid relying on stale migration.migrated_files.
                let migrated = state
                    .coverage_ledgers
                    .get(&state.active_group_id.unwrap_or_default())
                    .map(|l| l.log.counts_for_epoch(target_epoch).rewrapped_items)
                    .unwrap_or(0);

                (migration.total_files, migrated, pending_rewraps)
            } else {
                (0, 0, 0)
            };

        Ok(LocalRewrapSnapshot {
            total_files,
            migrated_files,
            pending_rewraps,
        })
    }

    /// Refresh on-disk state and return migration progress derived from coverage/file index.
    pub async fn migration_progress_snapshot(&self) -> Result<(u64, u64), ClientError> {
        self.ensure_state_loaded().await?;
        // Refresh file index from disk so counts match coverage scan.
        let _ = self.coverage_rescan(None).await;
        self.ensure_coverage_log_loaded().await?;
        let _ = self.reconcile_coverage_log_from_index().await;

        let (group_id, _, roots) = self.active_group_roots_map().await?;
        let root_ids: HashSet<Uuid> = roots
            .iter()
            .filter_map(|(id, root)| {
                if root.state == CoverageRootState::Active {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let (_target_epoch, migrated) = {
            let state = self.state.read().await;
            let target_epoch = state
                .migration
                .as_ref()
                .map(|m| m.to_epoch)
                .unwrap_or(state.current_epoch);
            let migrated = state
                .coverage_ledgers
                .get(&group_id)
                .map(|l| l.log.counts_for_epoch(target_epoch).rewrapped_items)
                .unwrap_or(0);
            (target_epoch, migrated)
        };

        let mut tracked = 0u64;
        for root_id in root_ids.iter().copied() {
            let entries = self.list_file_index_entries_for_root(root_id).await?;
            tracked += entries
                .iter()
                .filter(|entry| matches!(entry.state, FileCoverageState::Tracked))
                .count() as u64;
        }

        Ok((tracked, migrated))
    }

    /// Run a coverage scan and return counts directly from the coverage log (tracked/rewrapped).
    pub async fn coverage_progress_snapshot(&self) -> Result<(u64, u64), ClientError> {
        self.ensure_state_loaded().await?;
        let should_rescan = {
            let now = Instant::now();
            let mut cache = self.coverage_rescan_cache.lock().await;
            match cache.last_rescan_at {
                Some(last) if now.duration_since(last) < COVERAGE_RESCAN_TTL => false,
                _ => {
                    cache.last_rescan_at = Some(now);
                    true
                }
            }
        };
        if should_rescan {
            let _ = self.coverage_rescan(None).await;
        }
        self.ensure_coverage_log_loaded().await?;
        let _ = self.reconcile_coverage_log_from_index().await;

        let (group_id, _, roots) = self.active_group_roots_map().await?;
        let root_ids: HashSet<Uuid> = roots
            .iter()
            .filter_map(|(id, root)| {
                if root.state == CoverageRootState::Active {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let (_target_epoch, migrated) = {
            let state = self.state.read().await;
            let target_epoch = state
                .migration
                .as_ref()
                .map(|m| m.to_epoch)
                .unwrap_or(state.current_epoch);
            let migrated = state
                .coverage_ledgers
                .get(&group_id)
                .map(|l| l.log.counts_for_epoch(target_epoch).rewrapped_items)
                .unwrap_or(0);
            (target_epoch, migrated)
        };

        let mut tracked = 0u64;
        for root_id in root_ids.iter().copied() {
            let entries = self.list_file_index_entries_for_root(root_id).await?;
            tracked += entries
                .iter()
                .filter(|entry| matches!(entry.state, FileCoverageState::Tracked))
                .count() as u64;
        }

        Ok((tracked, migrated))
    }

    /// Compute migration progress from the current coverage ledger/file index, ignoring cached
    /// migration.migrated_files.
    pub(in super::super) async fn local_migration_progress(
        &self,
    ) -> Result<(u64, u64), ClientError> {
        self.ensure_state_loaded().await?;
        self.ensure_coverage_log_loaded().await?;
        // Keep coverage ledger aligned with file index before counting.
        let _ = self.reconcile_coverage_log_from_index().await;

        let (group_id, _, roots) = self.active_group_roots_map().await?;
        let root_ids: HashSet<Uuid> = roots
            .iter()
            .filter_map(|(id, root)| {
                if root.state == CoverageRootState::Active {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let (_target_epoch, migrated) = {
            let state = self.state.read().await;
            let target_epoch = state
                .migration
                .as_ref()
                .map(|m| m.to_epoch)
                .unwrap_or(state.current_epoch);
            let migrated = state
                .coverage_ledgers
                .get(&group_id)
                .map(|l| l.log.counts_for_epoch(target_epoch).rewrapped_items)
                .unwrap_or(0);
            (target_epoch, migrated)
        };

        let mut tracked = 0u64;
        for root_id in root_ids.iter().copied() {
            let entries = self.list_file_index_entries_for_root(root_id).await?;
            tracked += entries
                .iter()
                .filter(|entry| matches!(entry.state, FileCoverageState::Tracked))
                .count() as u64;
        }

        Ok((tracked, migrated))
    }

    /// Get the device identity public key
    pub fn device_public_key(&self) -> [u8; 32] {
        self.device_identity.public_key_bytes()
    }

    /// Start a new epoch transition
    ///
    /// This initiates a two-phase rekey operation:
    /// 1. Generate new epoch keys
    /// 2. Coordinate with group members
    /// 3. Begin file migration
    ///
    /// # Arguments
    /// * `new_members` - Updated group membership for the new epoch
    ///
    /// # Returns
    /// Ok(()) if transition started successfully
    ///
    /// # Errors
    /// - `InvalidState` if already migrating
    /// - `StorageError` if state cannot be persisted
    /// - `NetworkError` if coordination fails
    pub async fn start_epoch_transition(
        &self,
        new_members: Vec<GroupMember>,
    ) -> Result<(), ClientError> {
        let mut state = self.state.write().await;

        // Validate we're not already migrating
        if state.migration.is_some() {
            return Err(ClientError::InvalidState(
                "Migration already in progress".to_string(),
            ));
        }

        let group_id = state.active_group_id;

        // Generate new epoch ID
        let new_epoch = state.current_epoch + 1;

        // Create new epoch state
        let epoch_state = EpochState {
            group_id,
            epoch_id: new_epoch,
            encryption_key: [0u8; 32], // Will be derived from group key exchange
            key_source: EpochKeySource::Placeholder,
            members: new_members,
            created_at: Utc::now(),
            is_active: false, // Activated after successful migration
            file_count: 0,
            marked_for_removal: false,
            removal_eligible_at: None,
        };

        // Initialize migration state
        let migration = MigrationState {
            from_epoch: state.current_epoch,
            to_epoch: new_epoch,
            phase: MigrationPhase::Preparing,
            migrated_files: Vec::new(),
            migrated_files_set: HashSet::new(),
            failed_files: Vec::new(),
            total_files: 0, // Will be computed during preparation
            started_at: Utc::now(),
            estimated_completion: None,
        };

        // Update state
        match group_id {
            Some(active_group) => {
                Self::upsert_epoch_state(&mut state, active_group, epoch_state.clone());
            }
            None => {
                state
                    .epochs
                    .entry(epoch_state.epoch_id)
                    .or_insert_with(Vec::new)
                    .push(epoch_state.clone());
            }
        }
        state.migration = Some(migration);

        Ok(())
    }

    /// Rewrap a pending file, falling back to ciphertext header when metadata is missing.
    pub(in super::super) async fn rewrap_pending_entry(
        &self,
        pending: &PendingRewrap,
    ) -> Result<(), ClientError> {
        // If a rewrap targets a newer epoch than the current group epoch and there is no active
        // rekey, treat the task as stale (fallback likely occurred) and drop it.
        let (current_epoch_for_group, has_active_rekey) = {
            let state = self.state.read().await;
            let membership_epoch = state
                .group_memberships
                .get(&pending.group_id)
                .and_then(|m| m.current_epoch_id)
                .unwrap_or(state.current_epoch);
            let active = state
                .active_rekey
                .as_ref()
                .map(|op| op.group_id == pending.group_id)
                .unwrap_or(false);
            (membership_epoch, active)
        };

        if pending.to_epoch > current_epoch_for_group && !has_active_rekey {
            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!(
                    "Skipping stale rewrap for {} (pending epoch {} > current epoch {}, no active rekey)",
                    pending.path, pending.to_epoch, current_epoch_for_group
                ),
                Some("rewrap_skip_stale"),
            );
            let _ = self.update_file_pending_flag(&pending.path, false).await;
            return Ok(());
        }

        // Prefer metadata-backed rewrap when metadata exists and encrypted bytes are available.
        if self
            .storage
            .load_file_metadata(&pending.path)
            .await
            .map_err(ClientError::from)?
            .is_some()
        {
            // Ensure the ciphertext is actually present; if not, fall back to disk-header path.
            match self.storage.get_file(&pending.path).await {
                Ok(Some(_)) => {
                    return self
                        .rewrap_file_internal(&pending.path, pending.from_epoch, pending.to_epoch)
                        .await;
                }
                Ok(None) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Metadata found but encrypted bytes missing for {}; falling back to disk rewrap",
                            pending.path
                        ),
                        Some("rewrap_missing_ciphertext"),
                    );
                }
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Failed to read encrypted bytes for {} (fallback to disk): {}",
                            pending.path, err
                        ),
                        Some("rewrap_missing_ciphertext"),
                    );
                }
            }
        }

        // Fallback: use ciphertext header to rewrap orphaned on-disk files and update coverage/index.
        let disk_path = PathBuf::from(&pending.path);
        let header = Self::parse_encrypted_file_metadata(&disk_path).ok_or_else(|| {
            ClientError::InvalidState(format!(
                "Missing HybridCipher header for {} (cannot rewrap orphaned file)",
                pending.path
            ))
        })?;

        let header_file_id = header.file_id.clone();
        let header_new_id = header_file_id.clone();

        let (plaintext_size, encrypted_size, preserved_mtime) = self
            .rewrap_orphaned_file(
                &disk_path,
                pending.from_epoch,
                pending.to_epoch,
                pending.group_id,
            )
            .await?;

        // Update file metadata storage to reflect the new epoch
        let normalized_path = Self::normalize_storage_path(&pending.path);
        let existing_metadata = self
            .storage
            .load_file_metadata(&normalized_path)
            .await
            .map_err(ClientError::from)?;

        if let Some(mut metadata) = existing_metadata {
            // Update existing metadata
            metadata.epoch_id = pending.to_epoch;
            metadata.file_size = plaintext_size;
            metadata.encrypted_size = encrypted_size;
            metadata.modified_at = preserved_mtime.unwrap_or_else(Utc::now);
            metadata.file_id = Some(header_new_id.clone());
            // Recompute integrity hash would require decryption, skip for now

            self.storage
                .store_file_metadata(&normalized_path, &metadata)
                .await
                .map_err(ClientError::from)?;
        } else {
            // Create new metadata entry for orphaned file that had no metadata
            use crate::storage::{AccessControlData, FileMetadataData};

            let new_metadata = FileMetadataData {
                file_path: normalized_path.clone(),
                file_id: Some(header_new_id.clone()),
                group_id: Some(pending.group_id),
                epoch_id: pending.to_epoch,
                header_version: Some(1),
                wrapped_file_key: None,
                key_wrap_nonce: None,
                key_wrap_aad_hash: None,
                content_nonce: None,
                content_chunk_size: None,
                algorithm: "ChaCha20-Poly1305".to_string(),
                file_size: plaintext_size,
                modified_at: preserved_mtime.unwrap_or_else(Utc::now),
                integrity_hash: [0u8; 32], // Would need plaintext to compute
                permissions: AccessControlData {
                    readers: Vec::new(),
                    writers: Vec::new(),
                    is_public: true,
                },
                version: 1,
                chunks: Vec::new(),
                encrypted_size,
                encrypted_at: preserved_mtime.unwrap_or_else(Utc::now),
            };

            self.storage
                .store_file_metadata(&normalized_path, &new_metadata)
                .await
                .map_err(ClientError::from)?;
        }

        // Update coverage log entry (outside of the state lock to avoid deadlock)
        let normalized_pending_storage = Self::normalize_storage_path(&pending.path);

        if rekey_debug_enabled() {
            eprintln!("DEBUG coverage_replace: pending.path = {}", pending.path);
            eprintln!(
                "DEBUG coverage_replace: normalized_pending_storage = {}",
                normalized_pending_storage
            );
            eprintln!(
                "DEBUG coverage_replace: header.file_path = {}",
                header.file_path
            );
            eprintln!(
                "DEBUG coverage_replace: header_file_id = {}",
                header_file_id
            );
        }

        let coverage_old_ids: Vec<String> = {
            let state = self.state.read().await;
            let ledger = state
                .active_group_id
                .and_then(|gid| state.coverage_ledgers.get(&gid));

            let mut ids = Vec::new();
            if let Some(ledger) = ledger {
                if ledger.log.get_entry(&header_file_id).is_some() {
                    ids.push(header_file_id.clone());
                }

                if rekey_debug_enabled() {
                    eprintln!(
                        "DEBUG coverage_replace: coverage log has {} total entries; matched {} candidate IDs",
                        ledger.log.get_all_file_ids().len(),
                        ids.len()
                    );
                }
            }

            // Fallback: if neither candidate was present, still attempt the header ID so we at
            // least record the new epoch entry.
            if ids.is_empty() {
                if rekey_debug_enabled() {
                    eprintln!("DEBUG coverage_replace: No old IDs found in ledger, using header_file_id as fallback");
                }
                ids.push(header_file_id.clone());
            }

            if rekey_debug_enabled() {
                eprintln!(
                    "DEBUG coverage_replace: Will attempt to replace {} old ID(s): {:?}",
                    ids.len(),
                    ids
                );
            }

            ids
        };

        for old_id in coverage_old_ids {
            if let Err(err) = self
                .replace_coverage_for_file(
                    &old_id,
                    &header_new_id,
                    pending.to_epoch,
                    Some(pending.from_epoch),
                    Some(Utc::now()),
                )
                .await
            {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Failed to update coverage log for {} ({} -> {}): {}",
                        pending.path, pending.from_epoch, pending.to_epoch, err
                    ),
                    Some("rewrite_coverage_update"),
                );
            }
        }

        // Update file_index entry and migration bookkeeping
        let mut state = self.state.write().await;
        let root_match = state.coverage_roots.iter().find_map(|(id, root)| {
            disk_path.strip_prefix(&root.path).ok().map(|rel| {
                (
                    *id,
                    rel.to_string_lossy().trim_start_matches('/').to_string(),
                )
            })
        });

        if let Some(migration) = state.migration.as_mut() {
            if migration.to_epoch == pending.to_epoch {
                let normalized = Self::normalize_storage_path(&pending.path);
                migration.record_migrated_file(normalized);
            }
        }
        drop(state);

        if let Some((root_id, rel_path)) = root_match {
            if let Some(mut entry) = self
                .find_file_index_entry_for_root_path(root_id, &rel_path)
                .await?
            {
                entry.state = FileCoverageState::Tracked;
                entry.orphan_kind = None;
                entry.last_epoch = pending.to_epoch;
                entry.size = header.content_size;
                entry.last_seen = Utc::now();
                self.store_file_index_entry(&entry).await?;
            }
        }

        if rekey_debug_enabled() {
            eprintln!(
                "DEBUG idle_crawler: Completed rewrap {} -> epoch {}",
                pending.path, pending.to_epoch
            );
        }

        Ok(())
    }

    pub(in super::super) async fn synchronize_new_epoch(
        &self,
        operation: &ActiveRekeyOperation,
    ) -> Result<(), ClientError> {
        let Some(target_epoch_uuid) = operation.new_epoch_id else {
            return Ok(());
        };

        let Some(target_epoch_id) =
            EpochIdMapper::uuid_to_u64(target_epoch_uuid, operation.group_id.as_bytes())
        else {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Unable to derive client epoch identifier from descriptor {}",
                    target_epoch_uuid
                ),
                Some("epoch_mapping_failed"),
            );
            return Ok(());
        };

        let (active_group_matches, current_epoch_id, membership_epoch, have_epoch) = {
            let state = self.state.read().await;
            let active_match = state.active_group_id == Some(operation.group_id);
            let membership_epoch = state
                .group_memberships
                .get(&operation.group_id)
                .and_then(|m| m.current_epoch_id);
            let have_epoch =
                Self::get_epoch_state(&state, operation.group_id, target_epoch_id).is_some();
            (
                active_match,
                state.current_epoch,
                membership_epoch,
                have_epoch,
            )
        };

        if membership_epoch == Some(target_epoch_id) && have_epoch {
            return Ok(());
        }

        if !have_epoch {
            self.ensure_epoch_key_available(operation.group_id, target_epoch_id)
                .await?;
        }

        {
            let mut state = self.state.write().await;

            if let Some(membership) = state.group_memberships.get_mut(&operation.group_id) {
                membership.current_epoch_id = Some(target_epoch_id);
            }

            if let Some(entries) = state.epochs.get_mut(&target_epoch_id) {
                for epoch in entries
                    .iter_mut()
                    .filter(|e| e.group_id == Some(operation.group_id))
                {
                    epoch.is_active = true;
                }
            }

            if active_group_matches {
                if let Some(entries) = state.epochs.get_mut(&current_epoch_id) {
                    for epoch in entries
                        .iter_mut()
                        .filter(|e| e.group_id == Some(operation.group_id))
                    {
                        epoch.is_active = false;
                    }
                }

                let from_epoch = current_epoch_id;
                state.current_epoch = target_epoch_id;

                match state.migration.as_mut() {
                    Some(migration) if migration.to_epoch == target_epoch_id => {
                        migration.phase = MigrationPhase::Migrating;
                        migration.total_files = operation.progress.total_files;
                        migration.estimated_completion = operation
                            .progress
                            .estimated_time_remaining_minutes
                            .map(|mins| Utc::now() + chrono::Duration::minutes(mins as i64));
                    }
                    Some(migration) => {
                        migration.from_epoch = from_epoch;
                        migration.to_epoch = target_epoch_id;
                        migration.phase = MigrationPhase::Migrating;
                        migration.started_at = Utc::now();
                        migration.total_files = operation.progress.total_files;
                        migration.estimated_completion = operation
                            .progress
                            .estimated_time_remaining_minutes
                            .map(|mins| Utc::now() + chrono::Duration::minutes(mins as i64));
                        migration.clear_migrated_files();
                        migration.failed_files.clear();
                    }
                    None => {
                        state.migration = Some(MigrationState {
                            from_epoch,
                            to_epoch: target_epoch_id,
                            phase: MigrationPhase::Migrating,
                            migrated_files: Vec::new(),
                            migrated_files_set: HashSet::new(),
                            failed_files: Vec::new(),
                            total_files: operation.progress.total_files,
                            started_at: Utc::now(),
                            estimated_completion: operation
                                .progress
                                .estimated_time_remaining_minutes
                                .map(|mins| Utc::now() + chrono::Duration::minutes(mins as i64)),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    pub(in super::super) fn clear_migration_state_for_group(
        state: &mut ClientState,
        group_id: Uuid,
    ) {
        if state.migration.is_some() {
            state.migration = None;
        }

        if !state.pending_rewraps.is_empty() {
            state
                .pending_rewraps
                .retain(|task| task.group_id != group_id);
        }
    }

    /// Reset in-memory caches tied to a rekey operation so a new rekey starts from clean progress.
    pub(in super::super) fn reset_rekey_progress_state_locked(
        state: &mut ClientState,
        group_id: Uuid,
        previous_rekey: Option<Uuid>,
    ) {
        Self::clear_migration_state_for_group(state, group_id);
        if let Some(prev) = previous_rekey {
            state.rekey_heartbeats.remove(&prev);
        }
        let ledger = state.coverage_ledgers.entry(group_id).or_default();
        *ledger = CoverageLedgerState {
            skip_seed_once: true,
            ..CoverageLedgerState::default()
        };
    }

    /// Reset both in-memory and on-disk coverage/heartbeat state for a rekey.
    pub(in super::super) async fn reset_rekey_progress_state_async(
        &self,
        group_id: Uuid,
        previous_rekey: Option<Uuid>,
    ) -> Result<(), ClientError> {
        {
            let mut state = self.state.write().await;
            Self::reset_rekey_progress_state_locked(&mut state, group_id, previous_rekey);
        }

        // Persist an empty coverage log snapshot and compact deltas so future loads start clean.
        let empty_log = CoverageLog::new();
        if let Err(err) = self
            .persist_coverage_log_snapshot(group_id, empty_log, 0)
            .await
        {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Failed to reset coverage log snapshot for group {}: {}",
                    group_id, err
                ),
                Some("rekey_reset"),
            );
        } else if let Err(err) = self.compact_coverage_log_deltas(group_id, 0).await {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Failed to compact coverage log deltas for group {} during reset: {}",
                    group_id, err
                ),
                Some("rekey_reset"),
            );
        }

        Ok(())
    }

    pub(in super::super) async fn enqueue_opportunistic_rewrap(
        &self,
        path: &str,
        from_epoch: u64,
        to_epoch: u64,
    ) -> Result<(), ClientError> {
        if !self.config.migration_automation_enabled {
            return Ok(());
        }
        let normalized = Self::normalize_storage_path(path);
        let group_id = {
            let state = self.state.read().await;
            state
                .active_group_id
                .ok_or_else(|| ClientError::InvalidState("No active group selected".into()))?
        };

        let mut state = self.state.write().await;
        let already_pending = state
            .pending_rewraps
            .iter()
            .any(|entry| entry.path == normalized && entry.to_epoch == to_epoch);

        if !already_pending {
            state.pending_rewraps.push_back(PendingRewrap {
                path: normalized.clone(),
                from_epoch,
                to_epoch,
                group_id,
                attempts: 0,
                last_attempt: None,
            });
        }
        drop(state);

        self.ensure_idle_crawler().await;
        let _ = self.save_client_state().await;
        Ok(())
    }

    pub(in super::super) async fn rewrap_file_internal(
        &self,
        path: &str,
        from_epoch: u64,
        to_epoch: u64,
    ) -> Result<(), ClientError> {
        Self::validate_encrypt_path_label(path)?;

        if self.is_path_excluded(path) {
            return Err(ClientError::PathExcluded(path.to_string()));
        }

        if from_epoch == to_epoch {
            return Ok(());
        }

        let mut metadata = self
            .storage
            .load_file_metadata(path)
            .await
            .map_err(ClientError::from)?
            .ok_or_else(|| {
                ClientError::InvalidState(format!("File metadata not found for path: {path}"))
            })?;

        if metadata.epoch_id == to_epoch {
            return Ok(());
        }

        let group_id = {
            let state = self.state.read().await;
            state
                .active_group_id
                .ok_or_else(|| ClientError::InvalidState("No active group selected".into()))?
        };

        // Ensure KEKs for both epochs are available
        self.ensure_epoch_key_available(group_id, from_epoch)
            .await?;
        self.ensure_epoch_key_available(group_id, to_epoch).await?;

        let header_version = metadata.header_version.unwrap_or(1);
        let wrap_nonce_bytes = metadata
            .key_wrap_nonce
            .as_deref()
            .ok_or_else(|| ClientError::InvalidState("Missing key wrap nonce".to_string()))?;
        let wrap_nonce = AeadNonce::from_bytes(wrap_nonce_bytes)
            .map_err(|e| ClientError::DecryptionError(format!("Invalid key wrap nonce: {e:?}")))?;

        let wrapped_file_key = metadata.wrapped_file_key.as_ref().ok_or_else(|| {
            ClientError::InvalidState("Missing wrapped_file_key for rewrap".to_string())
        })?;

        let normalized_path = Self::normalize_file_identifier(path);
        let file_id = metadata
            .file_id
            .clone()
            .unwrap_or_else(|| normalized_path.clone());
        let wrap_aad = self.build_wrap_aad(
            &file_id,
            &normalized_path,
            group_id,
            from_epoch,
            header_version,
        );
        if let Some(expected_hash) = metadata.key_wrap_aad_hash.as_ref() {
            let actual = Sha256::digest(&wrap_aad).to_vec();
            if &actual != expected_hash {
                return Err(ClientError::DecryptionError(
                    "Key wrap AAD hash mismatch during rewrap".to_string(),
                ));
            }
        }

        // Unwrap DEK with old KEK
        let old_epoch_key = {
            let state = self.state.read().await;
            Self::get_epoch_state(&state, group_id, from_epoch)
                .ok_or_else(|| {
                    ClientError::InvalidState(format!(
                        "Epoch {from_epoch} not available for rewrap"
                    ))
                })?
                .encryption_key
        };
        let old_kek_bytes =
            hkdf_expand(&old_epoch_key, HkdfContext::KeyWrapping, 32).map_err(|e| {
                ClientError::DecryptionError(format!("HKDF(KeyWrapping) failed: {:?}", e))
            })?;
        let old_kek = AeadKey::from_bytes(&old_kek_bytes)
            .map_err(|e| ClientError::DecryptionError(format!("Invalid old KEK: {e:?}")))?;

        let file_key_bytes = open(
            &old_kek,
            &wrap_nonce,
            AeadContext::FileData,
            &wrap_aad,
            wrapped_file_key,
        )
        .map_err(|e| ClientError::DecryptionError(format!("Key unwrap failed: {e:?}")))?;

        // Wrap DEK with new KEK
        let new_kek_bytes = {
            let state = self.state.read().await;
            let epoch = Self::get_epoch_state(&state, group_id, to_epoch).ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Target epoch {to_epoch} not available after synchronization"
                ))
            })?;
            hkdf_expand(&epoch.encryption_key, HkdfContext::KeyWrapping, 32).map_err(|e| {
                ClientError::EncryptionError(format!("HKDF(KeyWrapping) failed: {e:?}"))
            })?
        };
        let new_kek = AeadKey::from_bytes(&new_kek_bytes)
            .map_err(|e| ClientError::EncryptionError(format!("Invalid new KEK: {e:?}")))?;

        let new_wrap_aad = self.build_wrap_aad(
            &file_id,
            &normalized_path,
            group_id,
            to_epoch,
            header_version,
        );
        let new_wrap_aad_hash = hash_wrap_aad(&new_wrap_aad);
        let file_key = AeadKey::from_bytes(&file_key_bytes)
            .map_err(|e| ClientError::EncryptionError(format!("Invalid DEK: {e:?}")))?;
        let (new_wrapped_key, new_wrap_nonce_bytes) =
            wrap_file_key(&file_key, &new_kek, &new_wrap_aad)
                .map_err(|e| ClientError::EncryptionError(format!("Key wrap failed: {e:?}")))?;

        // Update metadata only; ciphertext stays intact
        metadata.epoch_id = to_epoch;
        metadata.header_version = Some(header_version);
        metadata.wrapped_file_key = Some(new_wrapped_key);
        metadata.key_wrap_nonce = Some(new_wrap_nonce_bytes.clone());
        metadata.key_wrap_aad_hash = Some(new_wrap_aad_hash);
        metadata.modified_at = Utc::now();
        metadata.file_id = Some(file_id.clone());

        self.storage
            .store_file_metadata(path, &metadata)
            .await
            .map_err(ClientError::from)?;

        self.update_file_pending_flag(path, false).await?;
        self.replace_coverage_for_file(
            &file_id,
            &file_id,
            to_epoch,
            Some(from_epoch),
            Some(Utc::now()),
        )
        .await?;

        // Refresh file_index entry to reflect the new epoch and size so future scans use
        // the updated epoch for coverage reconciliation.
        let root_match = {
            let state = self.state.read().await;
            state.coverage_roots.iter().find_map(|(id, root)| {
                PathBuf::from(path)
                    .strip_prefix(&root.path)
                    .ok()
                    .map(|rel| {
                        (
                            *id,
                            rel.to_string_lossy().trim_start_matches('/').to_string(),
                        )
                    })
            })
        };

        if let Some((root_id, rel_path)) = root_match {
            if let Some(mut entry) = self
                .find_file_index_entry_for_root_path(root_id, &rel_path)
                .await?
            {
                entry.last_epoch = to_epoch;
                entry.size = metadata.file_size;
                entry.last_seen = metadata.modified_at;
                entry.state = FileCoverageState::Tracked;
                entry.orphan_kind = None;
                self.store_file_index_entry(&entry).await?;
            }
        }

        let normalized = Self::normalize_storage_path(path);
        {
            let mut state = self.state.write().await;
            if let Some(migration) = state.migration.as_mut() {
                if migration.to_epoch == to_epoch {
                    migration.record_migrated_file(normalized.clone());
                }
            }
        }

        Ok(())
    }

    /// Rewrap an orphaned encrypted file directly on disk (in-memory decrypt/encrypt, no plaintext on disk)
    pub(in super::super) async fn rewrap_orphaned_file(
        &self,
        disk_path: &Path,
        from_epoch: u64,
        to_epoch: u64,
        group_id: Uuid,
    ) -> Result<(u64, u64, Option<DateTime<Utc>>), ClientError> {
        use hybridcipher_crypto::kdf::{hkdf_expand, HkdfContext};

        let preserved_times = Self::capture_file_times(disk_path);
        let original_mtime = preserved_times.map(|(_, _, ts)| ts);
        let parent_dir = disk_path.parent().map(|p| p.to_path_buf());
        let parent_mtime = parent_dir
            .as_ref()
            .and_then(|dir| Self::capture_directory_mtime(dir));

        let encrypted_file_bytes =
            tokio::fs::read(disk_path)
                .await
                .map_err(|e| ClientError::FileError {
                    context: ErrorContext::new(
                        ErrorCode::StorageRead,
                        format!("Failed to read encrypted file: {}", e),
                        "rewrap_orphaned_file".to_string(),
                    ),
                    file_path: disk_path.display().to_string(),
                    file_size: None,
                })?;

        let sep_pos = encrypted_file_bytes
            .windows(ENCRYPTED_FILE_SEPARATOR.len())
            .position(|w| w == ENCRYPTED_FILE_SEPARATOR)
            .ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Encrypted file {} has no separator",
                    disk_path.display()
                ))
            })?;

        let header_bytes = &encrypted_file_bytes[..sep_pos];
        let old_ciphertext_with_nonce =
            &encrypted_file_bytes[sep_pos + ENCRYPTED_FILE_SEPARATOR.len()..];

        let mut header_json: serde_json::Value =
            serde_json::from_slice(header_bytes).map_err(|e| {
                ClientError::InvalidState(format!("Failed to parse header JSON: {}", e))
            })?;
        let metadata = Self::parse_encrypted_metadata_from_parts(
            disk_path,
            &header_json,
            old_ciphertext_with_nonce.to_vec(),
        )
        .ok_or_else(|| {
            ClientError::InvalidState(format!(
                "Missing required header fields for {}",
                disk_path.display()
            ))
        })?;

        let header_group = metadata.group_id.unwrap_or(group_id);
        if let Some(stored_group) = metadata.group_id {
            if stored_group != group_id {
                return Err(ClientError::InvalidState(format!(
                    "Encrypted file {} belongs to group {} but active group is {}",
                    disk_path.display(),
                    stored_group,
                    group_id
                )));
            }
        }

        let header_epoch = metadata.epoch_id;
        let header_version = metadata.header_version.unwrap_or(1);
        if from_epoch != header_epoch {
            self.logger.log(
                crate::logging::LogLevel::Debug,
                &format!(
                    "Using epoch {} from ciphertext header instead of requested {} for {}",
                    header_epoch,
                    from_epoch,
                    disk_path.display()
                ),
                Some("rewrap_epoch_source"),
            );
        }
        let wrap_nonce_bytes = metadata.key_wrap_nonce.clone().ok_or_else(|| {
            ClientError::InvalidState("Missing key_wrap_nonce in header".to_string())
        })?;
        let wrapped_file_key = metadata.wrapped_file_key.clone().ok_or_else(|| {
            ClientError::InvalidState("Missing wrapped_file_key in header".to_string())
        })?;
        let key_wrap_aad_hash = metadata.key_wrap_aad_hash.clone();

        let wrap_nonce = AeadNonce::from_bytes(&wrap_nonce_bytes)
            .map_err(|e| ClientError::DecryptionError(format!("Invalid key wrap nonce: {}", e)))?;

        if header_epoch == to_epoch {
            return Ok((0, 0, original_mtime));
        }

        if old_ciphertext_with_nonce.len() < 12 {
            return Err(ClientError::InvalidState(
                "Encrypted payload shorter than nonce".to_string(),
            ));
        }

        self.ensure_epoch_key_available(header_group, header_epoch)
            .await?;
        self.ensure_epoch_key_available(header_group, to_epoch)
            .await?;

        let wrap_aad = Self::compute_wrap_aad_bytes(
            &metadata.file_id,
            &metadata.file_path,
            header_group,
            header_epoch,
            header_version,
        );
        if let Some(expected) = key_wrap_aad_hash.as_ref() {
            let actual = Sha256::digest(&wrap_aad).to_vec();
            if &actual != expected {
                return Err(ClientError::DecryptionError(
                    "Key wrap AAD hash mismatch".to_string(),
                ));
            }
        }

        let old_epoch_key = {
            let state = self.state.read().await;
            Self::get_epoch_state(&state, header_group, header_epoch)
                .ok_or_else(|| {
                    ClientError::InvalidState(format!(
                        "Epoch {} not available for group {}",
                        header_epoch, header_group
                    ))
                })?
                .encryption_key
        };
        let old_kek_bytes = hkdf_expand(&old_epoch_key, HkdfContext::KeyWrapping, 32)
            .map_err(|e| ClientError::DecryptionError(format!("HKDF failed for old key: {}", e)))?;
        let old_kek = AeadKey::from_bytes(&old_kek_bytes)
            .map_err(|e| ClientError::DecryptionError(format!("Invalid old KEK: {}", e)))?;
        let file_key_bytes = open(
            &old_kek,
            &wrap_nonce,
            AeadContext::FileData,
            &wrap_aad,
            &wrapped_file_key,
        )
        .map_err(|e| ClientError::DecryptionError(format!("Key unwrap failed: {}", e)))?;

        let new_epoch_key = {
            let state = self.state.read().await;
            Self::get_epoch_state(&state, header_group, to_epoch)
                .ok_or_else(|| {
                    ClientError::InvalidState(format!(
                        "Epoch {} not available for group {}",
                        to_epoch, header_group
                    ))
                })?
                .encryption_key
        };
        let new_kek_bytes = hkdf_expand(&new_epoch_key, HkdfContext::KeyWrapping, 32)
            .map_err(|e| ClientError::EncryptionError(format!("HKDF failed for new key: {}", e)))?;
        let new_kek = AeadKey::from_bytes(&new_kek_bytes)
            .map_err(|e| ClientError::EncryptionError(format!("Invalid new KEK: {}", e)))?;

        let new_wrap_aad = Self::compute_wrap_aad_bytes(
            &metadata.file_id,
            &metadata.file_path,
            header_group,
            to_epoch,
            header_version,
        );
        let new_wrap_aad_hash = hash_wrap_aad(&new_wrap_aad);
        let file_key = AeadKey::from_bytes(&file_key_bytes)
            .map_err(|e| ClientError::EncryptionError(format!("Invalid DEK: {}", e)))?;
        let (new_wrapped_key, new_wrap_nonce_bytes) =
            wrap_file_key(&file_key, &new_kek, &new_wrap_aad).map_err(|e| {
                ClientError::EncryptionError(format!(
                    "Failed to wrap DEK for epoch {}: {}",
                    to_epoch, e
                ))
            })?;

        let now_ts = Utc::now().to_rfc3339();
        header_json["epoch_id"] = serde_json::json!(to_epoch);
        header_json["encrypted_at"] = serde_json::json!(now_ts);
        header_json["header_version"] = serde_json::json!(header_version);
        header_json["group_id"] = serde_json::json!(header_group.to_string());
        header_json["wrapped_file_key"] =
            serde_json::json!(general_purpose::STANDARD.encode(&new_wrapped_key));
        header_json["key_wrap_nonce"] =
            serde_json::json!(general_purpose::STANDARD.encode(&new_wrap_nonce_bytes));
        header_json["key_wrap_aad_hash"] =
            serde_json::json!(general_purpose::STANDARD.encode(&new_wrap_aad_hash));
        if header_json.get("file_size").is_none() {
            header_json["file_size"] = serde_json::json!(metadata.content_size);
        }

        let new_header_bytes = serde_json::to_vec_pretty(&header_json)
            .map_err(|e| ClientError::InvalidState(format!("Failed to serialize header: {}", e)))?;

        let mut new_file_bytes = Vec::with_capacity(
            new_header_bytes.len()
                + ENCRYPTED_FILE_SEPARATOR.len()
                + old_ciphertext_with_nonce.len(),
        );
        new_file_bytes.extend_from_slice(&new_header_bytes);
        new_file_bytes.extend_from_slice(ENCRYPTED_FILE_SEPARATOR);
        new_file_bytes.extend_from_slice(old_ciphertext_with_nonce);

        let temp_path = disk_path.with_extension("encrypted.tmp");
        tokio::fs::write(&temp_path, &new_file_bytes)
            .await
            .map_err(|e| ClientError::FileError {
                context: ErrorContext::new(
                    ErrorCode::StorageWrite,
                    format!("Failed to write temp file: {}", e),
                    "rewrap_orphaned_file".to_string(),
                ),
                file_path: temp_path.display().to_string(),
                file_size: Some(new_file_bytes.len() as u64),
            })?;

        tokio::fs::rename(&temp_path, disk_path)
            .await
            .map_err(|e| ClientError::FileError {
                context: ErrorContext::new(
                    ErrorCode::StorageWrite,
                    format!("Failed to rename temp file: {}", e),
                    "rewrap_orphaned_file".to_string(),
                ),
                file_path: disk_path.display().to_string(),
                file_size: None,
            })?;

        if let Some((atime, mtime, _)) = preserved_times.as_ref() {
            Self::restore_file_times(disk_path, *atime, *mtime)?;
        }

        if let Some(dir) = parent_dir.as_deref() {
            Self::restore_directory_mtime(dir, parent_mtime);
        }

        Ok((
            old_ciphertext_with_nonce.len() as u64,
            new_file_bytes.len() as u64,
            original_mtime,
        ))
    }

    pub(in super::super) async fn update_file_pending_flag(
        &self,
        path: &str,
        pending: bool,
    ) -> Result<(), ClientError> {
        self.logger.log(
            crate::logging::LogLevel::Debug,
            &format!(
                "Marked file {} as {} for rewrap scheduling",
                path,
                if pending { "pending" } else { "complete" }
            ),
            Some("rewrap_pending_flag"),
        );
        Ok(())
    }

    pub(in super::super) async fn maybe_schedule_rewrap(&self, path: &str, from_epoch: u64) {
        let migration = {
            let state = self.state.read().await;
            state
                .migration
                .as_ref()
                .filter(|m| m.to_epoch != from_epoch)
                .cloned()
        };

        if let Some(migration) = migration {
            if let Err(err) = self
                .enqueue_opportunistic_rewrap(path, from_epoch, migration.to_epoch)
                .await
            {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Failed to enqueue opportunistic rewrap for {}: {}",
                        path, err
                    ),
                    Some("enqueue_rewrap_failed"),
                );
            }
        }
    }
}
