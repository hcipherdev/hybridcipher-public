use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// Save current client state to persistent storage
    pub(super) async fn save_client_state(&self) -> Result<(), ClientError> {
        if self.should_defer_state_save().await {
            self.metrics.increment_counter("client_state.save_deferred");
            self.defer_state_save();
            return Ok(());
        }
        self.save_client_state_now().await
    }

    pub(super) async fn save_client_state_now(&self) -> Result<(), ClientError> {
        let start = Instant::now();
        let (state_json, epoch_count) = {
            let mut state = self.state.write().await;
            let epoch_count = state.epochs.len();
            state.state_generation = state.state_generation.saturating_add(1);

            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!("Saving client state with {} epochs", epoch_count),
                None,
            );

            // Create a serializable version of the state (excluding coverage_log which is not serializable)
            let serializable_state = SerializableClientState {
                epochs: state.epochs.clone(),
                current_epoch: state.current_epoch,
                active_group_id: state.active_group_id,
                migration: state.migration.clone(),
                active_rekey: state.active_rekey.clone(),
                rekey_heartbeats: state.rekey_heartbeats.clone(),
                pending_rewraps: state.pending_rewraps.clone(),
                coverage_roots: state.coverage_roots.clone(),
                coverage_ledgers_meta: {
                    let mut meta = state.coverage_ledgers_meta.clone();
                    for (gid, ledger) in state.coverage_ledgers.iter() {
                        meta.insert(*gid, ledger.to_meta());
                    }
                    meta
                },
                state_generation: state.state_generation,
                last_sync: state.last_sync,
                version: state.version,
                group_memberships: state.group_memberships.clone(),
                auth_credentials: state.auth_credentials.clone(),
                invitation_keypair: state.invitation_keypair.clone(),
                last_retention_warning: state.last_retention_warning.clone(),
                last_retention_purge_warning: state.last_retention_purge_warning.clone(),
            };

            let state_json = serde_json::to_string(&serializable_state).map_err(|e| {
                ClientError::InvalidState(format!("Failed to serialize client state: {}", e))
            })?;

            (state_json, epoch_count)
        };

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Serialized client state: {} bytes", state_json.len()),
            None,
        );

        self.storage
            .store_config("client_state", &state_json)
            .await
            .map_err(|e| {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!("Failed to store client state: {}", e),
                    None,
                );
                ClientError::storage_error(
                    ErrorCode::StorageWrite,
                    format!("Failed to save client state: {}", e),
                    "save_client_state".to_string(),
                    None,
                    false,
                )
            })?;

        self.state_save.mark_saved();
        self.metrics
            .record_operation_latency("client_state_save", start.elapsed());
        self.metrics.increment_counter("client_state.save");

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Client state saved successfully ({} epochs persisted)",
                epoch_count
            ),
            None,
        );
        Ok(())
    }

    pub(super) async fn should_defer_state_save(&self) -> bool {
        if self.config.state_save_debounce_ms == 0 {
            return false;
        }

        let bulk_depth = {
            let state = self.coverage_compaction.lock().await;
            state.bulk_depth
        };

        bulk_depth > 0
    }

    pub(super) fn defer_state_save(&self) {
        self.state_save.mark_pending();
        self.schedule_state_save();
    }

    pub(super) fn schedule_state_save(&self) {
        if !self.state_save.try_schedule() {
            return;
        }

        let client = self.clone();
        tokio::spawn(async move {
            let delay = client.state_save.next_delay();
            if !delay.is_zero() {
                sleep(delay).await;
            }

            if client.state_save.take_pending() {
                if let Err(err) = client.save_client_state_now().await {
                    client.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Deferred state save failed: {}", err),
                        Some("state_save_deferred"),
                    );
                }
            }

            client.state_save.clear_scheduled();
            if client.state_save.has_pending() {
                client.schedule_state_save();
            }
        });
    }

    pub(super) async fn flush_deferred_state_save(&self) {
        if !self.state_save.has_pending() {
            return;
        }

        self.metrics.increment_counter("client_state.save_flush");
        if let Err(err) = self.save_client_state_now().await {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Deferred state save flush failed: {}", err),
                Some("state_save_flush"),
            );
        }
    }

    pub(super) async fn reload_state_if_stale(
        &self,
        current_generation: u64,
    ) -> Result<(), ClientError> {
        let now = Instant::now();
        if let Some(cached_generation) = {
            let cache = self.state_reload_cache.lock().await;
            cache.last_checked_at.and_then(|last| {
                if now.duration_since(last) < STATE_RELOAD_CACHE_TTL {
                    cache.cached_generation
                } else {
                    None
                }
            })
        } {
            if cached_generation > current_generation {
                self.load_client_state().await?;
            }
            return Ok(());
        }

        let stored_state = self
            .storage
            .load_config_fresh("client_state")
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageRead,
                    format!("Failed to check client state generation: {}", e),
                    "client_state_generation_check".to_string(),
                    None,
                    false,
                )
            })?;

        let Some(state_json) = stored_state else {
            let mut cache = self.state_reload_cache.lock().await;
            cache.last_checked_at = Some(now);
            cache.cached_generation = Some(current_generation);
            return Ok(());
        };

        // Parse as full SerializableClientState to handle both legacy snapshots
        // and current full state format. This prevents "trailing characters" errors
        // when the mount daemon tries to read state written by CLI during rekey.
        let stored_generation =
            if let Ok(full_state) = serde_json::from_str::<SerializableClientState>(&state_json) {
                full_state.state_generation
            } else if let Ok(snapshot) =
                serde_json::from_str::<ClientStateGenerationSnapshot>(&state_json)
            {
                // Fallback for legacy format
                snapshot.state_generation
            } else {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    "Failed to parse client state during reload; using in-memory state",
                    Some("client_state_generation_parse"),
                );
                let mut cache = self.state_reload_cache.lock().await;
                cache.last_checked_at = Some(now);
                cache.cached_generation = Some(current_generation);
                return Ok(());
            };

        {
            let mut cache = self.state_reload_cache.lock().await;
            cache.last_checked_at = Some(now);
            cache.cached_generation = Some(stored_generation);
        }

        if stored_generation > current_generation {
            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!(
                    "Reloading client state (generation {} -> {})",
                    current_generation, stored_generation
                ),
                Some("client_state_generation_reload"),
            );
            self.load_client_state().await?;
        }

        Ok(())
    }

    /// Load client state from persistent storage
    pub(super) async fn load_client_state(&self) -> Result<(), ClientError> {
        match self.storage.load_config_fresh("client_state").await {
            Ok(Some(state_json)) => {
                let serializable_state: SerializableClientState =
                    match serde_json::from_str(&state_json) {
                        Ok(state) => state,
                        Err(err) => {
                            log::warn!(
                                "Failed to deserialize client state: {}, starting fresh",
                                err
                            );
                            return Ok(());
                        }
                    };

                let mut state = self.state.write().await;
                state.epochs = serializable_state.epochs;
                state.current_epoch = serializable_state.current_epoch;
                state.active_group_id = serializable_state.active_group_id;
                state.migration = serializable_state.migration;
                if let Some(migration) = state.migration.as_mut() {
                    migration.rebuild_migrated_cache();
                }
                state.active_rekey = serializable_state.active_rekey;
                state.rekey_heartbeats = serializable_state.rekey_heartbeats;
                state.pending_rewraps = serializable_state.pending_rewraps;
                state.coverage_roots = serializable_state.coverage_roots;
                state.coverage_ledgers_meta = serializable_state.coverage_ledgers_meta;
                // coverage_ledgers intentionally lazy-loaded; do not reconstruct here.
                state.state_generation = serializable_state.state_generation;
                state.last_sync = serializable_state.last_sync;
                state.version = serializable_state.version;
                state.group_memberships = serializable_state.group_memberships;
                state.auth_credentials = serializable_state.auth_credentials;
                state.invitation_keypair = serializable_state.invitation_keypair;
                state.last_retention_warning = serializable_state.last_retention_warning;
                state.last_retention_purge_warning =
                    serializable_state.last_retention_purge_warning;
                state.welcome_signing_keys.clear();

                log::info!("Loaded client state with {} epochs", state.epochs.len());
                Ok(())
            }
            Ok(None) => {
                log::info!("No saved client state found, starting fresh");
                Ok(())
            }
            Err(e) => {
                log::warn!("Failed to load client state: {}, starting fresh", e);
                Ok(())
            }
        }
    }

    /// Ensure client state is loaded (call this at the start of operations)
    ///
    /// This method is protected by a mutex to prevent concurrent state file access,
    /// which could cause corruption or parsing errors during bulk operations.
    pub async fn ensure_state_loaded(&self) -> Result<(), ClientError> {
        // Serialize state loading to prevent concurrent file access
        let _guard = self.state_loading.lock().await;

        let (has_state, current_generation) = {
            let state = self.state.read().await;
            (
                !state.epochs.is_empty() || state.current_epoch > 0,
                state.state_generation,
            )
        };

        if !has_state {
            self.load_client_state().await?;
        } else {
            self.reload_state_if_stale(current_generation).await?;
        }

        // Load coverage log lazily for the active group when needed.
        if self.state.read().await.active_group_id.is_some() {
            self.ensure_coverage_log_loaded().await?;
        }

        Ok(())
    }
}
