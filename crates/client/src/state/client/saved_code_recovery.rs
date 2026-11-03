use super::*;
use crate::saved_code_recovery::{RecoveryInstallResult, ValidatedRecovery};

impl<S: Storage, N: Network> Client<S, N> {
    /// Fetch the server's committed Welcome without initializing a new epoch.
    pub async fn refresh_committed_group_epoch(&self, group_id: Uuid) -> Result<u64, ClientError> {
        self.ensure_state_loaded().await?;
        self.fetch_committed_group_epoch(group_id).await
    }

    /// Select only the verified key matching authoritative current metadata.
    pub async fn use_group_at_epoch(
        &self,
        group_id: Uuid,
        current_epoch_uuid: Uuid,
    ) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;
        {
            let mut state = self.state.write().await;
            let selected = state
                .epochs
                .iter()
                .find_map(|(number, entries)| {
                    (EpochIdMapper::u64_to_uuid(*number, group_id.as_bytes()) == current_epoch_uuid
                        && entries.iter().any(|epoch| {
                            epoch.group_id == Some(group_id) && epoch.key_source.is_verified()
                        }))
                    .then_some(*number)
                })
                .ok_or_else(|| {
                    initialization::setup_error(
                        ErrorCode::GroupStateMissing,
                        "The current group encryption key is not available on this device",
                    )
                })?;
            // The caller confirmed this group's authoritative epoch. A fresh
            // Welcome can exist before paginated membership metadata is cached.
            let membership =
                state
                    .group_memberships
                    .entry(group_id)
                    .or_insert_with(|| GroupMembership {
                        group_id,
                        group_name: group_id.to_string(),
                        group_description: None,
                        user_role: GroupRole::Member,
                        joined_at: Utc::now(),
                        current_epoch_id: Some(selected),
                        last_sync: Utc::now(),
                        members: Vec::new(),
                    });
            membership.current_epoch_id = Some(selected);
            for (number, entries) in &mut state.epochs {
                for epoch in entries
                    .iter_mut()
                    .filter(|epoch| epoch.group_id == Some(group_id))
                {
                    epoch.is_active = *number == selected;
                }
            }
        }
        self.use_group(group_id).await?;
        self.save_client_state_now().await
    }

    /// Register this device's own Welcome for each recovered group whose current key is
    /// installed, so the server never re-flags the recovered device as awaiting approval.
    /// Returns the groups that could not be registered.
    pub async fn publish_recovered_self_welcomes(
        &self,
        ready_groups: &[Uuid],
    ) -> Result<Vec<Uuid>, ClientError> {
        let session = self.get_session_info().await?;
        let user_id = session
            .user_id
            .ok_or_else(|| ClientError::InvalidState("Authenticated account is missing.".into()))?;
        let server_base_url = Self::resolve_server_base_url(session.server_url.clone());
        let mut failed = Vec::new();
        for group_id in ready_groups {
            if let Err(err) = self
                .publish_self_welcome(*group_id, user_id, &server_base_url, &session.token)
                .await
            {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Failed to register recovered Welcome: {}", err),
                    Some(&format!("group_id: {}", group_id)),
                );
                failed.push(*group_id);
            }
        }
        Ok(failed)
    }

    /// Check a verified key against the server's exact current epoch UUID.
    pub async fn has_cached_group_epoch_key(
        &self,
        group_id: Uuid,
        current_epoch_uuid: Uuid,
    ) -> Result<bool, ClientError> {
        self.ensure_state_loaded().await?;
        let state = self.state.read().await;
        Ok(state.epochs.iter().any(|(number, entries)| {
            EpochIdMapper::u64_to_uuid(*number, group_id.as_bytes()) == current_epoch_uuid
                && entries
                    .iter()
                    .any(|epoch| epoch.group_id == Some(group_id) && epoch.key_source.is_verified())
        }))
    }

    /// Check local verified-key conflicts before requesting server trust changes.
    pub async fn validate_authenticated_recovery(
        &self,
        recovery: &ValidatedRecovery,
    ) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;
        let state = self.state.read().await;
        for (group_id, epoch) in &recovery.all_epochs {
            if Self::get_epoch_state(&state, *group_id, epoch.number).is_some_and(|existing| {
                existing.key_source.is_locally_usable() && existing.encryption_key != *epoch.key
            }) {
                return Err(initialization::setup_error(
                    ErrorCode::SecurityTampering,
                    "Recovery encryption key conflicts with a locally verified epoch",
                ));
            }
        }
        Ok(())
    }
    /// Install authenticated recovery keys without trusting arbitrary plaintext imports.
    /// Validate the whole batch and persist its staged state before exposing new keys.
    pub async fn install_authenticated_recovery(
        &self,
        recovery: &ValidatedRecovery,
    ) -> Result<RecoveryInstallResult, ClientError> {
        self.ensure_state_loaded().await?;
        let mut state = self.state.write().await;
        for (group_id, epoch) in &recovery.all_epochs {
            if Self::get_epoch_state(&state, *group_id, epoch.number).is_some_and(|existing| {
                existing.key_source.is_locally_usable() && existing.encryption_key != *epoch.key
            }) {
                return Err(initialization::setup_error(
                    ErrorCode::SecurityTampering,
                    "Recovery encryption key conflicts with a locally verified epoch",
                ));
            }
        }

        let mut epochs = state.epochs.clone();
        let mut memberships = state.group_memberships.clone();
        let mut current_epoch = state.current_epoch;
        let mut result = RecoveryInstallResult {
            imported_epochs: 0,
            ready_groups: Vec::new(),
            missing_current_groups: Vec::new(),
        };
        for group in &recovery.groups {
            let group_id = group.scope.group_id;
            // Server metadata is authoritative even for older locally cached
            // epochs that were not present in this particular backup.
            for (number, entries) in &mut epochs {
                let active = Some(EpochIdMapper::u64_to_uuid(*number, group_id.as_bytes()))
                    == group.scope.current_epoch_uuid;
                for epoch in entries
                    .iter_mut()
                    .filter(|epoch| epoch.group_id == Some(group_id))
                {
                    epoch.is_active = active;
                }
            }
            for recovered in &group.epochs {
                let entries = epochs.entry(recovered.number).or_default();
                let existing = entries
                    .iter_mut()
                    .find(|epoch| epoch.group_id == Some(group_id));
                let active = Some(recovered.uuid) == group.scope.current_epoch_uuid;
                match existing {
                    Some(epoch) => {
                        if !epoch.key_source.is_verified() {
                            epoch.encryption_key = *recovered.key;
                            epoch.key_source = EpochKeySource::Recovery;
                        }
                        epoch.is_active = active;
                    }
                    None => entries.push(EpochState {
                        group_id: Some(group_id),
                        epoch_id: recovered.number,
                        encryption_key: *recovered.key,
                        key_source: EpochKeySource::Recovery,
                        members: Vec::new(),
                        created_at: recovered.created_at,
                        is_active: active,
                        file_count: 0,
                        marked_for_removal: false,
                        removal_eligible_at: None,
                    }),
                }
                result.imported_epochs += 1;
            }
            let selected = epochs.iter().find_map(|(number, entries)| {
                let mapped = EpochIdMapper::u64_to_uuid(*number, group_id.as_bytes());
                entries
                    .iter()
                    .find(|epoch| {
                        epoch.group_id == Some(group_id)
                            && epoch.key_source.is_verified()
                            && Some(mapped) == group.scope.current_epoch_uuid
                    })
                    .map(|_| *number)
            });
            if let Some(number) = selected {
                if let Some(epoch) = epochs.get_mut(&number).and_then(|entries| {
                    entries
                        .iter_mut()
                        .find(|epoch| epoch.group_id == Some(group_id))
                }) {
                    epoch.is_active = true;
                }
                result.ready_groups.push(group_id);
            } else {
                result.missing_current_groups.push(group_id);
            }
            let membership = memberships
                .entry(group_id)
                .or_insert_with(|| GroupMembership {
                    group_id,
                    group_name: group.scope.group_name.clone(),
                    group_description: None,
                    user_role: group.scope.user_role.clone(),
                    joined_at: Utc::now(),
                    current_epoch_id: selected,
                    last_sync: Utc::now(),
                    members: Vec::new(),
                });
            membership.group_name = group.scope.group_name.clone();
            membership.user_role = group.scope.user_role.clone();
            membership.current_epoch_id = selected;
            membership.last_sync = Utc::now();
            if state.active_group_id == Some(group_id) {
                current_epoch = selected.unwrap_or(0);
            }
        }

        let generation = state.state_generation.saturating_add(1);
        let snapshot = SerializableClientState {
            epochs: epochs.clone(),
            current_epoch,
            active_group_id: state.active_group_id,
            migration: state.migration.clone(),
            active_rekey: state.active_rekey.clone(),
            rekey_heartbeats: state.rekey_heartbeats.clone(),
            pending_rewraps: state.pending_rewraps.clone(),
            coverage_roots: state.coverage_roots.clone(),
            coverage_ledgers_meta: {
                let mut meta = state.coverage_ledgers_meta.clone();
                for (id, ledger) in &state.coverage_ledgers {
                    meta.insert(*id, ledger.to_meta());
                }
                meta
            },
            state_generation: generation,
            last_sync: Utc::now(),
            version: state.version,
            group_memberships: memberships.clone(),
            auth_credentials: state.auth_credentials.clone(),
            invitation_keypair: state.invitation_keypair.clone(),
            last_retention_warning: state.last_retention_warning.clone(),
            last_retention_purge_warning: state.last_retention_purge_warning.clone(),
        };
        let serialized = zeroize::Zeroizing::new(
            serde_json::to_string(&snapshot)
                .map_err(|error| ClientError::InvalidState(error.to_string()))?,
        );
        self.storage
            .store_config("client_state", &serialized)
            .await?;
        state.epochs = epochs;
        state.group_memberships = memberships;
        state.current_epoch = current_epoch;
        state.state_generation = generation;
        state.last_sync = snapshot.last_sync;
        self.state_save.mark_saved();
        Ok(result)
    }
}

#[cfg(test)]
#[path = "../../../tests/recovery/test_saved_code_install.rs"]
mod tests;
