use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// Add a new member to the group.
    ///
    /// The offline client cannot currently coordinate membership changes without
    /// the server-side workflows. This method therefore reports an error so callers
    /// can fall back to the network-enabled path instead of working with placeholder data.
    pub async fn add_member(
        &self,
        join_card: MessagesJoinCard,
    ) -> Result<AddMemberResult, ClientError> {
        let _ = join_card;
        Err(ClientError::InvalidState(
            "Offline member addition is not supported in this release. Use the server API or CLI command that targets the server."
                .to_string(),
        ))
    }

    /// Remove a member from the group.
    ///
    /// The offline client does not support member removal without the coordination
    /// services that run on the server. Callers should use the server-facing workflow,
    /// and this method returns an explanatory error instead of emitting placeholder updates.
    pub async fn remove_member(
        &self,
        member_id: String,
        historical_revocation: bool,
    ) -> Result<RemoveMemberResult, ClientError> {
        let _ = (member_id, historical_revocation);
        Err(ClientError::InvalidState(
            "Offline member removal is not supported in this release. Use the server API or CLI command that targets the server."
                .to_string(),
        ))
    }

    /// Verify that a new member has been successfully integrated
    ///
    /// This checks that:
    /// - The member appears in the current epoch state
    /// - The member has proper cryptographic keys
    /// - The member can participate in group operations
    ///
    /// # Arguments
    /// * `member_id` - ID of the member to verify
    ///
    /// # Returns
    /// True if member is properly integrated, false otherwise
    pub async fn verify_new_member_integration(
        &self,
        member_id: &str,
    ) -> Result<bool, ClientError> {
        let state = self.state.read().await;
        let active_group = state.active_group_id.ok_or_else(|| {
            ClientError::InvalidState(
                "No active group selected. Run 'hybridcipher switch-group <group-id>' first."
                    .to_string(),
            )
        })?;

        let current_epoch_state = state
            .epochs
            .get(&state.current_epoch)
            .and_then(|entries| entries.iter().find(|e| e.group_id == Some(active_group)))
            .ok_or_else(|| ClientError::InvalidState("Current epoch not found".to_string()))?;

        let target_member_id = Uuid::parse_str(member_id).map_err(|_| {
            ClientError::InvalidState(format!("Invalid member identifier provided: {member_id}"))
        })?;

        for member in &current_epoch_state.members {
            if let Some(uuid) = Self::member_uuid(member) {
                if uuid == target_member_id {
                    // Basic sanity check on stored public key
                    let key_is_nonzero = member.public_key.iter().any(|byte| *byte != 0);
                    if !key_is_nonzero {
                        return Ok(false);
                    }

                    // Additional capability checks can be added as implementation matures
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    // ========================================
    // Phase 4: Group Management & Authentication
    // ========================================

    /// Create or join a group with server-side management
    ///
    /// This method handles both creating new groups and joining existing ones
    /// by communicating with the HybridCipher server for group management.
    ///
    /// # Arguments
    /// * `group_name` - Human-readable name for the group
    /// * `group_description` - Optional description for the group
    /// * `join_existing` - If true, attempts to join an existing group by name
    ///
    /// # Returns
    /// Group membership information on success
    pub async fn create_or_join_group(
        &self,
        group_name: String,
        group_description: Option<String>,
        join_existing: bool,
    ) -> Result<GroupMembership, ClientError> {
        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Creating/joining group: {}", group_name),
            Some(&format!("join_existing: {}", join_existing)),
        );

        // Ensure we have authentication credentials
        let auth_token = self.get_auth_token().await?;

        let group_membership = if join_existing {
            self.join_existing_group(group_name, auth_token).await?
        } else {
            self.create_new_group(group_name, group_description, auth_token)
                .await?
        };

        // Store group membership in client state
        {
            let mut state = self.state.write().await;
            state
                .group_memberships
                .insert(group_membership.group_id, group_membership.clone());
        }

        // Persist group membership to storage
        self.save_group_membership(&group_membership).await?;

        // Ensure the consolidated client state (including memberships) is persisted
        self.save_client_state().await?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Successfully joined group: {} ({})",
                group_membership.group_name, group_membership.group_id
            ),
            Some(&format!(
                "role: {:?}, members: {}",
                group_membership.user_role,
                group_membership.members.len()
            )),
        );

        Ok(group_membership)
    }

    /// Create a new group on the server
    pub(super) async fn create_new_group(
        &self,
        group_name: String,
        group_description: Option<String>,
        auth_token: String,
    ) -> Result<GroupMembership, ClientError> {
        // Prepare group creation request
        let create_request = serde_json::json!({
            "name": group_name,
            "description": group_description,
            "settings": {
                "auto_approve_members": false,
                "max_members": 100,
                "file_retention_days": 365
            }
        });

        // Send create group request to server
        let server_url = self.active_server_base_url().await;
        let create_url = format!("{}/api/v1/groups", server_url);

        let client = reqwest::Client::new();
        let response = client
            .post(&create_url)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .json(&create_request)
            .send()
            .await
            .map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to create group: {}", e),
                    "create_new_group".to_string(),
                    1,
                    "rejected".to_string(),
                )
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                format!(
                    "Group creation failed with status {}: {}",
                    status, error_text
                ),
                "create_new_group".to_string(),
                1,
                "rejected".to_string(),
            ));
        }

        // Parse response
        let group_info: serde_json::Value = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkConnection,
                format!("Failed to parse group creation response: {}", e),
                "create_new_group".to_string(),
                1,
                "parsing_failed".to_string(),
            )
        })?;

        // Extract group information
        let group_id =
            Uuid::parse_str(group_info["id"].as_str().unwrap_or_default()).map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Invalid group ID in response: {}", e),
                    "create_new_group".to_string(),
                    1,
                    "invalid_response".to_string(),
                )
            })?;

        let membership = GroupMembership {
            group_id,
            group_name: group_info["name"]
                .as_str()
                .unwrap_or(&group_name)
                .to_string(),
            group_description: group_info["description"].as_str().map(|s| s.to_string()),
            user_role: GroupRole::Admin, // Creator is admin
            joined_at: Utc::now(),
            current_epoch_id: None, // Will be set when first epoch is created
            last_sync: Utc::now(),
            members: vec![], // Will be populated when we fetch group details
        };

        Ok(membership)
    }

    /// Join an existing group (placeholder for future implementation)
    pub(super) async fn join_existing_group(
        &self,
        group_name: String,
        auth_token: String,
    ) -> Result<GroupMembership, ClientError> {
        let groups = self.fetch_group_list(&auth_token).await?;
        if groups.is_empty() {
            return Err(ClientError::InvalidState(
                "No groups available for discovery on the server".to_string(),
            ));
        }

        let query = group_name.trim();
        let parsed_id = Uuid::parse_str(query).ok();
        let query_lower = query.to_ascii_lowercase();

        let candidates: Vec<&ServerGroupInfo> = groups
            .iter()
            .filter(|group| {
                if let Some(id) = parsed_id {
                    group.id == id
                } else {
                    group.name.eq_ignore_ascii_case(query)
                        || group.name.to_ascii_lowercase().contains(&query_lower)
                }
            })
            .collect();

        let target_group = match candidates.len() {
            0 => {
                return Err(ClientError::InvalidState(format!(
                    "No group named '{}' found on the server",
                    group_name
                )))
            }
            1 => candidates[0],
            _ => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Group name '{}' is ambiguous; multiple matches returned",
                        group_name
                    ),
                    None,
                );
                return Err(ClientError::InvalidState(format!(
                    "Multiple groups match '{}'; provide a unique name or UUID",
                    group_name
                )));
            }
        };

        let server_epoch = target_group
            .current_epoch
            .as_ref()
            .and_then(|value| value.parse::<u64>().ok());

        // Sync welcome messages and hydrate membership state
        let _ = self
            .sync_group_with_auth(target_group, &auth_token)
            .await
            .map_err(|err| {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!(
                        "Failed to synchronize group {} ({}): {}",
                        target_group.name, target_group.id, err
                    ),
                    None,
                );
                err
            })?;

        // Ensure membership cache reflects the server result
        self.upsert_group_membership(target_group, server_epoch)
            .await?;

        if let Some(membership) = self
            .state
            .read()
            .await
            .group_memberships
            .get(&target_group.id)
            .cloned()
        {
            Ok(membership)
        } else {
            Err(ClientError::InvalidState(format!(
                "Failed to cache membership for group {}",
                target_group.name
            )))
        }
    }

    /// Remove a device via the HybridCipher API and return a summary of the outcome.
    pub async fn remove_device(
        &self,
        device_id: Option<String>,
    ) -> Result<DeviceRemovalSummary, ClientError> {
        let auth_token = self.get_auth_token().await?;
        let local_device_id = self.local_device_id();
        let target_device_id = device_id
            .and_then(|id| {
                let trimmed = id.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
            .unwrap_or_else(|| local_device_id.clone());

        let server_base = DEFAULT_SERVER_URL.trim_end_matches('/');
        let request_url = format!("{}/api/v1/auth/device/{}", server_base, target_device_id);

        let client = reqwest::Client::new();
        let response = client
            .delete(&request_url)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to contact device removal endpoint: {}", e),
                    "remove_device".to_string(),
                    1,
                    "request_failed".to_string(),
                )
            })?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.cleanup_conflicting_auth_state().await?;
            return Err(ClientError::network_error(
                ErrorCode::NetworkAuthentication,
                "Authentication token rejected while removing device".to_string(),
                "remove_device".to_string(),
                1,
                "unauthorized".to_string(),
            ));
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!(
                    "Device removal failed with status {}: {}",
                    status, error_text
                ),
                "remove_device".to_string(),
                1,
                "error_response".to_string(),
            ));
        }

        let payload: DeviceRemovalResponse = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to parse device removal response: {}", e),
                "remove_device".to_string(),
                0,
                "parse_error".to_string(),
            )
        })?;

        if payload.removed_device_id == local_device_id {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                "Current device revoked remotely; clearing local credentials",
                Some(&format!("device_id: {}", payload.removed_device_id)),
            );

            // Best-effort cleanup of cached credentials and session state
            if let Err(err) = self.cleanup_conflicting_auth_state().await {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Failed to remove cached authentication credentials after revocation: {}",
                        err
                    ),
                    None,
                );
            }

            {
                let mut state = self.state.write().await;
                state.auth_credentials = None;
            }
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Device {} revoked ({} sessions invalidated)",
                payload.removed_device_id, payload.revoked_sessions
            ),
            Some(&format!(
                "remaining_devices: {}, updated_groups: {}",
                payload.remaining_devices,
                payload.updated_groups.len()
            )),
        );

        Ok(DeviceRemovalSummary {
            removed_device_id: payload.removed_device_id,
            revoked_sessions: payload.revoked_sessions,
            updated_groups: payload.updated_groups,
            remaining_devices: payload.remaining_devices,
            removed_at: payload.removed_at,
        })
    }

    /// Save group membership to persistent storage
    pub(super) async fn save_group_membership(
        &self,
        membership: &GroupMembership,
    ) -> Result<(), ClientError> {
        let membership_json = serde_json::to_string(membership).map_err(|e| {
            ClientError::storage_error(
                ErrorCode::StorageWrite,
                format!("Failed to serialize group membership: {}", e),
                "save_group_membership".to_string(),
                None,
                false,
            )
        })?;

        let storage_key = format!("group_membership_{}", membership.group_id);
        self.storage
            .store_config(&storage_key, &membership_json)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageWrite,
                    format!("Failed to save group membership: {:?}", e),
                    "save_group_membership".to_string(),
                    None,
                    false,
                )
            })?;

        self.update_membership_index(membership.group_id).await?;

        Ok(())
    }

    pub(super) async fn load_membership_index(&self) -> Result<HashSet<Uuid>, ClientError> {
        match self.storage.load_config(GROUP_MEMBERSHIP_INDEX_KEY).await {
            Ok(Some(raw)) => {
                let entries: Vec<String> = serde_json::from_str(&raw).map_err(|e| {
                    ClientError::storage_error(
                        ErrorCode::StorageRead,
                        format!("Failed to parse membership index: {}", e),
                        "load_membership_index".to_string(),
                        None,
                        false,
                    )
                })?;

                let mut index = HashSet::new();
                for entry in entries {
                    match Uuid::parse_str(&entry) {
                        Ok(id) => {
                            index.insert(id);
                        }
                        Err(err) => {
                            log::warn!(
                                "Discarding invalid group ID '{}' in membership index: {}",
                                entry,
                                err
                            );
                        }
                    }
                }

                Ok(index)
            }
            Ok(None) => Ok(HashSet::new()),
            Err(err) => Err(ClientError::storage_error(
                ErrorCode::StorageRead,
                format!("Failed to load membership index: {:?}", err),
                "load_membership_index".to_string(),
                None,
                false,
            )),
        }
    }

    pub(super) async fn persist_membership_index(
        &self,
        index: &HashSet<Uuid>,
    ) -> Result<(), ClientError> {
        let ids: Vec<String> = index.iter().map(|id| id.to_string()).collect();
        let payload = serde_json::to_string(&ids).map_err(|e| {
            ClientError::storage_error(
                ErrorCode::StorageWrite,
                format!("Failed to serialize membership index: {}", e),
                "persist_membership_index".to_string(),
                None,
                false,
            )
        })?;

        self.storage
            .store_config(GROUP_MEMBERSHIP_INDEX_KEY, &payload)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageWrite,
                    format!("Failed to store membership index: {:?}", e),
                    "persist_membership_index".to_string(),
                    None,
                    false,
                )
            })?;

        Ok(())
    }

    pub(super) async fn update_membership_index(&self, group_id: Uuid) -> Result<(), ClientError> {
        let mut index = self.load_membership_index().await?;
        if index.insert(group_id) {
            self.persist_membership_index(&index).await?;
        }
        Ok(())
    }

    /// Load group memberships from storage during client initialization
    pub async fn load_group_memberships(&self) -> Result<(), ClientError> {
        // This would be called during client initialization to restore group state
        self.logger.log(
            crate::logging::LogLevel::Info,
            "Loading group memberships from storage",
            None,
        );

        let index = self.load_membership_index().await?;
        if index.is_empty() {
            self.logger.log(
                crate::logging::LogLevel::Info,
                "No cached group memberships found",
                None,
            );
            return Ok(());
        }

        let mut valid_ids = HashSet::new();
        let mut recovered_memberships = Vec::new();

        for group_id in index.iter().copied() {
            let storage_key = format!("group_membership_{}", group_id);
            match self.storage.load_config(&storage_key).await {
                Ok(Some(raw)) => match serde_json::from_str::<GroupMembership>(&raw) {
                    Ok(membership) => {
                        valid_ids.insert(group_id);
                        recovered_memberships.push(membership);
                    }
                    Err(err) => {
                        log::warn!("Failed to parse stored membership {}: {}", group_id, err);
                    }
                },
                Ok(None) => {
                    log::warn!(
                        "Membership entry {} referenced in index but missing on disk",
                        group_id
                    );
                }
                Err(err) => {
                    return Err(ClientError::storage_error(
                        ErrorCode::StorageRead,
                        format!("Failed to load membership {}: {:?}", group_id, err),
                        "load_group_memberships".to_string(),
                        None,
                        false,
                    ));
                }
            }
        }

        {
            let mut state = self.state.write().await;
            state.group_memberships.clear();
            for membership in &recovered_memberships {
                state
                    .group_memberships
                    .insert(membership.group_id, membership.clone());
            }

            if let Some(active) = state.active_group_id {
                if !state.group_memberships.contains_key(&active) {
                    state.active_group_id = None;
                }
            }

            if state.active_group_id.is_none() {
                if let Some(first) = recovered_memberships.first() {
                    state.active_group_id = Some(first.group_id);
                    if let Some(epoch) = first.current_epoch_id {
                        state.current_epoch = epoch;
                    }
                }
            }
        }

        if valid_ids.len() != index.len() {
            self.persist_membership_index(&valid_ids).await?;
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Restored {} group membership(s) from persistent cache",
                recovered_memberships.len()
            ),
            None,
        );

        Ok(())
    }

    /// Get current group memberships
    pub async fn get_group_memberships(&self) -> Vec<GroupMembership> {
        let state = self.state.read().await;
        state.group_memberships.values().cloned().collect()
    }

    /// Export all epoch secrets for the specified group as recovery material.
    pub async fn export_recovery_capsule(
        &self,
        group_id: Uuid,
    ) -> Result<RecoveryCapsulePlain, ClientError> {
        let state = self.state.read().await;

        let mut epochs = Vec::new();
        for (epoch_id, entries) in &state.epochs {
            if let Some(entry) = entries.iter().find(|e| e.group_id == Some(group_id)) {
                let epoch_uuid = EpochIdMapper::u64_to_uuid(*epoch_id, group_id.as_bytes());
                epochs.push(RecoveryEpochSecret {
                    epoch_number: *epoch_id,
                    epoch_uuid,
                    created_at: entry.created_at,
                    is_active: entry.is_active,
                    file_count: entry.file_count,
                    encryption_key_b64: general_purpose::STANDARD.encode(entry.encryption_key),
                });
            }
        }

        if epochs.is_empty() {
            return Err(ClientError::InvalidState(
                format!(
                    "No epoch secrets available for group {}. You must either: (1) receive a Welcome message from an existing group member, or (2) run 'hybridcipher recovery fetch' if you have a recovery backup.",
                    group_id
                )
            ));
        }

        epochs.sort_by_key(|entry| entry.epoch_number);

        Ok(RecoveryCapsulePlain {
            group_id,
            generated_at: Utc::now(),
            epochs,
        })
    }

    /// Import epoch secrets from a recovered capsule and persist them locally.
    pub async fn import_recovery_capsule(
        &self,
        capsule: &RecoveryCapsulePlain,
    ) -> Result<(), ClientError> {
        let mut state = self.state.write().await;

        for epoch in &capsule.epochs {
            let key_bytes = general_purpose::STANDARD
                .decode(&epoch.encryption_key_b64)
                .map_err(|err| {
                    ClientError::InvalidState(format!(
                        "Invalid epoch key encoding for epoch {}: {}",
                        epoch.epoch_number, err
                    ))
                })?;

            if key_bytes.len() != 32 {
                return Err(ClientError::InvalidState(format!(
                    "Epoch key for epoch {} must be 32 bytes, found {}",
                    epoch.epoch_number,
                    key_bytes.len()
                )));
            }

            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&key_bytes);

            let epoch_state = EpochState {
                group_id: Some(capsule.group_id),
                epoch_id: epoch.epoch_number,
                encryption_key: key_array,
                key_source: EpochKeySource::LocalInit,
                members: Vec::new(),
                created_at: epoch.created_at,
                is_active: epoch.is_active,
                file_count: epoch.file_count,
                marked_for_removal: false,
                removal_eligible_at: None,
            };

            Self::upsert_epoch_state(&mut state, capsule.group_id, epoch_state);
        }

        if let Some(latest_epoch) = capsule.epochs.iter().map(|epoch| epoch.epoch_number).max() {
            state.current_epoch = latest_epoch;
            if let Some(membership) = state.group_memberships.get_mut(&capsule.group_id) {
                membership.current_epoch_id = Some(latest_epoch);
                membership.last_sync = Utc::now();
            } else {
                state.group_memberships.insert(
                    capsule.group_id,
                    GroupMembership {
                        group_id: capsule.group_id,
                        group_name: format!("Recovered group {}", capsule.group_id),
                        group_description: None,
                        user_role: GroupRole::Member,
                        joined_at: Utc::now(),
                        current_epoch_id: Some(latest_epoch),
                        last_sync: Utc::now(),
                        members: Vec::new(),
                    },
                );
            }
        } else if state.group_memberships.get(&capsule.group_id).is_none() {
            state.group_memberships.insert(
                capsule.group_id,
                GroupMembership {
                    group_id: capsule.group_id,
                    group_name: format!("Recovered group {}", capsule.group_id),
                    group_description: None,
                    user_role: GroupRole::Member,
                    joined_at: Utc::now(),
                    current_epoch_id: None,
                    last_sync: Utc::now(),
                    members: Vec::new(),
                },
            );
        }

        // Always set the recovered group as active since that's what the user wants to use
        state.active_group_id = Some(capsule.group_id);

        drop(state);

        self.save_client_state().await
    }

    /// Use a specific group for encryption operations
    ///
    /// This method switches the client to use a specific group's epoch
    /// for subsequent encryption/decryption operations.
    pub async fn use_group(&self, group_id: Uuid) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;

        let auth_token = self.get_auth_token().await.ok();

        let needs_membership_refresh = {
            let state = self.state.read().await;
            match state.group_memberships.get(&group_id) {
                None => true,
                Some(membership) => membership.current_epoch_id.is_none(),
            }
        };

        if needs_membership_refresh {
            if let Some(token) = auth_token.as_ref() {
                let groups = self.fetch_group_list(token).await?;
                let server_group =
                    groups
                        .into_iter()
                        .find(|g| g.id == group_id)
                        .ok_or_else(|| {
                            ClientError::InvalidState(format!(
                                "Not a member of group {} on the server",
                                group_id
                            ))
                        })?;

                let _ = self.sync_group_with_auth(&server_group, token).await?;
            }
        }

        {
            let mut state = self.state.write().await;
            state.active_group_id = Some(group_id);
        }

        let membership_snapshot = {
            let state = self.state.read().await;
            state.group_memberships.get(&group_id).cloned()
        };

        let membership_snapshot = match membership_snapshot {
            Some(membership) => membership,
            None => {
                let mut state = self.state.write().await;
                if state.active_group_id == Some(group_id) {
                    state.active_group_id = None;
                }
                return Err(ClientError::InvalidState(format!(
                    "Not a member of group {}",
                    group_id
                )));
            }
        };

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Switching to group: {} ({})",
                membership_snapshot.group_name, group_id
            ),
            Some(&format!("role: {:?}", membership_snapshot.user_role)),
        );

        if membership_snapshot.current_epoch_id.is_none() {
            if auth_token.is_some() {
                if let Err(err) = self.fetch_any_available_epoch_from_server(group_id).await {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Failed to synchronize epoch for group {}: {}",
                            group_id, err
                        ),
                        Some(&group_id.to_string()),
                    );
                }
            }
        }

        let final_epoch = {
            let state = self.state.read().await;
            state
                .group_memberships
                .get(&group_id)
                .and_then(|membership| membership.current_epoch_id)
                .unwrap_or(0)
        };

        {
            let mut state = self.state.write().await;
            state.active_group_id = Some(group_id);
            state.current_epoch = final_epoch;
        }

        self.cache_group_id(group_id).await;
        self.save_client_state().await?;

        Ok(())
    }

    /// Accept a group invitation using invitation token
    ///
    /// This method handles the Phase 2.2 invitation acceptance flow:
    /// 1. Sends accept invitation request to server with dual-key device data
    /// 2. Receives crypto_welcome_message in response
    /// 3. Processes Welcome message to extract epoch keys
    /// 4. Sets up group membership with proper epoch key installation
    pub async fn accept_group_invitation(
        &self,
        invitation_id: Uuid,
        invitation_token: String,
    ) -> Result<GroupMembership, ClientError> {
        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Accepting group invitation: {}", invitation_id),
            None,
        );

        // Ensure we have authentication credentials
        let auth_token = self.get_auth_token().await?;

        // Get or generate our invitation keypair for Welcome message processing
        let invitation_keypair = {
            let state = self.state.read().await;
            if let Some(keypair) = state.invitation_keypair.clone() {
                keypair
            } else {
                drop(state);
                // Generate and store invitation keypair if it doesn't exist
                let keypair = self.load_or_generate_invitation_keypair().await?;
                let mut state = self.state.write().await;
                state.invitation_keypair = Some(keypair.clone());
                keypair
            }
        };

        // Prepare invitation acceptance request
        let accept_request = serde_json::json!({
            "invitation_token": invitation_token
        });

        // Send accept invitation request to server
        let server_url = self.active_server_base_url().await;
        let accept_url = format!("{}/api/v1/invitations/{}/accept", server_url, invitation_id);

        let client = reqwest::Client::new();
        let response = client
            .post(&accept_url)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .json(&accept_request)
            .send()
            .await
            .map_err(|e| {
                ClientError::network_error(
                    crate::errors::ErrorCode::NetworkConnection,
                    format!("Failed to accept invitation: {}", e),
                    "accept_group_invitation".to_string(),
                    1,
                    "rejected".to_string(),
                )
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ClientError::network_error(
                crate::errors::ErrorCode::NetworkAuthentication,
                format!(
                    "Invitation acceptance failed with status {}: {}",
                    status, error_text
                ),
                "accept_group_invitation".to_string(),
                1,
                "rejected".to_string(),
            ));
        }

        // Parse invitation acceptance response
        let acceptance_response: serde_json::Value = response.json().await.map_err(|e| {
            ClientError::network_error(
                crate::errors::ErrorCode::NetworkConnection,
                format!("Failed to parse invitation acceptance response: {}", e),
                "accept_group_invitation".to_string(),
                1,
                "parsing_failed".to_string(),
            )
        })?;

        let mut current_epoch_id_for_membership: Option<u64> = None;

        // Process crypto_welcome_message if present
        if let Some(crypto_welcome) = acceptance_response.get("crypto_welcome_message") {
            if !crypto_welcome.is_null() {
                // Parse server Welcome message
                let server_welcome: crate::welcome_manager::ServerWelcomeMessage =
                    serde_json::from_value(crypto_welcome.clone()).map_err(|e| {
                        ClientError::InvalidState(format!("Failed to parse Welcome message: {}", e))
                    })?;

                // Extract group ID from response
                let group_id = Uuid::parse_str(
                    acceptance_response["group"]["id"]
                        .as_str()
                        .unwrap_or_default(),
                )
                .map_err(|e| {
                    ClientError::InvalidState(format!("Invalid group ID in response: {}", e))
                })?;

                // Process Welcome message to get epoch key
                let welcome_manager = crate::welcome_manager::WelcomeManager::new(
                    self.storage.clone(),
                    invitation_keypair,
                );

                let signing_key_bytes = self.get_welcome_signing_key(&server_url).await?;

                if server_welcome.signing_public_key != signing_key_bytes {
                    return Err(ClientError::InvalidState(
                        "Server welcome signing key mismatch".to_string(),
                    ));
                }

                let current_epoch_str = acceptance_response["group"]
                    .get("current_epoch")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ClientError::InvalidState(
                            "Server response missing current epoch identifier".to_string(),
                        )
                    })?;

                let current_epoch_uuid = Uuid::parse_str(current_epoch_str).map_err(|e| {
                    ClientError::InvalidState(format!(
                        "Invalid epoch identifier in server response: {}",
                        e
                    ))
                })?;

                let epoch_secrets = welcome_manager
                    .process_server_welcome_message(&server_welcome, group_id, current_epoch_uuid)
                    .await?;

                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Successfully processed Welcome message for group {}",
                        group_id
                    ),
                    Some(&format!(
                        "epoch_id: {}, members: {}",
                        epoch_secrets.epoch_id,
                        epoch_secrets.group_members.len()
                    )),
                );

                // Convert epoch key bytes to proper format
                let epoch_key = epoch_secrets.epoch_key;

                // Generate internal epoch ID from string (consistent hashing)
                let mut hasher = Sha256::new();
                hasher.update(current_epoch_str.as_bytes());
                let hash = hasher.finalize();
                let internal_epoch_id = u64::from_be_bytes([
                    hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                ]);

                // Install the epoch key into client state
                let members = Self::hydrate_group_members(&epoch_secrets.group_members)?;

                let new_epoch = EpochState {
                    group_id: Some(group_id),
                    epoch_id: internal_epoch_id,
                    encryption_key: epoch_key,
                    key_source: EpochKeySource::Welcome,
                    members,
                    created_at: epoch_secrets.active_at,
                    is_active: true,
                    file_count: 0,
                    marked_for_removal: false,
                    removal_eligible_at: None,
                };

                {
                    let mut state = self.state.write().await;
                    Self::upsert_epoch_state(&mut state, group_id, new_epoch);
                    state.current_epoch = internal_epoch_id;
                    if let Some(membership) = state.group_memberships.get_mut(&group_id) {
                        membership.current_epoch_id = Some(internal_epoch_id);
                    }
                }

                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Successfully installed epoch {} for group {}",
                        internal_epoch_id, group_id
                    ),
                    Some(&format!(
                        "epoch_members: {}",
                        epoch_secrets.group_members.len()
                    )),
                );

                // Persist the epoch state to disk
                self.save_client_state().await?;

                // Store the epoch ID for group membership
                current_epoch_id_for_membership = Some(internal_epoch_id);
            }
        }

        // Create group membership from response
        let group_info = &acceptance_response["group"];
        let member_info = &acceptance_response["member"];

        let group_id =
            Uuid::parse_str(group_info["id"].as_str().unwrap_or_default()).map_err(|e| {
                ClientError::InvalidState(format!("Invalid group ID in response: {}", e))
            })?;

        let membership = GroupMembership {
            group_id,
            group_name: group_info["name"]
                .as_str()
                .unwrap_or("Unknown Group")
                .to_string(),
            group_description: group_info["description"].as_str().map(|s| s.to_string()),
            user_role: match member_info["role"].as_str().unwrap_or("member") {
                "admin" => GroupRole::Admin,
                _ => GroupRole::Member,
            },
            joined_at: chrono::Utc::now(),
            current_epoch_id: current_epoch_id_for_membership,
            last_sync: chrono::Utc::now(),
            members: vec![], // Will be populated when we fetch group details
        };

        // Store group membership in client state
        let auto_selected_group = {
            let mut state = self.state.write().await;
            state.group_memberships.insert(group_id, membership.clone());

            let should_select_group =
                state.active_group_id.is_none() && state.group_memberships.len() == 1;

            if should_select_group {
                state.active_group_id = Some(group_id);
                if let Some(epoch) = membership.current_epoch_id {
                    state.current_epoch = epoch;
                }
                Some(group_id)
            } else {
                None
            }
        };

        if let Some(selected_group) = auto_selected_group {
            self.cache_group_id(selected_group).await;
        }

        // Persist group membership to storage
        self.save_group_membership(&membership).await?;
        self.save_client_state().await?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Successfully accepted invitation and joined group: {} ({})",
                membership.group_name, group_id
            ),
            Some(&format!("role: {:?}", membership.user_role)),
        );

        Ok(membership)
    }
}
