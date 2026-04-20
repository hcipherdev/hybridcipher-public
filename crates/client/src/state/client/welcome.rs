use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// Process a Welcome message to establish epoch keys
    ///
    /// This method implements the proper Welcome message-based epoch key distribution
    /// required for cross-device compatibility. It replaces the fixed seed approach.
    ///
    /// # Arguments
    /// * `welcome_message` - Welcome message containing encrypted epoch secrets
    /// * `invitation_keypair` - Device invitation keypair for decryption
    /// * `admin_public_key` - Group admin's public key for signature verification
    ///
    /// # Returns
    /// The epoch ID that was established
    ///
    /// # Errors
    /// - `CryptographicError` if decryption or verification fails
    /// - `InvalidState` if Welcome message is malformed or expired
    pub async fn process_welcome_message(
        &self,
        welcome_message: &crate::welcome_manager::WelcomeMessage,
        invitation_keypair: &crate::invitation::InvitationKeyPair,
        admin_public_key: &hybridcipher_crypto::signatures::VerifyingKey,
    ) -> Result<u64, ClientError> {
        use crate::welcome_manager::WelcomeManager;

        // Create Welcome manager for processing
        let welcome_manager = WelcomeManager::new(self.storage.clone(), invitation_keypair.clone());

        // Process Welcome message to extract epoch secrets
        let epoch_secrets = welcome_manager
            .process_welcome_message(welcome_message, admin_public_key)
            .await?;

        let members = Self::hydrate_group_members(&epoch_secrets.group_members)?;

        // Update client state with new epoch
        let mut state = self.state.write().await;

        let epoch_state = EpochState {
            group_id: Some(welcome_message.group_id),
            epoch_id: epoch_secrets.epoch_id,
            encryption_key: epoch_secrets.epoch_key,
            key_source: EpochKeySource::Welcome,
            members,
            created_at: epoch_secrets.active_at,
            is_active: true,
            file_count: 0,
            marked_for_removal: false,
            removal_eligible_at: None,
        };

        // Set as current epoch
        Self::upsert_epoch_state(&mut state, welcome_message.group_id, epoch_state);
        state.current_epoch = epoch_secrets.epoch_id;

        if let Some(membership) = state.group_memberships.get_mut(&welcome_message.group_id) {
            membership.current_epoch_id = Some(epoch_secrets.epoch_id);
        }

        // Log successful epoch establishment
        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Established epoch {} via Welcome message",
                epoch_secrets.epoch_id
            ),
            Some(&format!(
                "epoch_id: {}, group_id: {}, member_count: {}",
                epoch_secrets.epoch_id,
                welcome_message.group_id,
                epoch_secrets.group_members.len()
            )),
        );

        Ok(epoch_secrets.epoch_id)
    }

    /// Ensure epoch key is available by fetching Welcome messages if needed
    ///
    /// This method is called when decryption fails due to missing epoch keys.
    /// It implements the automatic Welcome message distribution workflow:
    /// 1. Fetch Welcome messages from server for the missing epoch
    /// 2. Process Welcome messages using invitation private key
    /// 3. Extract and install epoch secrets
    /// 4. Update client state with new epoch
    ///
    /// # Arguments
    /// * `epoch_id` - The epoch ID we need the key for
    ///
    /// # Returns
    /// Success when epoch key is available
    ///
    /// # Errors
    /// - `NetworkError` if server communication fails
    /// - `DecryptionError` if Welcome message processing fails
    /// - `InvalidState` if epoch still unavailable after processing
    /// Fetch any available epoch from server for initial client setup
    /// This handles the case where the server may have epoch 1, 2, etc. but the client starts with epoch 0
    pub(super) async fn fetch_any_available_epoch_from_server(
        &self,
        group_id: Uuid,
    ) -> Result<(), ClientError> {
        self.logger.log(
            crate::logging::LogLevel::Info,
            "Fetching any available epoch from server for initial setup",
            None,
        );

        let auth_token = self.get_auth_token().await?;
        let session_info = self.get_session_info().await.ok();

        let client = reqwest::Client::new();
        let server_url = if let Some(info) = &session_info {
            Self::resolve_server_base_url(info.server_url.clone())
        } else {
            self.active_server_base_url().await
        };
        let welcome_url = format!("{}/api/v1/groups/{}/welcome", server_url, group_id);

        let response = client
            .get(&welcome_url)
            .header("Authorization", &format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkConnection,
                    format!("Failed to fetch Welcome messages: {:?}", e),
                    "welcome_request".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "request_failed".to_string(),
            })?;

        if response.status() == StatusCode::PRECONDITION_REQUIRED {
            let device_label = session_info
                .as_ref()
                .and_then(|info| info.device_id.clone())
                .unwrap_or_else(|| "this device".to_string());

            return Err(ClientError::InvalidState(format!(
                "Device '{}' is awaiting approval. Use an existing trusted device to run `hybridcipher issue-welcome --device {}` and then rerun `hybridcipher process-welcome-messages`.",
                device_label, device_label
            )));
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            if status == reqwest::StatusCode::BAD_REQUEST
                && error_text.contains("Group has no current epoch")
            {
                let guidance = format!(
                    "Group {} has no active epoch. Ask a group admin to run 'hybridcipher initialize-group --group-id {}' before encrypting files.",
                    group_id, group_id
                );
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &guidance,
                    Some(&format!("group_id: {}", group_id)),
                );
                return Err(ClientError::InvalidState(guidance));
            }

            return Err(ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkProtocol,
                    format!("Server returned error {}: {}", status, error_text),
                    "welcome_response".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "error_response".to_string(),
            });
        }

        let welcome_response: WelcomeMessagesResponse =
            response
                .json()
                .await
                .map_err(|e| ClientError::NetworkError {
                    context: ErrorContext::new(
                        ErrorCode::NetworkProtocol,
                        format!("Failed to parse Welcome messages response: {:?}", e),
                        "welcome_parsing".to_string(),
                    ),
                    retry_count: 0,
                    last_attempt: std::time::SystemTime::now(),
                    connection_state: "parse_error".to_string(),
                })?;

        if welcome_response.messages.is_empty() {
            let guidance = format!(
                "Server returned no Welcome messages for group {}. Initialize the group with 'hybridcipher initialize-group --group-id {}' before encrypting files.",
                group_id, group_id
            );
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &guidance,
                Some(&format!("group_id: {}", group_id)),
            );
            return Err(ClientError::InvalidState(guidance));
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Received {} Welcome messages from server",
                welcome_response.messages.len()
            ),
            Some(&format!("group_id: {}", group_id)),
        );

        self.process_welcome_messages_for_epoch(welcome_response, group_id)
            .await
    }

    pub(super) async fn fetch_server_welcome_messages(
        &self,
        group_id: Uuid,
        auth_token: &str,
    ) -> Result<Option<WelcomeMessagesResponse>, ClientError> {
        let session_info = self.get_session_info().await.ok();
        let client = reqwest::Client::new();
        let server_url = if let Some(info) = &session_info {
            Self::resolve_server_base_url(info.server_url.clone())
        } else {
            self.active_server_base_url().await
        };
        let welcome_url = format!("{}/api/v1/groups/{}/welcome", server_url, group_id);

        let response = client
            .get(&welcome_url)
            .header("Authorization", &format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkConnection,
                    format!("Failed to fetch Welcome messages: {:?}", e),
                    "welcome_request".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "request_failed".to_string(),
            })?;

        let status = response.status();
        if status == StatusCode::PRECONDITION_REQUIRED {
            let device_label = session_info
                .as_ref()
                .and_then(|info| info.device_id.clone())
                .unwrap_or_else(|| "this device".to_string());

            return Err(ClientError::InvalidState(format!(
                "Device '{}' is awaiting approval. Use an existing trusted device to run `hybridcipher issue-welcome --device {}` and then rerun `hybridcipher process-welcome-messages`.",
                device_label, device_label
            )));
        }

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            if status == StatusCode::BAD_REQUEST && error_text.contains("Group has no active epoch")
            {
                return Ok(None);
            }

            return Err(ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkProtocol,
                    format!("Server returned error {}: {}", status, error_text),
                    "welcome_response".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "error_response".to_string(),
            });
        }

        let welcome_response: WelcomeMessagesResponse =
            response
                .json()
                .await
                .map_err(|e| ClientError::NetworkError {
                    context: ErrorContext::new(
                        ErrorCode::NetworkProtocol,
                        format!("Failed to parse Welcome messages response: {:?}", e),
                        "welcome_parsing".to_string(),
                    ),
                    retry_count: 0,
                    last_attempt: std::time::SystemTime::now(),
                    connection_state: "parse_error".to_string(),
                })?;

        Ok(Some(welcome_response))
    }

    pub(super) async fn build_self_welcome_payloads(
        &self,
        target_group: Option<Uuid>,
        session_user_id: Uuid,
    ) -> Result<Vec<SelfIssuedWelcomePayload>, ClientError> {
        let group_scope: Vec<Uuid> = {
            let state = self.state.read().await;
            if let Some(group_id) = target_group {
                if state.group_memberships.contains_key(&group_id) {
                    vec![group_id]
                } else {
                    Vec::new()
                }
            } else {
                state.group_memberships.keys().cloned().collect()
            }
        };

        let mut payloads = Vec::new();
        for group_id in group_scope {
            match self
                .generate_self_welcome_after_recovery(group_id, session_user_id)
                .await
            {
                Ok(message) => payloads.push(SelfIssuedWelcomePayload::from((group_id, message))),
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Failed to generate self Welcome payload for group {}: {}",
                            group_id, err
                        ),
                        None,
                    );
                }
            }
        }

        Ok(payloads)
    }

    pub(super) async fn resubmit_invitation_public_key(
        &self,
        target_group: Option<Uuid>,
    ) -> Result<(), ClientError> {
        let invitation_keypair = self.ensure_invitation_keypair().await?;
        let invitation_public_key = invitation_keypair.invitation_public_key()?.to_bytes();
        let identity_public_key = self.device_identity.public_key_bytes();

        let session_info = self.get_session_info().await?;
        let device_id = session_info.device_id.clone().ok_or_else(|| {
            ClientError::InvalidState(
                "Session metadata missing device identifier. Please run 'hybridcipher login' and retry."
                    .to_string(),
            )
        })?;

        let server_base_url = Self::resolve_server_base_url(session_info.server_url.clone());
        let endpoint = format!("{}/api/v1/auth/device/rotate-invitation", server_base_url);

        let mut payload = serde_json::Map::new();
        payload.insert(
            "invitation_public_key".into(),
            Value::String(hex::encode(invitation_public_key)),
        );
        payload.insert(
            "identity_public_key".into(),
            Value::String(hex::encode(identity_public_key)),
        );

        let session_user_id = session_info.user_id;

        let self_welcome_messages = if let Some(user_id) = session_user_id {
            match self
                .build_self_welcome_payloads(target_group, user_id)
                .await
            {
                Ok(messages) => messages,
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Unable to prepare self Welcome payloads during invitation rotation: {}",
                            err
                        ),
                        None,
                    );
                    Vec::new()
                }
            }
        } else {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                "Session is missing user identifier; skipping self Welcome refresh",
                None,
            );
            Vec::new()
        };

        if !self_welcome_messages.is_empty() {
            match serde_json::to_value(&self_welcome_messages) {
                Ok(value) => {
                    payload.insert("self_welcome_messages".into(), value);
                }
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Failed to serialize self Welcome payloads during invitation rotation: {}",
                            err
                        ),
                        None,
                    );
                }
            }
        }

        let payload = Value::Object(payload);

        let client = reqwest::Client::new();
        let response = client
            .post(&endpoint)
            .header("Authorization", format!("Bearer {}", session_info.token))
            .json(&payload)
            .send()
            .await
            .map_err(|e| ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkConnection,
                    format!("Failed to submit invitation key rotation request: {}", e),
                    "resubmit_invitation_public_key".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "request_failed".to_string(),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());

            return Err(ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkProtocol,
                    format!(
                        "Server rejected invitation key rotation (status {}): {}",
                        status, error_text
                    ),
                    "resubmit_invitation_public_key".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "error_response".to_string(),
            });
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Invitation key resubmitted to server for welcome message recovery",
            Some(&format!("device_id: {}", device_id)),
        );

        if !self_welcome_messages.is_empty() {
            if let Err(err) = self
                .submit_self_welcome_payloads(
                    &client,
                    &server_base_url,
                    &session_info.token,
                    &self_welcome_messages,
                )
                .await
            {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Failed to submit self-generated Welcome payloads after invitation rotation: {}",
                        err
                    ),
                    None,
                );
            }
        }

        Ok(())
    }

    pub(super) async fn submit_self_welcome_payloads(
        &self,
        client: &reqwest::Client,
        server_base_url: &str,
        auth_token: &str,
        payloads: &[SelfIssuedWelcomePayload],
    ) -> Result<(), ClientError> {
        if payloads.is_empty() {
            return Ok(());
        }

        let api_base = if server_base_url.ends_with("/api/v1") {
            server_base_url.to_string()
        } else {
            format!("{}/api/v1", server_base_url)
        };

        for payload in payloads {
            let request = SubmitSelfWelcomeRequest {
                encrypted_epoch_key: payload.encrypted_epoch_key.clone(),
                signature: payload.signature.clone(),
                signing_public_key: payload.signing_public_key.clone(),
                created_at: payload.created_at,
                expires_at: payload.expires_at,
            };

            let endpoint = format!(
                "{}/groups/{}/devices/{}/welcome",
                api_base, payload.group_id, payload.device_id
            );

            let response = client
                .post(&endpoint)
                .header("Authorization", format!("Bearer {}", auth_token))
                .json(&request)
                .send()
                .await
                .map_err(|e| ClientError::NetworkError {
                    context: ErrorContext::new(
                        ErrorCode::NetworkConnection,
                        format!(
                            "Failed to submit self Welcome payload for group {}: {}",
                            payload.group_id, e
                        ),
                        "submit_self_welcome_payloads".to_string(),
                    ),
                    retry_count: 0,
                    last_attempt: std::time::SystemTime::now(),
                    connection_state: "request_failed".to_string(),
                })?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());

                return Err(ClientError::NetworkError {
                    context: ErrorContext::new(
                        ErrorCode::NetworkProtocol,
                        format!(
                            "Server rejected self Welcome payload for group {} (status {}): {}",
                            payload.group_id, status, error_text
                        ),
                        "submit_self_welcome_payloads".to_string(),
                    ),
                    retry_count: 0,
                    last_attempt: std::time::SystemTime::now(),
                    connection_state: "error_response".to_string(),
                });
            }
        }

        Ok(())
    }

    pub(super) async fn fetch_group_list(
        &self,
        auth_token: &str,
    ) -> Result<Vec<ServerGroupInfo>, ClientError> {
        let client = reqwest::Client::new();
        let server_url = self.active_server_base_url().await;

        let response = client
            .get(&format!("{}/api/v1/groups", server_url))
            .header("Authorization", &format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkConnection,
                    format!("Failed to list groups: {}", e),
                    "group_list".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "list_groups_failed".to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            return Err(ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkProtocol,
                    format!("Server returned error {}: {}", status, error_text),
                    "group_list".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "error_response".to_string(),
            });
        }

        let list_response: GroupListApiResponse =
            response
                .json()
                .await
                .map_err(|e| ClientError::NetworkError {
                    context: ErrorContext::new(
                        ErrorCode::NetworkProtocol,
                        format!("Failed to parse group list response: {}", e),
                        "group_list".to_string(),
                    ),
                    retry_count: 0,
                    last_attempt: std::time::SystemTime::now(),
                    connection_state: "parse_error".to_string(),
                })?;

        Ok(list_response.groups)
    }

    pub(super) async fn get_welcome_signing_key(
        &self,
        server_url: &str,
    ) -> Result<Vec<u8>, ClientError> {
        if let Some(cached) = {
            let state = self.state.read().await;
            state.welcome_signing_keys.get(server_url).cloned()
        } {
            return Ok(cached);
        }

        let key = self
            .fetch_welcome_signing_key_from_server(server_url)
            .await?;

        let mut state = self.state.write().await;
        state
            .welcome_signing_keys
            .insert(server_url.to_string(), key.clone());

        Ok(key)
    }

    pub(super) async fn fetch_welcome_signing_key_from_server(
        &self,
        server_url: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let client = reqwest::Client::new();
        let info_url = format!("{}/api/v1/server/info", server_url);

        let response = client
            .get(&info_url)
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkConnection,
                    format!("Failed to fetch server info: {}", e),
                    "fetch_server_info".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "welcome_signing_key_fetch_failed".to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            return Err(ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkProtocol,
                    format!(
                        "Server info endpoint returned status {}: {}",
                        status, error_text
                    ),
                    "fetch_server_info".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "welcome_signing_key_fetch_failed".to_string(),
            });
        }

        let info: ServerInfoResponse =
            response
                .json()
                .await
                .map_err(|e| ClientError::NetworkError {
                    context: ErrorContext::new(
                        ErrorCode::NetworkProtocol,
                        format!("Failed to parse server info response: {}", e),
                        "fetch_server_info".to_string(),
                    ),
                    retry_count: 0,
                    last_attempt: std::time::SystemTime::now(),
                    connection_state: "welcome_signing_key_parse_failed".to_string(),
                })?;

        let descriptor = info.public_keys.welcome_signing.ok_or_else(|| {
            ClientError::InvalidState("Server did not advertise a welcome signing key".to_string())
        })?;

        let key_bytes = general_purpose::STANDARD
            .decode(descriptor.public_key.trim().as_bytes())
            .map_err(|e| {
                ClientError::InvalidState(format!("Welcome signing key is not valid base64: {}", e))
            })?;

        if key_bytes.len() != 32 {
            return Err(ClientError::InvalidState(format!(
                "Welcome signing key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        Ok(key_bytes)
    }

    pub(super) async fn upsert_group_membership(
        &self,
        group: &ServerGroupInfo,
        current_epoch: Option<u64>,
    ) -> Result<(), ClientError> {
        let newly_selected_group = {
            let mut state = self.state.write().await;

            // Check conditions before modifying the state
            let was_empty = state.active_group_id.is_none();
            // Check if this will be the only group (either empty or contains only this group)
            let will_be_single_group = state.group_memberships.is_empty()
                || (state.group_memberships.len() == 1
                    && state.group_memberships.contains_key(&group.id));

            let entry =
                state
                    .group_memberships
                    .entry(group.id)
                    .or_insert_with(|| GroupMembership {
                        group_id: group.id,
                        group_name: group.name.clone(),
                        group_description: group.description.clone(),
                        user_role: GroupRole::from(group.user_role),
                        joined_at: Utc::now(),
                        current_epoch_id: current_epoch,
                        last_sync: Utc::now(),
                        members: Vec::new(),
                    });

            entry.group_name = group.name.clone();
            entry.group_description = group.description.clone();
            entry.user_role = GroupRole::from(group.user_role);
            entry.last_sync = Utc::now();
            let entry_epoch = if let Some(epoch) = current_epoch {
                entry.current_epoch_id = Some(epoch);
                Some(epoch)
            } else {
                entry.current_epoch_id
            };

            let should_select_group = was_empty && will_be_single_group;

            if should_select_group {
                state.active_group_id = Some(group.id);
                if let Some(epoch) = entry_epoch {
                    state.current_epoch = epoch;
                }
                Some(group.id)
            } else {
                None
            }
        };

        if let Some(group_id) = newly_selected_group {
            self.cache_group_id(group_id).await;
        }

        self.save_client_state().await?;
        Ok(())
    }

    pub(super) async fn sync_group_with_auth(
        &self,
        group: &ServerGroupInfo,
        auth_token: &str,
    ) -> Result<WelcomeSyncResult, ClientError> {
        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Syncing Welcome messages for group {}", group.name),
            Some(&group.id.to_string()),
        );

        let fetch_result = self
            .fetch_server_welcome_messages(group.id, auth_token)
            .await?;

        match fetch_result {
            None => {
                let server_current_epoch = group
                    .current_epoch
                    .as_ref()
                    .and_then(|epoch| epoch.parse::<u64>().ok());
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Group {} has no active epoch", group.name),
                    Some(&group.id.to_string()),
                );
                self.upsert_group_membership(group, server_current_epoch)
                    .await?;
                if server_current_epoch.is_none() {
                    self.purge_group_epoch_state(group.id).await;
                }
                Ok(WelcomeSyncResult {
                    group_id: group.id,
                    group_name: group.name.clone(),
                    processed_epoch: None,
                    messages_processed: 0,
                    status: WelcomeSyncStatus::NoActiveEpoch,
                    detail: Some("Group has no active epoch".to_string()),
                })
            }
            Some(welcome_response) => {
                let message_count = welcome_response.messages.len();
                let epoch_id = welcome_response.epoch_id;

                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Received {} Welcome messages for group {}",
                        message_count, group.name
                    ),
                    Some(&format!("group_id: {}", group.id)),
                );

                if message_count == 0 {
                    self.upsert_group_membership(group, Some(epoch_id)).await?;
                    return Ok(WelcomeSyncResult {
                        group_id: group.id,
                        group_name: group.name.clone(),
                        processed_epoch: Some(epoch_id),
                        messages_processed: 0,
                        status: WelcomeSyncStatus::NoMessages,
                        detail: Some(
                            "Server returned no Welcome messages for this device".to_string(),
                        ),
                    });
                }

                match self
                    .process_welcome_messages_for_epoch(welcome_response, group.id)
                    .await
                {
                    Ok(()) => {
                        self.upsert_group_membership(group, Some(epoch_id)).await?;
                        Ok(WelcomeSyncResult {
                            group_id: group.id,
                            group_name: group.name.clone(),
                            processed_epoch: Some(epoch_id),
                            messages_processed: message_count,
                            status: WelcomeSyncStatus::Updated,
                            detail: None,
                        })
                    }
                    Err(ClientError::InvalidState(message)) => {
                        // Capture cases where the server responded but no message matched this device
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Failed to install Welcome message for group {}: {}",
                                group.name, message
                            ),
                            Some(&group.id.to_string()),
                        );
                        self.upsert_group_membership(group, Some(epoch_id)).await?;
                        Ok(WelcomeSyncResult {
                            group_id: group.id,
                            group_name: group.name.clone(),
                            processed_epoch: Some(epoch_id),
                            messages_processed: message_count,
                            status: WelcomeSyncStatus::NoMessages,
                            detail: Some(message),
                        })
                    }
                    Err(e) => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            &format!(
                                "Error processing Welcome messages for group {}: {}",
                                group.name, e
                            ),
                            Some(&group.id.to_string()),
                        );
                        Err(e)
                    }
                }
            }
        }
    }

    /// Synchronize Welcome messages for all groups the user belongs to
    pub async fn sync_all_welcome_messages(&self) -> Result<Vec<WelcomeSyncResult>, ClientError> {
        self.ensure_state_loaded().await?;
        let auth_token = self.get_auth_token().await?;

        let groups = self.fetch_group_list(&auth_token).await?;
        if groups.is_empty() {
            self.logger.log(
                crate::logging::LogLevel::Info,
                "No groups found while syncing Welcome messages",
                None,
            );
            return Ok(Vec::new());
        }

        let (existing_memberships, existing_names) = {
            let state = self.state.read().await;
            let memberships = state
                .group_memberships
                .keys()
                .copied()
                .collect::<HashSet<_>>();
            let names = state
                .group_memberships
                .iter()
                .map(|(id, membership)| (*id, membership.group_name.clone()))
                .collect::<HashMap<_, _>>();
            (memberships, names)
        };

        let mut server_group_ids = HashSet::with_capacity(groups.len());
        let mut results = Vec::with_capacity(groups.len());
        for group in groups {
            server_group_ids.insert(group.id);

            if !existing_memberships.contains(&group.id) {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Discovered new group membership during Welcome sync: {}",
                        group.name
                    ),
                    Some(&group.id.to_string()),
                );
            }

            match self.sync_group_with_auth(&group, &auth_token).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Failed to sync Welcome messages for group {}: {}",
                            group.name, e
                        ),
                        Some(&group.id.to_string()),
                    );
                    results.push(WelcomeSyncResult {
                        group_id: group.id,
                        group_name: group.name.clone(),
                        processed_epoch: None,
                        messages_processed: 0,
                        status: WelcomeSyncStatus::Error,
                        detail: Some(e.to_string()),
                    });
                }
            }
        }

        let removed_group_ids: Vec<Uuid> = existing_memberships
            .difference(&server_group_ids)
            .copied()
            .collect();

        let mut persist_state = false;
        if !removed_group_ids.is_empty() {
            for removed_id in &removed_group_ids {
                let name = existing_names
                    .get(removed_id)
                    .cloned()
                    .unwrap_or_else(|| "<unknown>".to_string());
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Removing stale group membership during Welcome sync: {}",
                        name
                    ),
                    Some(&removed_id.to_string()),
                );
            }

            {
                let mut state = self.state.write().await;
                for removed_id in &removed_group_ids {
                    state.group_memberships.remove(removed_id);
                }
                persist_state = true;
            }
        }

        {
            let mut state = self.state.write().await;
            state.last_sync = Utc::now();
        }

        if persist_state {
            self.save_client_state().await?;
        }

        Ok(results)
    }

    /// Synchronize Welcome messages for a specific group
    pub async fn sync_welcome_messages_for_group(
        &self,
        group_id: Uuid,
    ) -> Result<WelcomeSyncResult, ClientError> {
        self.ensure_state_loaded().await?;
        let auth_token = self.get_auth_token().await?;

        let groups = self.fetch_group_list(&auth_token).await?;
        if let Some(group) = groups.into_iter().find(|g| g.id == group_id) {
            match self.sync_group_with_auth(&group, &auth_token).await {
                Ok(result) => Ok(result),
                Err(e) => {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Failed to sync Welcome messages for group {}: {}",
                            group.name, e
                        ),
                        Some(&group.id.to_string()),
                    );
                    Ok(WelcomeSyncResult {
                        group_id: group.id,
                        group_name: group.name.clone(),
                        processed_epoch: None,
                        messages_processed: 0,
                        status: WelcomeSyncStatus::Error,
                        detail: Some(e.to_string()),
                    })
                }
            }
        } else {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Group {} not found while syncing Welcome messages",
                    group_id
                ),
                Some(&group_id.to_string()),
            );
            Ok(WelcomeSyncResult {
                group_id,
                group_name: group_id.to_string(),
                processed_epoch: None,
                messages_processed: 0,
                status: WelcomeSyncStatus::Skipped,
                detail: Some("Device is not a member of this group".to_string()),
            })
        }
    }

    /// Automatically reconcile Welcome messages if the client cache is stale.
    pub async fn auto_sync_welcome_messages(
        &self,
        trigger: &str,
    ) -> Result<Vec<WelcomeSyncResult>, ClientError> {
        if !self.config.migration_automation_enabled {
            self.logger.log(
                crate::logging::LogLevel::Debug,
                &format!(
                    "Skipping auto Welcome sync (trigger: {}, automation disabled)",
                    trigger
                ),
                None,
            );
            return Ok(Vec::new());
        }

        self.ensure_state_loaded().await?;

        let now = Utc::now();
        let should_sync = {
            let state = self.state.read().await;
            state.group_memberships.is_empty()
                || now.signed_duration_since(state.last_sync).num_seconds()
                    >= Self::AUTO_SYNC_INTERVAL_SECS
        };

        if !should_sync {
            self.logger.log(
                crate::logging::LogLevel::Debug,
                &format!(
                    "Skipping auto Welcome sync (trigger: {}, last sync still fresh)",
                    trigger
                ),
                None,
            );
            return Ok(Vec::new());
        }

        match self.sync_all_welcome_messages().await {
            Ok(results) => {
                let updated_groups = results
                    .iter()
                    .filter(|r| r.status == WelcomeSyncStatus::Updated)
                    .count();

                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Auto Welcome sync triggered by '{}' processed {} group(s) with {} update(s)",
                        trigger,
                        results.len(),
                        updated_groups
                    ),
                    None,
                );

                Ok(results)
            }
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Auto Welcome sync triggered by '{}' failed: {}",
                        trigger, err
                    ),
                    None,
                );
                self.update_last_sync_timestamp().await;
                Err(err)
            }
        }
    }

    /// Ensure epoch key is available for the given group
    /// This is the core coordination function for cross-device epoch synchronization
    pub(super) async fn ensure_epoch_key_available(
        &self,
        group_id: Uuid,
        epoch_id: u64,
    ) -> Result<(), ClientError> {
        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Ensuring epoch key available for epoch {}", epoch_id),
            Some(&format!(
                "epoch_id: {}, checking local then server",
                epoch_id
            )),
        );

        let now = Utc::now();

        // Check if we already have this epoch locally
        let (had_local_epoch, last_sync_age_secs, local_key_verified, is_migration_target) = {
            let state = self.state.read().await;
            let epoch_state = Self::get_epoch_state(&state, group_id, epoch_id);
            let exists = epoch_state.is_some();
            let local_key_verified = epoch_state
                .map(|epoch| epoch.key_source.is_verified())
                .unwrap_or(false);
            let is_migration_target = state
                .migration
                .as_ref()
                .map(|migration| migration.to_epoch == epoch_id)
                .unwrap_or(false);

            // DEBUG: Log what epochs we actually have
            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!(
                    "DEBUG: Checking local epoch availability - epoch_id: {}, group_id: {}, exists: {}",
                    epoch_id, group_id, exists
                ),
                Some(&format!(
                    "total_epoch_keys: {}, epochs_for_id_{}: {}, all_epoch_ids: {:?}",
                    state.epochs.len(),
                    epoch_id,
                    state.epochs.get(&epoch_id).map(|v| v.len()).unwrap_or(0),
                    state.epochs.keys().collect::<Vec<_>>()
                )),
            );

            // DEBUG: Log all epochs we have
            for (eid, entries) in &state.epochs {
                for entry in entries {
                    self.logger.log(
                        crate::logging::LogLevel::Info,
                        &format!("DEBUG: Have epoch {} for group {:?}", eid, entry.group_id),
                        None,
                    );
                }
            }

            let age = now.signed_duration_since(state.last_sync).num_seconds();

            (exists, age, local_key_verified, is_migration_target)
        };

        if had_local_epoch
            && last_sync_age_secs >= 0
            && last_sync_age_secs < Self::AUTO_SYNC_INTERVAL_SECS
        {
            if !is_migration_target || local_key_verified {
                self.logger.log(
                    crate::logging::LogLevel::Debug,
                    &format!(
                        "Skipping server reconciliation for epoch {}; cached data refreshed {}s ago",
                        epoch_id, last_sync_age_secs
                    ),
                    Some(&format!("group_id: {}", group_id)),
                );
                return Ok(());
            }

            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!(
                    "Epoch {} key is not verified during migration; forcing Welcome sync",
                    epoch_id
                ),
                Some(&format!("group_id: {}", group_id)),
            );
        }

        // If we have the epoch locally and there's no auth token (recovery scenario),
        // trust the local epoch without server reconciliation
        if had_local_epoch && self.get_auth_token().await.is_err() {
            if is_migration_target && !local_key_verified {
                return Err(ClientError::InvalidState(format!(
                    "Rekey in progress; epoch {} key is not verified yet",
                    epoch_id
                )));
            }

            self.logger.log(
                crate::logging::LogLevel::Info,
                &format!(
                    "Using locally available epoch {} without server reconciliation (recovery scenario)",
                    epoch_id
                ),
                Some(&format!("group_id: {}", group_id)),
            );
            return Ok(());
        }

        // Get current group info and authentication
        let auth_token = self.get_auth_token().await?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Fetching welcome messages for group {} to reconcile epoch {}",
                group_id, epoch_id
            ),
            Some(&group_id.to_string()),
        );

        let welcome_response_result = self
            .fetch_server_welcome_messages(group_id, &auth_token)
            .await;

        let welcome_response_option = match welcome_response_result {
            Ok(response) => response,
            Err(err) => {
                if had_local_epoch {
                    if let ClientError::NetworkError { .. } = &err {
                        if is_migration_target && !local_key_verified {
                            return Err(ClientError::InvalidState(format!(
                                "Rekey in progress; epoch {} key is not verified yet",
                                epoch_id
                            )));
                        }

                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Network unreachable while reconciling epoch {}; continuing with cached key",
                                epoch_id
                            ),
                            Some(&format!("group_id: {}", group_id)),
                        );

                        {
                            let mut state = self.state.write().await;
                            state.last_sync = Utc::now();
                        }

                        return Ok(());
                    }
                }

                return Err(err);
            }
        };

        match welcome_response_option {
            None => {
                if had_local_epoch {
                    if is_migration_target && !local_key_verified {
                        return Err(ClientError::InvalidState(format!(
                            "Rekey in progress; epoch {} key is not verified yet",
                            epoch_id
                        )));
                    }

                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Server reports no current epoch; continuing with locally cached epoch {}",
                            epoch_id
                        ),
                        Some(&format!("group_id: {}", group_id)),
                    );
                    self.update_last_sync_timestamp().await;
                    Ok(())
                } else {
                    let guidance = format!(
                        "Group {} has no active epoch. Ask a group admin to run 'hybridcipher initialize-group --group-id {}' before continuing.",
                        group_id, group_id
                    );
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &guidance,
                        Some(&format!("group_id: {}, epoch_id: {}", group_id, epoch_id)),
                    );
                    Err(ClientError::InvalidState(guidance))
                }
            }
            Some(welcome_response) => {
                let message_count = welcome_response.messages.len();
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!("Received {} Welcome messages from server", message_count),
                    Some(&format!("group_id: {}, epoch_id: {}", group_id, epoch_id)),
                );

                if message_count == 0 {
                    if had_local_epoch {
                        if is_migration_target && !local_key_verified {
                            return Err(ClientError::InvalidState(format!(
                                "Rekey in progress; epoch {} key is not verified yet",
                                epoch_id
                            )));
                        }

                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Server returned no Welcome messages; continuing with locally cached epoch {}",
                                epoch_id
                            ),
                            Some(&format!("group_id: {}", group_id)),
                        );
                        self.update_last_sync_timestamp().await;
                        return Ok(());
                    }

                    let guidance = format!(
                        "Server returned no Welcome messages for epoch {} in group {}. Rekey is still pending; retry after Welcome sync.",
                        welcome_response.epoch_id, group_id
                    );
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &guidance,
                        Some(&format!(
                            "group_id: {}, epoch_id: {}",
                            group_id, welcome_response.epoch_id
                        )),
                    );
                    return Err(ClientError::InvalidState(guidance));
                }

                self.process_welcome_messages_for_epoch(welcome_response, group_id)
                    .await?;
                self.update_last_sync_timestamp().await;
                Ok(())
            }
        }
    }

    pub(super) async fn update_last_sync_timestamp(&self) {
        let mut state = self.state.write().await;
        state.last_sync = Utc::now();
    }

    /// Ensure that a future epoch state exists locally so we can generate Welcome payloads.
    pub async fn ensure_future_epoch_state(
        &self,
        group_id: Uuid,
        target_epoch: u64,
    ) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;

        let mut state = self.state.write().await;
        if Self::get_epoch_state(&state, group_id, target_epoch).is_some() {
            return Ok(());
        }

        let membership = state.group_memberships.get(&group_id).ok_or_else(|| {
            ClientError::InvalidState(format!(
                "No cached membership information for group {}",
                group_id
            ))
        })?;

        let source_epoch = membership.current_epoch_id.ok_or_else(|| {
            ClientError::InvalidState(format!(
                "Group {} does not have an active epoch in local state",
                group_id
            ))
        })?;

        let base_epoch = Self::get_epoch_state(&state, group_id, source_epoch)
            .cloned()
            .ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Epoch {} for group {} is not present in local state",
                    source_epoch, group_id
                ))
            })?;

        let mut epoch_key = [0u8; 32];
        OsRng.fill_bytes(&mut epoch_key);

        let new_epoch_state = EpochState {
            group_id: Some(group_id),
            epoch_id: target_epoch,
            encryption_key: epoch_key,
            key_source: EpochKeySource::LocalInit,
            members: base_epoch.members.clone(),
            created_at: Utc::now(),
            is_active: false,
            file_count: 0,
            marked_for_removal: false,
            removal_eligible_at: None,
        };

        Self::upsert_epoch_state(&mut state, group_id, new_epoch_state);
        state.last_sync = Utc::now();
        drop(state);
        self.save_client_state().await?;
        Ok(())
    }

    /// Helper method to process Welcome messages response without retry logic
    pub(super) async fn process_welcome_messages_inner(
        &self,
        welcome_response: WelcomeMessagesResponse,
        group_id: uuid::Uuid,
    ) -> Result<(), ClientError> {
        let now = Utc::now();

        let mut message_ids = HashSet::new();
        for message in &welcome_response.messages {
            if !message_ids.insert(message.message_id) {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Duplicate Welcome message {} detected for group {}",
                        message.message_id, group_id
                    ),
                    None,
                );
            }

            if message.group_id != welcome_response.group_id {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Welcome message {} targets group {} but response was for {}",
                        message.message_id, message.group_id, welcome_response.group_id
                    ),
                    None,
                );
            }
        }

        // Verify deterministic mapping between epoch_id and epoch_uuid using group context
        let expected_uuid =
            EpochIdMapper::u64_to_uuid(welcome_response.epoch_id, group_id.as_bytes());
        if !welcome_response.epoch_uuid.eq(&expected_uuid) && !welcome_response.legacy_mapping {
            return Err(ClientError::InvalidState(format!(
                "Untrusted server response: epoch mapping mismatch (expected {}, got {})",
                expected_uuid, welcome_response.epoch_uuid
            )));
        }
        if welcome_response.legacy_mapping {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                "Legacy epoch mapping detected; accepting without verification",
                Some(&format!("epoch_uuid: {}", welcome_response.epoch_uuid)),
            );
        }

        // Load or generate our invitation keypair
        let invitation_keypair = self.ensure_invitation_keypair().await?;
        let device_id = invitation_keypair.device_id.clone();
        let welcome_manager = WelcomeManager::new(self.storage.clone(), invitation_keypair);

        let session_context = match self.get_session_info().await {
            Ok(info) => Some(info),
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Unable to load session info for Welcome validation; continuing without user check: {}",
                        err
                    ),
                    None,
                );
                None
            }
        };
        let session_user_id = session_context.as_ref().and_then(|info| info.user_id);
        let device_pending_approval = session_context
            .as_ref()
            .and_then(|info| info.device_status.as_deref())
            .map(|status| status.eq_ignore_ascii_case("pending-welcome"))
            .unwrap_or(false);
        let device_already_verified = session_context
            .as_ref()
            .map(|info| info.device_verified)
            .unwrap_or(false);

        // Find welcome message intended for this device with group + expiry checks
        let welcome_payload = match welcome_response.messages.iter().find(|msg| {
            msg.recipient_device_id == device_id
                && msg.group_id == group_id
                && msg.expires_at.map_or(true, |expiry| expiry > now)
        }) {
            Some(payload) => payload,
            None => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    "No valid welcome message matched current device",
                    Some(&format!("device_id: {}", device_id)),
                );
                if device_pending_approval {
                    self.purge_group_epoch_state(group_id).await;
                    let guidance =
                        format!("Device '{}' is pending approval. Sign in on an existing trusted device and run `hybridcipher issue-welcome --device {}` before retrying.", device_id, device_id);
                    return Err(ClientError::InvalidState(guidance));
                }

                if device_already_verified {
                    // Device was recovered, but there's no Welcome message for it yet
                    // Check if we have the epoch locally from recovery
                    let have_current_epoch = {
                        let state = self.state.read().await;
                        Self::get_epoch_state(&state, group_id, welcome_response.epoch_id).is_some()
                    };

                    if have_current_epoch {
                        self.logger.log(
                            crate::logging::LogLevel::Info,
                            "Skipping Welcome enforcement because device recovery verified the epoch keys.",
                            Some(&format!("group_id: {}", group_id)),
                        );
                        return Ok(());
                    } else {
                        // Recovery has old epoch, but server has moved to new epoch
                        let guidance = format!(
                            "Device recovery successful but group has moved to epoch {}. \
                            Ask a group admin to run 'hybridcipher issue-welcome --device {}' to \
                            grant access to the current epoch.",
                            welcome_response.epoch_id, device_id
                        );
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &guidance,
                            Some(&format!(
                                "group_id: {}, current_epoch: {}",
                                group_id, welcome_response.epoch_id
                            )),
                        );
                        return Err(ClientError::InvalidState(guidance));
                    }
                }

                self.purge_group_epoch_state(group_id).await;
                return Err(ClientError::InvalidState(
                    "Server did not provide a valid Welcome message for this device".to_string(),
                ));
            }
        };

        if let Some(expected_user) = session_user_id {
            if welcome_payload.recipient_user_id != expected_user {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Welcome message {} was issued for user {} but active session is {}",
                        welcome_payload.message_id,
                        welcome_payload.recipient_user_id,
                        expected_user
                    ),
                    None,
                );
                return Err(ClientError::InvalidState(
                    "Welcome message recipient does not match active user".to_string(),
                ));
            }
        }

        let server_message = ServerWelcomeMessage {
            recipient_device_id: welcome_payload.recipient_device_id.clone(),
            encrypted_epoch_key: welcome_payload.encrypted_epoch_key.clone(),
            signature: welcome_payload.signature.clone(),
            signing_public_key: welcome_payload.signing_public_key.clone(),
            created_at: welcome_payload.created_at,
            expires_at: welcome_payload.expires_at,
        };

        let epoch_secrets = welcome_manager
            .process_server_welcome_message(&server_message, group_id, welcome_payload.epoch_id)
            .await?;

        if epoch_secrets.epoch_id != welcome_response.epoch_id {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Welcome message epoch sequence {} does not match server response {}",
                    epoch_secrets.epoch_id, welcome_response.epoch_id
                ),
                None,
            );
        }

        let members = Self::hydrate_group_members(&epoch_secrets.group_members)?;

        let new_epoch = EpochState {
            group_id: Some(welcome_response.group_id),
            epoch_id: welcome_response.epoch_id,
            encryption_key: epoch_secrets.epoch_key,
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
            state.current_epoch = welcome_response.epoch_id;
            if let Some(membership) = state.group_memberships.get_mut(&group_id) {
                membership.current_epoch_id = Some(welcome_response.epoch_id);
            }
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Installed epoch {} from server Welcome message",
                welcome_response.epoch_id
            ),
            Some(&format!("for_device: {}", device_id)),
        );

        // Persist epoch key so subsequent CLI invocations reuse it
        self.save_client_state().await?;

        Ok(())
    }

    /// Process Welcome messages with automatic recovery if invitation keys are stale.
    pub(super) async fn process_welcome_messages_for_epoch(
        &self,
        welcome_response: WelcomeMessagesResponse,
        group_id: uuid::Uuid,
    ) -> Result<(), ClientError> {
        if welcome_response.expires_at <= Utc::now() {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Discarding expired Welcome response for group {} (expired at {})",
                    group_id, welcome_response.expires_at
                ),
                None,
            );
            self.purge_group_epoch_state(group_id).await;
            return Err(ClientError::InvalidState(
                "Received Welcome response has expired. Please retry sync.".to_string(),
            ));
        }

        match self
            .process_welcome_messages_inner(welcome_response, group_id)
            .await
        {
            Ok(()) => Ok(()),
            Err(err) => {
                if !Self::is_crypto_decryption_error(&err) {
                    return Err(err);
                }

                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    "Welcome message decryption failed; attempting invitation key resubmission",
                    Some(&format!("group_id: {}", group_id)),
                );

                if let Err(sync_err) = self.resubmit_invitation_public_key(Some(group_id)).await {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!("Failed to resubmit invitation key to server: {}", sync_err),
                        Some(&format!("group_id: {}", group_id)),
                    );
                    return Err(err);
                }

                let auth_token = match self.get_auth_token().await {
                    Ok(token) => token,
                    Err(token_err) => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            &format!(
                                "Unable to refresh authentication token after invitation key rotation: {}",
                                token_err
                            ),
                            Some(&format!("group_id: {}", group_id)),
                        );
                        return Err(err);
                    }
                };

                match self
                    .fetch_server_welcome_messages(group_id, &auth_token)
                    .await
                {
                    Ok(Some(refetched_response)) => {
                        self.logger.log(
                            crate::logging::LogLevel::Info,
                            "Fetched refreshed Welcome messages after invitation key rotation",
                            Some(&format!("group_id: {}", group_id)),
                        );
                        self.process_welcome_messages_inner(refetched_response, group_id)
                            .await
                    }
                    Ok(None) => {
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            "Server returned no Welcome messages after invitation key rotation",
                            Some(&format!("group_id: {}", group_id)),
                        );
                        Err(err)
                    }
                    Err(fetch_err) => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            &format!(
                                "Failed to fetch Welcome messages after invitation key rotation: {}",
                                fetch_err
                            ),
                            Some(&format!("group_id: {}", group_id)),
                        );
                        Err(fetch_err)
                    }
                }
            }
        }
    }

    /// Load or generate invitation keypair for Welcome message processing
    pub(super) async fn load_or_generate_invitation_keypair(
        &self,
    ) -> Result<crate::invitation::InvitationKeyPair, ClientError> {
        let expected_device_id = {
            let state_device_id = {
                let state = self.state.read().await;
                state
                    .auth_credentials
                    .as_ref()
                    .map(|creds| creds.device_id.clone())
            };

            if let Some(id) = state_device_id {
                id
            } else if let Ok(Some(creds_json)) = self.storage.load_config("auth_credentials").await
            {
                if let Ok(creds) = serde_json::from_str::<AuthCredentials>(&creds_json) {
                    creds.device_id
                } else {
                    let public_key = self.device_identity.public_key_bytes();
                    format!("device_{}", hex::encode(&public_key[..8]))
                }
            } else {
                let public_key = self.device_identity.public_key_bytes();
                format!("device_{}", hex::encode(&public_key[..8]))
            }
        };

        // Try to load existing keypair from storage
        match self.storage.load_config("invitation_keypair").await {
            Ok(Some(data)) => {
                match serde_json::from_str::<crate::invitation::InvitationKeyPair>(&data) {
                    Ok(keypair) => {
                        if keypair.device_id == expected_device_id {
                            return Ok(keypair);
                        }
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Stored invitation keypair device ID ({}) mismatches expected ({})",
                                keypair.device_id, expected_device_id
                            ),
                            Some("Regenerating invitation keypair"),
                        );
                    }
                    Err(e) => {
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!("Failed to deserialize stored invitation keypair: {:?}", e),
                            Some("Will generate new keypair"),
                        );
                    }
                }
            }
            Ok(None) => {
                // No stored keypair, will generate new one
            }
            Err(e) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Failed to load invitation keypair from storage: {:?}", e),
                    Some("Will generate new keypair"),
                );
            }
        }

        // Generate new invitation keypair
        let keypair =
            crate::invitation::InvitationKeyPair::generate(expected_device_id).map_err(|e| {
                ClientError::crypto_error(
                    crate::errors::ErrorCode::CryptoKeyGeneration,
                    format!("Failed to generate invitation keypair: {:?}", e),
                    "load_or_generate_invitation_keypair".to_string(),
                    true,
                )
            })?;

        // Store the keypair for future use
        let serialized = serde_json::to_string(&keypair).map_err(|e| {
            ClientError::SerializationError(format!(
                "Failed to serialize invitation keypair: {:?}",
                e
            ))
        })?;

        if let Err(e) = self
            .storage
            .store_config("invitation_keypair", &serialized)
            .await
        {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Failed to store invitation keypair: {:?}", e),
                Some("Keypair will be regenerated on next use"),
            );
        }

        Ok(keypair)
    }

    /// Ensure an invitation keypair is available in memory, generating one if needed
    pub(super) async fn ensure_invitation_keypair(
        &self,
    ) -> Result<crate::invitation::InvitationKeyPair, ClientError> {
        if let Some(existing) = {
            let state = self.state.read().await;
            state.invitation_keypair.clone()
        } {
            return Ok(existing);
        }

        let keypair = self.load_or_generate_invitation_keypair().await?;
        let mut state = self.state.write().await;
        state.invitation_keypair = Some(keypair.clone());
        Ok(keypair)
    }

    /// Enhanced epoch creation that uses group-specific information with specified epoch ID
    ///
    /// This ensures proper coordination with server-side epoch management by using
    /// the epoch ID determined by the coordination logic.
    pub(super) async fn create_genesis_epoch_for_group_with_id(
        &self,
        group_id: Uuid,
        epoch_id: u64,
    ) -> Result<u64, ClientError> {
        let membership = {
            let state = self.state.read().await;
            state.group_memberships.get(&group_id).cloned()
        };

        // Generate epoch key using secure random generation
        let mut epoch_key = [0u8; 32];
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut rng = OsRng;
        rng.fill_bytes(&mut epoch_key);

        // Upload epoch to server for group members using the specified epoch_id
        self.upload_group_epoch_to_server(group_id, epoch_id, &epoch_key)
            .await?;

        // Create epoch state with the specified epoch_id
        let epoch_state = EpochState {
            group_id: Some(group_id),
            epoch_id,
            encryption_key: epoch_key,
            key_source: EpochKeySource::LocalInit,
            members: membership
                .as_ref()
                .map(|m| m.members.clone())
                .unwrap_or_default(),
            created_at: Utc::now(),
            is_active: true,
            file_count: 0,
            marked_for_removal: false,
            removal_eligible_at: None,
        };

        // Store the epoch state
        {
            let mut state = self.state.write().await;
            Self::upsert_epoch_state(&mut state, group_id, epoch_state);
            state.current_epoch = epoch_id;

            if let Some(mut existing) = membership.clone() {
                existing.current_epoch_id = Some(epoch_id);
                existing.last_sync = Utc::now();
                state.group_memberships.insert(group_id, existing);
            }
        }

        self.save_client_state().await?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Created genesis epoch {} for group {}", epoch_id, group_id),
            membership
                .as_ref()
                .map(|m| format!("group_name: {}", m.group_name))
                .or_else(|| Some(format!("group_id: {}", group_id)))
                .as_deref(),
        );

        Ok(epoch_id)
    }

    /// Initialize a group's genesis epoch on the server and persist it locally
    pub async fn initialize_group_epoch(
        &self,
        group_id: Uuid,
        epoch_id: u64,
    ) -> Result<u64, ClientError> {
        self.ensure_state_loaded().await?;
        self.create_genesis_epoch_for_group_with_id(group_id, epoch_id)
            .await
    }

    /// Upload epoch key to server for group sharing
    pub(super) async fn upload_group_epoch_to_server(
        &self,
        group_id: Uuid,
        epoch_id: u64,
        encryption_key: &[u8],
    ) -> Result<(), ClientError> {
        // Load session information for authenticated request
        let session_info = match self.get_session_info().await {
            Ok(info) => info,
            Err(e) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Unable to load session information for epoch upload: {}", e),
                    Some("Run 'hybridcipher login' and retry"),
                );
                return Err(e);
            }
        };
        let auth_token = session_info.token.clone();

        if !self.validate_auth_token(&auth_token).await? {
            self.logger.log(
                crate::logging::LogLevel::Error,
                "Authentication token rejected before epoch upload",
                Some("Please run 'hybridcipher login' to refresh credentials"),
            );
            return Err(ClientError::InvalidState(
                "Authentication token is invalid or expired. Please run 'hybridcipher login' to authenticate"
                    .to_string(),
            ));
        }

        let session_user_id = session_info.user_id.ok_or_else(|| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                "Session data missing user identifier; cannot initialize epoch",
                Some("Run 'hybridcipher login' to refresh credentials"),
            );
            ClientError::InvalidState(
                "Session is missing user information. Please log in again before initializing the group"
                    .to_string(),
            )
        })?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 1: Starting welcome message construction",
            Some(&format!(
                "user_id: {}, epoch_id: {}",
                session_user_id, epoch_id
            )),
        );

        let invitation_keypair = self.ensure_invitation_keypair().await?;
        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 2: Invitation keypair obtained",
            Some(&format!("device_id: {}", invitation_keypair.device_id)),
        );

        let welcome_manager = WelcomeManager::new(self.storage.clone(), invitation_keypair.clone());
        let invitation_public_key = match invitation_keypair.invitation_public_key() {
            Ok(key) => {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    "Step 3: Invitation public key extracted successfully",
                    Some(&format!("key_length: {}", key.as_bytes().len())),
                );
                key
            }
            Err(e) => {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!(
                        "Step 3 FAILED: Could not extract invitation public key: {}",
                        e
                    ),
                    None,
                );
                return Err(e);
            }
        };

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 4: Starting epoch key encryption",
            Some(&format!("epoch_key_length: {}", encryption_key.len())),
        );

        let encrypted_epoch_key = match welcome_manager
            .encrypt_epoch_key_for_device(encryption_key, &invitation_public_key)
        {
            Ok(encrypted) => {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    "Step 4: Epoch key encryption successful",
                    Some(&format!("encrypted_length: {}", encrypted.len())),
                );
                encrypted
            }
            Err(e) => {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!("Step 4 FAILED: Epoch key encryption failed: {}", e),
                    None,
                );
                return Err(e);
            }
        };

        let signing_public_key = self.device_identity.public_key_bytes().to_vec();
        let created_at = Utc::now();
        let expires_at = Some(created_at + Duration::days(7));
        let epoch_uuid = EpochIdMapper::u64_to_uuid(epoch_id, group_id.as_bytes());

        let signable = ServerWelcomeSignable::new(
            group_id,
            epoch_uuid,
            &invitation_keypair.device_id,
            &encrypted_epoch_key,
            created_at,
            expires_at,
        );

        let signable_bytes = signable.to_bytes().map_err(|e| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Step 5 FAILED: Unable to serialize welcome message for signing: {}",
                    e
                ),
                None,
            );
            ClientError::SerializationError(format!(
                "Failed to serialize welcome message for signing: {}",
                e
            ))
        })?;

        let signature = self.device_identity.sign(&signable_bytes).to_vec();

        let welcome_message = GeneratedWelcomeMessage {
            recipient_user_id: session_user_id,
            device_id: invitation_keypair.device_id.clone(),
            encrypted_epoch_key,
            signature,
            signing_public_key,
            created_at,
            expires_at,
        };

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 5: Welcome message constructed",
            Some(&format!(
                "recipient: {}, device: {}, encrypted_key_len: {}",
                welcome_message.recipient_user_id,
                welcome_message.device_id,
                welcome_message.encrypted_epoch_key.len()
            )),
        );

        let request_body = GenesisInitRequestBody {
            client_epoch_id: epoch_id,
            welcome_messages: vec![welcome_message],
        };

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 6: Request body constructed",
            Some(&format!(
                "epoch_id: {}, welcome_msg_count: {}",
                request_body.client_epoch_id,
                request_body.welcome_messages.len()
            )),
        );

        let base_server_url = Self::resolve_server_base_url(session_info.server_url.clone());
        let trimmed_server_url = base_server_url.trim_end_matches('/');
        let init_url = if trimmed_server_url.ends_with("/api/v1") {
            format!("{}/groups/{}/initialize", trimmed_server_url, group_id)
        } else {
            format!(
                "{}/api/v1/groups/{}/initialize",
                trimmed_server_url, group_id
            )
        };

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 7: Sending request to server",
            Some(&format!("url: {}", init_url)),
        );

        let client = reqwest::Client::new();

        // Try to serialize the request body to check for serialization issues
        let _serialized_body = match serde_json::to_string(&request_body) {
            Ok(json) => {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    "Step 7a: Request body serialization successful",
                    Some(&format!("json_length: {}", json.len())),
                );
                json
            }
            Err(e) => {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!("Step 7a FAILED: Request body serialization failed: {}", e),
                    None,
                );
                return Err(ClientError::InvalidState(format!(
                    "Failed to serialize request body: {}",
                    e
                )));
            }
        };

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 8: Making HTTP request",
            Some(&format!(
                "auth_token_prefix: {}...",
                &auth_token[..std::cmp::min(20, auth_token.len())]
            )),
        );

        let response = client
            .post(&init_url)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!("Step 8 FAILED: HTTP request failed: {}", e),
                    Some(&format!("error_type: {:?}", e)),
                );
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to submit genesis initialization request: {}", e),
                    "upload_group_epoch_to_server".to_string(),
                    1,
                    "rejected".to_string(),
                )
            })?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 9: HTTP request successful, checking response",
            Some(&format!("status: {}", response.status())),
        );

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!("Step 9 FAILED: Server returned error status"),
                Some(&format!("status: {}, error: {}", status, error_text)),
            );

            return Err(ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!(
                    "Genesis initialization failed with status {}: {}",
                    status, error_text
                ),
                "upload_group_epoch_to_server".to_string(),
                1,
                "rejected".to_string(),
            ));
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            "Step 10: Response status OK, parsing JSON",
            None,
        );

        let response_body: GenesisInitResponseBody = response.json().await.map_err(|e| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!("Step 10 FAILED: Response JSON parsing failed: {}", e),
                None,
            );
            ClientError::network_error(
                ErrorCode::NetworkProtocol,
                format!("Failed to parse genesis initialization response: {}", e),
                "upload_group_epoch_to_server".to_string(),
                0,
                "decode".to_string(),
            )
        })?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Initialized genesis epoch {} (UUID {}) for group {}",
                response_body.epoch_number, response_body.epoch_id, group_id
            ),
            Some(&format!(
                "welcome_messages: {}",
                response_body.welcome_message_count
            )),
        );

        Ok(())
    }

    /// Generate a signed, hybrid-encrypted Welcome payload for a join card using the current epoch state
    pub async fn generate_welcome_for_join_card(
        &self,
        group_id: Uuid,
        join_card: crate::invitation::JoinCard,
        target_epoch_override: Option<u64>,
    ) -> Result<GeneratedWelcomeMessage, ClientError> {
        self.generate_welcome_for_join_card_with_policy(
            group_id,
            join_card,
            target_epoch_override,
            PinningPolicy::default(),
        )
        .await
    }

    /// Generate a signed, hybrid-encrypted Welcome payload for a join card using the current epoch state
    /// with explicit pinning policy control.
    pub async fn generate_welcome_for_join_card_with_policy(
        &self,
        group_id: Uuid,
        join_card: crate::invitation::JoinCard,
        target_epoch_override: Option<u64>,
        pinning_policy: PinningPolicy,
    ) -> Result<GeneratedWelcomeMessage, ClientError> {
        self.ensure_state_loaded().await?;

        join_card.verify_signature()?;
        if !join_card.is_valid() {
            return Err(ClientError::InvalidState(
                "Join card has expired and cannot be used to generate a Welcome message"
                    .to_string(),
            ));
        }

        match self.verify_join_card_with_pinning(&join_card).await? {
            PinningVerificationResult::Verified => {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "Join card for {}:{} passed key pinning verification",
                        join_card.user_id, join_card.device_id
                    ),
                    Some("pinning_verification"),
                );
            }
            PinningVerificationResult::KeyMismatch {
                pinned_fingerprint,
                join_card_fingerprint,
            } => {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!(
                        "Join card key mismatch for {}:{} (pinned {}, provided {})",
                        join_card.user_id,
                        join_card.device_id,
                        pinned_fingerprint,
                        join_card_fingerprint
                    ),
                    Some("pinning_verification"),
                );
                return Err(ClientError::SecurityViolation(format!(
                    "Join card identity key mismatch for {}:{} (pinned {}, provided {}). Rejecting Welcome generation.",
                    join_card.user_id, join_card.device_id, pinned_fingerprint, join_card_fingerprint
                )));
            }
            PinningVerificationResult::RequiresVerification { prompt } => {
                let message = match prompt {
                    PinningPrompt::FirstContact {
                        user_id,
                        device_id,
                        fingerprint,
                        ..
                    } => format!(
                        "Join card for {user_id}:{device_id} has not been verified. Confirm fingerprint {fingerprint} via `hybridcipher pin add --user {user_id} --device {device_id}` (or equivalent) before generating a Welcome."
                    ),
                    PinningPrompt::Unverified {
                        user_id,
                        device_id,
                        fingerprint,
                        ..
                    } => format!(
                        "Join card for {user_id}:{device_id} is pinned but unverified. Confirm fingerprint {fingerprint} via `hybridcipher pin verify {user_id} {device_id} --fingerprint {fingerprint}` (or equivalent) before generating a Welcome."
                    ),
                    PinningPrompt::KeyChanged {
                        user_id,
                        device_id,
                        old_fingerprint,
                        new_fingerprint,
                        ..
                    } => format!(
                        "Join card key for {user_id}:{device_id} changed (pinned {old_fingerprint}, provided {new_fingerprint}). Verify out-of-band and update the pin before generating a Welcome."
                    ),
                };

                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Join card for {}:{} requires key verification before proceeding",
                        join_card.user_id, join_card.device_id
                    ),
                    Some("pinning_verification"),
                );

                if pinning_policy == PinningPolicy::RequireVerified {
                    return Err(ClientError::PinningRequired(message));
                }

                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    "Proceeding without pinning verification (policy override)",
                    Some("pinning_verification"),
                );
            }
        }

        let invitation_public_key = join_card.invitation_public_key()?;

        let (epoch_state, epoch_uuid) = {
            let state = self.state.read().await;
            let membership = state.group_memberships.get(&group_id).ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "No cached membership information for group {}",
                    group_id
                ))
            })?;

            let epoch_id = target_epoch_override
                .or(membership.current_epoch_id)
                .ok_or_else(|| {
                    ClientError::InvalidState(format!(
                        "Group {} does not have an active epoch in local state",
                        group_id
                    ))
                })?;

            let epoch_state = Self::get_epoch_state(&state, group_id, epoch_id)
                .cloned()
                .ok_or_else(|| {
                    ClientError::InvalidState(format!(
                        "Epoch {} for group {} is not present in local state",
                        epoch_id, group_id
                    ))
                })?;

            let epoch_uuid = EpochIdMapper::u64_to_uuid(epoch_state.epoch_id, group_id.as_bytes());
            (epoch_state, epoch_uuid)
        };

        let invitation_keypair = self.ensure_invitation_keypair().await?;
        let welcome_manager = WelcomeManager::new(self.storage.clone(), invitation_keypair);

        let encrypted_epoch_key = welcome_manager
            .encrypt_epoch_key_for_device(&epoch_state.encryption_key, &invitation_public_key)?;

        let signing_public_key = self.device_identity.public_key_bytes().to_vec();
        let created_at = Utc::now();
        let expires_at = Some(created_at + Duration::days(7));

        let signable = ServerWelcomeSignable::new(
            group_id,
            epoch_uuid,
            &join_card.device_id,
            &encrypted_epoch_key,
            created_at,
            expires_at,
        );

        let signable_bytes = signable.to_bytes().map_err(|e| {
            ClientError::SerializationError(format!(
                "Failed to serialize Welcome payload for signing: {}",
                e
            ))
        })?;

        let signature = self.device_identity.sign(&signable_bytes).to_vec();

        Ok(GeneratedWelcomeMessage {
            recipient_user_id: join_card.user_id,
            device_id: join_card.device_id,
            encrypted_epoch_key,
            signature,
            signing_public_key,
            created_at,
            expires_at,
        })
    }

    /// Generate a Welcome payload for a pending device using the stored invitation public key.
    pub async fn generate_welcome_for_pending_device(
        &self,
        group_id: Uuid,
        device_id: &str,
        recipient_user_id: Uuid,
        invitation_public_key_bytes: &[u8],
    ) -> Result<GeneratedWelcomeMessage, ClientError> {
        self.ensure_state_loaded().await?;

        let invitation_public_key = HybridPublicKey::from_bytes(invitation_public_key_bytes)
            .map_err(|e| ClientError::Crypto(e))?;

        let (epoch_state, epoch_uuid) = {
            let state = self.state.read().await;
            let membership = state.group_memberships.get(&group_id).ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "No cached membership information for group {}",
                    group_id
                ))
            })?;

            let epoch_id = membership.current_epoch_id.ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Group {} does not have an active epoch in local state",
                    group_id
                ))
            })?;

            let epoch_state = Self::get_epoch_state(&state, group_id, epoch_id)
                .cloned()
                .ok_or_else(|| {
                    ClientError::InvalidState(format!(
                        "Epoch {} for group {} is not present in local state",
                        epoch_id, group_id
                    ))
                })?;

            let epoch_uuid = EpochIdMapper::u64_to_uuid(epoch_state.epoch_id, group_id.as_bytes());
            (epoch_state, epoch_uuid)
        };

        let invitation_keypair = self.ensure_invitation_keypair().await?;
        let welcome_manager = WelcomeManager::new(self.storage.clone(), invitation_keypair);

        let encrypted_epoch_key = welcome_manager
            .encrypt_epoch_key_for_device(&epoch_state.encryption_key, &invitation_public_key)?;

        let signing_public_key = self.device_identity.public_key_bytes().to_vec();
        let created_at = Utc::now();
        let expires_at = Some(created_at + Duration::days(7));

        let signable = ServerWelcomeSignable::new(
            group_id,
            epoch_uuid,
            device_id,
            &encrypted_epoch_key,
            created_at,
            expires_at,
        );

        let signable_bytes = signable.to_bytes().map_err(|e| {
            ClientError::SerializationError(format!(
                "Failed to serialize Welcome payload for signing: {}",
                e
            ))
        })?;

        let signature = self.device_identity.sign(&signable_bytes).to_vec();

        Ok(GeneratedWelcomeMessage {
            recipient_user_id,
            device_id: device_id.to_string(),
            encrypted_epoch_key,
            signature,
            signing_public_key,
            created_at,
            expires_at,
        })
    }

    /// Generate a Welcome payload for the current device after recovery so the server
    /// treats the device as fully provisioned for the active epoch.
    pub async fn generate_self_welcome_after_recovery(
        &self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<GeneratedWelcomeMessage, ClientError> {
        self.ensure_state_loaded().await?;

        let invitation_keypair = self.ensure_invitation_keypair().await?;
        let invitation_public = invitation_keypair.invitation_public_key()?;
        let public_key_bytes = invitation_public.to_bytes();

        let device_id = self.local_device_id();
        if invitation_keypair.device_id != device_id {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                "Invitation keypair device ID mismatch detected during recovery welcome generation",
                Some(&format!(
                    "stored: {}, derived: {}",
                    invitation_keypair.device_id, device_id
                )),
            );
        }

        self.generate_welcome_for_pending_device(
            group_id,
            &device_id,
            user_id,
            public_key_bytes.as_ref(),
        )
        .await
    }
}
