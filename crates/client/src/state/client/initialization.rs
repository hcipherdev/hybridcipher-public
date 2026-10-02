//! Retry-safe group genesis setup and canonical device readiness.

use super::*;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Serialize, Deserialize)]
struct PendingGenesis {
    user_id: Uuid,
    device_id: String,
    server_url: String,
    group_id: Uuid,
    request: GenesisInitRequestBody,
    epoch_key: [u8; 32],
}

impl Drop for PendingGenesis {
    fn drop(&mut self) {
        self.epoch_key.zeroize();
    }
}

pub(super) fn setup_error(code: ErrorCode, message: impl Into<String>) -> ClientError {
    ClientError::ConsistencyError {
        context: ErrorContext::new(code, message.into(), "group_initialization".into()),
        recovery_action: crate::errors::RecoveryAction::Abort {
            safe_cleanup: false,
            user_notification: "Retry setup or approve this device from an authorized device"
                .into(),
        },
        affected_operations: vec!["group_initialization".into()],
    }
}

/// Classify the API's stable error code, with exact legacy compatibility.
pub(super) fn group_api_error_code(status: StatusCode, body: &str) -> Option<ErrorCode> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let code = value.get("code").and_then(serde_json::Value::as_str);
    match (status, code) {
        (StatusCode::BAD_REQUEST, Some("group_not_initialized")) => {
            Some(ErrorCode::GroupNotInitialized)
        }
        (StatusCode::BAD_REQUEST | StatusCode::CONFLICT, Some("genesis_already_initialized")) => {
            Some(ErrorCode::GroupGenesisConflict)
        }
        (StatusCode::PRECONDITION_REQUIRED, Some("device_approval_required")) => {
            Some(ErrorCode::GroupDeviceApprovalRequired)
        }
        (StatusCode::BAD_REQUEST, None)
            if matches!(
                value.get("error").and_then(serde_json::Value::as_str),
                Some("Group has no current epoch" | "Group has no active epoch")
            ) =>
        {
            Some(ErrorCode::GroupNotInitialized)
        }
        _ => None,
    }
}

pub(super) fn pending_key(
    server_url: &str,
    user_id: Uuid,
    device_id: &str,
    group_id: Uuid,
) -> String {
    let scope =
        serde_json::to_vec(&(server_url, user_id, device_id, group_id)).expect("scope serializes");
    format!("pending_genesis_{}", hex::encode(Sha256::digest(scope)))
}

impl<S: Storage, N: Network> Client<S, N> {
    /// Check locally saved current-group keys without any server request.
    /// A membership's epoch identifier alone is never sufficient.
    pub async fn has_cached_group_key(&self, group_id: Uuid) -> Result<bool, ClientError> {
        self.ensure_state_loaded().await?;
        let observed = self
            .storage
            .load_config_fresh(&format!("committed_group_epoch_{group_id}"))
            .await?
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    setup_error(
                        ErrorCode::StorageCorruption,
                        "Saved group epoch metadata cannot be read",
                    )
                })
            })
            .transpose()?;
        let state = self.state.read().await;
        let current = state
            .group_memberships
            .get(&group_id)
            .and_then(|membership| membership.current_epoch_id)
            .or(observed);
        Ok(current
            .and_then(|epoch_id| Self::get_epoch_state(&state, group_id, epoch_id))
            .is_some_and(|epoch| epoch.is_active && epoch.key_source.is_verified()))
    }

    /// Load a value from the client's configured per-account storage.
    pub async fn load_local_config(&self, key: &str) -> Result<Option<String>, ClientError> {
        Ok(self.storage.load_config_fresh(key).await?)
    }

    /// Store a value using the client's configured per-account protection.
    pub async fn store_local_config(&self, key: &str, value: &str) -> Result<(), ClientError> {
        Ok(self.storage.store_config(key, value).await?)
    }

    /// Prepare a group and distinguish approval from retryable setup errors.
    pub async fn prepare_group_for_use(
        &self,
        group_id: Uuid,
    ) -> Result<GroupInitializationReadiness, ClientError> {
        self.ensure_state_loaded().await?;
        let result = match self.fetch_committed_group_epoch(group_id).await {
            Err(error) if error.error_code() == Some(ErrorCode::GroupNotInitialized) => {
                self.initialize_group_epoch(group_id, 1).await
            }
            result => result,
        };
        match result {
            Ok(epoch_id) => Ok(GroupInitializationReadiness::Ready { epoch_id }),
            Err(error) if error.error_code() == Some(ErrorCode::GroupDeviceApprovalRequired) => {
                Ok(GroupInitializationReadiness::WaitingDeviceApproval)
            }
            Err(error) => Err(error),
        }
    }

    /// Return only after the committed server epoch has been decrypted and saved.
    pub async fn ensure_group_initialized(&self, group_id: Uuid) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;
        match self.fetch_any_available_epoch_from_server(group_id).await {
            Ok(()) => Ok(()),
            Err(error) if error.error_code() == Some(ErrorCode::GroupNotInitialized) => {
                self.initialize_group_epoch(group_id, 1).await.map(|_| ())
            }
            Err(error) => Err(error),
        }
    }

    /// Initialize genesis, reusing the exact protected request after an uncertain response.
    pub async fn initialize_group_epoch(
        &self,
        group_id: Uuid,
        epoch_id: u64,
    ) -> Result<u64, ClientError> {
        self.ensure_state_loaded().await?;
        if epoch_id != 1 {
            return Err(ClientError::InvalidInput(
                "Group genesis must use epoch 1".into(),
            ));
        }
        // A second device must consume an existing Welcome rather than invent keys.
        match self.fetch_committed_group_epoch(group_id).await {
            Ok(epoch_id) => return Ok(epoch_id),
            Err(error) if error.error_code() == Some(ErrorCode::GroupNotInitialized) => {}
            Err(error) => return Err(error),
        }
        let session = self.get_session_info().await?;
        let user_id = session
            .user_id
            .ok_or_else(|| ClientError::Auth("Sign in before preparing a group".into()))?;
        let server_url = Self::resolve_server_base_url(session.server_url.clone());
        let invitation = self.ensure_invitation_keypair().await?;
        let pending = self
            .load_or_create_pending_genesis(group_id, user_id, &server_url, &invitation)
            .await?;
        if pending.user_id != user_id
            || pending.device_id != invitation.device_id
            || pending.server_url != server_url
            || pending.group_id != group_id
            || pending.request.client_epoch_id != epoch_id
        {
            return Err(setup_error(
                ErrorCode::SecurityTampering,
                "Saved group setup does not match this account, device and group",
            ));
        }
        Self::submit_pending_genesis(&pending, &session.token, std::time::Duration::from_secs(30))
            .await?;
        self.fetch_committed_group_epoch(group_id).await
    }

    async fn load_or_create_pending_genesis(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        server_url: &str,
        invitation: &InvitationKeyPair,
    ) -> Result<PendingGenesis, ClientError> {
        let key = pending_key(server_url, user_id, &invitation.device_id, group_id);
        if let Some(value) = self.storage.load_config_fresh(&key).await? {
            let value = Zeroizing::new(value);
            return serde_json::from_str(&value).map_err(|_| {
                setup_error(
                    ErrorCode::StorageCorruption,
                    "Saved group setup cannot be read; it was preserved for recovery",
                )
            });
        }
        let candidate = self
            .build_pending_genesis(group_id, user_id, server_url, invitation)
            .await?;
        let encoded = Zeroizing::new(
            serde_json::to_string(&candidate)
                .map_err(|error| ClientError::SerializationError(error.to_string()))?,
        );
        self.storage
            .create_protected_config_if_absent(&key, &encoded)
            .await?;
        let persisted =
            Zeroizing::new(self.storage.load_config_fresh(&key).await?.ok_or_else(|| {
                setup_error(ErrorCode::StorageWrite, "Group setup could not be saved")
            })?);
        serde_json::from_str(&persisted).map_err(|_| {
            setup_error(
                ErrorCode::StorageCorruption,
                "Saved group setup cannot be read",
            )
        })
    }

    async fn submit_pending_genesis(
        pending: &PendingGenesis,
        auth_token: &str,
        timeout: std::time::Duration,
    ) -> Result<(), ClientError> {
        let api = pending.server_url.trim_end_matches('/');
        let group_id = pending.group_id;
        let endpoint = if api.ends_with("/api/v1") {
            format!("{api}/groups/{group_id}/initialize")
        } else {
            format!("{api}/api/v1/groups/{group_id}/initialize")
        };
        let response = reqwest::Client::new()
            .post(endpoint)
            .bearer_auth(auth_token)
            .json(&pending.request)
            .timeout(timeout)
            .send()
            .await
            .map_err(|error| {
                ClientError::network_error(
                    if error.is_timeout() {
                        ErrorCode::NetworkTimeout
                    } else {
                        ErrorCode::NetworkConnection
                    },
                    format!("Group setup response is uncertain: {error}"),
                    "group_initialization".into(),
                    0,
                    "pending".into(),
                )
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if group_api_error_code(status, &body) != Some(ErrorCode::GroupGenesisConflict) {
                if let Some(code) = group_api_error_code(status, &body) {
                    return Err(setup_error(
                        code,
                        "Group setup requires an authorized device",
                    ));
                }
                return Err(ClientError::network_error(
                    ErrorCode::NetworkProtocol,
                    format!("Group setup was rejected ({status}): {body}"),
                    "group_initialization".into(),
                    0,
                    "pending".into(),
                ));
            }
            // The caller must reconcile the canonical winner before reporting ready.
        }
        Ok(())
    }
    #[cfg(test)]
    async fn ready_group_epoch(&self, group_id: Uuid) -> Result<u64, ClientError> {
        let state = self.state.read().await;
        state
            .epochs
            .values()
            .flatten()
            .filter(|epoch| {
                epoch.group_id == Some(group_id)
                    && epoch.is_active
                    && epoch.key_source == EpochKeySource::Welcome
            })
            .map(|epoch| epoch.epoch_id)
            .max()
            .ok_or_else(|| {
                setup_error(
                    ErrorCode::GroupDeviceApprovalRequired,
                    "This device needs approval to receive group keys",
                )
            })
    }

    async fn build_pending_genesis(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        server_url: &str,
        invitation: &InvitationKeyPair,
    ) -> Result<PendingGenesis, ClientError> {
        use rand::RngCore;
        let mut epoch_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(epoch_key.as_mut());
        let manager = WelcomeManager::new(self.storage.clone(), invitation.clone());
        let encrypted_epoch_key = manager.encrypt_epoch_key_for_device(
            epoch_key.as_ref(),
            &invitation.invitation_public_key()?,
        )?;
        let created_at = Utc::now();
        // This self-Welcome bootstraps the registered creator device. Its fetch
        // remains subject to live membership/device approval; making it durable
        // lets a lost response be recovered even after a long offline interval.
        let expires_at = None;
        let signable = ServerWelcomeSignable::new(
            group_id,
            EpochIdMapper::u64_to_uuid(1, group_id.as_bytes()),
            &invitation.device_id,
            &encrypted_epoch_key,
            created_at,
            expires_at,
        );
        let bytes = signable
            .to_bytes()
            .map_err(|error| ClientError::SerializationError(error.to_string()))?;
        Ok(PendingGenesis {
            user_id,
            device_id: invitation.device_id.clone(),
            server_url: server_url.into(),
            group_id,
            epoch_key: *epoch_key,
            request: GenesisInitRequestBody {
                client_epoch_id: 1,
                welcome_messages: vec![GeneratedWelcomeMessage {
                    recipient_user_id: user_id,
                    device_id: invitation.device_id.clone(),
                    encrypted_epoch_key,
                    signature: self.device_identity.sign(&bytes).to_vec(),
                    signing_public_key: self.device_identity.public_key_bytes().to_vec(),
                    created_at,
                    expires_at,
                }],
            },
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/initialization/test_group_initialization.rs"]
mod tests;
