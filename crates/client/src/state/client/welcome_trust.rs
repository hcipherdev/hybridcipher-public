use super::*;
use crate::welcome_manager::EpochSecrets;
use crate::welcome_signers::{GroupSignerTrust, SignerIntroduction};

fn signer_trust_key(group_id: Uuid) -> String {
    format!("welcome_signer_trust_{group_id}")
}

#[derive(Deserialize)]
struct WelcomeSignersBody {
    signers: Vec<WelcomeSignerBody>,
}

#[derive(Deserialize)]
struct WelcomeSignerBody {
    identity_public_key_hex: String,
}

impl<S: Storage, N: Network> Client<S, N> {
    /// Open a Welcome, accepting it only when its signer may sign Welcomes for the group.
    pub(super) async fn open_trusted_welcome(
        &self,
        welcome_manager: &WelcomeManager<S>,
        message: &ServerWelcomeMessage,
        group_id: Uuid,
        epoch_id: Uuid,
    ) -> Result<EpochSecrets, ClientError> {
        let secrets = welcome_manager
            .process_server_welcome_message(message, group_id, epoch_id)
            .await?;
        self.authorize_welcome_signer(
            group_id,
            &message.signing_public_key,
            &secrets.signer_introductions,
        )
        .await?;
        Ok(secrets)
    }

    /// Accept `signer_key` only if this device trusts it for `group_id`, after learning
    /// from the introductions the Welcome carried.
    pub(super) async fn authorize_welcome_signer(
        &self,
        group_id: Uuid,
        signer_key: &[u8],
        introductions: &[SignerIntroduction],
    ) -> Result<(), ClientError> {
        let (mut trust, seeded) = self
            .load_or_seed_signer_trust(group_id, Some(signer_key))
            .await?;
        let learned = trust.absorb(introductions);
        if seeded || learned {
            self.store_signer_trust(&trust).await?;
        }
        if signer_key == self.device_identity.public_key_bytes() || trust.trusts(signer_key) {
            return Ok(());
        }

        self.logger.log(
            crate::logging::LogLevel::Warn,
            "Rejected a Welcome signed by a device this device does not trust for the group",
            Some(&format!(
                "group_id: {}, signer_sha256: {}",
                group_id,
                hex::encode(Sha256::digest(signer_key))
            )),
        );
        Err(initialization::setup_error(
            ErrorCode::SecurityTampering,
            "This group key was signed by a device this device does not trust. \
             Ask a group admin to approve this device again.",
        ))
    }

    /// Encrypt `epoch` for a recipient device together with the signer introductions it
    /// needs, including one vouching for the recipient, which this device is approving.
    pub(super) async fn encrypt_welcome_epoch(
        &self,
        welcome_manager: &WelcomeManager<S>,
        group_id: Uuid,
        epoch: &EpochState,
        recipient_identity_key: &[u8],
        recipient_invitation_key: &HybridPublicKey,
    ) -> Result<Vec<u8>, ClientError> {
        let secrets = EpochSecrets {
            epoch_key: epoch.encryption_key,
            epoch_id: epoch.epoch_id,
            group_members: Vec::new(),
            active_at: epoch.created_at,
            signer_introductions: self
                .welcome_signer_introductions(group_id, recipient_identity_key)
                .await?,
        };
        welcome_manager.encrypt_epoch_secrets_for_device(&secrets, recipient_invitation_key)
    }

    /// Introductions to send with a Welcome for the device whose identity key is
    /// `recipient_key`: everything this device knows for the group, plus one vouching
    /// for the recipient, which this device is approving.
    async fn welcome_signer_introductions(
        &self,
        group_id: Uuid,
        recipient_key: &[u8],
    ) -> Result<Vec<SignerIntroduction>, ClientError> {
        let (mut trust, seeded) = self.load_or_seed_signer_trust(group_id, None).await?;
        let introduced = trust.introduce(&self.device_identity, recipient_key);
        if seeded || introduced {
            self.store_signer_trust(&trust).await?;
        }
        Ok(trust.introductions().to_vec())
    }

    /// This device's trusted Welcome signers for `group_id`, and whether they were just
    /// seeded. The first time, the set is seeded from the group's approved devices as the
    /// server reports them (trust on first use), falling back to `first_signer` when that
    /// list is unavailable. This device's own key is always included.
    async fn load_or_seed_signer_trust(
        &self,
        group_id: Uuid,
        first_signer: Option<&[u8]>,
    ) -> Result<(GroupSignerTrust, bool), ClientError> {
        if let Some(stored) = self
            .storage
            .load_config(&signer_trust_key(group_id))
            .await?
            .filter(|stored| !stored.is_empty())
        {
            let trust = serde_json::from_str(&stored).map_err(|e| {
                ClientError::SerializationError(format!(
                    "Stored Welcome signer trust for group {} is unreadable: {}",
                    group_id, e
                ))
            })?;
            return Ok((trust, false));
        }

        let mut keys = vec![self.device_identity.public_key_bytes().to_vec()];
        match self.fetch_welcome_signer_roster(group_id).await {
            Ok(roster) => keys.extend(roster),
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Group device list unavailable; trusting this Welcome's signer on first use: {}",
                        err
                    ),
                    Some(&format!("group_id: {}", group_id)),
                );
                keys.extend(first_signer.map(<[u8]>::to_vec));
            }
        }
        let trust = GroupSignerTrust::seeded(group_id, keys.iter().map(Vec::as_slice));
        Ok((trust, true))
    }

    async fn store_signer_trust(&self, trust: &GroupSignerTrust) -> Result<(), ClientError> {
        let serialized = serde_json::to_string(trust).map_err(|e| {
            ClientError::SerializationError(format!("Failed to store Welcome signer trust: {}", e))
        })?;
        self.storage
            .store_config(&signer_trust_key(trust.group_id), &serialized)
            .await?;
        Ok(())
    }

    /// Identity keys of the group's approved devices, as the server reports them.
    async fn fetch_welcome_signer_roster(&self, group_id: Uuid) -> Result<Vec<Vec<u8>>, String> {
        let session = self
            .get_session_info()
            .await
            .map_err(|err| err.to_string())?;
        let server_url = self.active_server_base_url().await;
        let response = reqwest::Client::new()
            .get(format!(
                "{}/api/v1/groups/{}/welcome-signers",
                server_url, group_id
            ))
            .bearer_auth(&session.token)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|err| format!("request failed: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("server answered {}", response.status()));
        }
        let body: WelcomeSignersBody = response
            .json()
            .await
            .map_err(|err| format!("invalid response: {err}"))?;
        Ok(body
            .signers
            .into_iter()
            .filter_map(|signer| hex::decode(signer.identity_public_key_hex).ok())
            .filter(|key| key.len() == 32)
            .collect())
    }
}

#[cfg(test)]
#[path = "../../../tests/device_security/test_welcome_signer_enforcement.rs"]
mod tests;
