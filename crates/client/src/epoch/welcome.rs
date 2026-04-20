/// Welcome message processing with migration-aware key distribution
///
/// Handles Welcome message processing during migration phases, supporting
/// key distribution for multiple concurrent epochs with comprehensive validation,
/// migration awareness, and recovery capabilities.
use crate::{
    epoch::state::{EpochState, Member, MemberCapabilities, MemberStatus},
    epoch_key_source::EpochKeySource,
    storage::Storage,
};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hybridcipher_crypto::{
    aead::AeadContext,
    hybridkem::{decap, Context, HybridCiphertext, HybridSecretKey},
    signatures::{verify, Ed25519KeyPair, Signature, VerifyingKey},
};
use hybridcipher_messages::welcome::{EpochSecrets, Welcome};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

/// Welcome message processor for migration-aware key distribution
///
/// Processes Welcome messages containing cryptographic material for new group members,
/// with support for multi-epoch key distribution during migration phases.
#[derive(Debug)]
pub struct WelcomeProcessor<S: Storage> {
    /// Storage interface for persisting epoch state
    storage: Arc<S>,

    /// Device identity for signature verification
    device_identity: Ed25519KeyPair,

    /// Local device identifier
    device_id: String,

    /// Pending keys awaiting cutover activation
    pending_keys: HashMap<u64, PendingKeyState>,
}

/// State for keys pending activation during migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingKeyState {
    /// Epoch secrets for the pending epoch
    pub secrets: EpochSecrets,

    /// When these keys were received
    pub received_at: DateTime<Utc>,

    /// Whether activation is awaiting cutover completion
    pub awaiting_cutover: bool,

    /// Source Welcome message signature for verification
    pub welcome_signature: Vec<u8>,
}

/// Configuration for Welcome message processing
#[derive(Debug, Clone)]
pub struct WelcomeConfig {
    /// Maximum age for Welcome messages (seconds)
    pub max_message_age: u64,

    /// Enable partial Welcome processing during network partitions
    pub allow_partial_welcome: bool,

    /// Maximum retry attempts for failed Welcome processing
    pub max_retry_attempts: u32,

    /// Timeout for Welcome message validation (milliseconds)
    pub validation_timeout_ms: u64,
}

impl Default for WelcomeConfig {
    fn default() -> Self {
        Self {
            max_message_age: 3600, // 1 hour
            allow_partial_welcome: true,
            max_retry_attempts: 3,
            validation_timeout_ms: 5000, // 5 seconds
        }
    }
}

/// Welcome processing result with migration state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeResult {
    /// Successfully processed epochs
    pub processed_epochs: Vec<u64>,

    /// Epochs pending cutover activation
    pub pending_epochs: Vec<u64>,

    /// Any errors encountered during processing
    pub errors: Vec<WelcomeError>,

    /// Whether the member is now fully activated
    pub member_activated: bool,
}

impl<S: Storage> WelcomeProcessor<S> {
    /// Create new Welcome processor with device identity
    pub fn new(storage: Arc<S>, device_identity: Ed25519KeyPair, device_id: String) -> Self {
        Self {
            storage,
            device_identity,
            device_id,
            pending_keys: HashMap::new(),
        }
    }

    /// Process Welcome message with migration-aware key distribution
    ///
    /// Supports keys from multiple concurrent epochs during migration phases,
    /// with comprehensive validation and activation coordination.
    pub async fn process_welcome(
        &mut self,
        welcome: &Welcome,
        invitation_private_key: &HybridSecretKey,
        config: &WelcomeConfig,
    ) -> Result<WelcomeResult, WelcomeError> {
        // Validate Welcome message structure and freshness
        self.validate_welcome_message(welcome, config).await?;

        // Decrypt epoch secrets from Welcome payload
        let secrets = self
            .decrypt_welcome_secrets(welcome, invitation_private_key)
            .await?;

        // Verify admin signature on Welcome message
        self.verify_welcome_signature(welcome).await?;

        // Process epoch keys with migration awareness
        let result = self.process_epoch_keys(welcome, &secrets, config).await?;

        // Update member status and activation state
        self.update_member_status(welcome, &result).await?;

        // Persist Welcome processing results
        self.persist_welcome_state(welcome, &secrets, &result)
            .await?;

        Ok(result)
    }

    /// Validate Welcome message structure and freshness
    async fn validate_welcome_message(
        &self,
        welcome: &Welcome,
        config: &WelcomeConfig,
    ) -> Result<(), WelcomeError> {
        // Basic structure validation
        welcome.validate().map_err(|e| {
            WelcomeError::InvalidMessage(format!("Structure validation failed: {}", e))
        })?;

        // Check message freshness
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| WelcomeError::InvalidMessage(format!("Time error: {}", e)))?
            .as_secs();

        let message_age = current_time.saturating_sub(welcome.epoch_info.created_at);
        if message_age > config.max_message_age {
            return Err(WelcomeError::MessageTooOld(format!(
                "Message age {} exceeds maximum {}",
                message_age, config.max_message_age
            )));
        }

        // Verify epoch hasn't expired
        if welcome.epoch_info.is_expired(current_time) {
            return Err(WelcomeError::EpochExpired(format!(
                "Epoch {} has expired",
                welcome.epoch_info.sequence
            )));
        }

        // Check if this is our device
        if welcome.recipient_device_id != self.device_id {
            return Err(WelcomeError::WrongRecipient(
                "Welcome not intended for this device".to_string(),
            ));
        }

        Ok(())
    }

    /// Decrypt epoch secrets from Welcome message payload
    async fn decrypt_welcome_secrets(
        &self,
        welcome: &Welcome,
        invitation_private_key: &HybridSecretKey,
    ) -> Result<EpochSecrets, WelcomeError> {
        let kem_len = hybridcipher_crypto::hybridkem::HYBRID_CIPHERTEXT_LEN;
        let nonce_len = hybridcipher_crypto::aead::AEAD_NONCE_LEN;

        if welcome.encrypted_payload.len() < kem_len + nonce_len {
            return Err(WelcomeError::DecryptionFailed(
                "Encrypted payload too short".to_string(),
            ));
        }

        let (kem_bytes, rest) = welcome.encrypted_payload.split_at(kem_len);
        let (nonce_bytes, ciphertext) = rest.split_at(nonce_len);

        let kem_ciphertext = HybridCiphertext::from_bytes(kem_bytes).map_err(|e| {
            WelcomeError::DecryptionFailed(format!("Invalid ciphertext format: {}", e))
        })?;
        let nonce = hybridcipher_crypto::aead::Nonce::from_bytes(nonce_bytes)
            .map_err(|e| WelcomeError::DecryptionFailed(format!("Invalid nonce: {}", e)))?;

        let shared_secret = decap(invitation_private_key, &kem_ciphertext, Context::Welcome)
            .map_err(|e| {
                WelcomeError::DecryptionFailed(format!("HybridKEM decryption failed: {}", e))
            })?;

        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut key_bytes = [0u8; 32];
        hk.expand(b"welcome aead", &mut key_bytes)
            .map_err(|_| WelcomeError::DecryptionFailed("HKDF expand failed".into()))?;
        let aead_key = hybridcipher_crypto::aead::Key::from_bytes(&key_bytes)
            .map_err(|e| WelcomeError::DecryptionFailed(format!("AEAD key error: {}", e)))?;

        let plaintext = hybridcipher_crypto::aead::open(
            &aead_key,
            &nonce,
            AeadContext::Welcome,
            &[],
            ciphertext,
        )
        .map_err(|e| WelcomeError::DecryptionFailed(format!("AEAD decryption failed: {}", e)))?;

        // Deserialize epoch secrets
        let secrets = EpochSecrets::from_bytes(&plaintext).map_err(|e| {
            WelcomeError::InvalidMessage(format!("Failed to deserialize secrets: {}", e))
        })?;

        // Validate secrets structure
        secrets.validate().map_err(|e| {
            WelcomeError::InvalidMessage(format!("Secrets validation failed: {}", e))
        })?;

        Ok(secrets)
    }

    /// Verify admin signature on Welcome message
    async fn verify_welcome_signature(&self, welcome: &Welcome) -> Result<(), WelcomeError> {
        // Create message to verify (without signature)
        let mut welcome_copy = welcome.clone();
        welcome_copy.admin_signature = Vec::new();

        let message_bytes = serde_json::to_vec(&welcome_copy).map_err(|e| {
            WelcomeError::InvalidMessage(format!("Failed to serialize for verification: {}", e))
        })?;

        // Get admin's public key from group members
        let admin_member = welcome
            .group_members
            .iter()
            .find(|member| member.is_admin)
            .ok_or_else(|| {
                WelcomeError::InvalidMessage("No admin found in group members".to_string())
            })?;

        let admin_public_key =
            VerifyingKey::from_bytes(&admin_member.identity_public).map_err(|e| {
                WelcomeError::InvalidMessage(format!("Invalid admin public key: {}", e))
            })?;

        // Verify signature
        let signature = Signature::from_bytes(&welcome.admin_signature).map_err(|e| {
            WelcomeError::InvalidMessage(format!("Invalid admin signature format: {}", e))
        })?;

        verify(&admin_public_key, &message_bytes, &signature).map_err(|e| {
            WelcomeError::SignatureVerificationFailed(format!(
                "Admin signature verification failed: {}",
                e
            ))
        })?;

        Ok(())
    }

    /// Process epoch keys with migration awareness
    async fn process_epoch_keys(
        &mut self,
        welcome: &Welcome,
        secrets: &EpochSecrets,
        config: &WelcomeConfig,
    ) -> Result<WelcomeResult, WelcomeError> {
        let mut result = WelcomeResult {
            processed_epochs: Vec::new(),
            pending_epochs: Vec::new(),
            errors: Vec::new(),
            member_activated: false,
        };

        // Process current epoch key
        match self.process_current_epoch(welcome, secrets).await {
            Ok(activated) => {
                result.processed_epochs.push(welcome.epoch_info.sequence);
                result.member_activated = activated;
            }
            Err(e) => {
                if config.allow_partial_welcome {
                    result.errors.push(e);
                } else {
                    return Err(e);
                }
            }
        }

        // Process previous epoch keys for backward compatibility
        for (epoch_seq, epoch_key) in &secrets.previous_keys {
            match self.process_previous_epoch(*epoch_seq, epoch_key).await {
                Ok(_) => result.processed_epochs.push(*epoch_seq),
                Err(e) => {
                    if config.allow_partial_welcome {
                        result.errors.push(e);
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        // Check for pending migration epochs
        if let Ok(pending_epochs) = self.identify_pending_epochs(welcome).await {
            for epoch_id in pending_epochs {
                let pending_state = PendingKeyState {
                    secrets: secrets.clone(),
                    received_at: Utc::now(),
                    awaiting_cutover: true,
                    welcome_signature: welcome.admin_signature.clone(),
                };

                self.pending_keys.insert(epoch_id, pending_state);
                result.pending_epochs.push(epoch_id);
            }
        }

        Ok(result)
    }

    /// Process current epoch activation
    async fn process_current_epoch(
        &self,
        welcome: &Welcome,
        secrets: &EpochSecrets,
    ) -> Result<bool, WelcomeError> {
        let epoch_id = welcome.epoch_info.sequence;

        // Check if epoch already exists
        if let Ok(existing_epoch) = self.storage.load_epoch_state(epoch_id).await {
            // Verify keys match existing epoch
            if existing_epoch.encryption_key != secrets.epoch_key.as_slice() {
                return Err(WelcomeError::KeyMismatch(format!(
                    "Epoch {} key mismatch with existing state",
                    epoch_id
                )));
            }

            // Update member status in existing epoch
            return self.activate_member_in_epoch(epoch_id, welcome).await;
        }

        // Create new epoch state
        let epoch_state = self.create_epoch_from_welcome(welcome, secrets).await?;

        // Store new epoch
        self.storage
            .store_epoch_state(&epoch_state)
            .await
            .map_err(|e| WelcomeError::Storage(format!("Failed to store epoch state: {}", e)))?;

        Ok(true)
    }

    /// Process previous epoch for backward compatibility
    async fn process_previous_epoch(
        &self,
        epoch_seq: u64,
        epoch_key: &[u8],
    ) -> Result<(), WelcomeError> {
        // Check if we already have this epoch
        if let Ok(existing_epoch) = self.storage.load_epoch_state(epoch_seq).await {
            // Verify key matches
            if existing_epoch.encryption_key != epoch_key {
                return Err(WelcomeError::KeyMismatch(format!(
                    "Previous epoch {} key mismatch",
                    epoch_seq
                )));
            }
            return Ok(());
        }

        // For previous epochs, we store minimal state for backward compatibility
        let minimal_epoch = EpochState {
            epoch_id: epoch_seq,
            encryption_key: epoch_key
                .try_into()
                .map_err(|_| WelcomeError::InvalidMessage("Invalid key length".to_string()))?,
            key_source: EpochKeySource::Welcome,
            members: HashMap::new(),
            status: crate::epoch::state::EpochStatus::Deprecated {
                deprecated_at: Utc::now() - chrono::Duration::hours(1),
                successor_epoch: epoch_seq + 1,
            },
            created_at: Utc::now() - chrono::Duration::hours(1), // Approximate
            updated_at: Utc::now(),
            file_count: 0,
            metadata: Default::default(),
        };

        self.storage
            .store_epoch_state(&minimal_epoch)
            .await
            .map_err(|e| WelcomeError::Storage(format!("Failed to store previous epoch: {}", e)))?;

        Ok(())
    }

    /// Identify epochs pending cutover activation
    async fn identify_pending_epochs(&self, welcome: &Welcome) -> Result<Vec<u64>, WelcomeError> {
        let mut pending = Vec::new();

        // Check if there's an active migration
        if let Ok(current_epochs) = self.storage.list_active_epochs().await {
            for epoch_state in current_epochs {
                if matches!(
                    epoch_state.status,
                    crate::epoch::state::EpochStatus::Migrating { .. }
                ) {
                    // This epoch is in migration, keys may be pending
                    let next_epoch_id = epoch_state.epoch_id + 1;
                    if next_epoch_id == welcome.epoch_info.sequence {
                        pending.push(next_epoch_id);
                    }
                }
            }
        }

        Ok(pending)
    }

    /// Activate member in existing epoch
    async fn activate_member_in_epoch(
        &self,
        epoch_id: u64,
        welcome: &Welcome,
    ) -> Result<bool, WelcomeError> {
        let mut epoch_state = self.storage.load_epoch_state(epoch_id).await.map_err(|e| {
            WelcomeError::Storage(format!("Failed to load epoch {}: {}", epoch_id, e))
        })?;

        // Create member from Welcome information
        let member = self.create_member_from_welcome(welcome).await?;

        // Add member to epoch
        epoch_state
            .members
            .insert(welcome.recipient_device_id.as_bytes().to_vec(), member);

        // Update epoch metadata
        epoch_state.updated_at = Utc::now();

        // Store updated epoch
        self.storage
            .store_epoch_state(&epoch_state)
            .await
            .map_err(|e| WelcomeError::Storage(format!("Failed to update epoch state: {}", e)))?;

        Ok(true)
    }

    /// Create epoch state from Welcome message
    async fn create_epoch_from_welcome(
        &self,
        welcome: &Welcome,
        secrets: &EpochSecrets,
    ) -> Result<EpochState, WelcomeError> {
        // Create member roster from Welcome group members
        let mut members = HashMap::new();

        for group_member in &welcome.group_members {
            let member = Member {
                member_id: group_member.device_id.as_bytes().to_vec(),
                public_key: group_member.identity_public.clone(),
                status: MemberStatus::Active,
                capabilities: MemberCapabilities::default(),
                joined_at: DateTime::<Utc>::from_timestamp(group_member.joined_at as i64, 0)
                    .unwrap_or_else(|| Utc::now()),
                updated_at: Utc::now(),
            };

            members.insert(group_member.device_id.as_bytes().to_vec(), member);
        }

        // Add ourselves as a member
        let our_member = self.create_member_from_welcome(welcome).await?;
        members.insert(welcome.recipient_device_id.as_bytes().to_vec(), our_member);

        let epoch_state = EpochState {
            epoch_id: welcome.epoch_info.sequence,
            encryption_key: secrets.epoch_key.as_slice().try_into().map_err(|_| {
                WelcomeError::InvalidMessage("Invalid epoch key length".to_string())
            })?,
            key_source: EpochKeySource::Welcome,
            members,
            status: crate::epoch::state::EpochStatus::Active {
                activated_at: Utc::now(),
            },
            created_at: DateTime::<Utc>::from_timestamp(welcome.epoch_info.created_at as i64, 0)
                .unwrap_or_else(|| Utc::now()),
            updated_at: Utc::now(),
            file_count: 0,
            metadata: Default::default(),
        };

        Ok(epoch_state)
    }

    /// Create member from Welcome message information
    async fn create_member_from_welcome(&self, welcome: &Welcome) -> Result<Member, WelcomeError> {
        let member = Member {
            member_id: welcome.recipient_device_id.as_bytes().to_vec(),
            public_key: self.device_identity.public_key_bytes().to_vec(),
            status: MemberStatus::Active,
            capabilities: MemberCapabilities::default(),
            joined_at: Utc::now(),
            updated_at: Utc::now(),
        };

        Ok(member)
    }

    /// Update member status after Welcome processing
    async fn update_member_status(
        &self,
        welcome: &Welcome,
        result: &WelcomeResult,
    ) -> Result<(), WelcomeError> {
        // Update status in all processed epochs
        for epoch_id in &result.processed_epochs {
            if let Ok(mut epoch_state) = self.storage.load_epoch_state(*epoch_id).await {
                if let Some(member) = epoch_state
                    .members
                    .get_mut(welcome.recipient_device_id.as_bytes())
                {
                    member.status = MemberStatus::Active;
                    member.updated_at = Utc::now();

                    self.storage
                        .store_epoch_state(&epoch_state)
                        .await
                        .map_err(|e| {
                            WelcomeError::Storage(format!("Failed to update member status: {}", e))
                        })?;
                }
            }
        }

        Ok(())
    }

    /// Persist Welcome processing state
    async fn persist_welcome_state(
        &self,
        welcome: &Welcome,
        _secrets: &EpochSecrets,
        result: &WelcomeResult,
    ) -> Result<(), WelcomeError> {
        // Store Welcome message for replay protection
        let welcome_record = WelcomeRecord {
            epoch_id: welcome.epoch_info.sequence,
            recipient_device_id: welcome.recipient_device_id.clone(),
            processed_at: Utc::now(),
            signature: welcome.admin_signature.clone(),
            result: result.clone(),
        };

        self.storage
            .store_welcome_record(&welcome_record)
            .await
            .map_err(|e| WelcomeError::Storage(format!("Failed to store Welcome record: {}", e)))?;

        Ok(())
    }

    /// Activate pending keys after cutover completion
    pub async fn activate_pending_keys(
        &mut self,
        cutover_epoch_id: u64,
    ) -> Result<(), WelcomeError> {
        if let Some(pending_state) = self.pending_keys.remove(&cutover_epoch_id) {
            // Keys are now ready for activation
            // This would integrate with the cutover coordination system

            // For now, just mark as no longer awaiting cutover
            let mut activated_state = pending_state;
            activated_state.awaiting_cutover = false;

            // Store the activated keys
            self.storage
                .store_epoch_keys(cutover_epoch_id, &activated_state.secrets)
                .await
                .map_err(|e| {
                    WelcomeError::Storage(format!("Failed to activate pending keys: {}", e))
                })?;
        }

        Ok(())
    }

    /// Retry Welcome message processing with exponential backoff
    pub async fn retry_welcome(
        &mut self,
        welcome: &Welcome,
        invitation_private_key: &HybridSecretKey,
        config: &WelcomeConfig,
        attempt: u32,
    ) -> Result<WelcomeResult, WelcomeError> {
        if attempt >= config.max_retry_attempts {
            return Err(WelcomeError::MaxRetriesExceeded(format!(
                "Failed after {} attempts",
                config.max_retry_attempts
            )));
        }

        // Exponential backoff delay
        let delay_ms = 1000 * (1 << attempt).min(30); // Cap at 30 seconds
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

        self.process_welcome(welcome, invitation_private_key, config)
            .await
    }

    /// Get pending epoch states
    pub fn get_pending_epochs(&self) -> &HashMap<u64, PendingKeyState> {
        &self.pending_keys
    }

    /// Check if Welcome message has been processed before (replay protection)
    pub async fn is_welcome_replayed(&self, welcome: &Welcome) -> Result<bool, WelcomeError> {
        match self
            .storage
            .load_welcome_record(welcome.epoch_info.sequence, &welcome.recipient_device_id)
            .await
        {
            Ok(_) => Ok(true),   // Already processed
            Err(_) => Ok(false), // Not processed before
        }
    }
}

/// Record of processed Welcome message for replay protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeRecord {
    pub epoch_id: u64,
    pub recipient_device_id: String,
    pub processed_at: DateTime<Utc>,
    pub signature: Vec<u8>,
    pub result: WelcomeResult,
}

/// Welcome processing errors with comprehensive error types
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum WelcomeError {
    #[error("Invalid welcome message: {0}")]
    InvalidMessage(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Key mismatch: {0}")]
    KeyMismatch(String),

    #[error("Message too old: {0}")]
    MessageTooOld(String),

    #[error("Epoch expired: {0}")]
    EpochExpired(String),

    #[error("Wrong recipient: {0}")]
    WrongRecipient(String),

    #[error("Max retries exceeded: {0}")]
    MaxRetriesExceeded(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MockStorage;
    use hybridcipher_crypto::{hybridkem::HybridKeyPair, signatures::Ed25519KeyPair};
    use hybridcipher_messages::welcome::{EpochInfo, GroupMember, Welcome};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_decrypt_welcome_secrets_roundtrip() {
        let storage = Arc::new(MockStorage::new());
        let device_identity = Ed25519KeyPair::generate();
        let mut processor = WelcomeProcessor::new(storage, device_identity, "device1".into());

        // Generate invitation keys
        let mut rng = rand::rngs::OsRng;
        let invite_keys = HybridKeyPair::generate(&mut rng).unwrap();

        let secrets = EpochSecrets::new(vec![0u8; 32], vec![1u8; 32], HashMap::new()).unwrap();
        let encrypted = Welcome::encrypt_secrets(&secrets, &invite_keys.public.to_bytes()).unwrap();

        let epoch_info = EpochInfo::new(vec![1], "g".into(), 1, 0, None).unwrap();
        let welcome = Welcome {
            recipient_device_id: "device1".into(),
            recipient_user_id: "user1".into(),
            encrypted_payload: encrypted,
            epoch_info,
            group_members: vec![],
            admin_signature: vec![0u8; 64],
        };

        let result = processor
            .decrypt_welcome_secrets(&welcome, &invite_keys.secret)
            .await
            .unwrap();
        assert_eq!(result, secrets);

        // Tamper with payload
        let mut bad_welcome = welcome.clone();
        bad_welcome.encrypted_payload[0] ^= 1;
        assert!(processor
            .decrypt_welcome_secrets(&bad_welcome, &invite_keys.secret)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_verify_welcome_signature() {
        let storage = Arc::new(MockStorage::new());
        let device_identity = Ed25519KeyPair::generate();
        let processor = WelcomeProcessor::new(storage, device_identity, "device1".into());

        let admin_key = Ed25519KeyPair::generate();
        let epoch_info = EpochInfo::new(vec![1], "g".into(), 1, 0, None).unwrap();
        let member = GroupMember::new(
            "admin".into(),
            "dev".into(),
            admin_key.public_key_bytes().to_vec(),
            0,
            true,
        )
        .unwrap();
        let mut welcome = Welcome {
            recipient_device_id: "device1".into(),
            recipient_user_id: "user1".into(),
            encrypted_payload: vec![
                0u8;
                hybridcipher_crypto::hybridkem::HYBRID_CIPHERTEXT_LEN
                    + hybridcipher_crypto::aead::AEAD_NONCE_LEN
            ],
            epoch_info,
            group_members: vec![member],
            admin_signature: vec![],
        };

        // Sign the welcome message
        let mut to_sign = welcome.clone();
        to_sign.admin_signature = vec![];
        let msg = serde_json::to_vec(&to_sign).unwrap();
        let sig = hybridcipher_crypto::signatures::sign(
            &hybridcipher_crypto::signatures::SigningKey::from_bytes(
                &admin_key.private_key_bytes(),
            )
            .unwrap(),
            &msg,
        )
        .unwrap();
        welcome.admin_signature = sig.to_bytes().to_vec();

        processor.verify_welcome_signature(&welcome).await.unwrap();

        // Tamper signature
        let mut bad = welcome.clone();
        bad.admin_signature[0] ^= 1;
        assert!(processor.verify_welcome_signature(&bad).await.is_err());
    }
}
