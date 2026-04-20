/// Welcome message manager for secure epoch key distribution
///
/// Implements the HybridCipher Welcome message protocol for distributing epoch keys
/// to group members using hybrid encryption (X25519 + ML-KEM-768).
use crate::{
    errors::ClientError,
    invitation::{InvitationKeyPair, JoinCard},
    storage::Storage,
};
use chrono::{serde::ts_seconds, serde::ts_seconds_option, DateTime, Utc};
use hybridcipher_crypto::epoch_id::EpochIdMapper;
use hybridcipher_crypto::{
    hybridkem::{decap, encap, Context, HybridCiphertext, HybridPublicKey},
    kdf::{hkdf_expand, HkdfContext},
    open, seal,
    signatures::{sign, verify, Ed25519KeyPair, Signature, SigningKey, VerifyingKey},
    AeadContext, AeadKey, AeadNonce,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{collections::HashMap, convert::TryInto, sync::Arc};
use uuid::Uuid;

/// Server's Welcome message structure from invitation acceptance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerWelcomeMessage {
    pub recipient_device_id: String,
    pub encrypted_epoch_key: Vec<u8>, // Hybrid X25519+ML-KEM-768 encrypted epoch key
    pub signature: Vec<u8>,           // Ed25519 signature of message hash
    pub signing_public_key: Vec<u8>,  // Corresponding Ed25519 verifying key
    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub(crate) struct ServerWelcomeSignable<'a> {
    group_id: Uuid,
    epoch_id: Uuid,
    recipient_device_id: &'a str,
    encrypted_epoch_key: &'a [u8],
    created_at_ts: i64,
    expires_at_ts: Option<i64>,
}

impl<'a> ServerWelcomeSignable<'a> {
    pub(crate) fn new(
        group_id: Uuid,
        epoch_id: Uuid,
        recipient_device_id: &'a str,
        encrypted_epoch_key: &'a [u8],
        created_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            group_id,
            epoch_id,
            recipient_device_id,
            encrypted_epoch_key,
            created_at_ts: created_at.timestamp(),
            expires_at_ts: expires_at.map(|dt| dt.timestamp()),
        }
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// Welcome message containing encrypted epoch secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeMessage {
    /// Message identifier
    pub message_id: Uuid,

    /// Group identifier
    pub group_id: Uuid,

    /// Epoch identifier
    pub epoch_id: u64,

    /// Recipient device identifier
    pub recipient_device_id: String,

    /// Encrypted epoch secrets (HybridKEM + AEAD)
    pub encrypted_payload: Vec<u8>,

    /// Signature by group administrator
    pub admin_signature: Vec<u8>,

    /// When this message was created
    pub created_at: DateTime<Utc>,

    /// When this message expires
    pub expires_at: DateTime<Utc>,
}

/// Epoch secrets distributed via Welcome messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSecrets {
    /// The shared epoch encryption key
    pub epoch_key: [u8; 32],

    /// Epoch identifier
    pub epoch_id: u64,

    /// Group member list with their public keys
    pub group_members: Vec<GroupMember>,

    /// When this epoch becomes active
    pub active_at: DateTime<Utc>,
}

/// Group member information in Welcome messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// User identifier
    pub user_id: Uuid,

    /// Device identifier
    pub device_id: String,

    /// Identity public key
    pub identity_public: Vec<u8>,

    /// Whether this member is an administrator
    pub is_admin: bool,

    /// When this member joined
    pub joined_at: DateTime<Utc>,
}

/// Welcome message manager for creating and processing Welcome messages
#[derive(Debug)]
pub struct WelcomeManager<S: Storage> {
    /// Storage interface
    storage: Arc<S>,

    /// Device invitation keypair
    invitation_keypair: InvitationKeyPair,

    /// Cached join cards for group members
    join_card_cache: HashMap<String, JoinCard>,
}

impl<S: Storage> WelcomeManager<S> {
    /// Create a new Welcome message manager
    pub fn new(storage: Arc<S>, invitation_keypair: InvitationKeyPair) -> Self {
        Self {
            storage,
            invitation_keypair,
            join_card_cache: HashMap::new(),
        }
    }

    /// Create Welcome messages for new group members
    pub async fn create_welcome_messages(
        &mut self,
        group_id: Uuid,
        epoch_secrets: &EpochSecrets,
        recipient_join_cards: &[JoinCard],
        admin_identity: &Ed25519KeyPair,
    ) -> Result<Vec<WelcomeMessage>, ClientError> {
        let mut welcome_messages = Vec::new();

        for join_card in recipient_join_cards {
            // Verify join card is valid
            join_card.verify_signature()?;
            if !join_card.is_valid() {
                return Err(ClientError::InvalidState(
                    "Join card has expired".to_string(),
                ));
            }

            let welcome = self
                .create_single_welcome(group_id, epoch_secrets, join_card, admin_identity)
                .await?;

            welcome_messages.push(welcome);
        }

        Ok(welcome_messages)
    }

    /// Create a single Welcome message for a recipient
    async fn create_single_welcome(
        &mut self,
        group_id: Uuid,
        epoch_secrets: &EpochSecrets,
        recipient_join_card: &JoinCard,
        admin_identity: &Ed25519KeyPair,
    ) -> Result<WelcomeMessage, ClientError> {
        // Get recipient's invitation public key
        let invitation_public = recipient_join_card.invitation_public_key()?;

        // Serialize epoch secrets
        let secrets_bytes = serde_json::to_vec(epoch_secrets).map_err(|e| {
            ClientError::SerializationError(format!("Failed to serialize epoch secrets: {}", e))
        })?;

        // Encrypt epoch secrets using hybrid encryption
        let encrypted_payload = self.encrypt_for_recipient(&secrets_bytes, &invitation_public)?;

        let message_id = Uuid::new_v4();
        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::days(7); // 7-day expiration

        // Create Welcome message (without signature)
        let mut welcome = WelcomeMessage {
            message_id,
            group_id,
            epoch_id: epoch_secrets.epoch_id,
            recipient_device_id: recipient_join_card.device_id.clone(),
            encrypted_payload,
            admin_signature: Vec::new(), // Will be filled below
            created_at,
            expires_at,
        };

        // Sign the Welcome message
        welcome.admin_signature = self.sign_welcome_message(&welcome, admin_identity)?;

        if let Ok(serialized_join_card) = serde_json::to_string(recipient_join_card) {
            let cache_key = format!("join_card::{}", recipient_join_card.device_id);
            self.join_card_cache
                .insert(cache_key.clone(), recipient_join_card.clone());
            if let Err(err) = self
                .storage
                .store_config(&cache_key, &serialized_join_card)
                .await
            {
                log::warn!(
                    "Failed to persist join card cache for device {}: {}",
                    recipient_join_card.device_id,
                    err
                );
            }
        }

        Ok(welcome)
    }

    /// Encrypt epoch key for a specific device using hybrid Welcome encryption
    pub fn encrypt_epoch_key_for_device(
        &self,
        epoch_key: &[u8],
        device_public_key: &HybridPublicKey,
    ) -> Result<Vec<u8>, ClientError> {
        if epoch_key.len() != 32 {
            return Err(ClientError::InvalidState(
                "Epoch key must be 32 bytes for welcome encryption".to_string(),
            ));
        }

        self.encrypt_for_recipient(epoch_key, device_public_key)
    }

    /// Encrypt epoch secrets for a recipient using hybrid encryption
    fn encrypt_for_recipient(
        &self,
        secrets_bytes: &[u8],
        recipient_public_key: &HybridPublicKey,
    ) -> Result<Vec<u8>, ClientError> {
        // Generate shared secret using HybridKEM
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let (kem_ciphertext, shared_secret) =
            encap(recipient_public_key, Context::Welcome, &mut rng)
                .map_err(|e| ClientError::Crypto(e))?;

        // Derive AEAD key from shared secret
        let aead_key_bytes = hkdf_expand(&shared_secret.as_bytes(), HkdfContext::WelcomeKey, 32)
            .map_err(|e| ClientError::Crypto(e))?;

        let aead_key = AeadKey::from_bytes(&aead_key_bytes).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoInvalidKey,
                format!("Invalid AEAD key: {}", e),
                "encrypt_for_recipient".to_string(),
                false,
            )
        })?;

        // Generate nonce and encrypt
        let nonce = AeadNonce::generate_os().map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoInvalidNonce,
                format!("Failed to generate nonce: {}", e),
                "encrypt_for_recipient".to_string(),
                false,
            )
        })?;

        let ciphertext = seal(&aead_key, &nonce, AeadContext::Welcome, &[], secrets_bytes)
            .map_err(|e| {
                ClientError::crypto_error(
                    crate::errors::ErrorCode::CryptoEncryption,
                    format!("AEAD encryption failed: {}", e),
                    "encrypt_for_recipient".to_string(),
                    false,
                )
            })?;

        // Combine KEM ciphertext + nonce + AEAD ciphertext
        let mut encrypted_payload = Vec::new();
        encrypted_payload.extend_from_slice(&kem_ciphertext.as_bytes());
        encrypted_payload.extend_from_slice(nonce.as_bytes());
        encrypted_payload.extend_from_slice(&ciphertext);

        Ok(encrypted_payload)
    }

    /// Sign a Welcome message with admin identity
    fn sign_welcome_message(
        &self,
        welcome: &WelcomeMessage,
        admin_identity: &Ed25519KeyPair,
    ) -> Result<Vec<u8>, ClientError> {
        // Create message to sign (excluding signature field)
        let signable_data = WelcomeSignableData {
            message_id: welcome.message_id,
            group_id: welcome.group_id,
            epoch_id: welcome.epoch_id,
            recipient_device_id: welcome.recipient_device_id.clone(),
            encrypted_payload: welcome.encrypted_payload.clone(),
            created_at: welcome.created_at,
            expires_at: welcome.expires_at,
        };

        let message_bytes = serde_json::to_vec(&signable_data).map_err(|e| {
            ClientError::SerializationError(format!(
                "Failed to serialize Welcome for signing: {}",
                e
            ))
        })?;

        let signing_key =
            SigningKey::from_bytes(&admin_identity.private_key_bytes()).map_err(|e| {
                ClientError::crypto_error(
                    crate::errors::ErrorCode::CryptoInvalidKey,
                    format!("Invalid signing key: {}", e),
                    "sign_welcome_message".to_string(),
                    false,
                )
            })?;

        let signature = sign(&signing_key, &message_bytes).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoSignature,
                format!("Failed to sign Welcome message: {}", e),
                "sign_welcome_message".to_string(),
                false,
            )
        })?;

        Ok(signature.to_bytes().to_vec())
    }

    /// Process a received Welcome message and extract epoch secrets
    pub async fn process_welcome_message(
        &self,
        welcome: &WelcomeMessage,
        admin_public_key: &VerifyingKey,
    ) -> Result<EpochSecrets, ClientError> {
        // Verify Welcome message signature
        self.verify_welcome_signature(welcome, admin_public_key)?;

        // Check if message is still valid
        if Utc::now() > welcome.expires_at {
            return Err(ClientError::InvalidState(
                "Welcome message has expired".to_string(),
            ));
        }

        // Decrypt epoch secrets
        let secrets_bytes = self.decrypt_welcome_payload(&welcome.encrypted_payload)?;

        // Deserialize epoch secrets
        let epoch_secrets: EpochSecrets = serde_json::from_slice(&secrets_bytes).map_err(|e| {
            ClientError::SerializationError(format!("Failed to deserialize epoch secrets: {}", e))
        })?;

        // Validate epoch secrets
        if epoch_secrets.epoch_id != welcome.epoch_id {
            return Err(ClientError::InvalidState(
                "Epoch ID mismatch in Welcome message".to_string(),
            ));
        }

        Ok(epoch_secrets)
    }

    /// Process a server Welcome message from invitation acceptance response
    ///
    /// This handles the simplified Welcome message format returned by the server
    /// during group invitation acceptance with crypto_welcome_message field.
    pub async fn process_server_welcome_message(
        &self,
        server_welcome: &ServerWelcomeMessage,
        group_id: Uuid,
        epoch_id: Uuid,
    ) -> Result<EpochSecrets, ClientError> {
        log::info!(
            "Processing server Welcome message for device {}",
            server_welcome.recipient_device_id
        );

        // Verify device ID matches our invitation keypair
        if server_welcome.recipient_device_id != self.invitation_keypair.device_id {
            return Err(ClientError::InvalidState(format!(
                "Welcome message device ID mismatch: expected {}, got {}",
                self.invitation_keypair.device_id, server_welcome.recipient_device_id
            )));
        }

        // Ensure welcome message has not expired
        if let Some(expires_at) = server_welcome.expires_at {
            if Utc::now() > expires_at {
                return Err(ClientError::InvalidState(
                    "Server Welcome message expired".to_string(),
                ));
            }
        }

        // Verify server signature over the canonical payload
        let verifying_key =
            VerifyingKey::from_bytes(&server_welcome.signing_public_key).map_err(|e| {
                ClientError::crypto_error(
                    crate::errors::ErrorCode::CryptoInvalidKey,
                    format!("Invalid welcome signing key: {}", e),
                    "process_server_welcome_message".to_string(),
                    false,
                )
            })?;

        let signable = ServerWelcomeSignable::new(
            group_id,
            epoch_id,
            &server_welcome.recipient_device_id,
            &server_welcome.encrypted_epoch_key,
            server_welcome.created_at,
            server_welcome.expires_at,
        );

        let message_bytes = signable.to_bytes().map_err(|e| {
            ClientError::SerializationError(format!(
                "Failed to serialize server Welcome payload for verification: {}",
                e
            ))
        })?;

        let signature = Signature::from_bytes(&server_welcome.signature).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoVerification,
                format!("Invalid server Welcome signature format: {}", e),
                "process_server_welcome_message".to_string(),
                false,
            )
        })?;

        verify(&verifying_key, &message_bytes, &signature).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoVerification,
                format!("Server Welcome signature verification failed: {}", e),
                "process_server_welcome_message".to_string(),
                false,
            )
        })?;

        // Decrypt the epoch key using our invitation private key
        let epoch_key_payload =
            self.decrypt_server_welcome_epoch_key(&server_welcome.encrypted_epoch_key, group_id)?;

        let epoch_secrets: EpochSecrets = match serde_json::from_slice(&epoch_key_payload) {
            Ok(secrets) => secrets,
            Err(json_err) => {
                if epoch_key_payload.len() == 32 {
                    log::debug!(
                            "Welcome message for group {} used compact epoch key payload; hydrating minimal epoch context",
                            group_id
                        );

                    let epoch_id_u64 = EpochIdMapper::uuid_to_u64(epoch_id, group_id.as_bytes())
                            .ok_or_else(|| {
                                ClientError::InvalidState(format!(
                                    "Welcome message epoch identifier {} failed validation for group {}",
                                    epoch_id, group_id
                                ))
                            })?;

                    let epoch_key: [u8; 32] = epoch_key_payload
                            .as_slice()
                            .try_into()
                            .map_err(|_| {
                                ClientError::SerializationError(
                                    "Compact welcome payload must contain exactly 32 bytes of epoch key material"
                                        .to_string(),
                                )
                            })?;

                    EpochSecrets {
                        epoch_key,
                        epoch_id: epoch_id_u64,
                        group_members: Vec::new(),
                        active_at: server_welcome.created_at,
                    }
                } else {
                    return Err(ClientError::SerializationError(format!(
                            "Failed to deserialize epoch secrets from Welcome message: {} (payload length: {})",
                            json_err,
                            epoch_key_payload.len()
                        )));
                }
            }
        };

        Ok(epoch_secrets)
    }

    /// Decrypt epoch key from server Welcome message using hybrid KEM
    pub fn decrypt_server_welcome_epoch_key(
        &self,
        encrypted_epoch_key: &[u8],
        _group_id: Uuid,
    ) -> Result<Vec<u8>, ClientError> {
        // The encrypted_epoch_key now contains: KEM ciphertext + nonce + AEAD ciphertext
        // KEM ciphertext: 1120 bytes, nonce: 12 bytes, AEAD ciphertext: variable length

        const KEM_CIPHERTEXT_LEN: usize = 1120;
        const NONCE_LEN: usize = 12;

        if encrypted_epoch_key.len() < KEM_CIPHERTEXT_LEN + NONCE_LEN {
            return Err(ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                "Welcome message too short to contain KEM ciphertext and nonce".to_string(),
                "decrypt_server_welcome_epoch_key".to_string(),
                false,
            ));
        }

        // Split the data: KEM ciphertext | nonce | AEAD ciphertext
        let (kem_bytes, remainder) = encrypted_epoch_key.split_at(KEM_CIPHERTEXT_LEN);
        let (nonce_bytes, aead_ciphertext) = remainder.split_at(NONCE_LEN);

        // Parse hybrid ciphertext from KEM bytes
        let hybrid_ciphertext = HybridCiphertext::from_bytes(kem_bytes).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                format!("Failed to parse Welcome message ciphertext: {}", e),
                "decrypt_server_welcome_epoch_key".to_string(),
                false,
            )
        })?;

        // Get our invitation private key
        let invitation_private_key =
            self.invitation_keypair
                .invitation_secret_key()
                .map_err(|e| {
                    ClientError::crypto_error(
                        crate::errors::ErrorCode::CryptoDecryption,
                        format!("Failed to get invitation private key: {}", e),
                        "decrypt_server_welcome_epoch_key".to_string(),
                        false,
                    )
                })?;

        // Perform KEM decapsulation to get shared secret
        let shared_secret = decap(
            &invitation_private_key,
            &hybrid_ciphertext,
            Context::Welcome,
        )
        .map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                format!("Failed to decrypt Welcome message: {}", e),
                "decrypt_server_welcome_epoch_key".to_string(),
                false,
            )
        })?;

        // Derive AEAD key from shared secret using HKDF (must match encryption)
        let aead_key_bytes = hkdf_expand(&shared_secret.as_bytes(), HkdfContext::WelcomeKey, 32)
            .map_err(|e| ClientError::Crypto(e))?;

        let aead_key = AeadKey::from_bytes(&aead_key_bytes).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                format!("Failed to create AEAD key: {}", e),
                "decrypt_server_welcome_epoch_key".to_string(),
                false,
            )
        })?;

        // Create nonce from bytes
        let nonce = AeadNonce::from_bytes(nonce_bytes).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                format!("Failed to create AEAD nonce: {}", e),
                "decrypt_server_welcome_epoch_key".to_string(),
                false,
            )
        })?;

        // Decrypt the actual epoch key using AEAD
        let epoch_key = open(
            &aead_key,
            &nonce,
            AeadContext::Welcome,
            &[],
            aead_ciphertext,
        )
        .map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                format!("Failed to decrypt epoch key: {}", e),
                "decrypt_server_welcome_epoch_key".to_string(),
                false,
            )
        })?;

        Ok(epoch_key)
    }

    /// Decrypt Welcome message payload using invitation private key
    fn decrypt_welcome_payload(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>, ClientError> {
        // Parse encrypted payload: KEM ciphertext + nonce + AEAD ciphertext
        const KEM_CIPHERTEXT_LEN: usize = 1120; // X25519 (32) + ML-KEM-768 (1088)
        const NONCE_LEN: usize = 12;

        if encrypted_payload.len() < KEM_CIPHERTEXT_LEN + NONCE_LEN {
            return Err(ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                "Encrypted payload too short".to_string(),
                "decrypt_welcome_payload".to_string(),
                false,
            ));
        }

        let (kem_bytes, rest) = encrypted_payload.split_at(KEM_CIPHERTEXT_LEN);
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

        // Reconstruct KEM ciphertext
        let kem_ciphertext = HybridCiphertext::from_bytes(kem_bytes).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                format!("Invalid KEM ciphertext: {}", e),
                "decrypt_welcome_payload".to_string(),
                false,
            )
        })?;

        // Decapsulate shared secret
        let shared_secret = decap(
            &self.invitation_keypair.invitation_secret_key()?,
            &kem_ciphertext,
            Context::Welcome,
        )
        .map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoDecryption,
                format!("HybridKEM decapsulation failed: {}", e),
                "decrypt_welcome_payload".to_string(),
                false,
            )
        })?;

        // Derive AEAD key
        let aead_key_bytes = hkdf_expand(shared_secret.as_bytes(), HkdfContext::WelcomeKey, 32)
            .map_err(|e| {
                ClientError::crypto_error(
                    crate::errors::ErrorCode::CryptoHkdf,
                    format!("HKDF expansion failed: {}", e),
                    "decrypt_welcome_payload".to_string(),
                    false,
                )
            })?;

        let aead_key = AeadKey::from_bytes(&aead_key_bytes).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoInvalidKey,
                format!("Invalid AEAD key: {}", e),
                "decrypt_welcome_payload".to_string(),
                false,
            )
        })?;

        // Reconstruct nonce
        let nonce = AeadNonce::from_bytes(nonce_bytes).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoInvalidNonce,
                format!("Invalid nonce: {}", e),
                "decrypt_welcome_payload".to_string(),
                false,
            )
        })?;

        // Decrypt
        let plaintext =
            open(&aead_key, &nonce, AeadContext::Welcome, &[], ciphertext).map_err(|e| {
                ClientError::crypto_error(
                    crate::errors::ErrorCode::CryptoDecryption,
                    format!("AEAD decryption failed: {}", e),
                    "decrypt_welcome_payload".to_string(),
                    false,
                )
            })?;

        Ok(plaintext)
    }

    /// Verify Welcome message signature
    fn verify_welcome_signature(
        &self,
        welcome: &WelcomeMessage,
        admin_public_key: &VerifyingKey,
    ) -> Result<(), ClientError> {
        let signable_data = WelcomeSignableData {
            message_id: welcome.message_id,
            group_id: welcome.group_id,
            epoch_id: welcome.epoch_id,
            recipient_device_id: welcome.recipient_device_id.clone(),
            encrypted_payload: welcome.encrypted_payload.clone(),
            created_at: welcome.created_at,
            expires_at: welcome.expires_at,
        };

        let message_bytes = serde_json::to_vec(&signable_data).map_err(|e| {
            ClientError::SerializationError(format!(
                "Failed to serialize Welcome for verification: {}",
                e
            ))
        })?;

        let signature = Signature::from_bytes(&welcome.admin_signature).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoVerification,
                format!("Invalid signature format: {}", e),
                "verify_welcome_signature".to_string(),
                false,
            )
        })?;

        verify(admin_public_key, &message_bytes, &signature).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoVerification,
                format!("Welcome signature verification failed: {}", e),
                "verify_welcome_signature".to_string(),
                false,
            )
        })?;

        Ok(())
    }

    /// Cache a join card for future use
    pub fn cache_join_card(&mut self, join_card: JoinCard) {
        self.join_card_cache
            .insert(join_card.device_id.clone(), join_card);
    }

    /// Get cached join card for a device
    pub fn get_cached_join_card(&self, device_id: &str) -> Option<&JoinCard> {
        self.join_card_cache.get(device_id)
    }
}

/// Data structure for Welcome message signing (excludes signature field)
#[derive(Debug, Serialize, Deserialize)]
struct WelcomeSignableData {
    message_id: Uuid,
    group_id: Uuid,
    epoch_id: u64,
    recipient_device_id: String,
    encrypted_payload: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MockStorage;
    use hybridcipher_crypto::{
        aead::{AEAD_NONCE_LEN, AEAD_TAG_LEN},
        HYBRID_CIPHERTEXT_LEN,
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn test_welcome_message_creation_and_processing() {
        let storage = Arc::new(MockStorage::new());

        // Generate keypairs
        let admin_identity = Ed25519KeyPair::generate();
        let recipient_invitation =
            InvitationKeyPair::generate("recipient-device".to_string()).unwrap();

        // Create Welcome manager
        let mut welcome_manager = WelcomeManager::new(storage, recipient_invitation.clone());

        // Create epoch secrets
        let epoch_secrets = EpochSecrets {
            epoch_key: [42u8; 32], // Test key
            epoch_id: 1,
            group_members: vec![],
            active_at: Utc::now(),
        };

        // Create join card
        let user_id = Uuid::new_v4();
        let join_card = recipient_invitation.create_join_card(user_id).unwrap();

        // Create Welcome message
        let group_id = Uuid::new_v4();
        let welcome_messages = welcome_manager
            .create_welcome_messages(group_id, &epoch_secrets, &[join_card], &admin_identity)
            .await
            .unwrap();

        assert_eq!(welcome_messages.len(), 1);

        // Process Welcome message
        let admin_public_key =
            VerifyingKey::from_bytes(&admin_identity.public_key_bytes()).unwrap();
        let processed_secrets = welcome_manager
            .process_welcome_message(&welcome_messages[0], &admin_public_key)
            .await
            .unwrap();

        assert_eq!(processed_secrets.epoch_key, epoch_secrets.epoch_key);
        assert_eq!(processed_secrets.epoch_id, epoch_secrets.epoch_id);
    }

    #[tokio::test]
    async fn encrypt_epoch_key_for_device_produces_expected_length() {
        let storage = Arc::new(MockStorage::new());
        let invitation = InvitationKeyPair::generate("device-enc".to_string()).unwrap();
        let manager = WelcomeManager::new(storage, invitation.clone());

        let public_key = invitation.invitation_public_key().unwrap();
        let epoch_key = [7u8; 32];

        let encrypted = manager
            .encrypt_epoch_key_for_device(&epoch_key, &public_key)
            .unwrap();

        let expected_len = HYBRID_CIPHERTEXT_LEN + AEAD_NONCE_LEN + epoch_key.len() + AEAD_TAG_LEN;

        assert_eq!(encrypted.len(), expected_len);
        assert_ne!(encrypted, epoch_key);
    }
}
