//! Welcome message containing encrypted epoch secrets for new members
//!
//! Welcome messages are sent to new group members after they join via JoinCard.
//! They contain encrypted epoch secrets and group information.

use crate::error::{MessageError, MessageResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use hkdf::Hkdf;
use hybridcipher_crypto::{
    aead::{self, AeadContext, Key as AeadKey, Nonce},
    hybridkem::{decap, encap, Context, HybridCiphertext, HybridPublicKey, HybridSecretKey},
};
use rand::rngs::OsRng;
use sha2::Sha256;

/// Information about a group epoch
///
/// Contains metadata about the group and epoch being joined
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    /// Epoch identifier (unique across all epochs)
    pub epoch_id: Vec<u8>,
    /// Group identifier (unique across all groups)  
    pub group_id: String,
    /// Epoch sequence number (monotonically increasing)
    pub sequence: u64,
    /// Creation timestamp of this epoch (Unix seconds)
    pub created_at: u64,
    /// Optional epoch expiration time (Unix seconds)
    pub expires_at: Option<u64>,
}

/// Encrypted epoch secrets for new member
///
/// Contains all necessary cryptographic material for participating in the group
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EpochSecrets {
    /// Epoch encryption key for file operations
    pub epoch_key: Vec<u8>,
    /// Signing key for coverage log entries
    pub signing_key: Vec<u8>,
    /// Previous epoch keys for backward compatibility
    pub previous_keys: HashMap<u64, Vec<u8>>,
}

/// Welcome message sent to new group members
///
/// Encrypted using the member's invitation key from their JoinCard
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    /// Target device ID for this welcome (from JoinCard)
    pub recipient_device_id: String,
    /// Target user ID for this welcome (from JoinCard)
    pub recipient_user_id: String,
    /// HybridKEM encrypted payload containing epoch secrets
    pub encrypted_payload: Vec<u8>,
    /// Information about the epoch being joined
    pub epoch_info: EpochInfo,
    /// Current group member list (public information)
    pub group_members: Vec<GroupMember>,
    /// Signature from group administrator
    pub admin_signature: Vec<u8>,
}

/// Information about a group member
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    /// User identifier
    pub user_id: String,
    /// Device identifier
    pub device_id: String,
    /// Member's identity public key
    pub identity_public: Vec<u8>,
    /// When this member joined (Unix seconds)
    pub joined_at: u64,
    /// Whether this member has administrative capabilities
    pub is_admin: bool,
}

impl EpochInfo {
    /// Create new epoch info with validation
    pub fn new(
        epoch_id: Vec<u8>,
        group_id: String,
        sequence: u64,
        created_at: u64,
        expires_at: Option<u64>,
    ) -> MessageResult<Self> {
        let info = Self {
            epoch_id,
            group_id,
            sequence,
            created_at,
            expires_at,
        };
        info.validate()?;
        Ok(info)
    }

    /// Validate epoch info structure
    pub fn validate(&self) -> MessageResult<()> {
        if self.epoch_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "epoch_id cannot be empty".to_string(),
            ));
        }
        if self.group_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "group_id cannot be empty".to_string(),
            ));
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.created_at {
                return Err(MessageError::InvalidFormat(
                    "expires_at must be after created_at".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Check if epoch has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expires_at
            .map_or(false, |expires| current_time > expires)
    }
}

impl EpochSecrets {
    /// Create new epoch secrets with validation
    pub fn new(
        epoch_key: Vec<u8>,
        signing_key: Vec<u8>,
        previous_keys: HashMap<u64, Vec<u8>>,
    ) -> MessageResult<Self> {
        let secrets = Self {
            epoch_key,
            signing_key,
            previous_keys,
        };
        secrets.validate()?;
        Ok(secrets)
    }

    /// Validate epoch secrets structure
    pub fn validate(&self) -> MessageResult<()> {
        if self.epoch_key.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "epoch_key must be 32 bytes".to_string(),
            ));
        }
        if self.signing_key.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "signing_key must be 32 bytes".to_string(),
            ));
        }
        // Validate all previous keys are correct size
        for (seq, key) in &self.previous_keys {
            if key.len() != 32 {
                return Err(MessageError::InvalidFormat(format!(
                    "previous_key for epoch {} must be 32 bytes",
                    seq
                )));
            }
        }
        Ok(())
    }

    /// Serialize for encryption
    pub fn to_bytes(&self) -> MessageResult<Vec<u8>> {
        serde_cbor::to_vec(self).map_err(|e| {
            MessageError::SerializationError(format!("Failed to serialize secrets: {:?}", e))
        })
    }

    /// Deserialize from decrypted bytes
    pub fn from_bytes(data: &[u8]) -> MessageResult<Self> {
        let secrets: Self = serde_cbor::from_slice(data).map_err(|e| {
            MessageError::SerializationError(format!("Failed to deserialize secrets: {:?}", e))
        })?;
        secrets.validate()?;
        Ok(secrets)
    }
}

impl Welcome {
    /// Create new Welcome message with validation
    pub fn new(
        recipient_device_id: String,
        recipient_user_id: String,
        encrypted_payload: Vec<u8>,
        epoch_info: EpochInfo,
        group_members: Vec<GroupMember>,
        admin_signature: Vec<u8>,
    ) -> MessageResult<Self> {
        let welcome = Self {
            recipient_device_id,
            recipient_user_id,
            encrypted_payload,
            epoch_info,
            group_members,
            admin_signature,
        };
        welcome.validate()?;
        Ok(welcome)
    }

    /// Validate Welcome message structure
    pub fn validate(&self) -> MessageResult<()> {
        if self.recipient_device_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "recipient_device_id cannot be empty".to_string(),
            ));
        }
        if self.recipient_user_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "recipient_user_id cannot be empty".to_string(),
            ));
        }
        if self.encrypted_payload.is_empty() {
            return Err(MessageError::InvalidFormat(
                "encrypted_payload cannot be empty".to_string(),
            ));
        }
        if self.admin_signature.len() != 64 {
            return Err(MessageError::InvalidFormat(
                "admin_signature must be 64 bytes".to_string(),
            ));
        }

        // Validate nested structures
        self.epoch_info.validate()?;

        // Validate group members
        for member in &self.group_members {
            member.validate()?;
        }

        Ok(())
    }

    /// Encrypt epoch secrets for this welcome message
    pub fn encrypt_secrets(
        secrets: &EpochSecrets,
        recipient_invitation_key: &[u8],
    ) -> MessageResult<Vec<u8>> {
        let public_key = HybridPublicKey::from_bytes(recipient_invitation_key)
            .map_err(|e| MessageError::InvalidFormat(format!("Invalid invitation key: {}", e)))?;

        let mut rng = OsRng;
        let (kem_ciphertext, shared_secret) = encap(&public_key, Context::Welcome, &mut rng)
            .map_err(|e| MessageError::CryptoError(format!("HybridKEM failure: {}", e)))?;

        // Derive AEAD key from shared secret
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut aead_key_bytes = [0u8; 32];
        hk.expand(b"welcome aead", &mut aead_key_bytes)
            .map_err(|_| MessageError::CryptoError("HKDF expand failed".into()))?;
        let aead_key = AeadKey::from_bytes(&aead_key_bytes)
            .map_err(|e| MessageError::CryptoError(format!("AEAD key error: {}", e)))?;

        let nonce = Nonce::generate(&mut rng)
            .map_err(|e| MessageError::CryptoError(format!("Nonce generation failed: {}", e)))?;

        let plaintext_bytes = secrets.to_bytes()?;

        let ciphertext = aead::seal(
            &aead_key,
            &nonce,
            AeadContext::Welcome,
            &[],
            &plaintext_bytes,
        )
        .map_err(|e| MessageError::CryptoError(format!("AEAD encryption failed: {}", e)))?;

        let mut payload = Vec::new();
        payload.extend_from_slice(&kem_ciphertext.to_bytes());
        payload.extend_from_slice(&nonce.to_bytes());
        payload.extend_from_slice(&ciphertext);
        Ok(payload)
    }

    /// Decrypt epoch secrets from this welcome message
    pub fn decrypt_secrets(
        &self,
        recipient_invitation_private_key: &[u8],
    ) -> MessageResult<EpochSecrets> {
        let kem_len = hybridcipher_crypto::hybridkem::HYBRID_CIPHERTEXT_LEN;
        let nonce_len = hybridcipher_crypto::aead::AEAD_NONCE_LEN;

        if self.encrypted_payload.len() < kem_len + nonce_len {
            return Err(MessageError::InvalidFormat(
                "encrypted_payload too short".into(),
            ));
        }

        let (kem_bytes, rest) = self.encrypted_payload.split_at(kem_len);
        let (nonce_bytes, ciphertext) = rest.split_at(nonce_len);

        let kem_ciphertext = HybridCiphertext::from_bytes(kem_bytes).map_err(|e| {
            MessageError::CryptoError(format!("Invalid HybridKEM ciphertext: {}", e))
        })?;
        let nonce = Nonce::from_bytes(nonce_bytes)
            .map_err(|e| MessageError::CryptoError(format!("Invalid nonce: {}", e)))?;

        let secret_key = HybridSecretKey::from_bytes(recipient_invitation_private_key)
            .map_err(|e| MessageError::CryptoError(format!("Invalid invitation key: {}", e)))?;

        let shared_secret = decap(&secret_key, &kem_ciphertext, Context::Welcome).map_err(|e| {
            MessageError::CryptoError(format!("HybridKEM decryption failed: {}", e))
        })?;

        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut aead_key_bytes = [0u8; 32];
        hk.expand(b"welcome aead", &mut aead_key_bytes)
            .map_err(|_| MessageError::CryptoError("HKDF expand failed".into()))?;
        let aead_key = AeadKey::from_bytes(&aead_key_bytes)
            .map_err(|e| MessageError::CryptoError(format!("AEAD key error: {}", e)))?;

        let plaintext = aead::open(&aead_key, &nonce, AeadContext::Welcome, &[], ciphertext)
            .map_err(|e| MessageError::CryptoError(format!("AEAD decryption failed: {}", e)))?;

        EpochSecrets::from_bytes(&plaintext)
    }
}

impl GroupMember {
    /// Create new group member with validation
    pub fn new(
        user_id: String,
        device_id: String,
        identity_public: Vec<u8>,
        joined_at: u64,
        is_admin: bool,
    ) -> MessageResult<Self> {
        let member = Self {
            user_id,
            device_id,
            identity_public,
            joined_at,
            is_admin,
        };
        member.validate()?;
        Ok(member)
    }

    /// Validate group member structure
    pub fn validate(&self) -> MessageResult<()> {
        if self.user_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "user_id cannot be empty".to_string(),
            ));
        }
        if self.device_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "device_id cannot be empty".to_string(),
            ));
        }
        if self.identity_public.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "identity_public must be 32 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_epoch_info_creation() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let info = EpochInfo::new(
            vec![1, 2, 3, 4],
            "test-group".to_string(),
            1,
            now,
            Some(now + 3600),
        )
        .expect("EpochInfo creation failed");

        assert_eq!(info.sequence, 1);
        assert_eq!(info.group_id, "test-group");
        assert!(!info.is_expired(now));
        assert!(info.is_expired(now + 7200));
    }

    #[test]
    fn test_epoch_secrets_validation() {
        let secrets = EpochSecrets::new(
            vec![0u8; 32],  // epoch_key
            vec![1u8; 32],  // signing_key
            HashMap::new(), // previous_keys
        )
        .expect("EpochSecrets creation failed");

        assert_eq!(secrets.epoch_key.len(), 32);
        assert_eq!(secrets.signing_key.len(), 32);
    }

    #[test]
    fn test_group_member_validation() {
        let member = GroupMember::new(
            "alice".to_string(),
            "alice-laptop".to_string(),
            vec![0u8; 32],
            12345,
            true,
        )
        .expect("GroupMember creation failed");

        assert_eq!(member.user_id, "alice");
        assert_eq!(member.device_id, "alice-laptop");
    }

    #[test]
    fn test_welcome_message_creation() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let epoch_info =
            EpochInfo::new(vec![1, 2, 3, 4], "test-group".to_string(), 1, now, None).unwrap();

        let member = GroupMember::new(
            "alice".to_string(),
            "alice-laptop".to_string(),
            vec![0u8; 32],
            now,
            true,
        )
        .unwrap();

        let welcome = Welcome::new(
            "bob-phone".to_string(),
            "bob".to_string(),
            vec![1, 2, 3], // encrypted payload
            epoch_info,
            vec![member],
            vec![0u8; 64], // admin signature
        )
        .expect("Welcome creation failed");

        assert_eq!(welcome.recipient_user_id, "bob");
        assert_eq!(welcome.group_members.len(), 1);
    }

    #[test]
    fn test_secrets_serialization() {
        let secrets = EpochSecrets::new(vec![0u8; 32], vec![1u8; 32], HashMap::new()).unwrap();

        let bytes = secrets.to_bytes().expect("Serialization failed");
        let deserialized = EpochSecrets::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(secrets, deserialized);
    }

    #[test]
    fn test_welcome_encrypt_decrypt_roundtrip() {
        use hybridcipher_crypto::hybridkem::HybridKeyPair;
        use rand::rngs::OsRng;

        let secrets = EpochSecrets::new(vec![0u8; 32], vec![1u8; 32], HashMap::new()).unwrap();

        let mut rng = OsRng;
        let keypair = HybridKeyPair::generate(&mut rng).unwrap();
        let encrypted = Welcome::encrypt_secrets(&secrets, &keypair.public.to_bytes()).unwrap();
        let welcome = Welcome {
            recipient_device_id: "device1".into(),
            recipient_user_id: "user1".into(),
            encrypted_payload: encrypted,
            epoch_info: EpochInfo::new(vec![1, 2], "g".into(), 1, 0, None).unwrap(),
            group_members: vec![],
            admin_signature: vec![0u8; 64],
        };
        let decrypted = welcome.decrypt_secrets(&keypair.secret.to_bytes()).unwrap();
        assert_eq!(decrypted, secrets);

        // Tamper
        let mut tampered = welcome.clone();
        tampered.encrypted_payload[0] ^= 1;
        assert!(tampered
            .decrypt_secrets(&keypair.secret.to_bytes())
            .is_err());
    }
}
