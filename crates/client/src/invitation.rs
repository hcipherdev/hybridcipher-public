/// Invitation key management for secure device onboarding
///
/// Provides key pair generation for HybridCipher device invitation workflow.
use crate::errors::ClientError;
use chrono::{DateTime, Utc};
use hybridcipher_crypto::{
    hybridkem::{HybridKeyPair, HybridPublicKey, HybridSecretKey},
    signatures::{sign, verify, Ed25519KeyPair, Signature, SigningKey, VerifyingKey},
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use uuid::Uuid;

/// Invitation key pair for receiving Welcome messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationKeyPair {
    /// Device identifier
    pub device_id: String,

    /// Hybrid KEM public key bytes (X25519 + ML-KEM-768)
    hybrid_public_key: Vec<u8>,

    /// Hybrid KEM secret key bytes
    hybrid_secret_key: Vec<u8>,

    /// Identity public key bytes for join card
    identity_public_key: Vec<u8>,

    /// Identity secret key bytes
    identity_secret_key: Vec<u8>,

    /// When this key pair was generated
    pub created_at: DateTime<Utc>,

    /// When this key pair expires (for security rotation)
    pub expires_at: DateTime<Utc>,
}

/// Simplified join card for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinCard {
    /// User identifier
    pub user_id: Uuid,

    /// Device identifier
    pub device_id: String,

    /// Identity public key for verification
    pub identity_public: Vec<u8>,

    /// Invitation public key for Welcome message encryption
    pub invitation_public: Vec<u8>,

    /// When this join card expires
    pub expires_at: DateTime<Utc>,

    /// Signature over the join card by identity private key
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct JoinCardSignable<'a> {
    user_id: &'a str,
    device_id: &'a str,
    identity_public: &'a [u8],
    invitation_public: &'a [u8],
    expires: u64,
}

impl InvitationKeyPair {
    /// Generate a new invitation key pair for a device
    pub fn generate(device_id: String) -> Result<Self, ClientError> {
        use rand::rngs::OsRng;
        let mut rng = OsRng;

        // Generate hybrid keypair
        let hybrid_keypair =
            HybridKeyPair::generate(&mut rng).map_err(|e| ClientError::Crypto(e))?;

        // Generate identity keypair
        let identity_keypair = Ed25519KeyPair::generate();

        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::days(30); // 30-day expiration

        Ok(Self {
            device_id,
            hybrid_public_key: hybrid_keypair.public.to_bytes().to_vec(),
            hybrid_secret_key: hybrid_keypair.secret.to_bytes().to_vec(),
            identity_public_key: identity_keypair.public_key_bytes().to_vec(),
            identity_secret_key: identity_keypair.private_key_bytes().to_vec(),
            created_at,
            expires_at,
        })
    }

    /// Create a simple join card for testing
    pub fn create_join_card(&self, user_id: Uuid) -> Result<JoinCard, ClientError> {
        let expires_unix = self.expires_at.timestamp();
        if expires_unix < 0 {
            return Err(ClientError::InvalidInput(
                "Join card expiration precedes Unix epoch".to_string(),
            ));
        }

        // Convert UUID to string for signing (must match server's SignableJoinCard format)
        let user_id_str = user_id.to_string();

        let signable = JoinCardSignable {
            user_id: &user_id_str,
            device_id: &self.device_id,
            identity_public: &self.identity_public_key,
            invitation_public: &self.hybrid_public_key,
            expires: expires_unix as u64,
        };

        // Use CBOR serialization to match server's canonical_message format
        let message = serde_cbor::to_vec(&signable).map_err(|e| {
            ClientError::SerializationError(format!(
                "Failed to serialize join card for signing: {}",
                e
            ))
        })?;

        let signing_key = SigningKey::from_bytes(&self.identity_secret_key).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoInvalidKey,
                format!("Invalid identity signing key: {}", e),
                "create_join_card".to_string(),
                false,
            )
        })?;

        let signature = sign(&signing_key, &message).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoSignature,
                format!("Failed to sign join card: {}", e),
                "create_join_card".to_string(),
                false,
            )
        })?;

        Ok(JoinCard {
            user_id,
            device_id: self.device_id.clone(),
            identity_public: self.identity_public_key.clone(),
            invitation_public: self.hybrid_public_key.clone(),
            expires_at: self.expires_at,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Return the identity public key as a fixed-length byte array.
    pub fn identity_public_key_bytes(&self) -> Result<[u8; 32], ClientError> {
        self.identity_public_key.as_slice().try_into().map_err(|_| {
            ClientError::InvalidInput("Invitation identity public key must be 32 bytes".to_string())
        })
    }

    /// Sign an arbitrary message with the identity signing key.
    pub fn sign_identity_message(&self, message: &[u8]) -> Result<Signature, ClientError> {
        let signing_key = SigningKey::from_bytes(&self.identity_secret_key).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoInvalidKey,
                format!("Invalid identity signing key: {}", e),
                "sign_identity_message".to_string(),
                false,
            )
        })?;

        sign(&signing_key, message).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoSignature,
                format!("Failed to sign identity message: {}", e),
                "sign_identity_message".to_string(),
                false,
            )
        })
    }

    /// Get the hybrid secret key for Welcome message decryption
    pub fn invitation_secret_key(&self) -> Result<HybridSecretKey, ClientError> {
        HybridSecretKey::from_bytes(&self.hybrid_secret_key).map_err(|e| ClientError::Crypto(e))
    }

    /// Get the hybrid public key for Welcome message encryption
    pub fn invitation_public_key(&self) -> Result<HybridPublicKey, ClientError> {
        HybridPublicKey::from_bytes(&self.hybrid_public_key).map_err(|e| ClientError::Crypto(e))
    }

    /// Check if this invitation key pair is still valid
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

impl JoinCard {
    /// Simple verification for testing
    pub fn verify_signature(&self) -> Result<(), ClientError> {
        // Verify signature using the embedded identity public key
        if self.signature.is_empty() {
            return Err(ClientError::Auth("Join card signature missing".to_string()));
        }

        let verifying_key = VerifyingKey::from_bytes(&self.identity_public).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoInvalidKey,
                format!("Invalid join card identity key: {}", e),
                "verify_join_card_signature".to_string(),
                false,
            )
        })?;

        let signable =
            JoinCardSignable {
                user_id: &self.user_id.to_string(),
                device_id: &self.device_id,
                identity_public: &self.identity_public,
                invitation_public: &self.invitation_public,
                expires: self.expires_at.timestamp().try_into().map_err(|_| {
                    ClientError::InvalidInput("Join card expiration is invalid".into())
                })?,
            };

        // Use CBOR serialization to match server's canonical_message format
        let message = serde_cbor::to_vec(&signable).map_err(|e| {
            ClientError::SerializationError(format!(
                "Failed to serialize join card for verification: {}",
                e
            ))
        })?;

        let signature = Signature::from_bytes(&self.signature).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoSignature,
                format!("Invalid join card signature bytes: {}", e),
                "verify_join_card_signature".to_string(),
                false,
            )
        })?;

        verify(&verifying_key, &message, &signature).map_err(|e| {
            ClientError::crypto_error(
                crate::errors::ErrorCode::CryptoSignature,
                format!("Join card signature verification failed: {}", e),
                "verify_join_card_signature".to_string(),
                false,
            )
        })?;

        Ok(())
    }

    /// Get the invitation public key for Welcome message encryption
    pub fn invitation_public_key(&self) -> Result<HybridPublicKey, ClientError> {
        HybridPublicKey::from_bytes(&self.invitation_public).map_err(|e| ClientError::Crypto(e))
    }

    /// Check if this join card is still valid
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_keypair_generation() {
        let invitation = InvitationKeyPair::generate("test-device".to_string()).unwrap();

        assert_eq!(invitation.device_id, "test-device");
        assert!(invitation.is_valid());
        assert!(!invitation.hybrid_public_key.is_empty());
        assert!(!invitation.hybrid_secret_key.is_empty());
        assert!(!invitation.identity_public_key.is_empty());
        assert!(!invitation.identity_secret_key.is_empty());
    }

    #[test]
    fn test_join_card_creation() {
        let invitation = InvitationKeyPair::generate("test-device".to_string()).unwrap();
        let user_id = Uuid::new_v4();

        let join_card = invitation.create_join_card(user_id).unwrap();

        assert_eq!(join_card.user_id, user_id);
        assert_eq!(join_card.device_id, "test-device");
        assert!(join_card.is_valid());

        // Verify signature
        join_card.verify_signature().unwrap();
    }

    #[test]
    fn test_hybrid_key_reconstruction() {
        let invitation = InvitationKeyPair::generate("test-device".to_string()).unwrap();

        // Test that we can reconstruct the keys
        let _secret_key = invitation.invitation_secret_key().unwrap();
        let _public_key = invitation.invitation_public_key().unwrap();
    }
}
