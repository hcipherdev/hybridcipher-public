//! JoinCard message for secure user invitation with cryptographic validation
//!
//! JoinCards are published by devices wanting to join groups. They contain
//! cryptographic material for secure invitation and validation.

use crate::error::{MessageError, MessageResult};
use hybridcipher_crypto::hybridkem::HYBRID_PUBLIC_KEY_LEN;
use hybridcipher_crypto::signatures::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_cbor;
use std::time::{SystemTime, UNIX_EPOCH};

/// A join card published by a device wanting to join groups
///
/// JoinCards contain cryptographic material for secure invitation:
/// - Identity keys for authentication
/// - Invitation keys for receiving Welcome messages
/// - Expiration time for security
/// - Cryptographic signature for integrity
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JoinCard {
    /// User identifier (must be non-empty)
    pub user_id: String,
    /// Device identifier (must be non-empty and unique per user)
    pub device_id: String,
    /// Identity public key for signatures (Ed25519 - 32 bytes)
    pub identity_public: Vec<u8>,
    /// Invitation public key for receiving Welcome messages (HybridKEM - 1216 bytes: X25519 32 bytes + ML-KEM-768 1184 bytes)
    pub invitation_public: Vec<u8>,
    /// Expiration timestamp (Unix seconds since epoch)
    pub expires: u64,
    /// Ed25519 signature over canonical CBOR encoding of above fields
    pub signature: Vec<u8>,
}

/// Clock skew tolerance for expiration checking (5 minutes)
const CLOCK_SKEW_TOLERANCE_SECS: u64 = 300;

impl JoinCard {
    /// Create a new JoinCard with validation
    pub fn new(
        user_id: String,
        device_id: String,
        identity_public: Vec<u8>,
        invitation_public: Vec<u8>,
        expires: u64,
        signature: Vec<u8>,
    ) -> MessageResult<Self> {
        let card = Self {
            user_id,
            device_id,
            identity_public,
            invitation_public,
            expires,
            signature,
        };
        card.validate()?;
        Ok(card)
    }

    /// Validate the JoinCard structure and cryptographic properties
    pub fn validate(&self) -> MessageResult<()> {
        // Validate required fields
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

        // Validate key sizes
        if self.identity_public.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "identity_public must be 32 bytes (Ed25519)".to_string(),
            ));
        }
        // Accept both X25519-only (32 bytes) and HybridKEM (1216 bytes) for invitation_public
        if self.invitation_public.len() != 32
            && self.invitation_public.len() != HYBRID_PUBLIC_KEY_LEN
        {
            return Err(MessageError::InvalidFormat(
                format!(
                    "invitation_public must be either 32 bytes (X25519) or {} bytes (HybridKEM), got {} bytes",
                    HYBRID_PUBLIC_KEY_LEN,
                    self.invitation_public.len()
                ),
            ));
        }
        if self.signature.len() != 64 {
            return Err(MessageError::InvalidFormat(
                "signature must be 64 bytes (Ed25519)".to_string(),
            ));
        }

        // Validate expiration
        self.validate_expiration()?;

        Ok(())
    }

    /// Validate expiration time with clock skew tolerance
    pub fn validate_expiration(&self) -> MessageResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                MessageError::TimestampError("System clock before Unix epoch".to_string())
            })?
            .as_secs();

        // Allow for clock skew tolerance
        if self.expires < now.saturating_sub(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(MessageError::ExpiredCard(format!(
                "JoinCard expired at {} (current time: {})",
                self.expires, now
            )));
        }

        Ok(())
    }

    /// Verify the cryptographic signature on this JoinCard
    pub fn verify_signature(&self) -> MessageResult<()> {
        // Parse the identity public key
        let verifying_key = VerifyingKey::from_bytes(&self.identity_public)
            .map_err(|e| MessageError::SignatureError(format!("Invalid identity key: {:?}", e)))?;

        // Parse the signature
        let signature = Signature::from_bytes(&self.signature)
            .map_err(|e| MessageError::SignatureError(format!("Invalid signature: {:?}", e)))?;

        // Generate canonical message for signing
        let message = self.canonical_message()?;

        // Verify signature
        verifying_key.verify(&message, &signature).map_err(|e| {
            MessageError::SignatureError(format!("Signature verification failed: {:?}", e))
        })?;

        Ok(())
    }

    /// Generate canonical message for signing (without signature field)
    pub fn canonical_message(&self) -> MessageResult<Vec<u8>> {
        // Create a temporary structure without signature for canonical encoding
        let signable = SignableJoinCard {
            user_id: &self.user_id,
            device_id: &self.device_id,
            identity_public: &self.identity_public,
            invitation_public: &self.invitation_public,
            expires: self.expires,
        };

        // Use CBOR for canonical encoding
        serde_cbor::to_vec(&signable)
            .map_err(|e| MessageError::SerializationError(format!("CBOR encoding failed: {:?}", e)))
    }

    /// Perform complete validation: structure, expiration, and signature
    pub fn validate_complete(&self) -> MessageResult<()> {
        self.validate()?;
        self.verify_signature()?;
        Ok(())
    }
}

/// Temporary structure for canonical message generation
#[derive(Serialize)]
struct SignableJoinCard<'a> {
    user_id: &'a str,
    device_id: &'a str,
    identity_public: &'a [u8],
    invitation_public: &'a [u8],
    expires: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybridcipher_crypto::signatures::SigningKey;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    fn create_test_keys() -> (SigningKey, Vec<u8>, Vec<u8>) {
        let mut rng = ChaCha20Rng::from_entropy();
        let signing_key = SigningKey::generate(&mut rng).expect("Key generation failed");
        let identity_public = signing_key.verifying_key().to_bytes().to_vec();
        let invitation_public = vec![1u8; 32]; // Mock X25519 key
        (signing_key, identity_public, invitation_public)
    }

    #[test]
    fn test_join_card_creation() {
        let (signing_key, identity_public, invitation_public) = create_test_keys();
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour from now

        // Create signable card
        let signable = SignableJoinCard {
            user_id: "alice",
            device_id: "alice-laptop",
            identity_public: &identity_public,
            invitation_public: &invitation_public,
            expires,
        };

        let message = serde_cbor::to_vec(&signable).unwrap();
        let signature = signing_key
            .sign(&message)
            .expect("Signing failed")
            .to_bytes()
            .to_vec();

        let card = JoinCard::new(
            "alice".to_string(),
            "alice-laptop".to_string(),
            identity_public,
            invitation_public,
            expires,
            signature,
        )
        .expect("Card creation failed");

        assert_eq!(card.user_id, "alice");
        assert_eq!(card.device_id, "alice-laptop");
    }

    #[test]
    fn test_join_card_validation() {
        let (_, identity_public, invitation_public) = create_test_keys();
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        // Test empty user_id
        let result = JoinCard::new(
            "".to_string(),
            "device".to_string(),
            identity_public.clone(),
            invitation_public.clone(),
            expires,
            vec![0u8; 64],
        );
        assert!(result.is_err());

        // Test invalid key size
        let result = JoinCard::new(
            "user".to_string(),
            "device".to_string(),
            vec![0u8; 31], // Wrong size
            invitation_public,
            expires,
            vec![0u8; 64],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_expiration_validation() {
        let (_, identity_public, invitation_public) = create_test_keys();
        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600; // 1 hour ago

        let result = JoinCard::new(
            "user".to_string(),
            "device".to_string(),
            identity_public,
            invitation_public,
            past_time,
            vec![0u8; 64],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_verification() {
        let (signing_key, identity_public, invitation_public) = create_test_keys();
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        // Create properly signed card
        let signable = SignableJoinCard {
            user_id: "alice",
            device_id: "alice-laptop",
            identity_public: &identity_public,
            invitation_public: &invitation_public,
            expires,
        };

        let message = serde_cbor::to_vec(&signable).unwrap();
        let signature = signing_key
            .sign(&message)
            .expect("Signing failed")
            .to_bytes()
            .to_vec();

        let card = JoinCard {
            user_id: "alice".to_string(),
            device_id: "alice-laptop".to_string(),
            identity_public,
            invitation_public,
            expires,
            signature,
        };

        // Should validate completely
        assert!(card.validate_complete().is_ok());
    }
}
