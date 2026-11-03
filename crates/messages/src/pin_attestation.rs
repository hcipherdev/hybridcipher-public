//! Pin attestations.
//!
//! When one of a user's devices verifies another device's identity key, it signs this statement
//! with its own identity key so the user's other devices can accept the verification too. They
//! accept it only from a device of the same account that they verified themselves, so the server
//! that relays the statement can neither forge nor alter one.

use crate::error::{MessageError, MessageResult};
use chrono::{DateTime, Utc};
use hybridcipher_crypto::signatures::{Ed25519KeyPair, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Pin attestation format version.
pub const PIN_ATTESTATION_VERSION: u32 = 1;

/// Domain separation for the signature: the same identity key signs other statements.
const PIN_ATTESTATION_PURPOSE: &str = "hybridcipher/pin-attestation/v1";

const IDENTITY_KEY_LEN: usize = 32;

/// "Device `verifier_device_id` checked that `subject_device_id` has this identity key."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinAttestation {
    /// Format version.
    pub version: u32,
    /// Account of the device that verified.
    pub verifier_user_id: String,
    /// Device that verified, and whose identity key signs this statement.
    pub verifier_device_id: String,
    /// Account of the verified device.
    pub subject_user_id: String,
    /// Verified device.
    pub subject_device_id: String,
    /// The verified device's Ed25519 identity public key.
    pub subject_identity_public_key: Vec<u8>,
    /// When the verifier checked the key.
    pub verified_at: DateTime<Utc>,
    /// Signature by the verifier device's identity key.
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct PinAttestationSignable<'a> {
    purpose: &'a str,
    version: u32,
    verifier_user_id: &'a str,
    verifier_device_id: &'a str,
    subject_user_id: &'a str,
    subject_device_id: &'a str,
    subject_identity_public_key: &'a [u8],
    verified_at: DateTime<Utc>,
}

impl PinAttestation {
    /// Sign a statement that the verifier (the holder of `verifier_identity`) checked the
    /// subject device's identity key.
    ///
    /// # Errors
    /// Returns an error when a field is empty or the key is not 32 bytes.
    pub fn sign(
        verifier_identity: &Ed25519KeyPair,
        verifier_user_id: &str,
        verifier_device_id: &str,
        subject_user_id: &str,
        subject_device_id: &str,
        subject_identity_public_key: &[u8],
        verified_at: DateTime<Utc>,
    ) -> MessageResult<Self> {
        let mut attestation = Self {
            version: PIN_ATTESTATION_VERSION,
            verifier_user_id: verifier_user_id.to_string(),
            verifier_device_id: verifier_device_id.to_string(),
            subject_user_id: subject_user_id.to_string(),
            subject_device_id: subject_device_id.to_string(),
            subject_identity_public_key: subject_identity_public_key.to_vec(),
            verified_at,
            signature: Vec::new(),
        };
        attestation.validate_fields()?;
        attestation.signature = verifier_identity
            .sign(&attestation.signable_bytes()?)
            .to_vec();
        Ok(attestation)
    }

    /// Check the signature against the verifier's identity key, as the checking device knows it
    /// (its own pin of the verifier), never as the server reports it.
    ///
    /// # Errors
    /// Returns an error when a field is malformed or the signature does not verify.
    pub fn verify(&self, verifier_identity_public_key: &[u8]) -> MessageResult<()> {
        self.validate_fields()?;
        let verifying_key = VerifyingKey::from_bytes(verifier_identity_public_key)
            .map_err(MessageError::Crypto)?;
        let signature = Signature::from_bytes(&self.signature).map_err(MessageError::Crypto)?;
        verifying_key
            .verify(&self.signable_bytes()?, &signature)
            .map_err(MessageError::Crypto)
    }

    fn validate_fields(&self) -> MessageResult<()> {
        if self.version != PIN_ATTESTATION_VERSION {
            return Err(MessageError::InvalidFormat(format!(
                "Unsupported pin attestation version {}",
                self.version
            )));
        }
        let ids = [
            &self.verifier_user_id,
            &self.verifier_device_id,
            &self.subject_user_id,
            &self.subject_device_id,
        ];
        if ids.iter().any(|id| id.trim().is_empty()) {
            return Err(MessageError::InvalidFormat(
                "Pin attestation is missing a user or device".to_string(),
            ));
        }
        if self.verifier_device_id == self.subject_device_id {
            return Err(MessageError::InvalidFormat(
                "A device cannot attest to its own key".to_string(),
            ));
        }
        if self.subject_identity_public_key.len() != IDENTITY_KEY_LEN {
            return Err(MessageError::InvalidFormat(
                "Pin attestation identity key must be 32 bytes".to_string(),
            ));
        }
        Ok(())
    }

    fn signable_bytes(&self) -> MessageResult<Vec<u8>> {
        serde_cbor::to_vec(&PinAttestationSignable {
            purpose: PIN_ATTESTATION_PURPOSE,
            version: self.version,
            verifier_user_id: &self.verifier_user_id,
            verifier_device_id: &self.verifier_device_id,
            subject_user_id: &self.subject_user_id,
            subject_device_id: &self.subject_device_id,
            subject_identity_public_key: &self.subject_identity_public_key,
            verified_at: self.verified_at,
        })
        .map_err(|err| {
            MessageError::Serialization(format!("Failed to serialize pin attestation: {err}"))
        })
    }
}

#[cfg(test)]
#[path = "../tests/device_security/test_pin_attestation.rs"]
mod pin_attestation_tests;
