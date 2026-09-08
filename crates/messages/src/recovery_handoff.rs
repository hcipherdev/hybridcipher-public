//! Recovery writer handoff messages.
//!
//! These messages let a trusted device provision recovery auto-backup writer
//! material to another verified device without exposing recovery secrets to the
//! server.

use crate::error::{MessageError, MessageResult};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hybridcipher_crypto::{
    aead::{self, AeadContext, Key as AeadKey, Nonce},
    hybridkem::{decap, encap, Context, HybridCiphertext, HybridPublicKey, HybridSecretKey},
    signatures::{Signature, SigningKey, VerifyingKey},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Recovery writer handoff payload version.
pub const RECOVERY_WRITER_HANDOFF_VERSION: u32 = 1;

/// Recovery writer handoff purpose string.
pub const RECOVERY_WRITER_HANDOFF_PURPOSE: &str = "recovery_auto_backup_writer";

const HANDOFF_AAD: &[u8] = b"hybridcipher/recovery-writer-handoff/v1";
const HANDOFF_AEAD_LABEL: &[u8] = b"recovery writer handoff aead";
const KEY_LEN: usize = 32;

/// Decrypted recovery writer handoff payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWriterHandoffPlain {
    /// Payload version.
    pub version: u32,
    /// Account user identifier that owns the recovery artifact.
    pub user_id: String,
    /// Trusted source device identifier.
    pub source_device_id: String,
    /// Target device identifier.
    pub target_device_id: String,
    /// Time the handoff was issued.
    pub issued_at: DateTime<Utc>,
    /// Time after which the handoff must be rejected.
    pub expires_at: DateTime<Utc>,
    /// Payload purpose.
    pub purpose: String,
    /// Server recovery artifact version observed by the source device.
    pub recovery_artifact_version: u32,
    /// SHA-256 hex digest of the recovery artifact observed by the source device.
    pub recovery_artifact_sha256: String,
    /// Base64-encoded recovery artifact epoch AEAD key.
    pub epoch_key_b64: String,
}

/// Encrypted and signed recovery writer handoff envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWriterHandoffEnvelope {
    /// Envelope version.
    pub version: u32,
    /// Account user identifier that owns the recovery artifact.
    pub user_id: String,
    /// Trusted source device identifier.
    pub source_device_id: String,
    /// Target device identifier.
    pub target_device_id: String,
    /// Time the handoff was issued.
    pub issued_at: DateTime<Utc>,
    /// Time after which the handoff must be rejected.
    pub expires_at: DateTime<Utc>,
    /// Payload purpose.
    pub purpose: String,
    /// Server recovery artifact version observed by the source device.
    pub recovery_artifact_version: u32,
    /// SHA-256 hex digest of the recovery artifact observed by the source device.
    pub recovery_artifact_sha256: String,
    /// HybridKEM ciphertext for the target device.
    pub kem_ciphertext: Vec<u8>,
    /// AEAD nonce.
    pub nonce: Vec<u8>,
    /// Encrypted handoff payload.
    pub ciphertext: Vec<u8>,
    /// Source device identity public key.
    pub signing_public_key: Vec<u8>,
    /// Source device signature over the envelope.
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct RecoveryWriterHandoffSignable<'a> {
    version: u32,
    user_id: &'a str,
    source_device_id: &'a str,
    target_device_id: &'a str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    purpose: &'a str,
    recovery_artifact_version: u32,
    recovery_artifact_sha256: &'a str,
    kem_ciphertext: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
    signing_public_key: &'a [u8],
}

impl RecoveryWriterHandoffPlain {
    /// Validate the decrypted payload.
    ///
    /// # Errors
    /// Returns an error when required fields are missing or malformed.
    pub fn validate(&self) -> MessageResult<()> {
        validate_common_fields(
            self.version,
            &self.user_id,
            &self.source_device_id,
            &self.target_device_id,
            self.issued_at,
            self.expires_at,
            &self.purpose,
            self.recovery_artifact_version,
            &self.recovery_artifact_sha256,
        )?;
        validate_epoch_key(&self.epoch_key_b64)
    }
}

impl RecoveryWriterHandoffEnvelope {
    /// Encrypt and sign a recovery writer handoff for the target device.
    ///
    /// # Errors
    /// Returns an error when validation, encryption, or signing fails.
    pub fn seal(
        plain: RecoveryWriterHandoffPlain,
        recipient_invitation_public_key: &[u8],
        source_signing_key: &SigningKey,
    ) -> MessageResult<Self> {
        plain.validate()?;

        let public_key = HybridPublicKey::from_bytes(recipient_invitation_public_key)
            .map_err(MessageError::Crypto)?;
        let mut rng = OsRng;
        let (kem_ciphertext, shared_secret) =
            encap(&public_key, Context::RecoveryWriterHandoff, &mut rng)
                .map_err(MessageError::Crypto)?;
        let aead_key = derive_handoff_aead_key(shared_secret.as_bytes())?;
        let nonce = Nonce::generate(&mut rng).map_err(MessageError::Crypto)?;
        let plaintext = serde_cbor::to_vec(&plain).map_err(|err| {
            MessageError::SerializationError(format!("Failed to serialize handoff: {err}"))
        })?;
        let ciphertext = aead::seal(
            &aead_key,
            &nonce,
            AeadContext::RecoveryWriterHandoff,
            HANDOFF_AAD,
            &plaintext,
        )
        .map_err(MessageError::Crypto)?;

        let signing_public_key = source_signing_key.verifying_key().to_bytes().to_vec();
        let mut envelope = Self {
            version: RECOVERY_WRITER_HANDOFF_VERSION,
            user_id: plain.user_id,
            source_device_id: plain.source_device_id,
            target_device_id: plain.target_device_id,
            issued_at: plain.issued_at,
            expires_at: plain.expires_at,
            purpose: plain.purpose,
            recovery_artifact_version: plain.recovery_artifact_version,
            recovery_artifact_sha256: plain.recovery_artifact_sha256,
            kem_ciphertext: kem_ciphertext.to_bytes().to_vec(),
            nonce: nonce.to_bytes().to_vec(),
            ciphertext,
            signing_public_key,
            signature: Vec::new(),
        };
        envelope.validate_unsigned()?;
        let signable = envelope.signable_bytes()?;
        envelope.signature = source_signing_key
            .sign(&signable)
            .map_err(MessageError::Crypto)?
            .to_bytes()
            .to_vec();
        Ok(envelope)
    }

    /// Verify, decrypt, and validate a handoff for the expected target device.
    ///
    /// # Errors
    /// Returns an error when signature verification, decryption, payload
    /// validation, expiry, or target binding fails.
    pub fn open_and_verify_for(
        &self,
        recipient_invitation_private_key: &[u8],
        expected_user_id: &str,
        expected_target_device_id: &str,
        now: DateTime<Utc>,
    ) -> MessageResult<RecoveryWriterHandoffPlain> {
        self.validate_signed()?;
        if self.user_id != expected_user_id {
            return Err(MessageError::InvalidFormat(
                "Recovery handoff is for a different user".to_string(),
            ));
        }
        if self.target_device_id != expected_target_device_id {
            return Err(MessageError::InvalidFormat(
                "Recovery handoff is for a different device".to_string(),
            ));
        }
        if now > self.expires_at {
            return Err(MessageError::ExpiredCard(
                "Recovery writer handoff has expired".to_string(),
            ));
        }

        let verifying_key =
            VerifyingKey::from_bytes(&self.signing_public_key).map_err(MessageError::Crypto)?;
        let signature = Signature::from_bytes(&self.signature).map_err(MessageError::Crypto)?;
        verifying_key
            .verify(&self.signable_bytes()?, &signature)
            .map_err(MessageError::Crypto)?;

        let secret_key = HybridSecretKey::from_bytes(recipient_invitation_private_key)
            .map_err(MessageError::Crypto)?;
        let kem_ciphertext =
            HybridCiphertext::from_bytes(&self.kem_ciphertext).map_err(MessageError::Crypto)?;
        let shared_secret = decap(&secret_key, &kem_ciphertext, Context::RecoveryWriterHandoff)
            .map_err(MessageError::Crypto)?;
        let aead_key = derive_handoff_aead_key(shared_secret.as_bytes())?;
        let nonce = Nonce::from_bytes(&self.nonce).map_err(MessageError::Crypto)?;
        let plaintext = aead::open(
            &aead_key,
            &nonce,
            AeadContext::RecoveryWriterHandoff,
            HANDOFF_AAD,
            &self.ciphertext,
        )
        .map_err(MessageError::Crypto)?;
        let plain: RecoveryWriterHandoffPlain =
            serde_cbor::from_slice(&plaintext).map_err(|err| {
                MessageError::SerializationError(format!("Failed to parse handoff: {err}"))
            })?;
        plain.validate()?;
        self.validate_plain_binding(&plain)?;
        Ok(plain)
    }

    fn validate_unsigned(&self) -> MessageResult<()> {
        validate_common_fields(
            self.version,
            &self.user_id,
            &self.source_device_id,
            &self.target_device_id,
            self.issued_at,
            self.expires_at,
            &self.purpose,
            self.recovery_artifact_version,
            &self.recovery_artifact_sha256,
        )?;
        if self.kem_ciphertext.is_empty() {
            return Err(MessageError::InvalidFormat(
                "Recovery handoff KEM ciphertext is missing".to_string(),
            ));
        }
        if self.nonce.is_empty() {
            return Err(MessageError::InvalidFormat(
                "Recovery handoff nonce is missing".to_string(),
            ));
        }
        if self.ciphertext.is_empty() {
            return Err(MessageError::InvalidFormat(
                "Recovery handoff ciphertext is missing".to_string(),
            ));
        }
        if self.signing_public_key.is_empty() {
            return Err(MessageError::InvalidFormat(
                "Recovery handoff signing public key is missing".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_signed(&self) -> MessageResult<()> {
        self.validate_unsigned()?;
        if self.signature.is_empty() {
            return Err(MessageError::InvalidFormat(
                "Recovery handoff signature is missing".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_plain_binding(&self, plain: &RecoveryWriterHandoffPlain) -> MessageResult<()> {
        if plain.version != self.version
            || plain.user_id != self.user_id
            || plain.source_device_id != self.source_device_id
            || plain.target_device_id != self.target_device_id
            || plain.issued_at != self.issued_at
            || plain.expires_at != self.expires_at
            || plain.purpose != self.purpose
            || plain.recovery_artifact_version != self.recovery_artifact_version
            || plain.recovery_artifact_sha256 != self.recovery_artifact_sha256
        {
            return Err(MessageError::InvalidFormat(
                "Recovery handoff plaintext does not match envelope metadata".to_string(),
            ));
        }
        Ok(())
    }

    fn signable_bytes(&self) -> MessageResult<Vec<u8>> {
        let signable = RecoveryWriterHandoffSignable {
            version: self.version,
            user_id: &self.user_id,
            source_device_id: &self.source_device_id,
            target_device_id: &self.target_device_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            purpose: &self.purpose,
            recovery_artifact_version: self.recovery_artifact_version,
            recovery_artifact_sha256: &self.recovery_artifact_sha256,
            kem_ciphertext: &self.kem_ciphertext,
            nonce: &self.nonce,
            ciphertext: &self.ciphertext,
            signing_public_key: &self.signing_public_key,
        };
        serde_cbor::to_vec(&signable).map_err(|err| {
            MessageError::SerializationError(format!(
                "Failed to serialize handoff signature: {err}"
            ))
        })
    }
}

fn derive_handoff_aead_key(shared_secret: &[u8]) -> MessageResult<AeadKey> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key_bytes = [0u8; KEY_LEN];
    hk.expand(HANDOFF_AEAD_LABEL, &mut key_bytes)
        .map_err(|_| MessageError::CryptoError("Recovery handoff HKDF expand failed".into()))?;
    AeadKey::from_bytes(&key_bytes).map_err(MessageError::Crypto)
}

fn validate_common_fields(
    version: u32,
    user_id: &str,
    source_device_id: &str,
    target_device_id: &str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    purpose: &str,
    recovery_artifact_version: u32,
    recovery_artifact_sha256: &str,
) -> MessageResult<()> {
    if version != RECOVERY_WRITER_HANDOFF_VERSION {
        return Err(MessageError::InvalidFormat(format!(
            "Unsupported recovery handoff version {version}"
        )));
    }
    if user_id.trim().is_empty() {
        return Err(MessageError::InvalidFormat(
            "Recovery handoff user ID is required".to_string(),
        ));
    }
    if source_device_id.trim().is_empty() {
        return Err(MessageError::InvalidFormat(
            "Recovery handoff source device ID is required".to_string(),
        ));
    }
    if target_device_id.trim().is_empty() {
        return Err(MessageError::InvalidFormat(
            "Recovery handoff target device ID is required".to_string(),
        ));
    }
    if expires_at <= issued_at {
        return Err(MessageError::TimestampError(
            "Recovery handoff expiry must be after issue time".to_string(),
        ));
    }
    if purpose != RECOVERY_WRITER_HANDOFF_PURPOSE {
        return Err(MessageError::InvalidFormat(
            "Recovery handoff purpose is invalid".to_string(),
        ));
    }
    if recovery_artifact_version == 0 {
        return Err(MessageError::InvalidFormat(
            "Recovery artifact version is required".to_string(),
        ));
    }
    if recovery_artifact_sha256.len() != 64
        || !recovery_artifact_sha256
            .as_bytes()
            .iter()
            .all(u8::is_ascii_hexdigit)
    {
        return Err(MessageError::InvalidFormat(
            "Recovery artifact SHA-256 digest is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_epoch_key(epoch_key_b64: &str) -> MessageResult<()> {
    let decoded = general_purpose::STANDARD
        .decode(epoch_key_b64.trim())
        .map_err(|err| {
            MessageError::InvalidFormat(format!("Recovery handoff epoch key is invalid: {err}"))
        })?;
    if decoded.len() != KEY_LEN {
        return Err(MessageError::InvalidFormat(
            "Recovery handoff epoch key has invalid length".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use hybridcipher_crypto::hybridkem::HybridKeyPair;

    fn sample_plain(now: DateTime<Utc>) -> RecoveryWriterHandoffPlain {
        RecoveryWriterHandoffPlain {
            version: RECOVERY_WRITER_HANDOFF_VERSION,
            user_id: "user-1".to_string(),
            source_device_id: "device-primary".to_string(),
            target_device_id: "device-new".to_string(),
            issued_at: now,
            expires_at: now + Duration::minutes(15),
            purpose: RECOVERY_WRITER_HANDOFF_PURPOSE.to_string(),
            recovery_artifact_version: 7,
            recovery_artifact_sha256: "a".repeat(64),
            epoch_key_b64: general_purpose::STANDARD.encode([7u8; 32]),
        }
    }

    #[test]
    fn handoff_round_trips_for_target_device() {
        let now = Utc::now();
        let mut rng = OsRng;
        let target_keys = HybridKeyPair::generate(&mut rng).unwrap();
        let source_signing_key = SigningKey::generate(&mut rng).unwrap();
        let plain = sample_plain(now);

        let envelope = RecoveryWriterHandoffEnvelope::seal(
            plain.clone(),
            &target_keys.public.to_bytes(),
            &source_signing_key,
        )
        .unwrap();
        let opened = envelope
            .open_and_verify_for(
                &target_keys.secret.to_bytes(),
                "user-1",
                "device-new",
                now + Duration::minutes(1),
            )
            .unwrap();

        assert_eq!(opened, plain);
    }

    #[test]
    fn handoff_rejects_wrong_target_key() {
        let now = Utc::now();
        let mut rng = OsRng;
        let target_keys = HybridKeyPair::generate(&mut rng).unwrap();
        let other_keys = HybridKeyPair::generate(&mut rng).unwrap();
        let source_signing_key = SigningKey::generate(&mut rng).unwrap();

        let envelope = RecoveryWriterHandoffEnvelope::seal(
            sample_plain(now),
            &target_keys.public.to_bytes(),
            &source_signing_key,
        )
        .unwrap();

        assert!(envelope
            .open_and_verify_for(
                &other_keys.secret.to_bytes(),
                "user-1",
                "device-new",
                now + Duration::minutes(1),
            )
            .is_err());
    }

    #[test]
    fn handoff_rejects_wrong_user_or_device() {
        let now = Utc::now();
        let mut rng = OsRng;
        let target_keys = HybridKeyPair::generate(&mut rng).unwrap();
        let source_signing_key = SigningKey::generate(&mut rng).unwrap();
        let envelope = RecoveryWriterHandoffEnvelope::seal(
            sample_plain(now),
            &target_keys.public.to_bytes(),
            &source_signing_key,
        )
        .unwrap();

        assert!(envelope
            .open_and_verify_for(
                &target_keys.secret.to_bytes(),
                "user-2",
                "device-new",
                now + Duration::minutes(1),
            )
            .is_err());
        assert!(envelope
            .open_and_verify_for(
                &target_keys.secret.to_bytes(),
                "user-1",
                "device-other",
                now + Duration::minutes(1),
            )
            .is_err());
    }

    #[test]
    fn handoff_rejects_expired_or_tampered_payload() {
        let now = Utc::now();
        let mut rng = OsRng;
        let target_keys = HybridKeyPair::generate(&mut rng).unwrap();
        let source_signing_key = SigningKey::generate(&mut rng).unwrap();
        let envelope = RecoveryWriterHandoffEnvelope::seal(
            sample_plain(now),
            &target_keys.public.to_bytes(),
            &source_signing_key,
        )
        .unwrap();

        assert!(envelope
            .open_and_verify_for(
                &target_keys.secret.to_bytes(),
                "user-1",
                "device-new",
                now + Duration::hours(1),
            )
            .is_err());

        let mut tampered = envelope.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(tampered
            .open_and_verify_for(
                &target_keys.secret.to_bytes(),
                "user-1",
                "device-new",
                now + Duration::minutes(1),
            )
            .is_err());

        let mut wrong_purpose = sample_plain(now);
        wrong_purpose.purpose = "other".to_string();
        assert!(RecoveryWriterHandoffEnvelope::seal(
            wrong_purpose,
            &target_keys.public.to_bytes(),
            &source_signing_key,
        )
        .is_err());
    }
}
