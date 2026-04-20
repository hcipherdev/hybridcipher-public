//! Out-of-band key pinning implementation for secure first-contact trust establishment.
//!
//! This module provides secure key pinning mechanisms that allow users to verify
//! device identity keys through out-of-band channels (QR codes, safety numbers,
//! manual verification, or trusted introductions). This enables secure first contact
//! without requiring transparency log infrastructure.

use crate::storage::{Storage, StorageError};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use hybridcipher_crypto::signatures::{sign, Ed25519KeyPair, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;

/// Result of key pinning verification during join card processing
#[derive(Debug, Clone)]
pub enum PinningVerificationResult {
    /// Key is pinned and verified successfully
    Verified,
    /// Key is pinned but doesn't match (security concern)
    KeyMismatch {
        pinned_fingerprint: String,
        join_card_fingerprint: String,
    },
    /// No pinned key exists - verification required
    RequiresVerification { prompt: PinningPrompt },
}

/// Prompt for user verification of a new or changed key
#[derive(Debug, Clone)]
pub enum PinningPrompt {
    /// First contact with this user/device
    FirstContact {
        user_id: String,
        device_id: String,
        fingerprint: String,
        identity_key: Vec<u8>,
    },
    /// Key is pinned but not verified yet
    Unverified {
        user_id: String,
        device_id: String,
        fingerprint: String,
        identity_key: Vec<u8>,
    },
    /// Key has changed since last pinning
    KeyChanged {
        user_id: String,
        device_id: String,
        old_fingerprint: String,
        new_fingerprint: String,
        identity_key: Vec<u8>,
    },
}

/// Policy for handling unverified join cards when generating Welcome messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinningPolicy {
    /// Require prior pinning/verification before proceeding.
    RequireVerified,
    /// Allow unverified join cards to proceed (will still reject key mismatches).
    AllowUnverified,
}

impl Default for PinningPolicy {
    fn default() -> Self {
        Self::AllowUnverified
    }
}

/// Configuration for key pinning behavior
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PinningConfig {
    /// Maximum age for pinned keys before re-verification (in days)
    pub max_pin_age_days: Option<u32>,
    /// Enable QR code generation for pinning
    pub enable_qr_codes: bool,
    /// Require second-party verification for device trust
    #[serde(default = "default_require_second_party_verification")]
    pub require_second_party_verification: bool,
    /// Maximum age for signed pin URLs (in days)
    #[serde(default = "default_signed_url_max_age_days")]
    pub signed_url_max_age_days: Option<u32>,
    /// Allowable clock skew/future timestamp for signed pin URLs (seconds)
    #[serde(default = "default_signed_url_max_future_secs")]
    pub signed_url_max_future_secs: u32,
}

impl Default for PinningConfig {
    fn default() -> Self {
        Self {
            max_pin_age_days: Some(365), // Re-verify yearly
            enable_qr_codes: true,
            require_second_party_verification: true,
            signed_url_max_age_days: Some(7),
            signed_url_max_future_secs: 600,
        }
    }
}

fn default_require_second_party_verification() -> bool {
    true
}

fn default_signed_url_max_age_days() -> Option<u32> {
    Some(7)
}

fn default_signed_url_max_future_secs() -> u32 {
    600
}

fn default_verified() -> bool {
    true
}

/// A pinned device identity key with verification metadata
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PinnedKey {
    /// User identifier
    pub user_id: String,
    /// Device identifier for this user
    pub device_id: String,
    /// The pinned Ed25519 public key (32 bytes)
    pub identity_public_key: [u8; 32],
    /// Human-readable fingerprint of the key
    pub fingerprint: String,
    /// Timestamp when this key was pinned
    pub pinned_at: DateTime<Utc>,
    /// Whether this pin has been verified out-of-band
    #[serde(default = "default_verified")]
    pub verified: bool,
    /// Timestamp when this key was verified (if verified)
    #[serde(default)]
    pub verified_at: Option<DateTime<Utc>>,
    /// Method used to verify this key during pinning
    pub verification_method: PinningMethod,
    /// Optional notes about this pinning
    pub notes: Option<String>,
}

/// Method used to verify a key during the pinning process
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PinningMethod {
    /// Verified via QR code scan
    QrCode,
    /// Verified via Signal-style safety numbers
    SafetyNumber,
    /// Manually verified (user confirmed fingerprint)
    Manual,
    /// Auto-pinned without verification
    Unverified,
}

impl fmt::Display for PinningMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PinningMethod::QrCode => write!(f, "QR Code"),
            PinningMethod::SafetyNumber => write!(f, "Safety Number"),
            PinningMethod::Manual => write!(f, "Manual Verification"),
            PinningMethod::Unverified => write!(f, "Unverified (auto)"),
        }
    }
}

/// Errors that can occur during key pinning operations
#[derive(Debug, thiserror::Error)]
pub enum PinningError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Key mismatch: expected {expected}, got {actual}")]
    KeyMismatch { expected: String, actual: String },

    #[error("No pinned key found for user {user_id}, device {device_id}")]
    NoPinnedKey { user_id: String, device_id: String },

    #[error("Invalid fingerprint format: {0}")]
    InvalidFingerprint(String),

    #[error("Pinned key has expired (pinned at {pinned_at})")]
    ExpiredPin { pinned_at: DateTime<Utc> },

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
}

/// Secure storage and verification for pinned device identity keys
pub struct PinningStore<S: Storage> {
    storage: S,
    config: PinningConfig,
}

/// Type alias for the key pinning manager used in client operations
pub type KeyPinningManager<S> = PinningStore<Arc<S>>;

/// Signed payload for QR/URL-based pinning to provide freshness and authenticity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPinningPayload {
    /// Base pinning URL (includes user/device/key/fp).
    pub url: String,
    /// Issued-at timestamp (UTC)
    pub issued_at: DateTime<Utc>,
    /// Signer identifier (typically local device id)
    pub signer: String,
    /// Base64-encoded Ed25519 signature over `url || "|" || issued_at || "|" || signer`
    pub signature: String,
    /// Signer verifying key bytes
    pub signer_public_key: [u8; 32],
}

/// Parsed pinning URL with optional signed metadata.
#[derive(Debug, Clone)]
pub struct ParsedPinningUrl {
    pub user_id: String,
    pub device_id: String,
    pub public_key: [u8; 32],
    pub fingerprint: String,
    pub signature: Option<SignedPinMetadata>,
}

/// Metadata for signed pinning URLs.
#[derive(Debug, Clone)]
pub struct SignedPinMetadata {
    pub signer: String,
    pub issued_at: DateTime<Utc>,
}

/// Policy for signed URL freshness validation.
#[derive(Debug, Clone, Copy)]
pub struct SignedUrlPolicy {
    pub max_age_days: Option<u32>,
    pub max_future_secs: u32,
}

impl From<PinningConfig> for SignedUrlPolicy {
    fn from(cfg: PinningConfig) -> Self {
        Self {
            max_age_days: cfg.signed_url_max_age_days,
            max_future_secs: cfg.signed_url_max_future_secs,
        }
    }
}

impl From<&PinningConfig> for SignedUrlPolicy {
    fn from(cfg: &PinningConfig) -> Self {
        Self {
            max_age_days: cfg.signed_url_max_age_days,
            max_future_secs: cfg.signed_url_max_future_secs,
        }
    }
}

impl Default for SignedUrlPolicy {
    fn default() -> Self {
        Self {
            max_age_days: default_signed_url_max_age_days(),
            max_future_secs: default_signed_url_max_future_secs(),
        }
    }
}

// Add tests at the end
#[cfg(test)]
mod pinning_tests {
    use super::*;
    use crate::storage::mock::MockStorage;
    use hybridcipher_crypto::signatures::Ed25519KeyPair;
    use std::sync::Arc;
    use tokio;

    #[tokio::test]
    async fn test_pinning_qr_code_generation() {
        // Test that QR code generation works correctly
        let device_identity = Ed25519KeyPair::generate();
        let fingerprint = "test-fingerprint";

        let qr_result = generate_pinning_qr_code(
            "test-user",
            "test-device",
            &device_identity.verifying_key().to_bytes(),
            fingerprint,
        );

        assert!(qr_result.is_ok(), "QR code generation should succeed");

        let qr_code = qr_result.unwrap();
        assert!(!qr_code.is_empty(), "QR code should not be empty");
    }

    #[tokio::test]
    async fn test_pinning_url_generation_and_parsing() {
        // Test URL generation and parsing
        let device_identity = Ed25519KeyPair::generate();
        let fingerprint = "test-fingerprint";

        let url = generate_pinning_url(
            "test-user",
            "test-device",
            &device_identity.verifying_key().to_bytes(),
            fingerprint,
        );

        // Parse the URL back
        let parsed = parse_pinning_url(&url);
        assert!(parsed.is_ok(), "URL parsing should succeed");

        let (user_id, device_id, key, parsed_fingerprint) = parsed.unwrap();
        assert_eq!(user_id, "test-user");
        assert_eq!(device_id, "test-device");
        assert_eq!(
            &key[..],
            &device_identity.verifying_key().to_bytes().to_vec()[..]
        );
        assert_eq!(parsed_fingerprint, fingerprint);
    }

    #[tokio::test]
    async fn test_pinning_store_operations() {
        // Test basic pinning store operations
        let storage = Arc::new(MockStorage::new());
        let config = PinningConfig::default();
        let pinning_store = PinningStore::new(storage.clone(), config);

        let device_identity = Ed25519KeyPair::generate();

        // Test storing a pinned key
        let result = pinning_store
            .pin_key(
                "test-user",
                "test-device",
                &device_identity.verifying_key(),
                PinningMethod::Manual,
                Some("Test pinning".to_string()),
            )
            .await;

        assert!(result.is_ok(), "Pinning key should succeed");

        // Test getting the pinned key
        let pinned_key_result = pinning_store
            .get_pinned_key("test-user", "test-device")
            .await;

        assert!(
            pinned_key_result.is_ok(),
            "Getting pinned key should succeed"
        );
    }

    #[tokio::test]
    async fn test_pinning_config() {
        // Test that pinning configuration works
        let config = PinningConfig {
            max_pin_age_days: Some(30),
            enable_qr_codes: true,
            ..Default::default()
        };

        assert_eq!(config.max_pin_age_days, Some(30));
        assert!(config.enable_qr_codes);

        // Test default configuration
        let default_config = PinningConfig::default();
        assert_eq!(default_config.max_pin_age_days, Some(365));
        assert!(default_config.enable_qr_codes);
    }
}

impl<S: Storage> PinningStore<S> {
    /// Create a new pinning store with the given storage backend
    pub fn new(storage: S, config: PinningConfig) -> Self {
        Self { storage, config }
    }

    /// Create the canonical storage key for a pinned device entry.
    fn canonical_storage_key(user_id: &str, device_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        hasher.update(b":");
        hasher.update(device_id.as_bytes());
        let digest = hasher.finalize();
        let encoded = hex::encode(&digest[..16]); // 128-bit identifier is plenty
        format!("pinned_key-{}", encoded)
    }

    /// Pin a device identity key with the specified verification method
    pub async fn pin_key(
        &self,
        user_id: &str,
        device_id: &str,
        public_key: &VerifyingKey,
        verification_method: PinningMethod,
        notes: Option<String>,
    ) -> Result<PinnedKey, PinningError> {
        let key_bytes = public_key.to_bytes();
        let fingerprint = generate_fingerprint(&key_bytes);
        let now = Utc::now();

        let pinned_key = PinnedKey {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            identity_public_key: key_bytes,
            fingerprint,
            pinned_at: now,
            verified: true,
            verified_at: Some(now),
            verification_method,
            notes,
        };

        // Store the pinned key using config storage
        let key = Self::canonical_storage_key(user_id, device_id);
        let data = serde_json::to_string(&pinned_key)
            .map_err(|e| PinningError::InvalidPublicKey(e.to_string()))?;

        self.storage.store_config(&key, &data).await?;

        Ok(pinned_key)
    }

    /// Pin a device identity key without verification (auto-pin).
    pub async fn pin_key_unverified(
        &self,
        user_id: &str,
        device_id: &str,
        public_key: &VerifyingKey,
        notes: Option<String>,
    ) -> Result<PinnedKey, PinningError> {
        let key_bytes = public_key.to_bytes();
        let fingerprint = generate_fingerprint(&key_bytes);

        let pinned_key = PinnedKey {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            identity_public_key: key_bytes,
            fingerprint,
            pinned_at: Utc::now(),
            verified: false,
            verified_at: None,
            verification_method: PinningMethod::Unverified,
            notes,
        };

        let key = Self::canonical_storage_key(user_id, device_id);
        let data = serde_json::to_string(&pinned_key)
            .map_err(|e| PinningError::InvalidPublicKey(e.to_string()))?;

        self.storage.store_config(&key, &data).await?;

        Ok(pinned_key)
    }

    /// Retrieve a pinned key for a specific user and device
    pub async fn get_pinned_key(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<PinnedKey>, PinningError> {
        let primary_key = Self::canonical_storage_key(user_id, device_id);

        if let Some(data) = self.storage.load_config(&primary_key).await? {
            if data.trim().is_empty() {
                return Ok(None);
            }
            let pinned_key: PinnedKey = serde_json::from_str(&data)
                .map_err(|e| PinningError::InvalidPublicKey(e.to_string()))?;

            // Check if the pin has expired
            if let Some(max_age_days) = self.config.max_pin_age_days {
                if pinned_key.verified {
                    let max_age = chrono::Duration::days(max_age_days as i64);
                    let anchor = pinned_key.verified_at.unwrap_or(pinned_key.pinned_at);
                    if Utc::now() - anchor > max_age {
                        return Err(PinningError::ExpiredPin { pinned_at: anchor });
                    }
                }
            }

            return Ok(Some(pinned_key));
        }

        Ok(None)
    }

    /// Verify that a public key matches the pinned key for a user/device
    pub async fn verify_pinned_key(
        &self,
        user_id: &str,
        device_id: &str,
        public_key: &VerifyingKey,
    ) -> Result<bool, PinningError> {
        match self.get_pinned_key(user_id, device_id).await? {
            Some(pinned_key) => {
                let key_bytes = public_key.to_bytes();
                Ok(pinned_key.identity_public_key == key_bytes)
            }
            None => Ok(false),
        }
    }

    /// Remove a pinned key
    pub async fn unpin_key(&self, user_id: &str, device_id: &str) -> Result<(), PinningError> {
        let primary_key = Self::canonical_storage_key(user_id, device_id);
        self.storage.delete_config(&primary_key).await?;
        Ok(())
    }

    /// Update the notes for a pinned key
    pub async fn update_pin_notes(
        &self,
        user_id: &str,
        device_id: &str,
        notes: Option<String>,
    ) -> Result<(), PinningError> {
        let mut pinned_key = self
            .get_pinned_key(user_id, device_id)
            .await?
            .ok_or_else(|| PinningError::NoPinnedKey {
                user_id: user_id.to_string(),
                device_id: device_id.to_string(),
            })?;

        pinned_key.notes = notes;

        let key = Self::canonical_storage_key(user_id, device_id);
        let data = serde_json::to_string(&pinned_key)
            .map_err(|e| PinningError::InvalidPublicKey(e.to_string()))?;

        self.storage.store_config(&key, &data).await?;
        Ok(())
    }

    /// Mark an existing pinned key as verified.
    pub async fn mark_pin_verified(
        &self,
        user_id: &str,
        device_id: &str,
        verification_method: PinningMethod,
    ) -> Result<PinnedKey, PinningError> {
        let mut pinned_key = self
            .get_pinned_key(user_id, device_id)
            .await?
            .ok_or_else(|| PinningError::NoPinnedKey {
                user_id: user_id.to_string(),
                device_id: device_id.to_string(),
            })?;

        pinned_key.verified = true;
        pinned_key.verified_at = Some(Utc::now());
        pinned_key.verification_method = verification_method;

        let key = Self::canonical_storage_key(user_id, device_id);
        let data = serde_json::to_string(&pinned_key)
            .map_err(|e| PinningError::InvalidPublicKey(e.to_string()))?;

        self.storage.store_config(&key, &data).await?;
        Ok(pinned_key)
    }
}

/// Generate a human-readable fingerprint for a public key
pub fn generate_fingerprint(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    let hex = hex::encode(&hash[..8]); // Use first 8 bytes for shorter fingerprint

    // Format as groups of 4 characters separated by spaces
    let mut formatted = String::new();
    for (i, chunk) in hex.chars().collect::<Vec<char>>().chunks(4).enumerate() {
        if i > 0 {
            formatted.push(' ');
        }
        formatted.extend(chunk);
    }

    formatted.to_uppercase()
}

/// Generate a Signal-style safety number for two public keys
pub fn generate_safety_number(local_key: &[u8; 32], remote_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();

    // Ensure deterministic ordering by comparing keys
    if local_key < remote_key {
        hasher.update(local_key);
        hasher.update(remote_key);
    } else {
        hasher.update(remote_key);
        hasher.update(local_key);
    }

    let hash = hasher.finalize();
    let digits = hash
        .iter()
        .map(|b| b % 10)
        .take(12) // 12 digits like Signal
        .map(|d| d.to_string())
        .collect::<Vec<_>>()
        .join("");

    // Format as groups of 4 digits
    format!("{} {} {}", &digits[0..4], &digits[4..8], &digits[8..12])
}

/// Verify a fingerprint format is valid
pub fn verify_fingerprint_format(fingerprint: &str) -> Result<(), PinningError> {
    let clean = fingerprint.replace(' ', "");
    if clean.len() != 16 {
        return Err(PinningError::InvalidFingerprint(format!(
            "Expected 16 hex characters, got {}",
            clean.len()
        )));
    }

    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PinningError::InvalidFingerprint(
            "Fingerprint must contain only hex characters".to_string(),
        ));
    }

    Ok(())
}

/// Generate a QR code for key pinning verification
pub fn generate_pinning_qr_code(
    user_id: &str,
    device_id: &str,
    public_key: &[u8; 32],
    fingerprint: &str,
) -> Result<String, PinningError> {
    use base64::{engine::general_purpose, Engine as _};
    use qrcode::QrCode;

    // Encode the public key as base64
    let key_b64 = general_purpose::STANDARD.encode(public_key);

    // Create the HybridCipher pinning URL
    let url = format!(
        "hybridcipher://pin?user={}&device={}&key={}&fp={}",
        urlencoding::encode(user_id),
        urlencoding::encode(device_id),
        urlencoding::encode(&key_b64),
        urlencoding::encode(fingerprint)
    );

    // Generate QR code
    let code = QrCode::new(&url)
        .map_err(|e| PinningError::InvalidPublicKey(format!("QR code generation failed: {}", e)))?;

    // Convert to ASCII art for terminal display
    let ascii = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();

    Ok(ascii)
}

/// Generate QR code content URL for a pinned key
pub fn generate_pinning_url(
    user_id: &str,
    device_id: &str,
    public_key: &[u8; 32],
    fingerprint: &str,
) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let key_b64 = general_purpose::STANDARD.encode(public_key);

    format!(
        "hybridcipher://pin?user={}&device={}&key={}&fp={}",
        urlencoding::encode(user_id),
        urlencoding::encode(device_id),
        urlencoding::encode(&key_b64),
        urlencoding::encode(fingerprint)
    )
}

/// Generate a signed pinning URL with freshness.
pub fn generate_signed_pinning_url(
    user_id: &str,
    device_id: &str,
    public_key: &[u8; 32],
    fingerprint: &str,
    signer_device: &str,
    signer_key: &Ed25519KeyPair,
) -> Result<SignedPinningPayload, PinningError> {
    let base = generate_pinning_url(user_id, device_id, public_key, fingerprint);
    let issued_at = Utc::now();

    let message = format!("{}|{}|{}", base, issued_at.to_rfc3339(), signer_device);
    let signature: Signature = sign(signer_key.signing_key(), message.as_bytes()).map_err(|e| {
        PinningError::InvalidPublicKey(format!("Failed to sign pinning URL: {}", e))
    })?;
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_bytes());

    let signer_pk_b64 = general_purpose::STANDARD.encode(signer_key.verifying_key().to_bytes());

    let url = format!(
        "{}&ts={}&sig={}&signer={}&signer_pk={}",
        base,
        urlencoding::encode(&issued_at.to_rfc3339()),
        urlencoding::encode(&signature_b64),
        urlencoding::encode(signer_device),
        urlencoding::encode(&signer_pk_b64)
    );

    Ok(SignedPinningPayload {
        url,
        issued_at,
        signer: signer_device.to_string(),
        signature: signature_b64,
        signer_public_key: signer_key.verifying_key().to_bytes(),
    })
}

/// Parse a HybridCipher pinning URL and extract the components
pub fn parse_pinning_url(url: &str) -> Result<(String, String, [u8; 32], String), PinningError> {
    use base64::{engine::general_purpose, Engine as _};

    const PREFIX: &str = "hybridcipher://pin?";

    if !url.starts_with(PREFIX) {
        return Err(PinningError::InvalidFingerprint(
            "Invalid HybridCipher pinning URL format".to_string(),
        ));
    }

    let query_part = &url[PREFIX.len()..];
    let mut user_id = None;
    let mut device_id = None;
    let mut key_b64 = None;
    let mut fingerprint = None;

    for param in query_part.split('&') {
        let parts: Vec<&str> = param.splitn(2, '=').collect();
        if parts.len() != 2 {
            continue;
        }

        match parts[0] {
            "user" => {
                user_id = Some(
                    urlencoding::decode(parts[1])
                        .map_err(|_| {
                            PinningError::InvalidFingerprint("Invalid user ID encoding".to_string())
                        })?
                        .to_string(),
                )
            }
            "device" => {
                device_id = Some(
                    urlencoding::decode(parts[1])
                        .map_err(|_| {
                            PinningError::InvalidFingerprint(
                                "Invalid device ID encoding".to_string(),
                            )
                        })?
                        .to_string(),
                )
            }
            "key" => {
                key_b64 = Some(
                    urlencoding::decode(parts[1])
                        .map_err(|_| {
                            PinningError::InvalidFingerprint("Invalid key encoding".to_string())
                        })?
                        .to_string(),
                )
            }
            "fp" => {
                fingerprint = Some(
                    urlencoding::decode(parts[1])
                        .map_err(|_| {
                            PinningError::InvalidFingerprint(
                                "Invalid fingerprint encoding".to_string(),
                            )
                        })?
                        .to_string(),
                )
            }
            _ => {} // Ignore unknown parameters
        }
    }

    let user_id = user_id
        .ok_or_else(|| PinningError::InvalidFingerprint("Missing user parameter".to_string()))?;
    let device_id = device_id
        .ok_or_else(|| PinningError::InvalidFingerprint("Missing device parameter".to_string()))?;
    let key_b64 = key_b64
        .ok_or_else(|| PinningError::InvalidFingerprint("Missing key parameter".to_string()))?;
    let fingerprint = fingerprint.ok_or_else(|| {
        PinningError::InvalidFingerprint("Missing fingerprint parameter".to_string())
    })?;

    // Decode the base64 key
    let key_bytes = general_purpose::STANDARD
        .decode(&key_b64)
        .map_err(|_| PinningError::InvalidPublicKey("Invalid base64 key encoding".to_string()))?;

    if key_bytes.len() != 32 {
        return Err(PinningError::InvalidPublicKey(format!(
            "Invalid key length: expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&key_bytes);

    Ok((user_id, device_id, public_key, fingerprint))
}

/// Parse a pinning URL and verify the signature metadata if present.
pub fn parse_and_verify_signed_pinning_url_with_policy(
    url: &str,
    policy: SignedUrlPolicy,
) -> Result<ParsedPinningUrl, PinningError> {
    // Extract metadata parameters
    let query_part = url.split_once('?').map(|(_, q)| q).ok_or_else(|| {
        PinningError::InvalidFingerprint("Invalid HybridCipher pinning URL format".to_string())
    })?;

    let mut ts = None;
    let mut sig = None;
    let mut signer = None;
    let mut signer_pk_b64 = None;

    for param in query_part.split('&') {
        let parts: Vec<&str> = param.splitn(2, '=').collect();
        if parts.len() != 2 {
            continue;
        }
        match parts[0] {
            "ts" => {
                ts = Some(
                    urlencoding::decode(parts[1])
                        .unwrap_or_default()
                        .to_string(),
                )
            }
            "sig" => {
                sig = Some(
                    urlencoding::decode(parts[1])
                        .unwrap_or_default()
                        .to_string(),
                )
            }
            "signer" => {
                signer = Some(
                    urlencoding::decode(parts[1])
                        .unwrap_or_default()
                        .to_string(),
                )
            }
            "signer_pk" => {
                signer_pk_b64 = Some(
                    urlencoding::decode(parts[1])
                        .unwrap_or_default()
                        .to_string(),
                )
            }
            _ => {}
        }
    }

    let (user_id, device_id, public_key, fingerprint) = parse_pinning_url(url)?;

    // If signature components are missing, fall back to unsigned.
    if ts.is_none() || sig.is_none() || signer.is_none() || signer_pk_b64.is_none() {
        return Ok(ParsedPinningUrl {
            user_id,
            device_id,
            public_key,
            fingerprint,
            signature: None,
        });
    }

    let ts = ts.unwrap();
    let sig = sig.unwrap();
    let signer = signer.unwrap();
    let signer_pk_b64 = signer_pk_b64.unwrap();
    let issued_at = chrono::DateTime::parse_from_rfc3339(&ts)
        .map_err(|_| {
            PinningError::InvalidFingerprint("Invalid timestamp in signed pin URL".to_string())
        })?
        .with_timezone(&Utc);

    // Reconstruct canonical base URL for signature verification
    let base = generate_pinning_url(&user_id, &device_id, &public_key, &fingerprint);
    let message = format!("{}|{}|{}", base, ts, signer);

    // Basic freshness checks: reject links too old or too far in the future.
    let now = Utc::now();
    if let Some(max_age_days) = policy.max_age_days {
        if now.signed_duration_since(issued_at) > chrono::Duration::days(max_age_days as i64) {
            return Err(PinningError::InvalidFingerprint(
                "Signed pinning URL is stale".to_string(),
            ));
        }
    }
    if issued_at - now > chrono::Duration::seconds(policy.max_future_secs as i64) {
        return Err(PinningError::InvalidFingerprint(
            "Signed pinning URL timestamp is in the future".to_string(),
        ));
    }

    let sig_bytes = general_purpose::STANDARD
        .decode(&sig)
        .map_err(|_| PinningError::InvalidFingerprint("Invalid signature encoding".to_string()))?;
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        PinningError::InvalidFingerprint("Invalid signature length for signed payload".to_string())
    })?;
    let signature = Signature::from_bytes(&sig_array)
        .map_err(|e| PinningError::InvalidFingerprint(format!("Invalid signature bytes: {}", e)))?;

    let signer_pk_bytes = general_purpose::STANDARD
        .decode(&signer_pk_b64)
        .map_err(|_| {
            PinningError::InvalidPublicKey("Invalid signer public key encoding".to_string())
        })?;
    let signer_vk =
        VerifyingKey::from_bytes(signer_pk_bytes.as_slice().try_into().map_err(|_| {
            PinningError::InvalidPublicKey("Invalid signer public key length".to_string())
        })?)
        .map_err(|e| PinningError::InvalidPublicKey(format!("Invalid signer public key: {}", e)))?;

    signer_vk
        .verify(message.as_bytes(), &signature)
        .map_err(|e| {
            PinningError::InvalidFingerprint(format!("Signature verification failed: {}", e))
        })?;

    Ok(ParsedPinningUrl {
        user_id,
        device_id,
        public_key,
        fingerprint,
        signature: Some(SignedPinMetadata { signer, issued_at }),
    })
}

/// Parse a pinning URL using default signed URL policy.
pub fn parse_and_verify_signed_pinning_url(url: &str) -> Result<ParsedPinningUrl, PinningError> {
    parse_and_verify_signed_pinning_url_with_policy(url, SignedUrlPolicy::default())
}

#[cfg(test)]
fn short_policy() -> SignedUrlPolicy {
    SignedUrlPolicy {
        max_age_days: Some(1),
        max_future_secs: 60,
    }
}

/// Display a pinning QR code with instructions
pub fn display_pinning_qr_code(
    user_id: &str,
    device_id: &str,
    public_key: &[u8; 32],
    fingerprint: &str,
) -> Result<String, PinningError> {
    let qr_code = generate_pinning_qr_code(user_id, device_id, public_key, fingerprint)?;
    let url = generate_pinning_url(user_id, device_id, public_key, fingerprint);
    Ok(format_qr_display(
        user_id,
        device_id,
        fingerprint,
        &qr_code,
        &url,
    ))
}

/// Display a pinning QR code using a pre-built URL (e.g., signed/fresh payload).
pub fn display_pinning_qr_code_from_url(
    user_id: &str,
    device_id: &str,
    fingerprint: &str,
    qr_url: &str,
) -> Result<String, PinningError> {
    use qrcode::QrCode;

    let code = QrCode::new(qr_url)
        .map_err(|e| PinningError::InvalidPublicKey(format!("QR code generation failed: {}", e)))?;

    let ascii = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();

    Ok(format_qr_display(
        user_id,
        device_id,
        fingerprint,
        &ascii,
        qr_url,
    ))
}

fn format_qr_display(
    user_id: &str,
    device_id: &str,
    fingerprint: &str,
    qr_ascii: &str,
    url: &str,
) -> String {
    let centered_qr = qr_ascii
        .lines()
        .map(|line| format!("║ {:^61} ║", line))
        .collect::<Vec<_>>()
        .join("\n");

    let url_line = if url.len() <= 61 {
        format!("{:61}", url)
    } else {
        format!("{}...", &url[..58])
    };

    format!(
        "╔═══════════════════════════════════════════════════════════════╗\n\
         ║                     HybridCipher Key Pinning                      ║\n\
         ╠═══════════════════════════════════════════════════════════════╣\n\
         ║ User: {:50} ║\n\
         ║ Device: {:48} ║\n\
         ║ Fingerprint: {:43} ║\n\
         ╠═══════════════════════════════════════════════════════════════╣\n\
         ║ Scan this QR code to verify the device identity key:         ║\n\
         ║                                                               ║\n\
         {}\n\
         ║                                                               ║\n\
         ║ Or use this URL:                                              ║\n\
         ║ {}║\n\
         ╚═══════════════════════════════════════════════════════════════╝",
        user_id, device_id, fingerprint, centered_qr, url_line
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::mock::MockStorage;
    use hybridcipher_crypto::signatures::Ed25519KeyPair;

    #[tokio::test]
    async fn test_pin_and_verify_key() {
        let storage = MockStorage::new();
        let config = PinningConfig::default();
        let store = PinningStore::new(storage, config);

        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.verifying_key();

        // Pin the key
        let pinned = store
            .pin_key(
                "alice",
                "laptop",
                &public_key,
                PinningMethod::Manual,
                Some("Test pin".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(pinned.user_id, "alice");
        assert_eq!(pinned.device_id, "laptop");
        assert_eq!(pinned.identity_public_key, public_key.to_bytes());

        // Verify the pinned key
        let verified = store
            .verify_pinned_key("alice", "laptop", &public_key)
            .await
            .unwrap();
        assert!(verified);

        // Verify with wrong key should fail
        let other_keypair = Ed25519KeyPair::generate();
        let other_public_key = other_keypair.verifying_key();
        let verified = store
            .verify_pinned_key("alice", "laptop", &other_public_key)
            .await
            .unwrap();
        assert!(!verified);
    }

    #[tokio::test]
    async fn test_fingerprint_generation() {
        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.verifying_key();
        let fingerprint = generate_fingerprint(&public_key.to_bytes());

        // Should be formatted as hex with spaces
        assert!(fingerprint.contains(' '));
        assert!(fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c.is_whitespace()));

        // Should be deterministic
        let fingerprint2 = generate_fingerprint(&public_key.to_bytes());
        assert_eq!(fingerprint, fingerprint2);
    }

    #[tokio::test]
    async fn test_safety_number_generation() {
        let keypair1 = Ed25519KeyPair::generate();
        let keypair2 = Ed25519KeyPair::generate();

        let key1 = keypair1.verifying_key().to_bytes();
        let key2 = keypair2.verifying_key().to_bytes();

        let safety1 = generate_safety_number(&key1, &key2);
        let safety2 = generate_safety_number(&key2, &key1); // Reversed order

        // Should be the same regardless of order
        assert_eq!(safety1, safety2);

        // Should have correct format
        assert!(safety1.matches(' ').count() == 2); // Two spaces
        assert_eq!(safety1.replace(' ', "").len(), 12); // 12 digits
    }

    #[tokio::test]
    async fn test_qr_code_generation() {
        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.verifying_key().to_bytes();
        let fingerprint = generate_fingerprint(&public_key);

        // Test URL generation
        let url = generate_pinning_url("alice", "laptop", &public_key, &fingerprint);
        assert!(url.starts_with("hybridcipher://pin?"));
        assert!(url.contains("user=alice"));
        assert!(url.contains("device=laptop"));
        assert!(url.contains("key="));
        assert!(url.contains("fp="));

        // Test QR code generation
        let qr_code = generate_pinning_qr_code("alice", "laptop", &public_key, &fingerprint);
        assert!(qr_code.is_ok());
        let qr_ascii = qr_code.unwrap();
        assert!(!qr_ascii.is_empty());

        // Test display generation
        let display = display_pinning_qr_code("alice", "laptop", &public_key, &fingerprint);
        assert!(display.is_ok());
        let display_text = display.unwrap();
        assert!(display_text.contains("alice"));
        assert!(display_text.contains("laptop"));
        assert!(display_text.contains(&fingerprint));
    }

    #[tokio::test]
    async fn test_url_parsing() {
        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.verifying_key().to_bytes();
        let fingerprint = generate_fingerprint(&public_key);

        // Generate URL
        let url = generate_pinning_url("alice", "laptop", &public_key, &fingerprint);

        // Parse it back
        let parsed = parse_pinning_url(&url).unwrap();
        assert_eq!(parsed.0, "alice");
        assert_eq!(parsed.1, "laptop");
        assert_eq!(parsed.2, public_key);
        assert_eq!(parsed.3, fingerprint);

        // Test invalid URL
        let invalid_result = parse_pinning_url("invalid://url");
        assert!(invalid_result.is_err());

        // Test missing parameters
        let incomplete_url = "hybridcipher://pin?user=alice";
        let incomplete_result = parse_pinning_url(incomplete_url);
        assert!(incomplete_result.is_err());
    }

    #[tokio::test]
    async fn test_unpin_tombstone_is_treated_as_absent() {
        let storage = MockStorage::new();
        let config = PinningConfig::default();
        let store = PinningStore::new(storage.clone(), config);

        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.verifying_key();

        store
            .pin_key("alice", "phone", &public_key, PinningMethod::Manual, None)
            .await
            .unwrap();

        store.unpin_key("alice", "phone").await.unwrap();

        // MockStorage returns an empty string tombstone; this should be treated as None
        let result = store.get_pinned_key("alice", "phone").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_url_encoding() {
        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.verifying_key().to_bytes();
        let fingerprint = generate_fingerprint(&public_key);

        // Test with special characters that need encoding
        let special_user = "alice@example.com";
        let special_device = "laptop with spaces";

        let url = generate_pinning_url(special_user, special_device, &public_key, &fingerprint);

        // Should contain encoded characters
        assert!(url.contains("%40")); // @ symbol
        assert!(url.contains("%20")); // space

        // Parse it back should decode correctly
        let parsed = parse_pinning_url(&url).unwrap();
        assert_eq!(parsed.0, special_user);
        assert_eq!(parsed.1, special_device);
        assert_eq!(parsed.2, public_key);
        assert_eq!(parsed.3, fingerprint);
    }

    #[tokio::test]
    async fn test_signed_pinning_url_roundtrip_and_validation() {
        let signer_kp = Ed25519KeyPair::generate();
        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.verifying_key().to_bytes();
        let fingerprint = generate_fingerprint(&public_key);

        let payload = generate_signed_pinning_url(
            "alice",
            "laptop",
            &public_key,
            &fingerprint,
            "device-signer",
            &signer_kp,
        )
        .expect("should sign");

        let parsed = parse_and_verify_signed_pinning_url(&payload.url).expect("should verify");
        assert_eq!(parsed.user_id, "alice");
        assert_eq!(parsed.device_id, "laptop");
        assert_eq!(parsed.public_key, public_key);
        assert_eq!(parsed.fingerprint, fingerprint);
        assert!(parsed.signature.is_some());

        // Tamper with signature should fail
        let mut bad_url = payload.url.clone();
        bad_url.push_str("corrupt");
        let tampered = parse_and_verify_signed_pinning_url(&bad_url);
        assert!(tampered.is_err());

        // Stale timestamp should fail (manually replace ts parameter)
        let stale = payload.url.replace(
            &format!(
                "ts={}",
                urlencoding::encode(&payload.issued_at.to_rfc3339())
            ),
            &format!(
                "ts={}",
                urlencoding::encode(&(chrono::Utc::now() - chrono::Duration::days(8)).to_rfc3339())
            ),
        );
        let stale_res = parse_and_verify_signed_pinning_url(&stale);
        assert!(stale_res.is_err());
    }

    #[tokio::test]
    async fn test_signed_pinning_url_future_skew_policy() {
        let signer_kp = Ed25519KeyPair::generate();
        let keypair = Ed25519KeyPair::generate();
        let public_key = keypair.verifying_key().to_bytes();
        let fingerprint = generate_fingerprint(&public_key);

        let mut payload = generate_signed_pinning_url(
            "alice",
            "laptop",
            &public_key,
            &fingerprint,
            "device-signer",
            &signer_kp,
        )
        .expect("should sign");

        // Replace timestamp to far future
        let future_ts = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        payload.url = payload.url.replace(
            &format!(
                "ts={}",
                urlencoding::encode(&payload.issued_at.to_rfc3339())
            ),
            &format!("ts={}", urlencoding::encode(&future_ts)),
        );

        let res = parse_and_verify_signed_pinning_url_with_policy(
            &payload.url,
            SignedUrlPolicy {
                max_age_days: Some(7),
                max_future_secs: 60, // 1 minute allowed
            },
        );
        assert!(res.is_err());
    }
}
