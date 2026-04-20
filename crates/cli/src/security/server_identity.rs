use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, path::PathBuf};
use thiserror::Error;

/// Stores the pinned identity information for a server endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIdentity {
    pub server_url: String,
    pub public_key_b64: String,
    #[serde(default)]
    pub fingerprint_sha256_hex: String,
    #[serde(default)]
    pub welcome_signing_key_b64: Option<String>,
    #[serde(default)]
    pub welcome_signing_key_sha256_hex: Option<String>,
    #[serde(default)]
    pub welcome_signing_key_id: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub trust_level: TrustLevel,
    pub verification_method: VerificationMethod,
    #[serde(default)]
    pub safety_number: Option<String>,
    #[serde(default)]
    pub verified_at: Option<DateTime<Utc>>,
}

impl ServerIdentity {
    /// Convenience helper for displaying a short fingerprint preview
    pub fn fingerprint_preview(&self) -> String {
        if self.fingerprint_sha256_hex.is_empty() {
            return String::new();
        }
        let preview_len = self.fingerprint_sha256_hex.len().min(16);
        self.fingerprint_sha256_hex[..preview_len].to_string()
    }

    pub fn safety_number(&self) -> Option<&str> {
        self.safety_number.as_deref()
    }

    pub fn fingerprint_sha256_hex(&self) -> &str {
        &self.fingerprint_sha256_hex
    }
}

/// Represents the assurance level of the pinned server identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustLevel {
    Unknown,
    FirstContact,
    UserVerified,
    TransparencyLog,
}

/// Captures how the current trust level was attained
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationMethod {
    ToFU,
    QRCode,
    SafetyNumber,
    TransparencyProof,
}

/// Result of attempting to validate a server identity
#[derive(Debug, Clone)]
pub enum TrustDecision {
    Trusted(TrustLevel),
    FirstContact(ServerIdentity),
}

/// Errors raised during server identity verification and persistence
#[derive(Debug, Error)]
pub enum ServerIdentityError {
    #[error(
        "Server public key mismatch for {server_url}. Expected {expected}, received {received}"
    )]
    KeyMismatch {
        server_url: String,
        expected: String,
        received: String,
    },
    #[error(
        "Welcome signing key mismatch for {server_url}. Expected {expected}, received {received}"
    )]
    SigningKeyMismatch {
        server_url: String,
        expected: String,
        received: String,
    },
    #[error("Received empty server public key for {0}")]
    InvalidKey(String),
    #[error("No pinned server identity for {0}")]
    UnknownServer(String),
    #[error("Invalid base64 encoding: {0}")]
    InvalidEncoding(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Manages server identity persistence and Trust-on-First-Use (TOFU) decisions
#[derive(Debug)]
pub struct ServerIdentityManager {
    identities: HashMap<String, ServerIdentity>,
    storage_path: PathBuf,
}

impl ServerIdentityManager {
    /// Load identities from disk, creating a new store if none exists
    pub fn load(storage_path: PathBuf) -> Result<Self, ServerIdentityError> {
        let identities = if storage_path.exists() {
            let data = fs::read_to_string(&storage_path)?;
            if data.trim().is_empty() {
                HashMap::new()
            } else {
                let mut map: HashMap<String, ServerIdentity> = serde_json::from_str(&data)?;
                for identity in map.values_mut() {
                    ensure_fingerprint_fields(identity)?;
                }
                map
            }
        } else {
            HashMap::new()
        };

        Ok(Self {
            identities,
            storage_path,
        })
    }

    /// Return the pinned identity for the given server if present
    pub fn get_server_identity(&self, server_url: &str) -> Option<&ServerIdentity> {
        self.identities.get(&normalize_server_url(server_url))
    }

    /// Persist an updated set of identities to disk
    pub fn save_to_disk(&self) -> Result<(), ServerIdentityError> {
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&self.identities)?;
        fs::write(&self.storage_path, content)?;
        Ok(())
    }

    /// Verify the received server key against stored identities, applying TOFU rules
    pub fn verify_server_identity(
        &mut self,
        server_url: &str,
        received_key: &[u8],
    ) -> Result<TrustDecision, ServerIdentityError> {
        if received_key.is_empty() {
            return Err(ServerIdentityError::InvalidKey(server_url.to_string()));
        }

        let normalized_url = normalize_server_url(server_url);
        let key_b64 = BASE64.encode(received_key);

        if let Some(stored_identity) = self.identities.get_mut(&normalized_url) {
            if stored_identity.public_key_b64 == key_b64 {
                let (trust, needs_save) = {
                    let mut needs_save = false;
                    if stored_identity.fingerprint_sha256_hex.is_empty() {
                        stored_identity.fingerprint_sha256_hex = compute_sha256_hex(received_key);
                        needs_save = true;
                    }
                    if stored_identity.safety_number.is_none() {
                        stored_identity.safety_number = Some(compute_safety_number(received_key));
                        needs_save = true;
                    }
                    ensure_fingerprint_fields(stored_identity)?;
                    (stored_identity.trust_level.clone(), needs_save)
                };
                if needs_save {
                    self.save_to_disk()?;
                }
                return Ok(TrustDecision::Trusted(trust));
            }

            return Err(ServerIdentityError::KeyMismatch {
                server_url: stored_identity.server_url.clone(),
                expected: stored_identity.public_key_b64.clone(),
                received: key_b64,
            });
        }

        let mut identity = ServerIdentity {
            server_url: normalized_url.clone(),
            public_key_b64: key_b64,
            fingerprint_sha256_hex: compute_sha256_hex(received_key),
            welcome_signing_key_b64: None,
            welcome_signing_key_sha256_hex: None,
            welcome_signing_key_id: None,
            first_seen: Utc::now(),
            trust_level: TrustLevel::FirstContact,
            verification_method: VerificationMethod::ToFU,
            safety_number: Some(compute_safety_number(received_key)),
            verified_at: None,
        };

        ensure_fingerprint_fields(&mut identity)?;
        self.identities.insert(normalized_url, identity.clone());
        self.save_to_disk()?;

        Ok(TrustDecision::FirstContact(identity))
    }

    pub fn update_welcome_signing_key(
        &mut self,
        server_url: &str,
        key_b64: &str,
        key_id: Option<&str>,
    ) -> Result<(), ServerIdentityError> {
        let normalized = normalize_server_url(server_url);
        let trimmed = key_b64.trim();
        let key_bytes = BASE64
            .decode(trimmed.as_bytes())
            .map_err(|e| ServerIdentityError::InvalidEncoding(e.to_string()))?;

        if key_bytes.len() != 32 {
            return Err(ServerIdentityError::InvalidEncoding(format!(
                "Welcome signing key must be 32 bytes (got {})",
                key_bytes.len()
            )));
        }

        let identity = self
            .identities
            .get_mut(&normalized)
            .ok_or_else(|| ServerIdentityError::UnknownServer(normalized.clone()))?;

        if let Some(existing) = identity.welcome_signing_key_b64.as_ref() {
            if existing.trim() != trimmed {
                return Err(ServerIdentityError::SigningKeyMismatch {
                    server_url: identity.server_url.clone(),
                    expected: existing.clone(),
                    received: trimmed.to_string(),
                });
            }

            if identity.welcome_signing_key_id.as_deref() != key_id {
                identity.welcome_signing_key_id = key_id.map(|s| s.to_string());
                self.save_to_disk()?;
            }
            return Ok(());
        }

        identity.welcome_signing_key_b64 = Some(trimmed.to_string());
        identity.welcome_signing_key_sha256_hex = Some(compute_sha256_hex(&key_bytes));
        identity.welcome_signing_key_id = key_id.map(|s| s.to_string());
        self.save_to_disk()?;
        Ok(())
    }

    pub fn welcome_signing_key_bytes(&self, server_url: &str) -> Option<Vec<u8>> {
        self.identities
            .get(&normalize_server_url(server_url))
            .and_then(|identity| identity.welcome_signing_key_b64.as_ref())
            .and_then(|b64| BASE64.decode(b64.trim()).ok())
    }

    /// Update the trust level metadata for a pinned server identity.
    pub fn set_trust_level(
        &mut self,
        server_url: &str,
        trust_level: TrustLevel,
        method: VerificationMethod,
    ) -> Result<ServerIdentity, ServerIdentityError> {
        let normalized = normalize_server_url(server_url);
        let clone = {
            let identity = self
                .identities
                .get_mut(&normalized)
                .ok_or_else(|| ServerIdentityError::UnknownServer(server_url.to_string()))?;

            ensure_fingerprint_fields(identity)?;

            identity.trust_level = trust_level.clone();
            identity.verification_method = method.clone();
            identity.verified_at = match trust_level {
                TrustLevel::UserVerified | TrustLevel::TransparencyLog => Some(Utc::now()),
                _ => None,
            };

            if identity.safety_number.is_none() {
                let key_bytes = BASE64
                    .decode(identity.public_key_b64.as_bytes())
                    .map_err(|e| ServerIdentityError::InvalidEncoding(e.to_string()))?;
                identity.safety_number = Some(compute_safety_number(&key_bytes));
            }

            identity.clone()
        };

        self.save_to_disk()?;

        Ok(clone)
    }
}

fn normalize_server_url(server_url: &str) -> String {
    let trimmed = server_url.trim_end_matches('/');
    if trimmed.is_empty() {
        server_url.to_string()
    } else {
        trimmed.to_string()
    }
}

fn ensure_fingerprint_fields(identity: &mut ServerIdentity) -> Result<(), ServerIdentityError> {
    if identity.fingerprint_sha256_hex.is_empty() || identity.safety_number.is_none() {
        let key_bytes = BASE64
            .decode(identity.public_key_b64.as_bytes())
            .map_err(|e| ServerIdentityError::InvalidEncoding(e.to_string()))?;
        if identity.fingerprint_sha256_hex.is_empty() {
            identity.fingerprint_sha256_hex = compute_sha256_hex(&key_bytes);
        }
        if identity.safety_number.is_none() {
            identity.safety_number = Some(compute_safety_number(&key_bytes));
        }
    }
    Ok(())
}

fn compute_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode_upper(digest)
}

fn compute_safety_number(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let big = BigUint::from_bytes_be(&digest);
    let mut decimal = big.to_str_radix(10);
    if decimal.is_empty() {
        decimal.push('0');
    }

    while decimal.len() % 5 != 0 {
        decimal.insert(0, '0');
    }

    let mut remainder = 0u32;
    for ch in decimal.chars() {
        remainder = (remainder * 10 + ch.to_digit(10).unwrap()) % 97;
    }
    remainder = (remainder * 10) % 97;
    remainder = (remainder * 10) % 97;
    let check_value = (98 - remainder) % 97;
    let check_digits = format!("{:02}", check_value);

    let mut groups = decimal
        .as_bytes()
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).unwrap().to_string())
        .collect::<Vec<_>>();
    groups.push(check_digits);

    groups.join(" ")
}
