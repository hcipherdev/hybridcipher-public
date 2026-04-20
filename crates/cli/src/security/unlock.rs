use crate::error::CliError;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use hybridcipher_crypto::signatures::{Signature, VerifyingKey, SIGNATURE_LEN};
use serde::Deserialize;

/// Unlock code validation configuration delivered by the server.
#[derive(Debug, Clone)]
pub struct UnlockConfig {
    pub verifying_key: VerifyingKey,
    pub validity_hours: u64,
}

#[derive(Debug, Deserialize)]
struct UnlockPayload {
    user_id: String,
    issued_at: DateTime<Utc>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    purpose: String,
    #[serde(default)]
    #[allow(dead_code)]
    nonce: Option<String>,
}

/// Required purpose marker for SOS unlock tokens.
pub const SOS_UNLOCK_PURPOSE: &str = "sos-decrypt";

/// Validate a support-issued unlock code against server-provided policy.
pub fn validate_unlock_code(
    token: &str,
    expected_user_id: &str,
    config: &UnlockConfig,
) -> Result<(), CliError> {
    let normalized = token.trim();
    if normalized.is_empty() {
        return Err(CliError::invalid_input(
            "Unlock code cannot be empty".to_string(),
        ));
    }

    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(normalized)
        .or_else(|_| general_purpose::URL_SAFE.decode(normalized))
        .map_err(|e| CliError::validation(format!("Unlock code is not valid base64url: {}", e)))?;

    if decoded.len() <= SIGNATURE_LEN {
        return Err(CliError::validation(
            "Unlock code payload is too short to contain a signature".to_string(),
        ));
    }

    let (payload_bytes, signature_bytes) = decoded.split_at(decoded.len() - SIGNATURE_LEN);
    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|e| CliError::validation(format!("Unlock code signature is malformed: {}", e)))?;

    let payload: UnlockPayload = serde_json::from_slice(payload_bytes).map_err(|e| {
        CliError::validation(format!("Unlock code payload is not valid JSON: {}", e))
    })?;

    // Verify signature first to authenticate payload contents.
    config
        .verifying_key
        .verify(payload_bytes, &signature)
        .map_err(|e| {
            CliError::validation(format!("Unlock code signature verification failed: {}", e))
        })?;

    if payload.purpose.trim() != SOS_UNLOCK_PURPOSE {
        return Err(CliError::validation(format!(
            "Unlock code purpose '{}' does not match required '{}'",
            payload.purpose, SOS_UNLOCK_PURPOSE
        )));
    }

    if payload.user_id.trim() != expected_user_id.trim() {
        return Err(CliError::validation(
            "Unlock code does not belong to the authenticated user".to_string(),
        ));
    }

    let issued_at = payload.issued_at;
    let expires_at = if let Some(explicit) = payload.expires_at {
        explicit
    } else {
        issued_at + Duration::hours(config.validity_hours as i64)
    };

    let now = Utc::now();
    if now < issued_at {
        return Err(CliError::validation(
            "Unlock code is not yet valid".to_string(),
        ));
    }

    if now > expires_at {
        return Err(CliError::validation("Unlock code has expired".to_string()));
    }

    Ok(())
}
