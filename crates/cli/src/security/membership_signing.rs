use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hybridcipher_crypto::signatures::VerifyingKey;
use once_cell::sync::Lazy;
use serde_json::Value;

use crate::error::CliError;

static MEMBERSHIP_KEYS: Lazy<Vec<[u8; 32]>> = Lazy::new(|| {
    let raw = include_str!("memebership_signing_key.json");
    let value: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
    let mut keys: Vec<[u8; 32]> = Vec::new();

    let mut push_key = |b64: &str| {
        let decoded = BASE64.decode(b64.trim()).ok()?;
        if decoded.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        keys.push(out);
        Some(())
    };

    if let Some(array) = value
        .get("memebership_public_signing_key")
        .and_then(|v| v.as_array())
    {
        for entry in array {
            if let Some(b64) = entry.as_str() {
                let _ = push_key(b64);
            }
        }
    }

    if let Some(array) = value
        .get("membership_public_signing_key")
        .and_then(|v| v.as_array())
    {
        for entry in array {
            if let Some(b64) = entry.as_str() {
                let _ = push_key(b64);
            }
        }
    }

    if let Some(map) = value.get("keys").and_then(|v| v.as_object()) {
        for value in map.values() {
            if let Some(b64) = value.as_str() {
                let _ = push_key(b64);
            }
        }
    }

    keys
});

/// Return all compiled-in membership verifying keys.
pub fn membership_verifying_keys() -> Result<Vec<VerifyingKey>, CliError> {
    let mut keys = Vec::new();
    for bytes in MEMBERSHIP_KEYS.iter() {
        match VerifyingKey::from_bytes(bytes) {
            Ok(key) => keys.push(key),
            Err(err) => {
                return Err(CliError::cryptographic(format!(
                    "Invalid membership verifying key: {}",
                    err
                )))
            }
        }
    }

    if keys.is_empty() {
        return Err(CliError::cryptographic(
            "No membership signing keys configured".to_string(),
        ));
    }

    Ok(keys)
}

/// Check whether the provided verifying key matches any compiled-in membership key.
pub fn membership_key_matches(verifying_key: &VerifyingKey) -> bool {
    MEMBERSHIP_KEYS
        .iter()
        .any(|bytes| verifying_key.as_bytes() == bytes)
}
