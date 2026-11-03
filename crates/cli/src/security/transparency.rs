use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hybridcipher_crypto::signatures::{Signature, VerifyingKey};
use once_cell::sync::Lazy;
use serde_json;

use crate::error::CliError;

/// Key id trusted only by unit tests; never present in `transparency_keys.json`.
#[cfg(test)]
pub(crate) const TEST_TRANSPARENCY_KEY_ID: &str = "transparency-log-test-key";

static KNOWN_TRANSPARENCY_KEYS: Lazy<HashMap<String, [u8; 32]>> = Lazy::new(|| {
    let raw = include_str!("transparency_keys.json");
    #[allow(unused_mut)]
    let mut entries: HashMap<String, String> = serde_json::from_str(raw).unwrap_or_default();
    // Public key of the RFC 8032 Ed25519 test vector 1, whose private key is public.
    #[cfg(test)]
    entries.insert(
        TEST_TRANSPARENCY_KEY_ID.to_string(),
        "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string(),
    );
    entries
        .into_iter()
        .filter_map(|(key_id, b64)| {
            let decoded = BASE64.decode(b64.trim()).ok()?;
            if decoded.len() != 32 {
                return None;
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            Some((key_id, out))
        })
        .collect()
});

/// Retrieve the known verifying key for a transparency log signing key identifier.
pub fn verifying_key_for(signing_key_id: &str) -> Option<VerifyingKey> {
    KNOWN_TRANSPARENCY_KEYS
        .get(signing_key_id)
        .and_then(|bytes| VerifyingKey::from_bytes(bytes).ok())
}

/// Decode a base64-encoded Ed25519 signature used on transparency checkpoints.
pub fn signature_from_base64(signature_b64: &str) -> Result<Signature, CliError> {
    let bytes = BASE64.decode(signature_b64.trim()).map_err(|e| {
        CliError::cryptographic(format!(
            "Invalid transparency checkpoint signature encoding: {}",
            e
        ))
    })?;

    Signature::from_bytes(&bytes).map_err(|e| {
        CliError::cryptographic(format!("Transparency checkpoint signature invalid: {}", e))
    })
}

/// Return all compiled-in transparency verifying keys as `(key_id, base64)` pairs.
pub fn all_known_transparency_keys() -> Vec<(String, String)> {
    KNOWN_TRANSPARENCY_KEYS
        .iter()
        .map(|(key_id, bytes)| (key_id.clone(), BASE64.encode(bytes)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_key_list_trusts_only_production_keys() {
        let entries: HashMap<String, String> =
            serde_json::from_str(include_str!("transparency_keys.json"))
                .expect("transparency_keys.json is valid JSON");
        assert!(!entries.is_empty());
        for key_id in entries.keys() {
            let lowered = key_id.to_ascii_lowercase();
            assert!(
                !lowered.contains("dev") && !lowered.contains("test"),
                "non-production transparency key '{key_id}' in transparency_keys.json"
            );
        }
        assert!(verifying_key_for("transparency-log-dev-key").is_none());
    }
}
