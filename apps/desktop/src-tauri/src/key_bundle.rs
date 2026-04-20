use base64::engine::general_purpose;
use base64::Engine;
use keyring::{Entry, Error as KeyringError};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

const DESKTOP_KEY_BUNDLE_SERVICE: &str = "hybridcipher-desktop-keybundle";
const DESKTOP_KEY_BUNDLE_VERSION: u8 = 1;

static DESKTOP_KEY_BUNDLE_CACHE: Lazy<Mutex<HashMap<String, DesktopKeyBundle>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DesktopKeyBundle {
    #[serde(default = "default_bundle_version")]
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    writer_keys_b64: HashMap<String, String>,
}

fn default_bundle_version() -> u8 {
    DESKTOP_KEY_BUNDLE_VERSION
}

fn bundle_entry(storage_id: &str) -> Result<Entry, String> {
    Entry::new(DESKTOP_KEY_BUNDLE_SERVICE, storage_id)
        .map_err(|e| format!("Failed to access desktop secure key bundle: {}", e))
}

fn decode_fixed_32(label: &str, encoded: &str) -> Result<[u8; 32], String> {
    let bytes = general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| format!("Failed to decode {} from secure bundle: {}", label, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{} from secure bundle has invalid length {}",
            label,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_bundle(storage_id: &str) -> Result<Option<DesktopKeyBundle>, String> {
    if let Some(bundle) = {
        let cache = DESKTOP_KEY_BUNDLE_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.get(storage_id).cloned()
    } {
        return Ok(Some(bundle));
    }

    let entry = bundle_entry(storage_id)?;
    match entry.get_password() {
        Ok(serialized) => {
            let bundle: DesktopKeyBundle = serde_json::from_str(&serialized)
                .map_err(|e| format!("Secure bundle is malformed: {}", e))?;
            let mut cache = DESKTOP_KEY_BUNDLE_CACHE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.insert(storage_id.to_string(), bundle.clone());
            Ok(Some(bundle))
        }
        Err(KeyringError::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to read desktop secure bundle: {}", e)),
    }
}

fn save_bundle(storage_id: &str, bundle: &DesktopKeyBundle) -> Result<(), String> {
    let entry = bundle_entry(storage_id)?;
    let serialized = serde_json::to_string(bundle)
        .map_err(|e| format!("Failed to serialize desktop secure bundle: {}", e))?;
    entry
        .set_password(&serialized)
        .map_err(|e| format!("Failed to persist desktop secure bundle: {}", e))?;

    let mut cache = DESKTOP_KEY_BUNDLE_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.insert(storage_id.to_string(), bundle.clone());
    Ok(())
}

/// Check whether a state key exists in the desktop key bundle without exposing it.
pub fn has_state_key(storage_id: &str) -> Result<bool, String> {
    load_state_key(storage_id).map(|opt| opt.is_some())
}

pub fn load_state_key(storage_id: &str) -> Result<Option<[u8; 32]>, String> {
    let bundle = match load_bundle(storage_id)? {
        Some(bundle) => bundle,
        None => return Ok(None),
    };
    let Some(encoded) = bundle.state_key_b64 else {
        return Ok(None);
    };
    decode_fixed_32("state key", &encoded).map(Some)
}

pub fn store_state_key(storage_id: &str, key: &[u8; 32]) -> Result<(), String> {
    let mut bundle = load_bundle(storage_id)?.unwrap_or_default();
    bundle.version = DESKTOP_KEY_BUNDLE_VERSION;
    bundle.state_key_b64 = Some(general_purpose::STANDARD.encode(key));
    save_bundle(storage_id, &bundle)
}

pub fn load_writer_key(storage_id: &str, device_id: &str) -> Result<Option<[u8; 32]>, String> {
    let bundle = match load_bundle(storage_id)? {
        Some(bundle) => bundle,
        None => return Ok(None),
    };
    let Some(encoded) = bundle.writer_keys_b64.get(device_id) else {
        return Ok(None);
    };
    decode_fixed_32("writer key", encoded).map(Some)
}

pub fn store_writer_key(storage_id: &str, device_id: &str, key: &[u8; 32]) -> Result<(), String> {
    let mut bundle = load_bundle(storage_id)?.unwrap_or_default();
    bundle.version = DESKTOP_KEY_BUNDLE_VERSION;
    bundle
        .writer_keys_b64
        .insert(device_id.to_string(), general_purpose::STANDARD.encode(key));
    save_bundle(storage_id, &bundle)
}
