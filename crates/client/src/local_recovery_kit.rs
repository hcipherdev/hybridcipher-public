//! Code-only recovery kits for accountless vaults held on a single device.
//!
//! An account backup needs both the password and the saved code. A local vault
//! has no password, so its kit is sealed by the recovery code alone and is never
//! uploaded. Entries reuse the saved-code entry format so an upgraded account can
//! seal the same epoch keys into its server backup.

use crate::saved_code_recovery::{
    derive_root_key, BackupEntryPlain, EncryptedEntry, RECOVERY_CODE_BYTES,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hybridcipher_crypto::account_protection::{decrypt_with_ad, encrypt_with_ad};
use hybridcipher_crypto::epoch_id::EpochIdMapper;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const LOCAL_KIT_VERSION: u32 = 1;
pub const LOCAL_KIT_KIND: &str = "hybridcipher-local-recovery-kit";
const MAX_KIT_BYTES: usize = 1024 * 1024;
const MAX_KIT_ENTRIES: usize = 10_000;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const ENTRY_KEY_LABEL: &[u8] = b"hybridcipher/local-kit/v1/entry-key";
const ENTRY_AAD: &[u8] = b"hybridcipher/local-kit/v1/entry";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalRecoveryKit {
    pub kind: String,
    pub version: u32,
    pub salt_b64: String,
    pub entries: Vec<EncryptedEntry>,
}

/// One authenticated epoch key from a kit.
pub struct LocalKitEpoch {
    pub number: u64,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub key: Zeroizing<[u8; KEY_LEN]>,
}

/// Authenticated kit contents. Every entry belongs to one vault group.
pub struct LocalKitContents {
    pub group_id: Uuid,
    pub epochs: Vec<LocalKitEpoch>,
}

impl LocalKitContents {
    /// Re-encode as saved-code entries for an account backup at upgrade.
    pub fn to_backup_entries(&self) -> Vec<BackupEntryPlain> {
        self.epochs
            .iter()
            .map(|epoch| BackupEntryPlain {
                group_id: self.group_id,
                epoch_number: epoch.number,
                epoch_uuid: EpochIdMapper::u64_to_uuid(epoch.number, self.group_id.as_bytes()),
                created_at: epoch.created_at,
                is_active: epoch.is_active,
                encryption_key_b64: general_purpose::STANDARD.encode(epoch.key.as_ref()),
            })
            .collect()
    }
}

/// Generate a fresh recovery code. Callers show it once and never persist it.
pub fn generate_recovery_code() -> Zeroizing<[u8; RECOVERY_CODE_BYTES]> {
    let mut code = Zeroizing::new([0u8; RECOVERY_CODE_BYTES]);
    OsRng.fill_bytes(code.as_mut());
    code
}

impl LocalRecoveryKit {
    /// Seal the vault's epoch keys under the recovery code alone.
    pub fn create(recovery_code: &[u8], entries: &[BackupEntryPlain]) -> Result<Self, String> {
        if recovery_code.len() != RECOVERY_CODE_BYTES {
            return Err("A 32-byte recovery code is required".into());
        }
        validate_entries(entries)?;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let entry_key = derive_entry_key(recovery_code, &salt)?;
        let mut sealed = Vec::with_capacity(entries.len());
        for entry in entries {
            let plaintext = Zeroizing::new(
                serde_json::to_vec(entry).map_err(|e| format!("Failed to encode entry: {e}"))?,
            );
            let protected = encrypt_with_ad(plaintext.as_slice(), *entry_key, ENTRY_AAD)
                .map_err(|e| format!("Failed to seal recovery kit entry: {e}"))?;
            sealed.push(EncryptedEntry { protected });
        }
        Ok(Self {
            kind: LOCAL_KIT_KIND.into(),
            version: LOCAL_KIT_VERSION,
            salt_b64: general_purpose::STANDARD.encode(salt),
            entries: sealed,
        })
    }

    /// Authenticate every entry with the recovery code before returning keys.
    pub fn open(&self, recovery_code: &[u8]) -> Result<LocalKitContents, String> {
        if recovery_code.len() != RECOVERY_CODE_BYTES {
            return Err("A 32-byte recovery code is required".into());
        }
        self.check_header()?;
        let salt = general_purpose::STANDARD
            .decode(&self.salt_b64)
            .map_err(|_| "Recovery kit has an invalid salt".to_string())?;
        let entry_key = derive_entry_key(recovery_code, &salt)?;
        let mut entries = Vec::with_capacity(self.entries.len());
        for (index, entry) in self.entries.iter().enumerate() {
            let plaintext = Zeroizing::new(
                decrypt_with_ad(&entry.protected, *entry_key, ENTRY_AAD).map_err(|_| {
                    if index == 0 {
                        "Recovery code does not match this recovery kit".to_string()
                    } else {
                        "Recovery kit contains a corrupted entry".to_string()
                    }
                })?,
            );
            let parsed: BackupEntryPlain = serde_json::from_slice(&plaintext)
                .map_err(|_| "Recovery kit contains a malformed entry".to_string())?;
            entries.push(parsed);
        }
        let contents = validate_entries(&entries);
        for entry in &mut entries {
            entry.encryption_key_b64.zeroize();
        }
        contents
    }

    pub fn to_base64(&self) -> Result<String, String> {
        let serialized =
            serde_json::to_vec(self).map_err(|e| format!("Failed to encode recovery kit: {e}"))?;
        Ok(general_purpose::STANDARD.encode(serialized))
    }

    pub fn from_base64(encoded: &str) -> Result<Self, String> {
        if encoded.len() > MAX_KIT_BYTES * 4 / 3 + 4 {
            return Err("Recovery kit exceeds the size limit".into());
        }
        let decoded = general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_| "This file is not a HybridCipher recovery kit".to_string())?;
        let kit: Self = serde_json::from_slice(&decoded)
            .map_err(|_| "This file is not a HybridCipher recovery kit".to_string())?;
        kit.check_header()?;
        Ok(kit)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let metadata =
            fs::metadata(path).map_err(|e| format!("Failed to read recovery kit: {e}"))?;
        if metadata.len() as usize > MAX_KIT_BYTES * 4 / 3 + 4 {
            return Err("Recovery kit exceeds the size limit".into());
        }
        let contents =
            fs::read_to_string(path).map_err(|e| format!("Failed to read recovery kit: {e}"))?;
        Self::from_base64(&contents)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        let encoded = self.to_base64()?;
        fs::write(path, encoded).map_err(|e| format!("Failed to save recovery kit: {e}"))
    }

    fn check_header(&self) -> Result<(), String> {
        if self.kind != LOCAL_KIT_KIND {
            return Err("This file is not a HybridCipher recovery kit".into());
        }
        if self.version != LOCAL_KIT_VERSION {
            return Err(format!(
                "Unsupported recovery kit version {} (expected {})",
                self.version, LOCAL_KIT_VERSION
            ));
        }
        if self.entries.is_empty() {
            return Err("Recovery kit contains no keys".into());
        }
        if self.entries.len() > MAX_KIT_ENTRIES {
            return Err("Recovery kit contains too many entries".into());
        }
        Ok(())
    }
}

fn derive_entry_key(recovery_code: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if salt.len() != SALT_LEN {
        return Err("Recovery kit has an invalid salt".into());
    }
    let root = Zeroizing::new(derive_root_key(recovery_code, salt)?);
    let mut entry_key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(salt), root.as_ref())
        .expand(ENTRY_KEY_LABEL, entry_key.as_mut())
        .map_err(|_| "Failed to derive recovery kit key".to_string())?;
    Ok(entry_key)
}

/// One group, consistent epoch identifiers, and no conflicting or empty keys.
fn validate_entries(entries: &[BackupEntryPlain]) -> Result<LocalKitContents, String> {
    let group_id = entries
        .first()
        .map(|entry| entry.group_id)
        .ok_or_else(|| "Recovery kit contains no keys".to_string())?;
    if entries.len() > MAX_KIT_ENTRIES {
        return Err("Recovery kit contains too many entries".into());
    }
    let mut epochs: BTreeMap<u64, LocalKitEpoch> = BTreeMap::new();
    for entry in entries {
        if entry.group_id != group_id {
            return Err("Recovery kit mixes keys from different vaults".into());
        }
        if entry.epoch_number == 0
            || entry.epoch_uuid
                != EpochIdMapper::u64_to_uuid(entry.epoch_number, group_id.as_bytes())
        {
            return Err("Recovery kit epoch identifier does not match its vault".into());
        }
        let decoded = Zeroizing::new(
            general_purpose::STANDARD
                .decode(&entry.encryption_key_b64)
                .map_err(|_| "Recovery kit key has invalid encoding".to_string())?,
        );
        if decoded.len() != KEY_LEN || decoded.iter().all(|byte| *byte == 0) {
            return Err("Recovery kit key is invalid".into());
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&decoded);
        if let Some(existing) = epochs.get(&entry.epoch_number) {
            if existing.key.as_ref() != key.as_ref() {
                return Err("Recovery kit contains conflicting keys for one epoch".into());
            }
            continue;
        }
        epochs.insert(
            entry.epoch_number,
            LocalKitEpoch {
                number: entry.epoch_number,
                created_at: entry.created_at,
                is_active: entry.is_active,
                key,
            },
        );
    }
    Ok(LocalKitContents {
        group_id,
        epochs: epochs.into_values().collect(),
    })
}

#[cfg(test)]
#[path = "../tests/local_vault/test_local_recovery_kit.rs"]
mod tests;
