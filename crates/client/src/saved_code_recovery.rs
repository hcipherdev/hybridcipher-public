//! Shared sealed saved-code recovery artifacts and authenticated restore planning.

use crate::state::client::GroupRole;
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use hybridcipher_crypto::account_protection::{decrypt_with_ad, encrypt_with_ad, ProtectedData};
use hybridcipher_crypto::epoch_id::EpochIdMapper;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const BACKUP_VERSION: u32 = 1;
pub const RECOVERY_CODE_BYTES: usize = 32;
const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const ENTRY_AAD: &[u8] = b"hybridcipher/backup/entry";
const K1_AAD: &[u8] = b"hybridcipher/backup/k1";
const K2_AAD: &[u8] = b"hybridcipher/backup/k2";
const EPOCH_KEY_LABEL: &[u8] = b"hybridcipher-backup";

/// Plaintext representation of a single epoch entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupEntryPlain {
    pub group_id: Uuid,
    pub epoch_number: u64,
    pub epoch_uuid: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
    pub encryption_key_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEntry {
    pub protected: ProtectedData,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupArtifact {
    pub version: u32,
    pub k1_salt_b64: String,
    pub k2_salt_b64: String,
    pub hkdf_salt_b64: String,
    pub k1_wrapped: ProtectedData,
    pub k2_wrapped: ProtectedData,
    pub entries: Vec<EncryptedEntry>,
}

impl BackupArtifact {
    /// Entries from different encryption envelopes cannot be combined.
    pub fn has_same_envelope(&self, other: &Self) -> bool {
        self.k1_salt_b64 == other.k1_salt_b64
            && self.k2_salt_b64 == other.k2_salt_b64
            && self.hkdf_salt_b64 == other.hkdf_salt_b64
            && self.k1_wrapped == other.k1_wrapped
            && self.k2_wrapped == other.k2_wrapped
    }
    /// Authenticate both wrapped shares and every encrypted entry before use.
    pub fn unlock(&self, password: &str, recovery_code: &[u8]) -> Result<UnlockedRecovery, String> {
        if recovery_code.len() != RECOVERY_CODE_BYTES || password.is_empty() {
            return Err("An account password and 32-byte recovery code are required".into());
        }
        let file_key = self.unwrap_file_key(password, recovery_code)?;
        let entry_key = Zeroizing::new(self.derive_epoch_key(file_key.as_ref())?);
        if self.entries.len() > MAX_ENTRIES {
            return Err("Recovery artifact contains too many entries".into());
        }
        let mut unlocked = UnlockedRecovery {
            file_key,
            entry_key,
            recovery_secret: Zeroizing::new(recovery_code.to_vec()),
            entries: Vec::with_capacity(self.entries.len()),
        };
        for entry in &self.entries {
            let plaintext = Zeroizing::new(
                decrypt_with_ad(&entry.protected, *unlocked.entry_key, ENTRY_AAD)
                    .map_err(|_| "Recovery backup contains a corrupted entry".to_string())?,
            );
            let parsed: BackupEntryPlain = serde_json::from_slice(&plaintext)
                .map_err(|_| "Recovery backup contains a malformed epoch entry".to_string())?;
            unlocked.entries.push(parsed);
        }
        Ok(unlocked)
    }

    pub fn decrypt_entries(
        &self,
        password: &str,
        recovery_code: &[u8],
    ) -> Result<Vec<BackupEntryPlain>, String> {
        Ok(self.unlock(password, recovery_code)?.entries.clone())
    }

    pub fn derive_epoch_key(&self, file_key: &[u8]) -> Result<[u8; KEY_LEN], String> {
        let salt = general_purpose::STANDARD
            .decode(&self.hkdf_salt_b64)
            .map_err(|_| "Recovery backup has invalid entry-key salt".to_string())?;
        self.derive_epoch_key_from_file_key(file_key, &salt)
    }

    /// Create a brand new artifact with no entries.
    pub fn new(password: &str, recovery_code: &[u8]) -> Result<Self, String> {
        if password.trim().is_empty() || recovery_code.len() != RECOVERY_CODE_BYTES {
            return Err("An account password and 32-byte recovery code are required".to_string());
        }

        let mut k_file = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(k_file.as_mut());
        let mut k1 = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(k1.as_mut());

        let mut k2 = Zeroizing::new([0u8; KEY_LEN]);
        xor_into(&mut k2, k_file.as_ref(), k1.as_ref());

        let mut k1_salt = [0u8; SALT_LEN]; // lgtm[rust/hard-coded-cryptographic-value] zeroed buffer is immediately filled from OsRng
        let mut k2_salt = [0u8; SALT_LEN]; // lgtm[rust/hard-coded-cryptographic-value] zeroed buffer is immediately filled from OsRng
        let mut hkdf_salt = [0u8; SALT_LEN]; // lgtm[rust/hard-coded-cryptographic-value] zeroed buffer is immediately filled from OsRng
        OsRng.fill_bytes(&mut k1_salt);
        OsRng.fill_bytes(&mut k2_salt);
        OsRng.fill_bytes(&mut hkdf_salt);

        let k1_root = Zeroizing::new(derive_root_key(recovery_code, &k1_salt)?);
        let k2_root = Zeroizing::new(derive_root_key(password.as_bytes(), &k2_salt)?);

        let k1_wrapped = encrypt_with_ad(k1.as_ref(), *k1_root, K1_AAD)
            .map_err(|err| format!("Failed to wrap K1: {}", err))?;
        let k2_wrapped = encrypt_with_ad(k2.as_ref(), *k2_root, K2_AAD)
            .map_err(|err| format!("Failed to wrap K2: {}", err))?;

        Ok(Self {
            version: BACKUP_VERSION,
            k1_salt_b64: general_purpose::STANDARD.encode(k1_salt),
            k2_salt_b64: general_purpose::STANDARD.encode(k2_salt),
            hkdf_salt_b64: general_purpose::STANDARD.encode(hkdf_salt),
            k1_wrapped,
            k2_wrapped,
            entries: Vec::new(),
        })
    }

    pub fn to_base64(&self) -> Result<String, String> {
        let serialized =
            serde_json::to_vec(self).map_err(|e| format!("Failed to serialize backup: {}", e))?;
        Ok(general_purpose::STANDARD.encode(serialized))
    }

    pub fn from_base64(encoded: &str) -> Result<Self, String> {
        if encoded.len() > MAX_ARTIFACT_BYTES * 4 / 3 + 4 {
            return Err("Recovery artifact exceeds the size limit".into());
        }
        let decoded = general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|e| format!("Artifact is not valid base64: {}", e))?;
        let mut artifact: BackupArtifact = serde_json::from_slice(&decoded)
            .map_err(|e| format!("Artifact JSON is invalid: {}", e))?;
        if artifact.version != BACKUP_VERSION {
            if artifact.version == BACKUP_VERSION + 1 {
                artifact.version = BACKUP_VERSION;
            } else {
                return Err(format!(
                    "Unsupported backup version {} (expected {})",
                    artifact.version, BACKUP_VERSION
                ));
            }
        }
        if artifact.entries.len() > MAX_ENTRIES {
            return Err("Recovery artifact contains too many entries".into());
        }
        Ok(artifact)
    }

    /// Load an artifact from a base64-encoded file.
    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read backup artifact: {}", e))?;
        Self::from_base64(&contents)
    }

    /// Persist the artifact to a base64-encoded file.
    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create backup directory: {}", e))?;
        }
        let encoded = self.to_base64()?;
        fs::write(path, encoded).map_err(|e| format!("Failed to write backup artifact: {}", e))
    }

    /// Recover the combined file key using the provided secrets.
    pub fn unwrap_file_key(
        &self,
        password: &str,
        recovery_code: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
        let k1_salt = general_purpose::STANDARD
            .decode(&self.k1_salt_b64)
            .map_err(|e| format!("Invalid K1 salt encoding: {}", e))?;
        let k2_salt = general_purpose::STANDARD
            .decode(&self.k2_salt_b64)
            .map_err(|e| format!("Invalid K2 salt encoding: {}", e))?;

        let k1_root = Zeroizing::new(derive_root_key(recovery_code, &k1_salt)?);
        let k2_root = Zeroizing::new(derive_root_key(password.as_bytes(), &k2_salt)?);

        let k1_bytes = Zeroizing::new(
            decrypt_with_ad(&self.k1_wrapped, *k1_root, K1_AAD)
                .map_err(|_| "Recovery code does not match this backup".to_string())?,
        );
        let k2_bytes = Zeroizing::new(
            decrypt_with_ad(&self.k2_wrapped, *k2_root, K2_AAD)
                .map_err(|_| "Password does not match this backup".to_string())?,
        );

        if k1_bytes.len() != KEY_LEN || k2_bytes.len() != KEY_LEN {
            return Err("Wrapped shares have unexpected length".to_string());
        }

        let mut k_file = Zeroizing::new([0u8; KEY_LEN]);
        xor_into(&mut k_file, &k1_bytes, &k2_bytes);
        Ok(k_file)
    }

    /// Append new entries using the provided secrets.
    pub fn append_entries(
        &mut self,
        entries: &[BackupEntryPlain],
        password: &str,
        recovery_code: &[u8],
    ) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }
        let k_file = self.unwrap_file_key(password, recovery_code)?;
        let hkdf_salt = general_purpose::STANDARD
            .decode(&self.hkdf_salt_b64)
            .map_err(|e| format!("Invalid HKDF salt encoding: {}", e))?;

        let hkdf_key =
            Zeroizing::new(self.derive_epoch_key_from_file_key(k_file.as_ref(), &hkdf_salt)?);
        self.append_entries_with_epoch_key(entries, &hkdf_key)?;

        Ok(())
    }

    /// Append entries using a pre-derived epoch AEAD key (HKDF(K_file, hkdf_salt)).
    pub fn append_entries_with_epoch_key(
        &mut self,
        entries: &[BackupEntryPlain],
        epoch_key: &[u8; KEY_LEN],
    ) -> Result<(), String> {
        for entry in entries {
            let plaintext = Zeroizing::new(
                serde_json::to_vec(entry).map_err(|e| format!("Failed to encode entry: {}", e))?,
            );
            let protected = encrypt_with_ad(plaintext.as_slice(), *epoch_key, ENTRY_AAD)
                .map_err(|e| format!("Failed to encrypt entry: {}", e))?;
            self.entries.push(EncryptedEntry { protected });
        }
        Ok(())
    }

    /// Derive the epoch AEAD key from K_file and the artifact HKDF salt.
    pub fn derive_epoch_key_from_file_key(
        &self,
        k_file: &[u8],
        hkdf_salt: &[u8],
    ) -> Result<[u8; KEY_LEN], String> {
        if hkdf_salt.len() != SALT_LEN {
            return Err("Invalid HKDF salt length for recovery backup".to_string());
        }

        let mut hkdf_key = [0u8; KEY_LEN];
        let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), k_file);
        hk.expand(EPOCH_KEY_LABEL, &mut hkdf_key)
            .map_err(|_| "Failed to derive entry key".to_string())?;
        Ok(hkdf_key)
    }
}

/// Authenticated material cannot be constructed from unauthenticated plaintext.
/// It deliberately has no Debug or serialization implementation.
pub struct UnlockedRecovery {
    file_key: Zeroizing<[u8; KEY_LEN]>,
    entry_key: Zeroizing<[u8; KEY_LEN]>,
    recovery_secret: Zeroizing<Vec<u8>>,
    entries: Vec<BackupEntryPlain>,
}

impl Drop for UnlockedRecovery {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.encryption_key_b64.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct RecoveryGroupScope {
    pub group_id: Uuid,
    pub group_name: String,
    pub user_role: GroupRole,
    pub current_epoch_uuid: Option<Uuid>,
}

#[derive(Clone)]
pub(crate) struct ValidatedEpoch {
    pub number: u64,
    pub uuid: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub key: Zeroizing<[u8; KEY_LEN]>,
}

pub(crate) struct ValidatedGroup {
    pub scope: RecoveryGroupScope,
    pub epochs: Vec<ValidatedEpoch>,
}

/// A restore plan created only from a successfully authenticated artifact.
pub struct ValidatedRecovery {
    pub(crate) groups: Vec<ValidatedGroup>,
    pub(crate) all_epochs: Vec<(Uuid, ValidatedEpoch)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryGroupReadiness {
    pub group_id: Uuid,
    pub restored_epochs: usize,
    pub current_epoch_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryInstallResult {
    pub imported_epochs: usize,
    pub ready_groups: Vec<Uuid>,
    pub missing_current_groups: Vec<Uuid>,
}

impl UnlockedRecovery {
    pub fn file_key(&self) -> &[u8; KEY_LEN] {
        &self.file_key
    }
    pub fn entry_key(&self) -> &[u8; KEY_LEN] {
        &self.entry_key
    }
    /// Used only by saved-code challenge signing, never persisted or handed off.
    pub fn recovery_secret(&self) -> &[u8] {
        &self.recovery_secret
    }

    pub fn validate_for_groups(
        &self,
        scopes: &[RecoveryGroupScope],
        filter: Option<Uuid>,
    ) -> Result<ValidatedRecovery, String> {
        let allowed: HashSet<Uuid> = scopes.iter().map(|scope| scope.group_id).collect();
        if allowed.len() != scopes.len() {
            return Err("Recovery group metadata contains duplicates".into());
        }
        if filter.is_some_and(|id| !allowed.contains(&id)) {
            return Err("The recovery group is not an authorized account group".into());
        }
        let mut validated: BTreeMap<(Uuid, u64), ValidatedEpoch> = BTreeMap::new();
        for entry in &self.entries {
            if entry.epoch_number == 0
                || entry.epoch_uuid
                    != EpochIdMapper::u64_to_uuid(entry.epoch_number, entry.group_id.as_bytes())
            {
                return Err("Recovery epoch identifier does not match its group and number".into());
            }
            let decoded = Zeroizing::new(
                general_purpose::STANDARD
                    .decode(&entry.encryption_key_b64)
                    .map_err(|_| "Recovery epoch key has invalid encoding".to_string())?,
            );
            if decoded.len() != KEY_LEN || decoded.iter().all(|byte| *byte == 0) {
                return Err("Recovery epoch key is invalid".into());
            }
            if !allowed.contains(&entry.group_id) {
                return Err(
                    "Recovery backup contains a group outside current account memberships".into(),
                );
            }
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&decoded);
            let identity = (entry.group_id, entry.epoch_number);
            if let Some(existing) = validated.get(&identity) {
                if existing.key.as_ref() != key.as_ref() {
                    return Err("Recovery backup contains conflicting keys for one epoch".into());
                }
            } else {
                validated.insert(
                    identity,
                    ValidatedEpoch {
                        number: entry.epoch_number,
                        uuid: entry.epoch_uuid,
                        created_at: entry.created_at,
                        key,
                    },
                );
            }
        }
        let all_epochs = validated
            .iter()
            .map(|((id, _), epoch)| (*id, epoch.clone()))
            .collect();
        let groups = scopes
            .iter()
            .filter(|scope| filter.is_none_or(|id| id == scope.group_id))
            .filter_map(|scope| {
                let identities = validated
                    .keys()
                    .filter(|(id, _)| *id == scope.group_id)
                    .copied()
                    .collect::<Vec<_>>();
                let epochs = identities
                    .into_iter()
                    .map(|id| validated.remove(&id).expect("validated key exists"))
                    .collect::<Vec<_>>();
                (!epochs.is_empty()).then(|| ValidatedGroup {
                    scope: scope.clone(),
                    epochs,
                })
            })
            .collect::<Vec<_>>();
        if groups.is_empty() {
            return Err(
                "The backup contains no recoverable epochs for the selected account groups".into(),
            );
        }
        Ok(ValidatedRecovery { groups, all_epochs })
    }
}

impl ValidatedRecovery {
    /// Narrow import scope after validating the entire authenticated artifact.
    pub fn retain_groups(&mut self, selected: &[Uuid]) -> Result<(), String> {
        self.groups
            .retain(|group| selected.contains(&group.scope.group_id));
        if self.groups.is_empty() {
            return Err("No authorized recovery groups were selected".into());
        }
        Ok(())
    }
    pub fn group_ids(&self) -> Vec<Uuid> {
        self.groups
            .iter()
            .map(|group| group.scope.group_id)
            .collect()
    }
    pub fn contains_current(&self, id: Uuid) -> bool {
        self.groups
            .iter()
            .find(|group| group.scope.group_id == id)
            .is_some_and(|group| {
                group
                    .epochs
                    .iter()
                    .any(|epoch| Some(epoch.uuid) == group.scope.current_epoch_uuid)
            })
    }
    pub fn group_readiness(&self) -> Vec<RecoveryGroupReadiness> {
        self.groups
            .iter()
            .map(|group| RecoveryGroupReadiness {
                group_id: group.scope.group_id,
                restored_epochs: group.epochs.len(),
                current_epoch_available: self.contains_current(group.scope.group_id),
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "../tests/recovery/test_saved_code_artifact.rs"]
mod tests;

pub(crate) fn derive_root_key(secret: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    if salt.len() != SALT_LEN {
        return Err("Invalid salt length for root key derivation".to_string());
    }

    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|e| format!("Invalid Argon2 parameters for backup derivation: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = [0u8; KEY_LEN];
    argon2
        .hash_password_into(secret, salt, &mut derived)
        .map_err(|e| format!("Failed to derive root key: {}", e))?;
    Ok(derived)
}

fn xor_into(out: &mut [u8; KEY_LEN], lhs: &[u8], rhs: &[u8]) {
    for i in 0..KEY_LEN {
        let l = lhs.get(i).copied().unwrap_or(0);
        let r = rhs.get(i).copied().unwrap_or(0);
        out[i] = l ^ r;
    }
}

pub fn format_recovery_code(code: &[u8]) -> String {
    let hex = hex::encode_upper(code);
    let mut grouped = String::with_capacity(hex.len() + hex.len() / 8);
    for (idx, ch) in hex.chars().enumerate() {
        if idx > 0 && idx % 8 == 0 {
            grouped.push('-');
        }
        grouped.push(ch);
    }
    grouped
}

/// Accept a recovery code typed with or without dashes and whitespace.
pub fn parse_recovery_code(input: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let normalized = Zeroizing::new(
        input
            .chars()
            .filter(|character| !character.is_whitespace() && *character != '-')
            .collect::<String>(),
    );
    if normalized.len() != RECOVERY_CODE_BYTES * 2 {
        return Err(format!(
            "Recovery code must contain exactly {} hexadecimal characters, ignoring dashes.",
            RECOVERY_CODE_BYTES * 2
        ));
    }
    let bytes = Zeroizing::new(
        hex::decode(normalized.as_str())
            .map_err(|err| format!("Recovery code is not valid hexadecimal: {}", err))?,
    );
    if bytes.len() != RECOVERY_CODE_BYTES {
        return Err("Recovery code has an unexpected length.".to_string());
    }
    Ok(bytes)
}
