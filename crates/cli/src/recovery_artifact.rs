use crate::error::CliError;
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use hybridcipher_crypto::account_protection::{decrypt_with_ad, encrypt_with_ad, ProtectedData};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const BACKUP_VERSION: u32 = 1;
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
    /// Create a brand new artifact with no entries.
    pub fn new(password: &str, recovery_code: &[u8]) -> Result<Self, CliError> {
        if password.trim().is_empty() {
            return Err(CliError::invalid_input(
                "Password is required to create a recovery backup".to_string(),
            ));
        }

        let mut k_file = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k_file);
        let mut k1 = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k1);

        let mut k2 = [0u8; KEY_LEN];
        xor_into(&mut k2, &k_file, &k1);

        let mut k1_salt = [0u8; SALT_LEN];
        let mut k2_salt = [0u8; SALT_LEN];
        let mut hkdf_salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut k1_salt);
        OsRng.fill_bytes(&mut k2_salt);
        OsRng.fill_bytes(&mut hkdf_salt);

        let k1_root = derive_root_key(recovery_code, &k1_salt)?;
        let k2_root = derive_root_key(password.as_bytes(), &k2_salt)?;

        let k1_wrapped = encrypt_with_ad(&k1, k1_root, K1_AAD)
            .map_err(|err| CliError::encryption(format!("Failed to wrap K1: {}", err)))?;
        let k2_wrapped = encrypt_with_ad(&k2, k2_root, K2_AAD)
            .map_err(|err| CliError::encryption(format!("Failed to wrap K2: {}", err)))?;

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

    pub fn to_base64(&self) -> Result<String, CliError> {
        let serialized = serde_json::to_vec(self)
            .map_err(|e| CliError::format(format!("Failed to serialize backup: {}", e)))?;
        Ok(general_purpose::STANDARD.encode(serialized))
    }

    pub fn from_base64(encoded: &str) -> Result<Self, CliError> {
        let decoded = general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|e| CliError::format(format!("Artifact is not valid base64: {}", e)))?;
        let mut artifact: BackupArtifact = serde_json::from_slice(&decoded)
            .map_err(|e| CliError::format(format!("Artifact JSON is invalid: {}", e)))?;
        if artifact.version != BACKUP_VERSION {
            // Compatibility: earlier client builds incorrectly incremented the format
            // version field while uploading. Treat version 2 as identical to 1.
            if artifact.version == BACKUP_VERSION + 1 {
                artifact.version = BACKUP_VERSION;
            } else {
                return Err(CliError::format(format!(
                    "Unsupported backup version {} (expected {})",
                    artifact.version, BACKUP_VERSION
                )));
            }
        }
        Ok(artifact)
    }

    /// Load an artifact from a base64-encoded file.
    pub fn load_from_path(path: &Path) -> Result<Self, CliError> {
        let contents = fs::read_to_string(path)
            .map_err(|e| CliError::io(format!("Failed to read backup artifact: {}", e)))?;
        Self::from_base64(&contents)
    }

    /// Persist the artifact to a base64-encoded file.
    pub fn save_to_path(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| CliError::io(format!("Failed to create backup directory: {}", e)))?;
        }
        let encoded = self.to_base64()?;
        fs::write(path, encoded)
            .map_err(|e| CliError::io(format!("Failed to write backup artifact: {}", e)))
    }

    /// Recover the combined file key using the provided secrets.
    pub fn unwrap_file_key(
        &self,
        password: &str,
        recovery_code: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CliError> {
        let k1_salt = general_purpose::STANDARD
            .decode(&self.k1_salt_b64)
            .map_err(|e| CliError::format(format!("Invalid K1 salt encoding: {}", e)))?;
        let k2_salt = general_purpose::STANDARD
            .decode(&self.k2_salt_b64)
            .map_err(|e| CliError::format(format!("Invalid K2 salt encoding: {}", e)))?;

        let k1_root = derive_root_key(recovery_code, &k1_salt)?;
        let k2_root = derive_root_key(password.as_bytes(), &k2_salt)?;

        let k1_bytes = decrypt_with_ad(&self.k1_wrapped, k1_root, K1_AAD).map_err(|_| {
            CliError::decryption(
                "Recovery code does not match this backup (or the backup is corrupted)".to_string(),
            )
        })?;
        let k2_bytes = decrypt_with_ad(&self.k2_wrapped, k2_root, K2_AAD).map_err(|_| {
            CliError::decryption(
                "Password does not match this backup (or the backup is corrupted)".to_string(),
            )
        })?;

        if k1_bytes.len() != KEY_LEN || k2_bytes.len() != KEY_LEN {
            return Err(CliError::decryption(
                "Wrapped shares have unexpected length".to_string(),
            ));
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
    ) -> Result<(), CliError> {
        if entries.is_empty() {
            return Ok(());
        }
        let k_file = self.unwrap_file_key(password, recovery_code)?;
        let hkdf_salt = general_purpose::STANDARD
            .decode(&self.hkdf_salt_b64)
            .map_err(|e| CliError::format(format!("Invalid HKDF salt encoding: {}", e)))?;

        let hkdf_key = self.derive_epoch_key_from_file_key(k_file.as_ref(), &hkdf_salt)?;
        self.append_entries_with_epoch_key(entries, &hkdf_key)?;

        Ok(())
    }

    /// Append entries using a pre-derived epoch AEAD key (HKDF(K_file, hkdf_salt)).
    pub fn append_entries_with_epoch_key(
        &mut self,
        entries: &[BackupEntryPlain],
        epoch_key: &[u8; KEY_LEN],
    ) -> Result<(), CliError> {
        for entry in entries {
            let plaintext =
                serde_json::to_vec(entry).map_err(|e| CliError::format(format!("{}", e)))?;
            let protected = encrypt_with_ad(plaintext.as_slice(), *epoch_key, ENTRY_AAD)
                .map_err(|e| CliError::encryption(format!("Failed to encrypt entry: {}", e)))?;
            self.entries.push(EncryptedEntry { protected });
        }
        Ok(())
    }

    /// Decrypt all entries using the provided secrets.
    pub fn decrypt_entries(
        &self,
        password: &str,
        recovery_code: &[u8],
    ) -> Result<Vec<BackupEntryPlain>, CliError> {
        let k_file = self.unwrap_file_key(password, recovery_code)?;
        let hkdf_salt = general_purpose::STANDARD
            .decode(&self.hkdf_salt_b64)
            .map_err(|e| CliError::format(format!("Invalid HKDF salt encoding: {}", e)))?;

        let hkdf_key = self.derive_epoch_key_from_file_key(k_file.as_ref(), &hkdf_salt)?;

        let mut results = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let plaintext = decrypt_with_ad(&entry.protected, hkdf_key, ENTRY_AAD)
                .map_err(|e| CliError::decryption(format!("Failed to decrypt entry: {}", e)))?;
            let parsed: BackupEntryPlain = serde_json::from_slice(&plaintext).map_err(|e| {
                CliError::format(format!("Decrypted entry is malformed JSON: {}", e))
            })?;
            results.push(parsed);
        }
        Ok(results)
    }

    /// Derive the epoch AEAD key from K_file and the artifact HKDF salt.
    pub fn derive_epoch_key_from_file_key(
        &self,
        k_file: &[u8],
        hkdf_salt: &[u8],
    ) -> Result<[u8; KEY_LEN], CliError> {
        if hkdf_salt.len() != SALT_LEN {
            return Err(CliError::format(
                "Invalid HKDF salt length for recovery backup".to_string(),
            ));
        }

        let mut hkdf_key = [0u8; KEY_LEN];
        let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), k_file);
        hk.expand(EPOCH_KEY_LABEL, &mut hkdf_key)
            .map_err(|_| CliError::encryption("Failed to derive entry key".to_string()))?;
        Ok(hkdf_key)
    }

    /// Derive the epoch AEAD key directly using the stored HKDF salt and provided K_file.
    pub fn derive_epoch_key(&self, k_file: &[u8]) -> Result<[u8; KEY_LEN], CliError> {
        let hkdf_salt = general_purpose::STANDARD
            .decode(&self.hkdf_salt_b64)
            .map_err(|e| CliError::format(format!("Invalid HKDF salt encoding: {}", e)))?;
        self.derive_epoch_key_from_file_key(k_file, &hkdf_salt)
    }
}

fn derive_root_key(secret: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], CliError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    if salt.len() != SALT_LEN {
        return Err(CliError::format(
            "Invalid salt length for root key derivation".to_string(),
        ));
    }

    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN)).map_err(|e| {
        CliError::encryption(format!(
            "Invalid Argon2 parameters for backup derivation: {}",
            e
        ))
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = [0u8; KEY_LEN];
    argon2
        .hash_password_into(secret, salt, &mut derived)
        .map_err(|e| CliError::encryption(format!("Failed to derive root key: {}", e)))?;
    Ok(derived)
}

fn xor_into(out: &mut [u8; KEY_LEN], lhs: &[u8], rhs: &[u8]) {
    for i in 0..KEY_LEN {
        let l = lhs.get(i).copied().unwrap_or(0);
        let r = rhs.get(i).copied().unwrap_or(0);
        out[i] = l ^ r;
    }
}
