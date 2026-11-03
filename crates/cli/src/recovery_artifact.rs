//! CLI error and filesystem adapter for the shared recovery artifact format.
use crate::error::CliError;
use hybridcipher_client::saved_code_recovery as shared;
use serde::{Deserialize, Serialize};
use std::{
    ops::{Deref, DerefMut},
    path::Path,
};
use zeroize::Zeroizing;

pub use shared::{BackupEntryPlain, BACKUP_VERSION};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BackupArtifact(shared::BackupArtifact);

impl Deref for BackupArtifact {
    type Target = shared::BackupArtifact;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for BackupArtifact {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl BackupArtifact {
    pub fn new(password: &str, code: &[u8]) -> Result<Self, CliError> {
        shared::BackupArtifact::new(password, code)
            .map(Self)
            .map_err(CliError::format)
    }
    pub fn from_base64(encoded: &str) -> Result<Self, CliError> {
        shared::BackupArtifact::from_base64(encoded)
            .map(Self)
            .map_err(CliError::format)
    }
    pub fn load_from_path(path: &Path) -> Result<Self, CliError> {
        shared::BackupArtifact::load_from_path(path)
            .map(Self)
            .map_err(CliError::format)
    }
    pub fn to_base64(&self) -> Result<String, CliError> {
        self.0.to_base64().map_err(CliError::format)
    }
    pub fn save_to_path(&self, path: &Path) -> Result<(), CliError> {
        self.0.save_to_path(path).map_err(CliError::io)
    }
    pub fn unwrap_file_key(
        &self,
        password: &str,
        code: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, CliError> {
        self.0
            .unwrap_file_key(password, code)
            .map_err(CliError::decryption)
    }
    pub fn unlock(
        &self,
        password: &str,
        code: &[u8],
    ) -> Result<shared::UnlockedRecovery, CliError> {
        self.0.unlock(password, code).map_err(CliError::decryption)
    }
    pub fn append_entries(
        &mut self,
        entries: &[BackupEntryPlain],
        password: &str,
        code: &[u8],
    ) -> Result<(), CliError> {
        self.0
            .append_entries(entries, password, code)
            .map_err(CliError::encryption)
    }
    pub fn append_entries_with_epoch_key(
        &mut self,
        entries: &[BackupEntryPlain],
        key: &[u8; 32],
    ) -> Result<(), CliError> {
        self.0
            .append_entries_with_epoch_key(entries, key)
            .map_err(CliError::encryption)
    }
    pub fn decrypt_entries(
        &self,
        password: &str,
        code: &[u8],
    ) -> Result<Vec<BackupEntryPlain>, CliError> {
        self.0
            .decrypt_entries(password, code)
            .map_err(CliError::decryption)
    }
    pub fn derive_epoch_key(&self, key: &[u8]) -> Result<[u8; 32], CliError> {
        self.0.derive_epoch_key(key).map_err(CliError::encryption)
    }
}

#[cfg(test)]
#[path = "../tests/recovery/test_artifact_adapter.rs"]
mod tests;
