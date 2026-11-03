//! Desktop and CLI use the same authenticated recovery artifact format.
#[cfg(test)]
pub use hybridcipher_client::saved_code_recovery::EncryptedEntry;
pub use hybridcipher_client::saved_code_recovery::{
    format_recovery_code, BackupArtifact, BackupEntryPlain, BACKUP_VERSION, RECOVERY_CODE_BYTES,
};
