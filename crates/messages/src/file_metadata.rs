//! File metadata and coverage tracking messages with integrity proofs
//!
//! This module defines messages for tracking file encryption state with
//! cryptographic proofs of proper epoch management and access control.

use crate::error::{MessageError, MessageResult};
use serde::{Deserialize, Serialize};
use serde_cbor;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// File encryption algorithm identifiers
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// ChaCha20-Poly1305 AEAD
    ChaCha20Poly1305,
    /// AES-256-GCM AEAD  
    Aes256Gcm,
    /// Future algorithm support
    Future(String),
}

/// Key derivation parameters for file encryption
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivationParams {
    /// HKDF salt for key derivation
    pub salt: Vec<u8>,
    /// Key derivation context/info
    pub context: String,
    /// Number of iterations (for future PBKDF2 support)
    pub iterations: Option<u32>,
}

/// File encryption information
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileEncryptionInfo {
    /// Encryption algorithm used
    pub algorithm: EncryptionAlgorithm,
    /// Key derivation parameters
    pub key_derivation: KeyDerivationParams,
    /// Initialization vector/nonce
    pub iv_nonce: Vec<u8>,
    /// Authentication tag
    pub auth_tag: Vec<u8>,
    /// Additional authenticated data
    pub aad: Vec<u8>,
}

/// File version information for backward compatibility
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileVersion {
    /// Major version number
    pub major: u32,
    /// Minor version number
    pub minor: u32,
    /// Patch version number
    pub patch: u32,
    /// Optional pre-release identifier
    pub pre_release: Option<String>,
}

/// Access control permissions for files
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccessControl {
    /// Users with read access
    pub read_users: Vec<String>,
    /// Users with write access
    pub write_users: Vec<String>,
    /// Users with admin access
    pub admin_users: Vec<String>,
    /// Group-level permissions
    pub group_permissions: HashMap<String, Vec<String>>,
}

/// Metadata for encrypted files with comprehensive tracking
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    /// Unique file identifier (SHA-256 of original file path)
    pub file_id: Vec<u8>,
    /// Original file path (for user reference)
    pub file_path: String,
    /// Epoch identifier when file was encrypted
    pub epoch_id: Vec<u8>,
    /// File key wrapped with epoch key
    pub wrapped_file_key: Vec<u8>,
    /// File encryption details
    pub encryption_info: FileEncryptionInfo,
    /// File size in bytes
    pub file_size: u64,
    /// Original file hash (before encryption)
    pub original_hash: Vec<u8>,
    /// Encrypted file hash
    pub encrypted_hash: Vec<u8>,
    /// File version for compatibility
    pub version: FileVersion,
    /// Access control permissions
    pub access_control: AccessControl,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Last modification timestamp (Unix seconds)
    pub modified_at: u64,
    /// Signature from file owner
    pub owner_signature: Vec<u8>,
}

/// Coverage update message for atomic file epoch transitions
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CoverageUpdate {
    /// File identifier being updated
    pub file_id: Vec<u8>,
    /// Source epoch identifier
    pub from_epoch_id: Vec<u8>,
    /// Target epoch identifier
    pub to_epoch_id: Vec<u8>,
    /// Updated file metadata
    pub new_metadata: FileMetadata,
    /// Merkle tree inclusion proof
    pub inclusion_proof: Vec<Vec<u8>>,
    /// Timestamp of update (Unix seconds)
    pub timestamp: u64,
    /// Administrator signature
    pub admin_signature: Vec<u8>,
}

/// Coverage root message containing signed Merkle roots for integrity verification
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CoverageRoot {
    /// Epoch identifier this root covers
    pub epoch_id: Vec<u8>,
    /// Merkle tree root hash
    pub root_hash: Vec<u8>,
    /// Total number of files in this epoch
    pub file_count: u64,
    /// Coverage log sequence number
    pub sequence: u64,
    /// Timestamp when root was generated (Unix seconds)
    pub timestamp: u64,
    /// Coverage of files by epoch
    pub epoch_coverage: HashMap<Vec<u8>, u64>, // epoch_id -> file_count
    /// Administrator signature over the root
    pub admin_signature: Vec<u8>,
}

/// Batch update message for efficient multi-file operations
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BatchCoverageUpdate {
    /// Source epoch identifier
    pub from_epoch_id: Vec<u8>,
    /// Target epoch identifier
    pub to_epoch_id: Vec<u8>,
    /// File updates in this batch
    pub file_updates: Vec<CoverageUpdate>,
    /// Combined Merkle root after all updates
    pub combined_root: Vec<u8>,
    /// Batch timestamp (Unix seconds)
    pub timestamp: u64,
    /// Total files affected
    pub total_files: u64,
    /// Administrator signature over entire batch
    pub admin_signature: Vec<u8>,
}

/// Maximum message size to prevent DoS attacks (1MB)
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Maximum batch size for updates
const MAX_BATCH_SIZE: usize = 1000;

impl EncryptionAlgorithm {
    /// Get algorithm identifier string
    pub fn identifier(&self) -> &str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Aes256Gcm => "aes256-gcm",
            Self::Future(name) => name,
        }
    }

    /// Get required IV/nonce size for this algorithm
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 12, // 96-bit nonce
            Self::Aes256Gcm => 12,        // 96-bit nonce
            Self::Future(_) => 12,        // Default assumption
        }
    }

    /// Get authentication tag size for this algorithm
    pub fn tag_size(&self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 16, // 128-bit tag
            Self::Aes256Gcm => 16,        // 128-bit tag
            Self::Future(_) => 16,        // Default assumption
        }
    }
}

impl FileVersion {
    /// Create new file version
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre_release: None,
        }
    }

    /// Current protocol version
    pub fn current() -> Self {
        Self::new(1, 0, 0)
    }

    /// Check if this version is compatible with another
    pub fn is_compatible(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl AccessControl {
    /// Create new access control with owner permissions
    pub fn new_owner_only(owner: String) -> Self {
        Self {
            read_users: vec![owner.clone()],
            write_users: vec![owner.clone()],
            admin_users: vec![owner],
            group_permissions: HashMap::new(),
        }
    }

    /// Check if user has read permission
    pub fn can_read(&self, user: &str) -> bool {
        self.read_users.contains(&user.to_string())
            || self.write_users.contains(&user.to_string())
            || self.admin_users.contains(&user.to_string())
    }

    /// Check if user has write permission
    pub fn can_write(&self, user: &str) -> bool {
        self.write_users.contains(&user.to_string()) || self.admin_users.contains(&user.to_string())
    }

    /// Check if user has admin permission
    pub fn can_admin(&self, user: &str) -> bool {
        self.admin_users.contains(&user.to_string())
    }
}

impl FileMetadata {
    /// Create new file metadata with validation
    pub fn new(
        file_path: String,
        epoch_id: Vec<u8>,
        wrapped_file_key: Vec<u8>,
        encryption_info: FileEncryptionInfo,
        file_size: u64,
        original_hash: Vec<u8>,
        encrypted_hash: Vec<u8>,
        access_control: AccessControl,
        owner_signature: Vec<u8>,
    ) -> MessageResult<Self> {
        let file_id = Self::calculate_file_id(&file_path);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| MessageError::TimestampError("System clock error".to_string()))?
            .as_secs();

        let metadata = Self {
            file_id,
            file_path,
            epoch_id,
            wrapped_file_key,
            encryption_info,
            file_size,
            original_hash,
            encrypted_hash,
            version: FileVersion::current(),
            access_control,
            created_at: now,
            modified_at: now,
            owner_signature,
        };

        metadata.validate()?;
        Ok(metadata)
    }

    /// Calculate file ID from file path
    pub fn calculate_file_id(file_path: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"hybridcipher-file-id-v1:");
        hasher.update(file_path.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Validate file metadata structure
    pub fn validate(&self) -> MessageResult<()> {
        if self.file_path.is_empty() {
            return Err(MessageError::InvalidFormat(
                "file_path cannot be empty".to_string(),
            ));
        }
        if self.epoch_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "epoch_id cannot be empty".to_string(),
            ));
        }
        if self.wrapped_file_key.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "wrapped_file_key must be 32 bytes".to_string(),
            ));
        }
        if self.original_hash.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "original_hash must be 32 bytes".to_string(),
            ));
        }
        if self.encrypted_hash.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "encrypted_hash must be 32 bytes".to_string(),
            ));
        }
        if self.owner_signature.len() != 64 {
            return Err(MessageError::InvalidFormat(
                "owner_signature must be 64 bytes".to_string(),
            ));
        }

        // Validate encryption info
        self.encryption_info.validate()?;

        // Validate calculated file_id matches
        let calculated_id = Self::calculate_file_id(&self.file_path);
        if self.file_id != calculated_id {
            return Err(MessageError::InvalidFormat(
                "file_id does not match file_path".to_string(),
            ));
        }

        // Check timestamps
        if self.modified_at < self.created_at {
            return Err(MessageError::InvalidFormat(
                "modified_at cannot be before created_at".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if metadata exceeds size limits
    pub fn check_size_limits(&self) -> MessageResult<()> {
        let serialized = serde_cbor::to_vec(self).map_err(|e| {
            MessageError::SerializationError(format!("Serialization failed: {:?}", e))
        })?;

        if serialized.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::InvalidFormat(format!(
                "FileMetadata exceeds maximum size: {} > {}",
                serialized.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        Ok(())
    }
}

impl FileEncryptionInfo {
    /// Create new encryption info with validation
    pub fn new(
        algorithm: EncryptionAlgorithm,
        key_derivation: KeyDerivationParams,
        iv_nonce: Vec<u8>,
        auth_tag: Vec<u8>,
        aad: Vec<u8>,
    ) -> MessageResult<Self> {
        let info = Self {
            algorithm,
            key_derivation,
            iv_nonce,
            auth_tag,
            aad,
        };
        info.validate()?;
        Ok(info)
    }

    /// Validate encryption info structure
    pub fn validate(&self) -> MessageResult<()> {
        // Validate IV/nonce size
        let expected_nonce_size = self.algorithm.nonce_size();
        if self.iv_nonce.len() != expected_nonce_size {
            return Err(MessageError::InvalidFormat(format!(
                "IV/nonce size {} does not match expected {} for algorithm {}",
                self.iv_nonce.len(),
                expected_nonce_size,
                self.algorithm.identifier()
            )));
        }

        // Validate auth tag size
        let expected_tag_size = self.algorithm.tag_size();
        if self.auth_tag.len() != expected_tag_size {
            return Err(MessageError::InvalidFormat(format!(
                "Auth tag size {} does not match expected {} for algorithm {}",
                self.auth_tag.len(),
                expected_tag_size,
                self.algorithm.identifier()
            )));
        }

        // Validate key derivation
        self.key_derivation.validate()?;

        Ok(())
    }
}

impl KeyDerivationParams {
    /// Create new key derivation params
    pub fn new_hkdf(salt: Vec<u8>, context: String) -> Self {
        Self {
            salt,
            context,
            iterations: None,
        }
    }

    /// Validate key derivation parameters
    pub fn validate(&self) -> MessageResult<()> {
        if self.salt.len() < 16 {
            return Err(MessageError::InvalidFormat(
                "Salt must be at least 16 bytes".to_string(),
            ));
        }
        if self.context.is_empty() {
            return Err(MessageError::InvalidFormat(
                "Context cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

impl CoverageUpdate {
    /// Create new coverage update with validation
    pub fn new(
        file_id: Vec<u8>,
        from_epoch_id: Vec<u8>,
        to_epoch_id: Vec<u8>,
        new_metadata: FileMetadata,
        inclusion_proof: Vec<Vec<u8>>,
        admin_signature: Vec<u8>,
    ) -> MessageResult<Self> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| MessageError::TimestampError("System clock error".to_string()))?
            .as_secs();

        let update = Self {
            file_id,
            from_epoch_id,
            to_epoch_id,
            new_metadata,
            inclusion_proof,
            timestamp,
            admin_signature,
        };

        update.validate()?;
        Ok(update)
    }

    /// Validate coverage update structure
    pub fn validate(&self) -> MessageResult<()> {
        if self.file_id != self.new_metadata.file_id {
            return Err(MessageError::InvalidFormat(
                "file_id must match metadata file_id".to_string(),
            ));
        }
        if self.to_epoch_id != self.new_metadata.epoch_id {
            return Err(MessageError::InvalidFormat(
                "to_epoch_id must match metadata epoch_id".to_string(),
            ));
        }
        if self.admin_signature.len() != 64 {
            return Err(MessageError::InvalidFormat(
                "admin_signature must be 64 bytes".to_string(),
            ));
        }

        // Validate metadata
        self.new_metadata.validate()?;

        Ok(())
    }
}

impl BatchCoverageUpdate {
    /// Create new batch update with validation
    pub fn new(
        from_epoch_id: Vec<u8>,
        to_epoch_id: Vec<u8>,
        file_updates: Vec<CoverageUpdate>,
        combined_root: Vec<u8>,
        admin_signature: Vec<u8>,
    ) -> MessageResult<Self> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| MessageError::TimestampError("System clock error".to_string()))?
            .as_secs();

        let total_files = file_updates.len() as u64;

        let batch = Self {
            from_epoch_id,
            to_epoch_id,
            file_updates,
            combined_root,
            timestamp,
            total_files,
            admin_signature,
        };

        batch.validate()?;
        Ok(batch)
    }

    /// Validate batch update structure
    pub fn validate(&self) -> MessageResult<()> {
        if self.file_updates.is_empty() {
            return Err(MessageError::InvalidFormat(
                "file_updates cannot be empty".to_string(),
            ));
        }
        if self.file_updates.len() > MAX_BATCH_SIZE {
            return Err(MessageError::InvalidFormat(format!(
                "Batch size {} exceeds maximum {}",
                self.file_updates.len(),
                MAX_BATCH_SIZE
            )));
        }
        if self.combined_root.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "combined_root must be 32 bytes".to_string(),
            ));
        }
        if self.admin_signature.len() != 64 {
            return Err(MessageError::InvalidFormat(
                "admin_signature must be 64 bytes".to_string(),
            ));
        }

        // Validate all file updates
        for update in &self.file_updates {
            update.validate()?;
            // Ensure epoch consistency
            if update.from_epoch_id != self.from_epoch_id {
                return Err(MessageError::InvalidFormat(
                    "Inconsistent from_epoch_id in batch".to_string(),
                ));
            }
            if update.to_epoch_id != self.to_epoch_id {
                return Err(MessageError::InvalidFormat(
                    "Inconsistent to_epoch_id in batch".to_string(),
                ));
            }
        }

        // Check size limits
        let serialized = serde_cbor::to_vec(self).map_err(|e| {
            MessageError::SerializationError(format!("Serialization failed: {:?}", e))
        })?;

        if serialized.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::InvalidFormat(format!(
                "BatchCoverageUpdate exceeds maximum size: {} > {}",
                serialized.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_encryption_info() -> FileEncryptionInfo {
        FileEncryptionInfo::new(
            EncryptionAlgorithm::ChaCha20Poly1305,
            KeyDerivationParams::new_hkdf(vec![0u8; 32], "test-context".to_string()),
            vec![0u8; 12], // ChaCha20Poly1305 nonce
            vec![0u8; 16], // ChaCha20Poly1305 tag
            vec![1u8; 16], // AAD
        )
        .unwrap()
    }

    #[test]
    fn test_encryption_algorithm() {
        let algo = EncryptionAlgorithm::ChaCha20Poly1305;
        assert_eq!(algo.identifier(), "chacha20-poly1305");
        assert_eq!(algo.nonce_size(), 12);
        assert_eq!(algo.tag_size(), 16);
    }

    #[test]
    fn test_file_version() {
        let v1 = FileVersion::new(1, 0, 0);
        let v2 = FileVersion::new(1, 1, 0);
        let v3 = FileVersion::new(2, 0, 0);

        assert!(v1.is_compatible(&v2)); // Same major version
        assert!(!v1.is_compatible(&v3)); // Different major version
    }

    #[test]
    fn test_access_control() {
        let ac = AccessControl::new_owner_only("alice".to_string());

        assert!(ac.can_read("alice"));
        assert!(ac.can_write("alice"));
        assert!(ac.can_admin("alice"));

        assert!(!ac.can_read("bob"));
        assert!(!ac.can_write("bob"));
        assert!(!ac.can_admin("bob"));
    }

    #[test]
    fn test_file_metadata_creation() {
        let encryption_info = create_test_encryption_info();
        let access_control = AccessControl::new_owner_only("alice".to_string());

        let metadata = FileMetadata::new(
            "test/file.txt".to_string(),
            vec![1u8; 32], // epoch_id
            vec![0u8; 32], // wrapped_file_key
            encryption_info,
            1024,          // file_size
            vec![2u8; 32], // original_hash
            vec![3u8; 32], // encrypted_hash
            access_control,
            vec![0u8; 64], // owner_signature
        )
        .expect("FileMetadata creation failed");

        assert_eq!(metadata.file_path, "test/file.txt");
        assert_eq!(metadata.file_size, 1024);

        // Verify file_id calculation
        let expected_id = FileMetadata::calculate_file_id("test/file.txt");
        assert_eq!(metadata.file_id, expected_id);
    }

    #[test]
    fn test_file_metadata_validation() {
        let encryption_info = create_test_encryption_info();
        let access_control = AccessControl::new_owner_only("alice".to_string());

        // Test with invalid wrapped_file_key size
        let result = FileMetadata::new(
            "test.txt".to_string(),
            vec![1u8; 32],
            vec![0u8; 31], // Wrong size
            encryption_info.clone(),
            1024,
            vec![2u8; 32],
            vec![3u8; 32],
            access_control.clone(),
            vec![0u8; 64],
        );
        assert!(result.is_err());

        // Test with invalid hash size
        let result = FileMetadata::new(
            "test.txt".to_string(),
            vec![1u8; 32],
            vec![0u8; 32],
            encryption_info,
            1024,
            vec![2u8; 31], // Wrong size
            vec![3u8; 32],
            access_control,
            vec![0u8; 64],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_coverage_update() {
        let encryption_info = create_test_encryption_info();
        let access_control = AccessControl::new_owner_only("alice".to_string());

        let metadata = FileMetadata::new(
            "test.txt".to_string(),
            vec![2u8; 32], // to_epoch_id
            vec![0u8; 32],
            encryption_info,
            1024,
            vec![2u8; 32],
            vec![3u8; 32],
            access_control,
            vec![0u8; 64],
        )
        .unwrap();

        let update = CoverageUpdate::new(
            metadata.file_id.clone(),
            vec![1u8; 32], // from_epoch_id
            vec![2u8; 32], // to_epoch_id
            metadata,
            vec![vec![0u8; 32]], // inclusion_proof
            vec![0u8; 64],       // admin_signature
        )
        .expect("CoverageUpdate creation failed");

        assert_eq!(update.from_epoch_id, vec![1u8; 32]);
        assert_eq!(update.to_epoch_id, vec![2u8; 32]);
    }

    #[test]
    fn test_batch_coverage_update() {
        let encryption_info = create_test_encryption_info();
        let access_control = AccessControl::new_owner_only("alice".to_string());

        let metadata1 = FileMetadata::new(
            "test1.txt".to_string(),
            vec![2u8; 32],
            vec![0u8; 32],
            encryption_info.clone(),
            1024,
            vec![2u8; 32],
            vec![3u8; 32],
            access_control.clone(),
            vec![0u8; 64],
        )
        .unwrap();

        let metadata2 = FileMetadata::new(
            "test2.txt".to_string(),
            vec![2u8; 32],
            vec![0u8; 32],
            encryption_info,
            2048,
            vec![4u8; 32],
            vec![5u8; 32],
            access_control,
            vec![0u8; 64],
        )
        .unwrap();

        let update1 = CoverageUpdate::new(
            metadata1.file_id.clone(),
            vec![1u8; 32],
            vec![2u8; 32],
            metadata1,
            vec![],
            vec![0u8; 64],
        )
        .unwrap();

        let update2 = CoverageUpdate::new(
            metadata2.file_id.clone(),
            vec![1u8; 32],
            vec![2u8; 32],
            metadata2,
            vec![],
            vec![0u8; 64],
        )
        .unwrap();

        let batch = BatchCoverageUpdate::new(
            vec![1u8; 32], // from_epoch_id
            vec![2u8; 32], // to_epoch_id
            vec![update1, update2],
            vec![6u8; 32], // combined_root
            vec![0u8; 64], // admin_signature
        )
        .expect("BatchCoverageUpdate creation failed");

        assert_eq!(batch.total_files, 2);
        assert_eq!(batch.file_updates.len(), 2);
    }

    #[test]
    fn test_encryption_info_validation() {
        // Test invalid nonce size
        let result = FileEncryptionInfo::new(
            EncryptionAlgorithm::ChaCha20Poly1305,
            KeyDerivationParams::new_hkdf(vec![0u8; 32], "context".to_string()),
            vec![0u8; 11], // Wrong size
            vec![0u8; 16],
            vec![],
        );
        assert!(result.is_err());

        // Test invalid auth tag size
        let result = FileEncryptionInfo::new(
            EncryptionAlgorithm::ChaCha20Poly1305,
            KeyDerivationParams::new_hkdf(vec![0u8; 32], "context".to_string()),
            vec![0u8; 12],
            vec![0u8; 15], // Wrong size
            vec![],
        );
        assert!(result.is_err());
    }
}
