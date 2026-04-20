/// File operations with dual-epoch support and opportunistic rewrapping
///
/// This module provides file access operations that work seamlessly during
/// epoch migrations. It implements opportunistic rewrapping triggered by
/// file access patterns and intelligent scheduling for optimal performance.
pub mod access;
pub mod cache;
pub mod decrypt;
pub mod encrypt;
pub mod rewrap;
pub mod streaming;

// Re-export core types
// Re-export public types from submodules
pub use access::{AccessMode, FileAccessManager};
pub use cache::{CacheConfig, CacheError, CacheManager};
pub use decrypt::{
    DecryptionError, DecryptionMetrics, DecryptionResult, FileDecryption, FileDecryptionMetadata,
};
pub use encrypt::{
    write_encrypted_file, write_encrypted_file_atomic_for_coverage,
    write_encrypted_file_atomic_for_coverage_with_sync, EncryptionError, EncryptionResult,
    FileEncryption, FileEncryptionMetadata, MacOsFileMetadata, PlatformFileMetadata, PlatformXattr,
    SerializedEncryptedHeader,
};
pub use rewrap::{RewrapError, RewrapManager};
pub use streaming::{
    ChunkConfig, ChunkMetadata, ChunkMigrationStatus, FileStream, FileStreaming, FileWriteStream,
    StreamConfig, StreamProgress, StreamingContext, StreamingError, StreamingResult,
};

use crate::{network::NetworkError, storage::StorageError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// File operation errors
#[derive(Debug, Error)]
pub enum FileError {
    #[error("File not found: {path}")]
    NotFound { path: String },

    #[error("Access denied for file: {path}")]
    AccessDenied { path: String },

    #[error("File corrupted or invalid: {path}")]
    Corrupted { path: String },

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    #[error("Epoch error: {0}")]
    Epoch(String),
}

/// File metadata with epoch tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// File path
    pub path: String,

    /// File size in bytes
    pub size: u64,

    /// Current epoch ID
    pub epoch_id: u64,

    /// Last access timestamp
    pub last_access: chrono::DateTime<chrono::Utc>,

    /// Last modification timestamp
    pub last_modified: chrono::DateTime<chrono::Utc>,

    /// Access frequency for rewrapping prioritization
    pub access_count: u64,

    /// Indicates if file is pending rewrapping
    pub pending_rewrap: bool,

    /// File checksum for integrity verification
    pub checksum: Vec<u8>,
}

/// File operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStats {
    /// Total files managed
    pub total_files: u64,

    /// Files in current epoch
    pub current_epoch_files: u64,

    /// Files pending rewrapping
    pub pending_rewrap_files: u64,

    /// Total bytes managed
    pub total_bytes: u64,

    /// Bytes rewrapped
    pub rewrapped_bytes: u64,

    /// Average access latency
    pub avg_access_latency_ms: f64,

    /// Rewrapping throughput (bytes/sec)
    pub rewrap_throughput: f64,
}

/// Result type for file operations
pub type FileResult<T> = Result<T, FileError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_metadata_creation() {
        let metadata = FileMetadata {
            path: "/test/file.txt".to_string(),
            size: 1024,
            epoch_id: 1,
            last_access: chrono::Utc::now(),
            last_modified: chrono::Utc::now(),
            access_count: 0,
            pending_rewrap: false,
            checksum: vec![0; 32],
        };

        assert_eq!(metadata.path, "/test/file.txt");
        assert_eq!(metadata.size, 1024);
        assert_eq!(metadata.epoch_id, 1);
        assert!(!metadata.pending_rewrap);
    }

    #[test]
    fn test_file_stats_tracking() {
        let stats = FileStats {
            total_files: 100,
            current_epoch_files: 80,
            pending_rewrap_files: 20,
            total_bytes: 1_000_000,
            rewrapped_bytes: 200_000,
            avg_access_latency_ms: 5.2,
            rewrap_throughput: 1_000_000.0,
        };

        assert_eq!(stats.total_files, 100);
        assert_eq!(stats.current_epoch_files, 80);
        assert_eq!(stats.pending_rewrap_files, 20);
    }
}
