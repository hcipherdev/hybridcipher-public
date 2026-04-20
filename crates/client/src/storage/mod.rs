use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::coverage::FileIndexEntry;
use crate::epoch_key_source::EpochKeySource;

pub mod local_fs;
pub mod mock;

pub use local_fs::LocalFsStorage;
pub use mock::MockStorage;

/// Persistent storage abstraction with ACID guarantees and crash recovery
///
/// The Storage trait provides a secure, persistent layer for client state
/// with atomic operations, encryption at rest, and comprehensive recovery.
///
/// ## Security Properties
/// - All data is encrypted at rest using ChaCha20-Poly1305
/// - Keys are derived using HKDF with device-specific salt
/// - Access control prevents unauthorized data access
/// - Integrity verification detects corruption and tampering
///
/// ## Consistency Guarantees
/// - All operations are atomic within transactions
/// - Write-ahead logging ensures durability and crash recovery
/// - Concurrent operations are serialized to prevent races
/// - Storage versioning enables backward compatibility
#[async_trait]
pub trait Storage: Send + Sync + 'static {
    /// Store device identity key securely with device binding
    ///
    /// # Arguments
    /// * `device_id` - Unique device identifier
    /// * `identity_key` - Ed25519 private key bytes
    ///
    /// # Security
    /// The identity key is encrypted using a device-specific key derived
    /// from hardware identifiers and stored salt. This prevents key
    /// extraction even with physical device access.
    async fn store_identity_key(
        &self,
        device_id: &str,
        identity_key: &[u8],
    ) -> Result<(), StorageError>;

    /// Load device identity key with authentication
    ///
    /// # Arguments
    /// * `device_id` - Unique device identifier
    ///
    /// # Returns
    /// Decrypted identity key bytes or None if not found
    ///
    /// # Security
    /// Requires device authentication before key access.
    /// Returns None for invalid device_id or authentication failure.
    async fn load_identity_key(&self, device_id: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Store epoch state with atomic updates
    ///
    /// # Arguments
    /// * `epoch_id` - Epoch identifier
    /// * `state` - Serialized epoch state
    ///
    /// # Consistency
    /// Updates are atomic - either the entire epoch state is stored
    /// or the operation fails with no partial updates.
    async fn store_epoch_state_data(
        &self,
        epoch_id: u64,
        state: &EpochStateData,
    ) -> Result<(), StorageError>;

    /// Load epoch state with validation
    ///
    /// # Arguments
    /// * `epoch_id` - Epoch identifier
    ///
    /// # Returns
    /// Validated epoch state or None if not found
    ///
    /// # Validation
    /// Performs integrity checks and version compatibility validation
    /// before returning state data.
    async fn load_epoch_state_data(
        &self,
        epoch_id: u64,
    ) -> Result<Option<EpochStateData>, StorageError>;

    /// List all stored epoch IDs
    ///
    /// # Returns
    /// Sorted list of all epoch IDs in storage
    async fn list_epochs(&self) -> Result<Vec<u64>, StorageError>;

    /// Get current active epoch ID
    ///
    /// # Returns
    /// Current epoch ID or error if no active epoch found
    async fn get_current_epoch_id(&self) -> Result<u64, StorageError>;

    /// Store file metadata with efficient indexing
    ///
    /// # Arguments
    /// * `file_path` - Canonical file path
    /// * `metadata` - File encryption and access metadata
    ///
    /// # Indexing
    /// Metadata is indexed by file path for efficient lookup
    /// and supports batch operations for large directories.
    async fn store_file_metadata(
        &self,
        file_path: &str,
        metadata: &FileMetadataData,
    ) -> Result<(), StorageError>;

    /// Load file metadata by path
    ///
    /// # Arguments
    /// * `file_path` - Canonical file path
    ///
    /// # Returns
    /// File metadata or None if file not found
    async fn load_file_metadata(
        &self,
        file_path: &str,
    ) -> Result<Option<FileMetadataData>, StorageError>;

    /// Store multiple file metadata entries in batch
    ///
    /// # Arguments
    /// * `metadata_batch` - Map of file paths to metadata
    ///
    /// # Performance
    /// Batch operations are significantly more efficient than
    /// individual operations for large numbers of files.
    ///
    /// # Atomicity
    /// Either all metadata is stored or the entire batch fails.
    async fn store_file_metadata_batch(
        &self,
        metadata_batch: &HashMap<String, FileMetadataData>,
    ) -> Result<(), StorageError>;

    /// List files with optional prefix filter
    ///
    /// # Arguments
    /// * `prefix` - Optional path prefix filter
    ///
    /// # Returns
    /// List of file paths matching the prefix
    async fn list_files(&self, prefix: Option<&str>) -> Result<Vec<String>, StorageError>;

    /// Store a file index entry for coverage tracking
    async fn store_file_index_entry(&self, entry: &FileIndexEntry) -> Result<(), StorageError>;

    /// Store multiple file index entries in batch
    async fn store_file_index_entries(
        &self,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError>;

    /// Replace all file index entries for a root with the provided list
    async fn replace_file_index_entries_for_root(
        &self,
        root_id: Uuid,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError>;

    /// Load a file index entry by file UUID
    async fn load_file_index_entry(
        &self,
        file_uuid: Uuid,
    ) -> Result<Option<FileIndexEntry>, StorageError>;

    /// Load a file index entry by root and relative path
    async fn load_file_index_entry_by_root_path(
        &self,
        root_id: Uuid,
        relative_path: &str,
    ) -> Result<Option<FileIndexEntry>, StorageError>;

    /// List file index entries for a specific root
    async fn list_file_index_entries_by_root(
        &self,
        root_id: Uuid,
    ) -> Result<Vec<FileIndexEntry>, StorageError>;

    /// Remove a file index entry by file UUID
    async fn remove_file_index_entry(&self, file_uuid: Uuid) -> Result<(), StorageError>;

    /// Store coverage log with write-ahead logging (scoped per group)
    ///
    /// # Arguments
    /// * `group_id` - Group identifier
    /// * `coverage_log` - Serialized coverage log state
    ///
    /// # Durability
    /// Uses write-ahead logging to ensure coverage updates
    /// are durable even in case of system crash.
    async fn store_coverage_log(
        &self,
        group_id: Uuid,
        coverage_log: &CoverageLogData,
    ) -> Result<(), StorageError>;

    /// Load coverage log with consistency verification (scoped per group)
    ///
    /// # Arguments
    /// * `group_id` - Group identifier
    ///
    /// # Returns
    /// Validated coverage log or empty log if not found
    ///
    /// # Recovery
    /// Automatically recovers from write-ahead log if the
    /// main coverage log is corrupted or incomplete.
    async fn load_coverage_log(&self, group_id: Uuid) -> Result<CoverageLogData, StorageError>;

    /// Append a delta update to the coverage log journal without rewriting the full snapshot.
    async fn append_coverage_log_delta(
        &self,
        group_id: Uuid,
        delta: &CoverageLogDeltaData,
    ) -> Result<(), StorageError>;

    /// Load coverage log deltas greater than the provided sequence number.
    async fn load_coverage_log_deltas(
        &self,
        group_id: Uuid,
        since_sequence: u64,
    ) -> Result<Vec<CoverageLogDeltaData>, StorageError>;

    /// Permanently discard coverage log deltas at or below the provided sequence number.
    async fn compact_coverage_log_deltas(
        &self,
        group_id: Uuid,
        up_to_sequence: u64,
    ) -> Result<(), StorageError>;

    /// Return the on-disk coverage journal size in bytes when available.
    async fn coverage_log_journal_size(
        &self,
        _group_id: Uuid,
    ) -> Result<Option<u64>, StorageError> {
        Ok(None)
    }

    /// Store file content (encrypted)
    ///
    /// # Arguments
    /// * `file_path` - Full file path
    /// * `content` - Encrypted file content
    async fn store_file(&self, file_path: &str, content: &[u8]) -> Result<(), StorageError>;

    /// Load file content (encrypted)
    ///
    /// # Arguments
    /// * `file_path` - Full file path
    ///
    /// # Returns
    /// Encrypted file content or None if not found
    async fn get_file(&self, file_path: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Load file metadata
    ///
    /// # Arguments  
    /// * `file_path` - Full file path
    ///
    /// # Returns
    /// File metadata or None if not found
    async fn get_file_metadata(
        &self,
        file_path: &str,
    ) -> Result<Option<crate::file::FileMetadata>, StorageError>;

    /// Delete file and its metadata
    ///
    /// # Arguments
    /// * `file_path` - Full file path
    async fn delete_file(&self, file_path: &str) -> Result<(), StorageError>;

    /// Store client configuration and preferences
    ///
    /// # Arguments
    /// * `key` - Configuration key
    /// * `value` - Configuration value
    async fn store_config(&self, key: &str, value: &str) -> Result<(), StorageError>;

    /// Load client configuration
    ///
    /// # Arguments
    /// * `key` - Configuration key
    ///
    /// # Returns
    /// Configuration value or None if not set
    async fn load_config(&self, key: &str) -> Result<Option<String>, StorageError>;

    /// Delete a configuration key if present. Default implementation tombstones the key.
    async fn delete_config(&self, key: &str) -> Result<(), StorageError> {
        self.store_config(key, "").await
    }

    /// Load configuration bypassing in-memory caches so multiple processes can
    /// observe the latest persisted value.
    async fn load_config_fresh(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.load_config(key).await
    }

    /// Begin atomic transaction
    ///
    /// # Returns
    /// Transaction handle for batching operations
    ///
    /// # Usage
    /// ```ignore
    /// let tx = storage.begin_transaction().await?;
    /// tx.store_epoch_state(epoch_id, state).await?;
    /// tx.store_coverage_log(log).await?;
    /// tx.commit().await?;
    /// ```
    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, StorageError>;

    /// Get storage statistics and health information
    ///
    /// # Returns
    /// Storage usage, performance metrics, and health status
    async fn get_stats(&self) -> Result<StorageStats, StorageError>;

    /// Perform storage maintenance and optimization
    ///
    /// # Operations
    /// - Compacts storage to reclaim space
    /// - Rebuilds indexes for optimal performance
    /// - Validates data integrity
    /// - Purges old versions beyond retention policy
    async fn maintenance(&self) -> Result<(), StorageError>;

    /// Create encrypted backup of all storage data
    ///
    /// # Arguments
    /// * `backup_path` - Destination path for backup file
    /// * `encryption_key` - Key for backup encryption
    ///
    /// # Security
    /// Backup is encrypted using ChaCha20-Poly1305 with provided key.
    /// Backup includes all storage data and metadata for full recovery.
    async fn create_backup(
        &self,
        backup_path: &str,
        encryption_key: &[u8; 32],
    ) -> Result<(), StorageError>;

    /// Restore storage from encrypted backup
    ///
    /// # Arguments
    /// * `backup_path` - Path to backup file
    /// * `encryption_key` - Key for backup decryption
    ///
    /// # Recovery
    /// Completely replaces current storage with backup data.
    /// Validates backup integrity before restoration.
    async fn restore_backup(
        &self,
        backup_path: &str,
        encryption_key: &[u8; 32],
    ) -> Result<(), StorageError>;

    /// Store epoch state with direct EpochState type
    ///
    /// # Arguments
    /// * `epoch_state` - The epoch state to store
    async fn store_epoch_state(
        &self,
        epoch_state: &crate::epoch::state::EpochState,
    ) -> Result<(), StorageError>;

    /// Load epoch state with direct EpochState type
    ///
    /// # Arguments
    /// * `epoch_id` - Epoch identifier
    async fn load_epoch_state(
        &self,
        epoch_id: u64,
    ) -> Result<crate::epoch::state::EpochState, StorageError>;

    /// List active epochs (non-deprecated)
    ///
    /// # Returns
    /// List of active epoch states
    async fn list_active_epochs(
        &self,
    ) -> Result<Vec<crate::epoch::state::EpochState>, StorageError>;

    /// Store Welcome record for replay protection
    ///
    /// # Arguments
    /// * `record` - Welcome processing record
    async fn store_welcome_record(
        &self,
        record: &crate::epoch::welcome::WelcomeRecord,
    ) -> Result<(), StorageError>;

    /// Load Welcome record for replay protection
    ///
    /// # Arguments
    /// * `epoch_id` - Epoch identifier
    /// * `device_id` - Recipient device identifier
    async fn load_welcome_record(
        &self,
        epoch_id: u64,
        device_id: &str,
    ) -> Result<crate::epoch::welcome::WelcomeRecord, StorageError>;

    /// Store epoch keys for activation
    ///
    /// # Arguments
    /// * `epoch_id` - Epoch identifier
    /// * `secrets` - Epoch secrets to store
    async fn store_epoch_keys(
        &self,
        epoch_id: u64,
        secrets: &hybridcipher_messages::welcome::EpochSecrets,
    ) -> Result<(), StorageError>;
}

/// Transaction interface for atomic storage operations
#[async_trait]
pub trait StorageTransaction: Send + Sync {
    /// Store epoch state within transaction
    async fn store_epoch_state(
        &self,
        epoch_id: u64,
        state: &EpochStateData,
    ) -> Result<(), StorageError>;

    /// Store file metadata within transaction
    async fn store_file_metadata(
        &self,
        file_path: &str,
        metadata: &FileMetadataData,
    ) -> Result<(), StorageError>;

    /// Store coverage log within transaction
    async fn store_coverage_log(
        &self,
        group_id: Uuid,
        coverage_log: &CoverageLogData,
    ) -> Result<(), StorageError>;

    /// Append coverage log delta within transaction
    async fn append_coverage_log_delta(
        &self,
        group_id: Uuid,
        delta: &CoverageLogDeltaData,
    ) -> Result<(), StorageError>;

    /// Store file content within transaction
    async fn store_file(&self, file_path: &str, content: &[u8]) -> Result<(), StorageError>;

    /// Store file metadata within transaction (with FileMetadata type)
    async fn store_file_metadata_typed(
        &self,
        file_path: &str,
        metadata: &crate::file::FileMetadata,
    ) -> Result<(), StorageError>;

    /// Commit all transaction operations atomically
    async fn commit(self: Box<Self>) -> Result<(), StorageError>;

    /// Rollback transaction and discard all operations
    async fn rollback(self: Box<Self>) -> Result<(), StorageError>;
}

/// Serializable epoch state for storage persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochStateData {
    /// Epoch identifier
    pub epoch_id: u64,

    /// Encrypted epoch key (encrypted with storage key)
    pub encrypted_key: Vec<u8>,

    /// Provenance for the epoch key material.
    #[serde(default)]
    pub key_source: EpochKeySource,

    /// Group member public keys and capabilities
    pub members: Vec<MemberData>,

    /// Epoch creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Whether this epoch is currently active
    pub is_active: bool,

    /// Number of files encrypted under this epoch
    pub file_count: u64,

    /// Storage format version for compatibility
    pub version: u32,
}

/// Serializable member data for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberData {
    /// Member unique identifier
    pub member_id: [u8; 32],

    /// Member's Ed25519 public key
    pub public_key: [u8; 32],

    /// Member permissions and capabilities
    pub capabilities: CapabilityData,

    /// When this member joined the group
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

/// Serializable capability data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityData {
    pub can_read: bool,
    pub can_write: bool,
    pub can_invite: bool,
    pub can_rekey: bool,
    pub can_remove: bool,
}

/// Serializable file metadata for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadataData {
    /// Canonical file path
    pub file_path: String,

    /// File identifier (normalized path-derived)
    #[serde(default)]
    pub file_id: Option<String>,

    /// Group identifier that encrypted the file
    #[serde(default)]
    pub group_id: Option<Uuid>,

    /// Current epoch ID for this file
    pub epoch_id: u64,

    /// Header format/version
    #[serde(default)]
    pub header_version: Option<u32>,

    /// Wrapped DEK
    #[serde(default)]
    pub wrapped_file_key: Option<Vec<u8>>,

    /// Nonce used for key wrapping
    #[serde(default)]
    pub key_wrap_nonce: Option<Vec<u8>>,

    /// Hash of the wrap AAD
    #[serde(default)]
    pub key_wrap_aad_hash: Option<Vec<u8>>,

    /// Nonce used for content encryption (if stored)
    #[serde(default)]
    pub content_nonce: Option<Vec<u8>>,

    /// Chunk size for chunked content encryption (header_version >= 2)
    #[serde(default)]
    pub content_chunk_size: Option<u64>,

    /// File encryption algorithm identifier
    pub algorithm: String,

    /// File size in bytes
    pub file_size: u64,

    /// File modification timestamp
    pub modified_at: chrono::DateTime<chrono::Utc>,

    /// File integrity hash (SHA-256)
    pub integrity_hash: [u8; 32],

    /// Access control permissions
    pub permissions: AccessControlData,

    /// Storage format version
    pub version: u32,

    /// File chunk metadata for streaming operations (optional)
    #[serde(default)]
    pub chunks: Vec<u8>, // Serialized chunk metadata

    /// Encrypted size including authentication tags
    #[serde(default)]
    pub encrypted_size: u64,

    /// File encryption timestamp
    #[serde(default = "chrono::Utc::now")]
    pub encrypted_at: chrono::DateTime<chrono::Utc>,
}

/// Serializable access control data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlData {
    /// Members with read access
    pub readers: Vec<[u8; 32]>,

    /// Members with write access
    pub writers: Vec<[u8; 32]>,

    /// Whether file is public to all group members
    pub is_public: bool,
}

/// Serializable coverage log data for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageLogData {
    /// Root hash of the coverage Merkle tree
    pub root_hash: [u8; 32],

    /// Serialized coverage log payload (JSON blob)
    pub tree_nodes: Vec<u8>,

    /// File path to epoch ID mappings
    pub file_epochs: HashMap<String, u64>,

    /// Coverage log sequence number
    pub sequence: u64,

    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Storage format version
    pub version: u32,
}

/// Coverage delta action used for server replication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageDeltaAction {
    Upsert,
    Remove,
}

impl Default for CoverageDeltaAction {
    fn default() -> Self {
        Self::Upsert
    }
}

/// Append-only record describing a single coverage log mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageLogDeltaData {
    /// Monotonic sequence number assigned on the client.
    pub sequence: u64,
    /// File identifier associated with the update.
    pub file_id: String,
    /// Epoch identifier the file was rewrapped into.
    pub epoch_id: u64,
    /// Previous epoch identifier if this delta represents a rewrap.
    #[serde(default)]
    pub from_epoch: Option<u64>,
    /// Timestamp recorded when the delta was written.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// When present, marks the time the rewrap completed (header rewrite).
    #[serde(default)]
    pub rewrap_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Mutation type for the server-side coverage_current ledger.
    #[serde(default)]
    pub action: CoverageDeltaAction,
}

/// Storage performance and health statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total storage size in bytes
    pub total_size: u64,

    /// Used storage size in bytes
    pub used_size: u64,

    /// Number of stored epochs
    pub epoch_count: u64,

    /// Number of stored files
    pub file_count: u64,

    /// Average operation latency in milliseconds
    pub avg_latency_ms: f64,

    /// Storage health status
    pub health: StorageHealth,

    /// Last maintenance timestamp
    pub last_maintenance: chrono::DateTime<chrono::Utc>,
}

/// Storage health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageHealth {
    /// Storage is healthy and operating normally
    Healthy,

    /// Storage has minor issues but is functional
    Warning,

    /// Storage has serious issues affecting performance
    Degraded,

    /// Storage is corrupted or inaccessible
    Critical,
}

/// Storage operation errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Data corruption detected: {0}")]
    Corruption(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Storage full or quota exceeded")]
    StorageFull,

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Version incompatibility: {0}")]
    VersionMismatch(String),

    #[error("Backup/restore error: {0}")]
    Backup(String),

    #[error("Item not found: {0}")]
    NotFound(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Storage configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum storage size in bytes
    pub max_storage_size: u64,

    /// Enable storage compression
    pub enable_compression: bool,

    /// Encryption key derivation iterations
    pub key_derivation_iterations: u32,

    /// Storage maintenance interval in seconds
    pub maintenance_interval_seconds: u64,

    /// Enable write-ahead logging
    pub enable_wal: bool,

    /// Storage file path
    pub storage_path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_storage_size: 10 * 1024 * 1024 * 1024, // 10 GB
            enable_compression: true,
            key_derivation_iterations: 100_000,
            maintenance_interval_seconds: 86400, // 24 hours
            enable_wal: true,
            storage_path: "./hybridcipher_storage".to_string(),
        }
    }
}

// Implement Storage for Arc<S> where S: Storage
#[async_trait]
impl<S: Storage + Sync + Send> Storage for std::sync::Arc<S> {
    async fn store_identity_key(
        &self,
        device_id: &str,
        identity_key: &[u8],
    ) -> Result<(), StorageError> {
        self.as_ref()
            .store_identity_key(device_id, identity_key)
            .await
    }

    async fn load_identity_key(&self, device_id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.as_ref().load_identity_key(device_id).await
    }

    async fn store_epoch_state_data(
        &self,
        epoch_id: u64,
        state: &EpochStateData,
    ) -> Result<(), StorageError> {
        self.as_ref().store_epoch_state_data(epoch_id, state).await
    }

    async fn load_epoch_state_data(
        &self,
        epoch_id: u64,
    ) -> Result<Option<EpochStateData>, StorageError> {
        self.as_ref().load_epoch_state_data(epoch_id).await
    }

    async fn store_epoch_state(
        &self,
        epoch_state: &crate::epoch::state::EpochState,
    ) -> Result<(), StorageError> {
        self.as_ref().store_epoch_state(epoch_state).await
    }

    async fn load_epoch_state(
        &self,
        epoch_id: u64,
    ) -> Result<crate::epoch::state::EpochState, StorageError> {
        self.as_ref().load_epoch_state(epoch_id).await
    }

    async fn list_epochs(&self) -> Result<Vec<u64>, StorageError> {
        self.as_ref().list_epochs().await
    }

    async fn get_current_epoch_id(&self) -> Result<u64, StorageError> {
        self.as_ref().get_current_epoch_id().await
    }

    async fn store_file_metadata_batch(
        &self,
        metadata_batch: &HashMap<String, FileMetadataData>,
    ) -> Result<(), StorageError> {
        self.as_ref()
            .store_file_metadata_batch(metadata_batch)
            .await
    }

    async fn store_file(&self, file_path: &str, content: &[u8]) -> Result<(), StorageError> {
        self.as_ref().store_file(file_path, content).await
    }

    async fn get_file(&self, file_path: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.as_ref().get_file(file_path).await
    }

    async fn get_file_metadata(
        &self,
        file_path: &str,
    ) -> Result<Option<crate::file::FileMetadata>, StorageError> {
        self.as_ref().get_file_metadata(file_path).await
    }

    async fn delete_file(&self, file_path: &str) -> Result<(), StorageError> {
        self.as_ref().delete_file(file_path).await
    }

    async fn store_config(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.as_ref().store_config(key, value).await
    }

    async fn load_config(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.as_ref().load_config(key).await
    }

    async fn load_config_fresh(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.as_ref().load_config_fresh(key).await
    }

    async fn list_files(&self, prefix: Option<&str>) -> Result<Vec<String>, StorageError> {
        self.as_ref().list_files(prefix).await
    }

    async fn store_file_index_entry(&self, entry: &FileIndexEntry) -> Result<(), StorageError> {
        self.as_ref().store_file_index_entry(entry).await
    }

    async fn store_file_index_entries(
        &self,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError> {
        self.as_ref().store_file_index_entries(entries).await
    }

    async fn replace_file_index_entries_for_root(
        &self,
        root_id: Uuid,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError> {
        self.as_ref()
            .replace_file_index_entries_for_root(root_id, entries)
            .await
    }

    async fn load_file_index_entry(
        &self,
        file_uuid: Uuid,
    ) -> Result<Option<FileIndexEntry>, StorageError> {
        self.as_ref().load_file_index_entry(file_uuid).await
    }

    async fn load_file_index_entry_by_root_path(
        &self,
        root_id: Uuid,
        relative_path: &str,
    ) -> Result<Option<FileIndexEntry>, StorageError> {
        self.as_ref()
            .load_file_index_entry_by_root_path(root_id, relative_path)
            .await
    }

    async fn list_file_index_entries_by_root(
        &self,
        root_id: Uuid,
    ) -> Result<Vec<FileIndexEntry>, StorageError> {
        self.as_ref().list_file_index_entries_by_root(root_id).await
    }

    async fn remove_file_index_entry(&self, file_uuid: Uuid) -> Result<(), StorageError> {
        self.as_ref().remove_file_index_entry(file_uuid).await
    }

    async fn store_file_metadata(
        &self,
        file_path: &str,
        metadata: &FileMetadataData,
    ) -> Result<(), StorageError> {
        self.as_ref().store_file_metadata(file_path, metadata).await
    }

    async fn load_file_metadata(
        &self,
        file_path: &str,
    ) -> Result<Option<FileMetadataData>, StorageError> {
        self.as_ref().load_file_metadata(file_path).await
    }

    async fn get_stats(&self) -> Result<StorageStats, StorageError> {
        self.as_ref().get_stats().await
    }

    async fn maintenance(&self) -> Result<(), StorageError> {
        self.as_ref().maintenance().await
    }

    async fn create_backup(
        &self,
        backup_path: &str,
        encryption_key: &[u8; 32],
    ) -> Result<(), StorageError> {
        self.as_ref()
            .create_backup(backup_path, encryption_key)
            .await
    }

    async fn restore_backup(
        &self,
        backup_path: &str,
        encryption_key: &[u8; 32],
    ) -> Result<(), StorageError> {
        self.as_ref()
            .restore_backup(backup_path, encryption_key)
            .await
    }

    async fn list_active_epochs(
        &self,
    ) -> Result<Vec<crate::epoch::state::EpochState>, StorageError> {
        self.as_ref().list_active_epochs().await
    }

    async fn store_welcome_record(
        &self,
        record: &crate::epoch::welcome::WelcomeRecord,
    ) -> Result<(), StorageError> {
        self.as_ref().store_welcome_record(record).await
    }

    async fn load_welcome_record(
        &self,
        epoch_id: u64,
        device_id: &str,
    ) -> Result<crate::epoch::welcome::WelcomeRecord, StorageError> {
        self.as_ref().load_welcome_record(epoch_id, device_id).await
    }

    async fn store_epoch_keys(
        &self,
        epoch_id: u64,
        secrets: &hybridcipher_messages::welcome::EpochSecrets,
    ) -> Result<(), StorageError> {
        self.as_ref().store_epoch_keys(epoch_id, secrets).await
    }

    async fn store_coverage_log(
        &self,
        group_id: Uuid,
        log: &CoverageLogData,
    ) -> Result<(), StorageError> {
        self.as_ref().store_coverage_log(group_id, log).await
    }

    async fn load_coverage_log(&self, group_id: Uuid) -> Result<CoverageLogData, StorageError> {
        self.as_ref().load_coverage_log(group_id).await
    }

    async fn append_coverage_log_delta(
        &self,
        group_id: Uuid,
        delta: &CoverageLogDeltaData,
    ) -> Result<(), StorageError> {
        self.as_ref()
            .append_coverage_log_delta(group_id, delta)
            .await
    }

    async fn load_coverage_log_deltas(
        &self,
        group_id: Uuid,
        since_sequence: u64,
    ) -> Result<Vec<CoverageLogDeltaData>, StorageError> {
        self.as_ref()
            .load_coverage_log_deltas(group_id, since_sequence)
            .await
    }

    async fn compact_coverage_log_deltas(
        &self,
        group_id: Uuid,
        up_to_sequence: u64,
    ) -> Result<(), StorageError> {
        self.as_ref()
            .compact_coverage_log_deltas(group_id, up_to_sequence)
            .await
    }

    async fn coverage_log_journal_size(&self, group_id: Uuid) -> Result<Option<u64>, StorageError> {
        self.as_ref().coverage_log_journal_size(group_id).await
    }

    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, StorageError> {
        self.as_ref().begin_transaction().await
    }
}
