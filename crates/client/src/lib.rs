pub mod audit;
/// HybridCipher Client Library
///
/// Provides comprehensive client-side functionality for the HybridCipher secure file sharing system,
/// including authentication, storage, networking, state management, and epoch operations.
///
/// # Architecture Overview
///
/// The client library is organized into several key modules:
///
/// - **Authentication**: OPAQUE-PAKE based user authentication with device identity
/// - **Storage**: Persistent storage abstraction with ACID transaction support  
/// - **Network**: Secure communication layer with Byzantine fault tolerance
/// - **State Management**: Thread-safe client state with epoch and migration tracking
/// - **Epoch Management**: Two-phase rekey operations and migration coordination
///
/// # Example Usage
///
/// ```
/// use hybridcipher_client::{Client, storage::MockStorage, network::MockNetwork};
/// use hybridcipher_crypto::signatures::Ed25519KeyPair;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let device_identity = Ed25519KeyPair::generate();
/// let storage = Arc::new(MockStorage::new());
/// let network = Arc::new(MockNetwork::new());
///
/// let client = Client::new(device_identity, storage, network);
/// let current_epoch = client.current_epoch().await;
/// # Ok(())
/// # }
/// ```
pub mod auth;
pub mod compression;
pub mod config;
pub mod config_loader;
pub mod coverage;
pub mod epoch;
pub mod epoch_key_source;
pub mod errors;
pub mod file;
pub mod group;
pub mod invitation;
pub mod ipc;
pub mod logging;
pub mod metrics;
pub mod network;
pub mod performance_simple;
pub mod pinning;
pub mod recovery;
pub mod rekey;
pub mod resource_management;
pub mod scalable_groups;
pub mod security;
pub mod state;
pub mod storage;
pub mod transparency;
pub mod welcome_manager;

// Public re-exports for external use
pub use audit::{
    audit_logger, init_audit_logger, AuditConfig, AuditEvent, AuditEventType, AuditLogger,
    AuditOutcome, SecuritySeverity,
};
pub use compression::{CompressedData, CompressionConfig, CompressionManager, CompressionStats};
pub use config::{
    ConfigManager, DeploymentConfig, ErrorHandlingConfig, LoggingConfig,
    PerformanceConfig as ConfigPerformanceConfig, ProductionConfig, SecurityConfig,
};
pub use performance_simple::{HighPerformanceClient, PerformanceConfig, PerformanceMetrics};
pub use resource_management::{
    IoOperation, ResourceConfig, ResourceManager, ResourceStats, SecureBuffer,
};
pub use scalable_groups::{
    GroupManagerMetrics, MemberInfo, MemberStatus, ScalableGroupConfig, ScalableGroupManager,
};

pub use group::{GroupContext, GroupId, GroupPolicies, MemberId};
pub use welcome_manager::{
    EpochSecrets as WelcomeEpochSecrets, GroupMember as WelcomeGroupMember, ServerWelcomeMessage,
    WelcomeManager, WelcomeMessage,
};

#[cfg(test)]
mod errors_test;

#[cfg(test)]
mod logging_test;

// Re-export core types for convenience
pub use epoch::{EpochManager, EpochState, Member};
pub use errors::{ClientError, ErrorCode, ErrorContext, ErrorSeverity, RecoveryAction};
pub use file::{AccessMode, FileAccessManager, RewrapManager};
pub use file::{MacOsFileMetadata, PlatformFileMetadata, PlatformXattr};
pub use hybridcipher_coverage::{CoverageManager, CoverageManagerError, CoverageResult};
pub use recovery::{get_recovery_manager, CircuitBreaker, ErrorRecoveryManager, RetryPolicy};
pub use state::client::{
    ActiveRekeyOperation, Client, CoveragePendingFile, CutoverSummary, DeviceRemovalSummary,
    EncryptedFileMetadata, LocalRewrapSnapshot, RecoveryCapsulePlain, RecoveryEpochSecret,
    RekeyErrorEntry, RekeyInitiationOptions, RekeyProgress,
};
#[cfg(feature = "mount-fs")]
pub use state::client::{
    CoverageEpochSummary, CoverageOverview, CoverageSnapshotInfo, PendingRewrapSummary,
    RekeyHeartbeatSummary, RekeyOverlayState,
};
// Re-export key types
pub use rekey::{
    EpochId, EpochSecret, MigrationProgress, MigrationState, RekeyError, RekeyManager,
};

// Re-export welcome types
pub use storage::{
    CoverageLogData, EpochStateData, FileMetadataData, Storage, StorageConfig, StorageError,
    StorageHealth, StorageStats, StorageTransaction,
};

pub use network::{
    BroadcastResult, CutoverResult, MessagePriority, MessageType, Network, NetworkConfig,
    NetworkError, NetworkMessage, NetworkStatus, PeerInfo,
};

pub use transparency::{TransparencyClient, TransparencyVerifier};

pub use pinning::{
    display_pinning_qr_code, generate_fingerprint, generate_pinning_qr_code, generate_pinning_url,
    generate_safety_number, parse_pinning_url, verify_fingerprint_format, KeyPinningManager,
    PinnedKey, PinningConfig, PinningError, PinningMethod, PinningPolicy, PinningPrompt,
    PinningStore, PinningVerificationResult,
};

// Re-export from messages crate for transparency log structures
pub use hybridcipher_messages::transparency::{
    ConsistencyProof, InclusionProof, TransparencyCheckpoint, TransparencyConfig,
};

/// Client library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Supported protocol version
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Maximum supported group size
pub const MAX_GROUP_SIZE: usize = 1000;

/// Maximum file size for single operations (1 GB)
pub const MAX_FILE_SIZE: u64 = 1_073_741_824;

/// Default client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Maximum number of concurrent epoch states
    pub max_epochs: usize,

    /// Migration timeout in seconds
    pub migration_timeout_seconds: u64,

    /// State synchronization interval in seconds
    pub sync_interval_seconds: u64,

    /// Debounce interval (ms) for bulk state saves
    pub state_save_debounce_ms: u64,

    /// Max files to process before persisting rekey migration state
    pub migration_state_save_batch_size: u64,

    /// Max seconds between persisted rekey migration state saves
    pub migration_state_save_max_interval_secs: u64,

    /// Maximum roots cached for file index entries
    pub file_index_cache_max_roots: usize,

    /// Maximum entries for the file access metadata cache
    pub metadata_cache_max_entries: usize,

    /// Maximum retry attempts for operations
    pub max_retries: u32,

    /// Enable debug logging
    pub debug_logging: bool,

    /// Storage configuration
    pub storage_config: StorageConfig,

    /// Network configuration
    pub network_config: NetworkConfig,

    /// Transparency log configuration
    pub transparency_config: TransparencyConfig,

    /// Key pinning configuration
    pub pinning_config: pinning::PinningConfig,

    /// Maximum age (hours) for membership proofs before the client rejects them (0 disables).
    pub membership_proof_max_age_hours: u64,

    /// File patterns to exclude from encryption and coverage processing.
    pub excluded_file_patterns: Vec<String>,

    /// Coverage replication batch size (files per request)
    pub coverage_batch_size: usize,

    /// Number of parallel coverage upload workers (1 = sequential)
    pub coverage_parallel_uploads: usize,

    /// Minimum interval (milliseconds) between coverage replication requests
    pub coverage_upload_min_interval_ms: u64,

    /// Base backoff delay (milliseconds) for retryable coverage replication failures
    pub coverage_upload_backoff_base_ms: u64,

    /// Maximum backoff delay (milliseconds) for retryable coverage replication failures
    pub coverage_upload_backoff_max_ms: u64,

    /// Pending delta threshold that triggers baseline coverage sync (0 disables baseline sync)
    pub coverage_baseline_threshold: usize,

    /// Coverage journal compaction configuration
    pub coverage_compaction: CoverageCompactionConfig,

    /// Minimum interval (seconds) between rekey heartbeat emissions
    pub migration_heartbeat_min_interval_secs: u64,

    /// Enable background migration automation (heartbeat, queue, idle crawler)
    pub migration_automation_enabled: bool,

    /// Enable coverage filesystem watchers for enrolled roots
    pub coverage_watchers_enabled: bool,

    /// Name of the env var that disables coverage IPC auto-detect for the CLI.
    /// Set to empty to disable opt-out behavior entirely.
    pub coverage_ipc_opt_out_env: String,

    /// Admin Operations panel auto-refresh interval (seconds) for the desktop app (0 disables)
    pub admin_operations_refresh_interval_secs: u64,

    /// Desktop session health poll interval (seconds). 0 disables background checks.
    pub session_health_check_interval_secs: u64,

    /// Grace window (seconds) used when deciding an expiring session is already stale.
    pub session_health_expiry_grace_secs: u64,

    /// Desktop mount modal: seconds before "Continue in background" is enabled.
    pub mount_continue_enable_secs: u64,

    /// Desktop mount modal: seconds before "Cancel mount" is enabled in foreground mode.
    pub mount_cancel_enable_secs: u64,

    /// Desktop mount workflow: max seconds to wait after continuing in background.
    pub mount_background_timeout_secs: u64,
}

/// Coverage journal compaction thresholds and scheduling behavior
#[derive(Debug, Clone)]
pub struct CoverageCompactionConfig {
    /// Minimum pending delta entries before compaction is triggered
    pub min_entries: u64,
    /// Idle time since last coverage update before compaction is allowed
    pub idle_quiet_secs: u64,
    /// Minimum time between compactions
    pub min_interval_secs: u64,
    /// Maximum time between compactions while pending updates exist
    pub max_interval_secs: u64,
    /// Journal size threshold (bytes) that forces compaction
    pub max_journal_bytes: u64,
    /// When bulk mode is active, allow compaction if journal exceeds this size
    pub bulk_force_journal_bytes: u64,
    /// Backoff applied after compaction failure
    pub error_backoff_secs: u64,
    /// Whether bulk operations should skip compaction until completion
    pub bulk_mode_enabled: bool,
}

impl Default for CoverageCompactionConfig {
    fn default() -> Self {
        Self {
            min_entries: 1000,
            idle_quiet_secs: 10,
            min_interval_secs: 30,
            max_interval_secs: 300,
            max_journal_bytes: 8_000_000,
            bulk_force_journal_bytes: 64_000_000,
            error_backoff_secs: 60,
            bulk_mode_enabled: true,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_epochs: 10,
            migration_timeout_seconds: 3600, // 1 hour
            sync_interval_seconds: 300,      // 5 minutes
            state_save_debounce_ms: 500,
            migration_state_save_batch_size: 250,
            migration_state_save_max_interval_secs: 2,
            file_index_cache_max_roots: 2,
            metadata_cache_max_entries: 2048,
            max_retries: 3,
            debug_logging: false,
            storage_config: StorageConfig::default(),
            network_config: NetworkConfig::default(),
            transparency_config: TransparencyConfig::default(),
            pinning_config: pinning::PinningConfig::default(),
            membership_proof_max_age_hours: 24,
            excluded_file_patterns: vec![
                ".hybridcipher-root-*.json".to_string(),
                ".DS_Store".to_string(),
            ],
            coverage_batch_size: 128,
            coverage_parallel_uploads: 1,
            coverage_upload_min_interval_ms: 200,
            coverage_upload_backoff_base_ms: 1_000,
            coverage_upload_backoff_max_ms: 30_000,
            coverage_baseline_threshold: 50_000,
            coverage_compaction: CoverageCompactionConfig::default(),
            migration_heartbeat_min_interval_secs: 1,
            migration_automation_enabled: true,
            coverage_watchers_enabled: true,
            coverage_ipc_opt_out_env: "HYBRIDCIPHER_COVERAGE_IPC_DISABLE".to_string(),
            admin_operations_refresh_interval_secs: 300,
            session_health_check_interval_secs: 60,
            session_health_expiry_grace_secs: 5,
            mount_continue_enable_secs: 10,
            mount_cancel_enable_secs: 120,
            mount_background_timeout_secs: 120,
        }
    }
}

/// Client builder for convenient initialization
pub struct ClientBuilder<S, N> {
    device_identity: Option<hybridcipher_crypto::signatures::Ed25519KeyPair>,
    storage: Option<std::sync::Arc<S>>,
    network: Option<std::sync::Arc<N>>,
    config: ClientConfig,
}

impl<S: Storage, N: Network> ClientBuilder<S, N> {
    /// Create new client builder
    pub fn new() -> Self {
        Self {
            device_identity: None,
            storage: None,
            network: None,
            config: ClientConfig::default(),
        }
    }

    /// Set device identity key pair
    pub fn with_identity(
        mut self,
        identity: hybridcipher_crypto::signatures::Ed25519KeyPair,
    ) -> Self {
        self.device_identity = Some(identity);
        self
    }

    /// Set storage backend
    pub fn with_storage(mut self, storage: std::sync::Arc<S>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set network layer
    pub fn with_network(mut self, network: std::sync::Arc<N>) -> Self {
        self.network = Some(network);
        self
    }

    /// Set client configuration
    pub fn with_config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }

    /// Build the client instance
    pub fn build(self) -> Result<Client<S, N>, ClientError> {
        let device_identity = self
            .device_identity
            .ok_or_else(|| ClientError::InvalidState("Device identity not set".to_string()))?;

        let storage = self
            .storage
            .ok_or_else(|| ClientError::InvalidState("Storage not set".to_string()))?;

        let network = self
            .network
            .ok_or_else(|| ClientError::InvalidState("Network not set".to_string()))?;

        Ok(Client::with_client_config(
            device_identity,
            storage,
            network,
            self.config,
        ))
    }
}

impl<S: Storage, N: Network> Default for ClientBuilder<S, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for client operations
pub mod utils {
    use super::*;

    /// Generate a new device identity key pair
    pub fn generate_device_identity() -> hybridcipher_crypto::signatures::Ed25519KeyPair {
        let keypair = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();

        // Log key generation event asynchronously
        tokio::spawn(async move {
            if let Some(logger) = crate::audit::audit_logger() {
                let _ = logger.log_key_management(
                    "device_identity_generation",
                    "new_device",
                    "Ed25519",
                    None,
                    crate::audit::AuditOutcome::Success,
                );
            }
        });

        keypair
    }

    /// Validate client configuration
    pub fn validate_config(config: &ClientConfig) -> Result<(), ClientError> {
        if config.max_epochs == 0 {
            return Err(ClientError::InvalidState(
                "max_epochs must be greater than 0".to_string(),
            ));
        }

        if config.migration_timeout_seconds == 0 {
            return Err(ClientError::InvalidState(
                "migration_timeout_seconds must be greater than 0".to_string(),
            ));
        }

        if config.sync_interval_seconds == 0 {
            return Err(ClientError::InvalidState(
                "sync_interval_seconds must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Create a mock client for testing
    #[cfg(test)]
    pub fn create_mock_client() -> Client<storage::MockStorage, network::MockNetwork> {
        use std::sync::Arc;

        let device_identity = generate_device_identity();
        let storage = Arc::new(storage::MockStorage::new());
        let network = Arc::new(network::MockNetwork::new());

        Client::with_client_config(device_identity, storage, network, ClientConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = create_mock_client();

        assert_eq!(client.current_epoch().await, 0);
        assert!(!client.is_migrating().await);
    }

    #[tokio::test]
    async fn test_client_builder() {
        use std::sync::Arc;

        let identity = generate_device_identity();
        let storage = Arc::new(storage::MockStorage::new());
        let network = Arc::new(network::MockNetwork::new());

        let client = ClientBuilder::new()
            .with_identity(identity)
            .with_storage(storage)
            .with_network(network)
            .build()
            .unwrap();

        assert_eq!(client.current_epoch().await, 0);
    }

    #[test]
    fn test_config_validation() {
        let valid_config = ClientConfig::default();
        assert!(validate_config(&valid_config).is_ok());

        let invalid_config = ClientConfig {
            max_epochs: 0,
            ..Default::default()
        };
        assert!(validate_config(&invalid_config).is_err());
    }

    #[test]
    fn test_constants() {
        assert!(!VERSION.is_empty());
        assert_eq!(PROTOCOL_VERSION, "1.0.0");
        assert_eq!(MAX_GROUP_SIZE, 1000);
        assert_eq!(MAX_FILE_SIZE, 1_073_741_824);
    }
}
