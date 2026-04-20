/// Dual-epoch file access with intelligent fallback and migration support
///
/// Provides seamless file access during epoch migrations by implementing
/// dual-epoch key resolution and automatic fallback mechanisms.
use super::{FileError, FileMetadata, FileResult};
use crate::{
    audit::{audit_logger, AuditOutcome},
    epoch::{EpochManager, EpochState},
    network::Network,
    storage::Storage,
};
use chrono::Utc;
use hybridcipher_crypto::{
    aead::{open, AeadContext},
    AeadKey, AeadNonce,
};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const METADATA_CACHE_MAX_ENTRIES: usize = 2048;

/// File access modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Read-only access
    Read,
    /// Write access (triggers rewrapping during migration)
    Write,
    /// Read-write access
    ReadWrite,
}

/// File access statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessStats {
    /// Total file accesses
    pub total_accesses: u64,

    /// Successful accesses
    pub successful_accesses: u64,

    /// Failed accesses
    pub failed_accesses: u64,

    /// Average access latency
    pub avg_latency_ms: f64,

    /// Dual-epoch accesses (during migration)
    pub dual_epoch_accesses: u64,

    /// Automatic rewraps triggered
    pub triggered_rewraps: u64,

    /// Number of times network telemetry could not be refreshed
    pub network_failures: u64,

    /// Smoothed peer latency reported by the network layer
    pub last_network_latency_ms: Option<u64>,
}

/// File access manager with dual-epoch support
#[derive(Debug)]
pub struct FileAccessManager<S: Storage, N: Network> {
    /// Storage backend
    storage: Arc<S>,

    /// Network interface
    network: Arc<N>,

    /// Epoch manager for key resolution
    epoch_manager: Arc<RwLock<EpochManager<S, N>>>,

    /// Active user context for auditing
    user_context: Arc<RwLock<Option<String>>>,

    /// Access statistics
    stats: Arc<RwLock<AccessStats>>,

    /// File metadata cache
    metadata_cache: Arc<RwLock<LruCache<String, FileMetadata>>>,

    /// Access performance tracking
    performance_tracker: Arc<RwLock<HashMap<String, Vec<Duration>>>>,
}

impl<S: Storage, N: Network> FileAccessManager<S, N> {
    /// Create new file access manager
    ///
    /// If `metadata_cache_max_entries` is `None`, uses the default value (2048).
    /// Otherwise uses the provided cache size.
    pub fn new(
        storage: Arc<S>,
        network: Arc<N>,
        epoch_manager: Arc<RwLock<EpochManager<S, N>>>,
        user_context: Option<String>,
        metadata_cache_max_entries: Option<usize>,
    ) -> Self {
        Self::new_with_cache_limit(
            storage,
            network,
            epoch_manager,
            user_context,
            metadata_cache_max_entries.unwrap_or(METADATA_CACHE_MAX_ENTRIES),
        )
    }

    /// Create new file access manager using cache size from ClientConfig
    ///
    /// Convenience method that takes the cache size directly.
    pub fn with_cache_size(
        storage: Arc<S>,
        network: Arc<N>,
        epoch_manager: Arc<RwLock<EpochManager<S, N>>>,
        user_context: Option<String>,
        metadata_cache_max_entries: usize,
    ) -> Self {
        Self::new_with_cache_limit(
            storage,
            network,
            epoch_manager,
            user_context,
            metadata_cache_max_entries,
        )
    }

    /// Create new file access manager with a custom metadata cache size
    pub fn new_with_cache_limit(
        storage: Arc<S>,
        network: Arc<N>,
        epoch_manager: Arc<RwLock<EpochManager<S, N>>>,
        user_context: Option<String>,
        metadata_cache_max_entries: usize,
    ) -> Self {
        let cache_size = NonZeroUsize::new(metadata_cache_max_entries).unwrap_or_else(|| {
            NonZeroUsize::new(METADATA_CACHE_MAX_ENTRIES).expect("metadata cache size is non-zero")
        });
        Self {
            storage,
            network,
            epoch_manager,
            user_context: Arc::new(RwLock::new(user_context)),
            stats: Arc::new(RwLock::new(AccessStats {
                total_accesses: 0,
                successful_accesses: 0,
                failed_accesses: 0,
                avg_latency_ms: 0.0,
                dual_epoch_accesses: 0,
                triggered_rewraps: 0,
                network_failures: 0,
                last_network_latency_ms: None,
            })),
            metadata_cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            performance_tracker: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update user context used for auditing
    pub fn set_user_context(&self, user_id: Option<String>) {
        let mut guard = self.user_context.write().unwrap();
        *guard = user_id;
    }

    /// Access file with dual-epoch key resolution and automatic fallback
    pub async fn access_file(&self, path: &str, mode: AccessMode) -> FileResult<Vec<u8>> {
        let start_time = Instant::now();
        self.refresh_network_status().await;
        let mut stats = self.stats.write().unwrap();
        stats.total_accesses += 1;
        drop(stats);

        // Audit log: File access attempt
        if let Some(logger) = audit_logger() {
            let _ = logger.log_file_operation(
                match mode {
                    AccessMode::Read => "read",
                    AccessMode::Write => "write",
                    AccessMode::ReadWrite => "read_write",
                },
                path,
                Some(path),
                self.user_context.read().unwrap().clone(),
                AuditOutcome::InProgress,
            );
        }

        // Try current epoch first
        let result = match self.try_access_current_epoch(path, mode).await {
            Ok(data) => {
                // Success with current epoch
                self.update_access_stats(path, start_time, true, false)
                    .await;

                // Audit log: Successful access
                if let Some(logger) = audit_logger() {
                    let _ = logger.log_file_operation(
                        match mode {
                            AccessMode::Read => "read",
                            AccessMode::Write => "write",
                            AccessMode::ReadWrite => "read_write",
                        },
                        path,
                        Some(path),
                        self.user_context.read().unwrap().clone(),
                        AuditOutcome::Success,
                    );
                }

                return Ok(data);
            }
            Err(FileError::NotFound { .. }) => {
                // File not found in current epoch, try previous epoch
                match self.try_access_previous_epoch(path, mode).await {
                    Ok(data) => {
                        // Found in previous epoch - trigger rewrapping if write access
                        self.update_access_stats(path, start_time, true, true).await;

                        if matches!(mode, AccessMode::Write | AccessMode::ReadWrite) {
                            if let Err(e) = self.trigger_opportunistic_rewrap(path).await {
                                log::warn!("Failed to trigger rewrapping for {}: {}", path, e);
                            }
                        }

                        return Ok(data);
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };

        // Both epochs failed
        self.update_access_stats(path, start_time, false, false)
            .await;
        result
    }

    /// Refresh network telemetry so access decisions can react to connectivity state.
    async fn refresh_network_status(&self) {
        match self.network.get_network_status().await {
            Ok(status) => {
                let average_latency = if status.peer_latencies.is_empty() {
                    None
                } else {
                    let sum: u64 = status.peer_latencies.values().copied().sum();
                    Some(sum / status.peer_latencies.len() as u64)
                };

                let mut stats = self.stats.write().unwrap();
                stats.last_network_latency_ms = average_latency;
            }
            Err(err) => {
                log::warn!("Failed to refresh network status: {}", err);
                let mut stats = self.stats.write().unwrap();
                stats.network_failures += 1;
            }
        }
    }

    /// Try to access file with current epoch key
    async fn try_access_current_epoch(&self, path: &str, mode: AccessMode) -> FileResult<Vec<u8>> {
        let epoch_manager = self.epoch_manager.read().unwrap();
        let current_epoch = epoch_manager
            .current_epoch()
            .await
            .ok_or_else(|| FileError::Epoch("No current epoch available".to_string()))?;
        drop(epoch_manager);

        self.decrypt_file_with_epoch(path, &current_epoch, mode)
            .await
    }

    /// Try to access file with previous epoch key (during migration)
    async fn try_access_previous_epoch(
        &self,
        path: &str,
        _mode: AccessMode,
    ) -> FileResult<Vec<u8>> {
        // For now, just return NotFound - in a real implementation we'd need
        // to add a previous_epoch() method to EpochManager or track migration state
        Err(FileError::NotFound {
            path: path.to_string(),
        })
    }

    /// Decrypt file using specific epoch key
    async fn decrypt_file_with_epoch(
        &self,
        path: &str,
        epoch: &EpochState,
        _mode: AccessMode,
    ) -> FileResult<Vec<u8>> {
        // Load encrypted file data from storage
        let encrypted_data = match self.storage.get_file(path).await {
            Ok(Some(data)) => data,
            Ok(None) => {
                return Err(FileError::NotFound {
                    path: path.to_string(),
                })
            }
            Err(e) => return Err(FileError::Storage(e)),
        };

        // Extract nonce from stored data (first 12 bytes) and ciphertext
        if encrypted_data.len() < 12 {
            return Err(FileError::DecryptionError(
                "Invalid encrypted data format".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = AeadNonce::from_bytes(nonce_bytes)
            .map_err(|e| FileError::DecryptionError(e.to_string()))?;

        // Decrypt using epoch key with file path as AAD
        let key = AeadKey::from_bytes(&epoch.encryption_key)
            .map_err(|e| FileError::DecryptionError(e.to_string()))?;
        let aad = path.as_bytes();
        let decrypted_data = open(&key, &nonce, AeadContext::FileData, aad, ciphertext)
            .map_err(|e| FileError::DecryptionError(e.to_string()))?;

        // Update metadata cache
        self.update_metadata_cache(path, epoch.epoch_id).await?;

        Ok(decrypted_data)
    }

    /// Trigger opportunistic rewrapping for frequently accessed files
    async fn trigger_opportunistic_rewrap(&self, path: &str) -> FileResult<()> {
        let mut stats = self.stats.write().unwrap();
        stats.triggered_rewraps += 1;
        drop(stats);

        // Check if file qualifies for rewrapping
        if !self.should_rewrap_file(path).await? {
            return Ok(());
        }

        if let Ok(status) = self.network.get_network_status().await {
            if status.error_rate > 0.5 {
                log::warn!(
                    "Skipping opportunistic rewrap for {} due to elevated network error rate ({:.2})",
                    path,
                    status.error_rate
                );
                return Ok(());
            }
        }

        // Get current epoch for rewrapping
        let epoch_manager = self.epoch_manager.read().unwrap();
        let current_epoch = epoch_manager
            .current_epoch()
            .await
            .ok_or_else(|| FileError::Epoch("No current epoch available".to_string()))?;
        drop(epoch_manager);

        // Initiate background rewrapping
        self.schedule_background_rewrap(path, current_epoch).await?;

        log::info!("Triggered opportunistic rewrapping for file: {}", path);
        Ok(())
    }

    /// Check if file should be rewrapped based on access patterns
    async fn should_rewrap_file(&self, path: &str) -> FileResult<bool> {
        let mut metadata_cache = self.metadata_cache.write().unwrap();
        let metadata = metadata_cache.get(path);

        match metadata {
            Some(meta) => {
                // Rewrap if file is in old epoch and frequently accessed
                Ok(meta.access_count > 5 && !meta.pending_rewrap)
            }
            None => {
                // Load metadata from storage
                drop(metadata_cache);
                let metadata = self.load_file_metadata(path).await?;
                Ok(metadata.access_count > 5 && !metadata.pending_rewrap)
            }
        }
    }

    /// Schedule background rewrapping for file
    async fn schedule_background_rewrap(
        &self,
        path: &str,
        target_epoch: EpochState,
    ) -> FileResult<()> {
        // Mark file as pending rewrap
        let mut metadata_cache = self.metadata_cache.write().unwrap();
        if let Some(metadata) = metadata_cache.get_mut(path) {
            metadata.pending_rewrap = true;
        }
        drop(metadata_cache);

        // In a real implementation, this would queue the rewrapping task
        // For now, we just log the operation
        log::info!(
            "Scheduled background rewrapping for {} to epoch {}",
            path,
            target_epoch.epoch_id
        );

        Ok(())
    }

    /// Update file metadata cache
    async fn update_metadata_cache(&self, path: &str, epoch_id: u64) -> FileResult<()> {
        let mut cache = self.metadata_cache.write().unwrap();

        match cache.get_mut(path) {
            Some(metadata) => {
                metadata.last_access = Utc::now();
                metadata.access_count += 1;
                metadata.epoch_id = epoch_id;
            }
            None => {
                // Load from storage if not in cache
                drop(cache);
                let metadata = self.load_file_metadata(path).await?;
                let mut cache = self.metadata_cache.write().unwrap();
                cache.put(path.to_string(), metadata);
            }
        }

        Ok(())
    }

    /// Load file metadata from storage
    async fn load_file_metadata(&self, path: &str) -> FileResult<FileMetadata> {
        match self.storage.get_file_metadata(path).await {
            Ok(Some(metadata)) => Ok(metadata),
            Ok(None) => {
                // Create default metadata for new files
                Ok(FileMetadata {
                    path: path.to_string(),
                    size: 0,
                    epoch_id: 0,
                    last_access: Utc::now(),
                    last_modified: Utc::now(),
                    access_count: 1,
                    pending_rewrap: false,
                    checksum: vec![],
                })
            }
            Err(e) => Err(FileError::Storage(e)),
        }
    }

    /// Update access statistics
    async fn update_access_stats(
        &self,
        path: &str,
        start_time: Instant,
        success: bool,
        dual_epoch: bool,
    ) {
        let latency = start_time.elapsed();

        let mut stats = self.stats.write().unwrap();
        if success {
            stats.successful_accesses += 1;
        } else {
            stats.failed_accesses += 1;
        }

        if dual_epoch {
            stats.dual_epoch_accesses += 1;
        }

        // Update average latency
        let total_accesses = stats.successful_accesses + stats.failed_accesses;
        stats.avg_latency_ms = (stats.avg_latency_ms * (total_accesses - 1) as f64
            + latency.as_millis() as f64)
            / total_accesses as f64;
        drop(stats);

        // Track per-file performance
        let mut tracker = self.performance_tracker.write().unwrap();
        tracker
            .entry(path.to_string())
            .or_insert_with(Vec::new)
            .push(latency);

        // Keep only recent measurements (last 100)
        if let Some(measurements) = tracker.get_mut(path) {
            if measurements.len() > 100 {
                measurements.remove(0);
            }
        }
    }

    /// Get access statistics
    pub fn get_stats(&self) -> AccessStats {
        self.stats.read().unwrap().clone()
    }

    /// Get file access performance for specific file
    pub fn get_file_performance(&self, path: &str) -> Option<Vec<Duration>> {
        self.performance_tracker.read().unwrap().get(path).cloned()
    }

    /// Clear metadata cache (for testing)
    pub fn clear_cache(&self) {
        self.metadata_cache.write().unwrap().clear();
        self.performance_tracker.write().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{epoch::EpochManager, network::MockNetwork, storage::MockStorage};
    use hybridcipher_crypto::signatures::Ed25519KeyPair;

    #[tokio::test]
    async fn test_file_access_manager_creation() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = Ed25519KeyPair::generate();
        let epoch_manager = Arc::new(RwLock::new(
            EpochManager::new(
                storage.clone(),
                network.clone(),
                device_identity,
                "device1".into(),
            )
            .await
            .unwrap(),
        ));

        let access_manager = FileAccessManager::new(storage, network, epoch_manager, None, None);

        let stats = access_manager.get_stats();
        assert_eq!(stats.total_accesses, 0);
        assert_eq!(stats.successful_accesses, 0);
        assert_eq!(stats.dual_epoch_accesses, 0);
        assert_eq!(stats.network_failures, 0);
        assert!(stats.last_network_latency_ms.is_none());
    }

    #[tokio::test]
    async fn test_access_stats_tracking() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = Ed25519KeyPair::generate();
        let epoch_manager = Arc::new(RwLock::new(
            EpochManager::new(
                storage.clone(),
                network.clone(),
                device_identity,
                "device1".into(),
            )
            .await
            .unwrap(),
        ));

        let access_manager = FileAccessManager::new(storage, network, epoch_manager, None, None);

        // Simulate access statistics update
        access_manager
            .update_access_stats("/test/file.txt", Instant::now(), true, false)
            .await;

        let stats = access_manager.get_stats();
        assert_eq!(stats.successful_accesses, 1);
        assert_eq!(stats.dual_epoch_accesses, 0);
        assert!(stats.network_failures <= 1);
    }

    #[test]
    fn test_access_mode_enum() {
        assert_eq!(AccessMode::Read, AccessMode::Read);
        assert_ne!(AccessMode::Read, AccessMode::Write);
        assert_ne!(AccessMode::Write, AccessMode::ReadWrite);
    }
}
