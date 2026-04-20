//! On-demand decryption with migration fallback and performance optimization
//!
//! This module implements high-performance file decryption with intelligent
//! migration coordination, multi-epoch fallback, and adaptive caching.

use crate::{
    cache::{CacheKey, CacheManager},
    error::{MountError, Result},
    filesystem::lookup::MigrationStatus,
};
#[cfg(test)]
use hybridcipher_client::errors::ClientError;
use hybridcipher_client::{network::Network, storage::Storage, Client};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
#[cfg(test)]
use std::{future::Future, pin::Pin};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Default chunk size for decryption operations (64KB)
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size for adaptive sizing (1MB)
const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Minimum chunk size for adaptive sizing (4KB)
const MIN_CHUNK_SIZE: usize = 4 * 1024;

/// Performance metrics for decryption operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionMetrics {
    /// Total operations performed
    pub total_operations: u64,
    /// Cache hit count
    pub cache_hits: u64,
    /// Cache miss count
    pub cache_misses: u64,
    /// Average decryption time in microseconds
    pub avg_decrypt_time_us: u64,
    /// Total bytes decrypted
    pub total_bytes_decrypted: u64,
    /// Epoch fallback count
    pub epoch_fallbacks: u64,
    /// Background prefetch hits
    pub prefetch_hits: u64,
}

impl Default for DecryptionMetrics {
    fn default() -> Self {
        Self {
            total_operations: 0,
            cache_hits: 0,
            cache_misses: 0,
            avg_decrypt_time_us: 0,
            total_bytes_decrypted: 0,
            epoch_fallbacks: 0,
            prefetch_hits: 0,
        }
    }
}

/// Decryption context for tracking operation state
#[derive(Debug, Clone)]
pub struct DecryptionContext {
    /// File identifier
    pub file_id: String,
    /// Current epoch ID
    pub current_epoch: u64,
    /// Migration status
    pub migration_status: MigrationStatus,
    /// Preferred chunk size for this file
    pub preferred_chunk_size: usize,
    /// Access pattern hint
    pub access_pattern: AccessPattern,
}

/// Access pattern detection for intelligent prefetching
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub enum AccessPattern {
    /// Unknown access pattern (default)
    #[default]
    Unknown,
    /// Sequential access pattern
    Sequential,
    /// Random access pattern
    Random,
    /// Mixed access pattern
    Mixed,
}

#[cfg(test)]
type ChunkReaderOverrideFuture =
    Pin<Box<dyn Future<Output = std::result::Result<Vec<u8>, ClientError>> + Send>>;
#[cfg(test)]
type ChunkReaderOverride =
    Arc<dyn Fn(String, u64, usize) -> ChunkReaderOverrideFuture + Send + Sync>;

/// Chunked decryption result
#[derive(Debug, Clone)]
pub struct DecryptedChunk {
    /// Decrypted data
    pub data: Vec<u8>,
    /// Epoch used for decryption
    pub epoch_id: u64,
    /// Timestamp when decrypted
    pub decrypted_at: SystemTime,
    /// Size of the chunk
    pub size: usize,
    /// Whether this was a cache hit
    pub from_cache: bool,
}

/// High-performance decryption manager with migration awareness
pub struct DecryptionManager<S: Storage, N: Network> {
    /// HybridCipher client
    client: Arc<Client<S, N>>,

    /// Cache manager for decrypted chunks
    cache_manager: Arc<CacheManager<S, N>>,

    /// Performance metrics
    metrics: Arc<RwLock<DecryptionMetrics>>,

    /// Adaptive chunk sizing configuration
    chunk_config: Arc<RwLock<ChunkConfig>>,

    /// Background prefetch manager
    prefetch_manager: Arc<PrefetchManager>,

    /// Memory pressure monitor
    memory_monitor: Arc<MemoryMonitor>,

    /// Optional test hook for overriding chunk reads
    #[cfg(test)]
    chunk_reader_override: Arc<RwLock<Option<ChunkReaderOverride>>>,
}

/// Configuration for adaptive chunk sizing
#[derive(Debug, Clone)]
pub struct ChunkConfig {
    /// Base chunk size
    pub base_size: usize,
    /// Size multiplier for sequential access
    pub sequential_multiplier: f32,
    /// Size divisor for random access
    pub random_divisor: f32,
    /// Maximum allowed chunk size
    pub max_size: usize,
    /// Minimum allowed chunk size
    pub min_size: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            base_size: DEFAULT_CHUNK_SIZE,
            sequential_multiplier: 2.0,
            random_divisor: 2.0,
            max_size: MAX_CHUNK_SIZE,
            min_size: MIN_CHUNK_SIZE,
        }
    }
}

/// Background prefetch manager
pub struct PrefetchManager {
    /// Active prefetch tasks
    active_tasks: Arc<RwLock<HashMap<String, PrefetchTask>>>,
}

/// Individual prefetch task
#[derive(Debug, Clone)]
pub struct PrefetchTask {
    /// File being prefetched
    pub file_id: String,
    /// Next offset to prefetch
    pub next_offset: u64,
    /// Chunk size for prefetching
    pub chunk_size: usize,
    /// Task creation time
    pub created_at: SystemTime,
}

/// Memory pressure monitor
pub struct MemoryMonitor {
    /// Current memory usage estimate
    current_usage: Arc<RwLock<usize>>,
    /// Memory pressure threshold (bytes)
    pressure_threshold: usize,
    /// Critical memory threshold (bytes)
    critical_threshold: usize,
}

impl<S: Storage, N: Network> DecryptionManager<S, N> {
    /// Create a new decryption manager
    pub fn new(client: Arc<Client<S, N>>, cache_manager: Arc<CacheManager<S, N>>) -> Self {
        let prefetch_manager = Arc::new(PrefetchManager {
            active_tasks: Arc::new(RwLock::new(HashMap::new())),
        });

        let memory_monitor = Arc::new(MemoryMonitor {
            current_usage: Arc::new(RwLock::new(0)),
            pressure_threshold: 512 * 1024 * 1024,  // 512MB
            critical_threshold: 1024 * 1024 * 1024, // 1GB
        });

        Self {
            client,
            cache_manager,
            metrics: Arc::new(RwLock::new(DecryptionMetrics::default())),
            chunk_config: Arc::new(RwLock::new(ChunkConfig::default())),
            prefetch_manager,
            memory_monitor,
            #[cfg(test)]
            chunk_reader_override: Arc::new(RwLock::new(None)),
        }
    }

    #[cfg(test)]
    pub async fn set_chunk_reader_override(&self, override_fn: Option<ChunkReaderOverride>) {
        let mut guard = self.chunk_reader_override.write().await;
        *guard = override_fn;
    }

    /// Decrypt a chunk with multi-epoch fallback and automatic epoch selection
    pub async fn decrypt_chunk(
        &self,
        context: &DecryptionContext,
        offset: u64,
        size: usize,
    ) -> Result<DecryptedChunk> {
        let start_time = Instant::now();

        debug!(
            "Decrypting chunk: file={}, offset={}, size={}, epoch={}",
            context.file_id, offset, size, context.current_epoch
        );

        // Update metrics
        self.update_metrics_start().await;

        // Check cache first
        let cache_key = CacheKey::new(&context.file_id, offset, size);
        if let Some(cached_chunk) = self.cache_manager.get_chunk(&cache_key).await {
            debug!(
                "Cache hit for chunk: file={}, offset={}",
                context.file_id, offset
            );
            self.update_metrics_cache_hit().await;
            return Ok(DecryptedChunk {
                data: cached_chunk.data,
                epoch_id: cached_chunk.epoch_id,
                decrypted_at: cached_chunk.timestamp,
                size,
                from_cache: true,
            });
        }

        self.update_metrics_cache_miss().await;

        // Determine optimal chunk size based on access pattern
        let optimal_size = self.calculate_optimal_chunk_size(context, size).await;

        // Attempt decryption (client handles epoch internally)
        match self
            .decrypt_with_epoch(context, offset, optimal_size, 0)
            .await
        {
            Ok(chunk) => {
                // Cache the successful decryption
                self.cache_with_migration_awareness(context, &cache_key, &chunk)
                    .await?;

                // Trigger background prefetching if appropriate
                self.maybe_trigger_prefetch(context, offset, optimal_size)
                    .await;

                // Update metrics
                let duration = start_time.elapsed();
                self.update_metrics_success(duration, optimal_size).await;

                Ok(chunk)
            }
            Err(e) => {
                warn!("Decryption failed, attempting fallback: {}", e);

                // Attempt fallback to previous epochs
                self.decrypt_with_fallback(context, offset, optimal_size)
                    .await
            }
        }
    }

    /// Decrypt with a specific epoch
    async fn decrypt_with_epoch(
        &self,
        context: &DecryptionContext,
        offset: u64,
        size: usize,
        _epoch_id: u64, // Epoch is now handled internally by the client
    ) -> Result<DecryptedChunk> {
        // Read and decrypt chunk from storage
        // The client now handles epoch selection internally
        let decrypted_data = {
            #[cfg(test)]
            {
                if let Some(reader) = self.chunk_reader_override.read().await.clone() {
                    reader(context.file_id.clone(), offset, size)
                        .await
                        .map_err(MountError::Client)?
                } else {
                    self.client
                        .read_file_chunk(&context.file_id, offset, size as u64)
                        .await
                        .map_err(MountError::Client)?
                }
            }
            #[cfg(not(test))]
            {
                self.client
                    .read_file_chunk(&context.file_id, offset, size as u64)
                    .await
                    .map_err(MountError::Client)?
            }
        };

        debug!(
            "Decrypted chunk: {} bytes for file {} at offset {}",
            decrypted_data.len(),
            context.file_id,
            offset
        );

        let current_epoch = self.client.current_epoch().await;
        let reported_size = decrypted_data.len().min(size);
        Ok(DecryptedChunk {
            data: decrypted_data,
            epoch_id: current_epoch,
            decrypted_at: SystemTime::now(),
            size: reported_size,
            from_cache: false,
        })
    }

    /// Attempt decryption with epoch fallback
    async fn decrypt_with_fallback(
        &self,
        context: &DecryptionContext,
        offset: u64,
        size: usize,
    ) -> Result<DecryptedChunk> {
        // Get available epochs for fallback
        let current_epoch = self.client.current_epoch().await;
        let epochs_to_try = if current_epoch > 0 {
            vec![current_epoch - 1, current_epoch]
        } else {
            vec![current_epoch]
        };

        for epoch_id in epochs_to_try {
            match self
                .decrypt_with_epoch(context, offset, size, epoch_id)
                .await
            {
                Ok(chunk) => {
                    info!(
                        "Successfully decrypted with fallback epoch {}: file={}",
                        epoch_id, context.file_id
                    );
                    self.update_metrics_fallback().await;
                    return Ok(chunk);
                }
                Err(e) => {
                    debug!(
                        "Fallback epoch {} failed for file {}: {}",
                        epoch_id, context.file_id, e
                    );
                    continue;
                }
            }
        }

        Err(MountError::Decryption(
            "All epoch fallback attempts failed".to_string(),
        ))
    }

    /// Cache decrypted chunk with migration awareness
    pub async fn cache_with_migration_awareness(
        &self,
        context: &DecryptionContext,
        cache_key: &CacheKey,
        chunk: &DecryptedChunk,
    ) -> Result<()> {
        // Check if we should cache based on migration status
        let should_cache = match context.migration_status {
            MigrationStatus::Current => true,
            MigrationStatus::PendingMigration => true, // Cache but with shorter TTL
            MigrationStatus::InProgress => false,      // Don't cache during active migration
            MigrationStatus::Completed => true,
            MigrationStatus::Failed(_) => false,
        };

        if !should_cache {
            debug!(
                "Skipping cache due to migration status: {:?}",
                context.migration_status
            );
            return Ok(());
        }

        // Determine cache TTL based on migration status
        let ttl = match context.migration_status {
            MigrationStatus::PendingMigration => Duration::from_secs(30), // Short TTL
            _ => Duration::from_secs(300),                                // Normal TTL
        };

        // Store in cache
        self.cache_manager.store_chunk(cache_key, chunk, ttl).await;

        debug!(
            "Cached chunk: file={}, offset={}, size={}, ttl={:?}",
            context.file_id, cache_key.offset, chunk.size, ttl
        );

        Ok(())
    }

    /// Calculate optimal chunk size based on access pattern and migration status
    async fn calculate_optimal_chunk_size(
        &self,
        context: &DecryptionContext,
        requested_size: usize,
    ) -> usize {
        let config = self.chunk_config.read().await;

        let base_size = match context.access_pattern {
            AccessPattern::Sequential => {
                (config.base_size as f32 * config.sequential_multiplier) as usize
            }
            AccessPattern::Random => (config.base_size as f32 / config.random_divisor) as usize,
            AccessPattern::Mixed | AccessPattern::Unknown => config.base_size,
        };

        // Adjust for migration status
        let migration_adjusted = match context.migration_status {
            MigrationStatus::InProgress => base_size / 2, // Smaller chunks during migration
            MigrationStatus::PendingMigration => base_size, // Normal size
            _ => base_size,
        };

        // Clamp to configured limits and requested size
        let final_size = migration_adjusted
            .max(config.min_size)
            .min(config.max_size)
            .min(requested_size);

        debug!(
            "Calculated optimal chunk size: requested={}, base={}, final={}",
            requested_size, base_size, final_size
        );

        final_size
    }

    /// Maybe trigger background prefetching based on access patterns
    async fn maybe_trigger_prefetch(
        &self,
        context: &DecryptionContext,
        current_offset: u64,
        chunk_size: usize,
    ) {
        // Only prefetch for sequential access patterns
        if context.access_pattern != AccessPattern::Sequential {
            return;
        }

        // Check memory pressure
        if self.memory_monitor.is_under_pressure().await {
            debug!("Skipping prefetch due to memory pressure");
            return;
        }

        // Check if prefetch task already exists
        let mut tasks = self.prefetch_manager.active_tasks.write().await;
        if tasks.contains_key(&context.file_id) {
            return;
        }

        let next_offset = current_offset + chunk_size as u64;

        // Create new prefetch task
        let prefetch_task = PrefetchTask {
            file_id: context.file_id.clone(),
            next_offset,
            chunk_size,
            created_at: SystemTime::now(),
        };

        tasks.insert(context.file_id.clone(), prefetch_task);
        drop(tasks);

        debug!(
            "Scheduled prefetch for file={}, next_offset={}",
            context.file_id,
            current_offset + chunk_size as u64
        );

        let client = self.client.clone();
        let cache_manager = self.cache_manager.clone();
        let active_tasks = self.prefetch_manager.active_tasks.clone();
        let file_id = context.file_id.clone();

        tokio::spawn(async move {
            let key = CacheKey::new(&file_id, next_offset, chunk_size);
            match client
                .read_file_chunk(&file_id, next_offset, chunk_size as u64)
                .await
            {
                Ok(data) if !data.is_empty() => {
                    let epoch = client.current_epoch().await;
                    let chunk_len = data.len();
                    let chunk = DecryptedChunk {
                        data,
                        epoch_id: epoch,
                        decrypted_at: SystemTime::now(),
                        size: chunk_len,
                        from_cache: false,
                    };

                    cache_manager
                        .store_chunk(&key, &chunk, Duration::from_secs(120))
                        .await;

                    debug!(
                        "Prefetched chunk stored for file={} offset={}",
                        file_id, next_offset
                    );
                }
                Ok(_) => {
                    debug!(
                        "Prefetch produced no data for file={} offset={}",
                        file_id, next_offset
                    );
                }
                Err(err) => {
                    debug!(
                        "Prefetch read failed for file={} offset={}: {}",
                        file_id, next_offset, err
                    );
                }
            }

            let mut tasks = active_tasks.write().await;
            tasks.remove(&file_id);
        });
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> DecryptionMetrics {
        self.metrics.read().await.clone()
    }

    /// Update metrics at operation start
    async fn update_metrics_start(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.total_operations += 1;
    }

    /// Update metrics for cache hit
    async fn update_metrics_cache_hit(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.cache_hits += 1;
    }

    /// Update metrics for cache miss
    async fn update_metrics_cache_miss(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.cache_misses += 1;
    }

    /// Update metrics for successful decryption
    async fn update_metrics_success(&self, duration: Duration, bytes: usize) {
        let mut metrics = self.metrics.write().await;

        // Update average decryption time
        let total_ops = metrics.total_operations;
        let current_avg = metrics.avg_decrypt_time_us;
        let new_time = duration.as_micros() as u64;

        metrics.avg_decrypt_time_us = ((current_avg * (total_ops - 1)) + new_time) / total_ops;

        metrics.total_bytes_decrypted += bytes as u64;
    }

    /// Update metrics for epoch fallback
    async fn update_metrics_fallback(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.epoch_fallbacks += 1;
    }
}

impl MemoryMonitor {
    /// Check if system is under memory pressure
    pub async fn is_under_pressure(&self) -> bool {
        let current = *self.current_usage.read().await;
        current > self.pressure_threshold
    }

    /// Check if system is under critical memory pressure
    pub async fn is_critical(&self) -> bool {
        let current = *self.current_usage.read().await;
        current > self.critical_threshold
    }

    /// Update current memory usage estimate
    pub async fn update_usage(&self, bytes: usize) {
        let mut usage = self.current_usage.write().await;
        *usage = bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheConfig;
    use hybridcipher_client::{network::MockNetwork, storage::MockStorage};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::SystemTime,
    };
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_decrypt_chunk_cache_hit() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager =
            Arc::new(CacheManager::new(client.clone(), CacheConfig::default()).await);
        let manager = DecryptionManager::new(client, cache_manager.clone());

        let cache_key = CacheKey::new("file1", 0, 4);
        let cached_chunk = DecryptedChunk {
            data: vec![1, 2, 3, 4],
            epoch_id: 0,
            decrypted_at: SystemTime::now(),
            size: 4,
            from_cache: false,
        };

        cache_manager
            .store_chunk(&cache_key, &cached_chunk, Duration::from_secs(60))
            .await;

        let context = DecryptionContext {
            file_id: "file1".to_string(),
            current_epoch: 0,
            migration_status: MigrationStatus::Current,
            preferred_chunk_size: 4,
            access_pattern: AccessPattern::Sequential,
        };

        let result = manager.decrypt_chunk(&context, 0, 4).await.unwrap();
        assert!(result.from_cache);
        assert_eq!(result.data, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_decrypt_chunk_epoch_fallback() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager =
            Arc::new(CacheManager::new(client.clone(), CacheConfig::default()).await);
        let manager = DecryptionManager::new(client, cache_manager);

        let attempts = Arc::new(AtomicUsize::new(0));
        let override_fn: ChunkReaderOverride = {
            let attempts = attempts.clone();
            Arc::new(move |_file_id: String, _offset: u64, size: usize| {
                let attempts = attempts.clone();
                Box::pin(async move {
                    let current = attempts.fetch_add(1, Ordering::SeqCst);
                    if current == 0 {
                        Err(ClientError::InvalidState("simulated failure".to_string()))
                    } else {
                        Ok(vec![7u8; size])
                    }
                })
            })
        };

        manager.set_chunk_reader_override(Some(override_fn)).await;

        let context = DecryptionContext {
            file_id: "file2".to_string(),
            current_epoch: 2,
            migration_status: MigrationStatus::Current,
            preferred_chunk_size: 8,
            access_pattern: AccessPattern::Sequential,
        };

        let result = manager.decrypt_chunk(&context, 0, 8).await.unwrap();
        assert_eq!(result.data.len(), 8);
        let metrics = manager.metrics.read().await.clone();
        assert_eq!(metrics.epoch_fallbacks, 1);
    }

    #[tokio::test]
    async fn test_adaptive_chunk_sizing() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager =
            Arc::new(CacheManager::new(client.clone(), CacheConfig::default()).await);
        let manager = DecryptionManager::new(client, cache_manager);

        let seq_context = DecryptionContext {
            file_id: "file3".to_string(),
            current_epoch: 0,
            migration_status: MigrationStatus::Current,
            preferred_chunk_size: DEFAULT_CHUNK_SIZE,
            access_pattern: AccessPattern::Sequential,
        };

        let rand_context = DecryptionContext {
            access_pattern: AccessPattern::Random,
            ..seq_context.clone()
        };

        let seq_size = manager
            .calculate_optimal_chunk_size(&seq_context, DEFAULT_CHUNK_SIZE * 2)
            .await;
        let rand_size = manager
            .calculate_optimal_chunk_size(&rand_context, DEFAULT_CHUNK_SIZE * 2)
            .await;

        assert!(seq_size > rand_size);
        assert!(seq_size <= DEFAULT_CHUNK_SIZE * 2);
    }

    #[tokio::test]
    async fn test_migration_aware_caching() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager =
            Arc::new(CacheManager::new(client.clone(), CacheConfig::default()).await);
        let manager = DecryptionManager::new(client, cache_manager.clone());

        let cache_key = CacheKey::new("file4", 0, 4);
        let chunk = DecryptedChunk {
            data: vec![9, 9, 9, 9],
            epoch_id: 1,
            decrypted_at: SystemTime::now(),
            size: 4,
            from_cache: false,
        };

        let in_progress_context = DecryptionContext {
            file_id: "file4".to_string(),
            current_epoch: 1,
            migration_status: MigrationStatus::InProgress,
            preferred_chunk_size: 4,
            access_pattern: AccessPattern::Sequential,
        };

        manager
            .cache_with_migration_awareness(&in_progress_context, &cache_key, &chunk)
            .await
            .unwrap();

        assert!(cache_manager.get_chunk(&cache_key).await.is_none());

        let current_context = DecryptionContext {
            migration_status: MigrationStatus::Current,
            ..in_progress_context
        };

        manager
            .cache_with_migration_awareness(&current_context, &cache_key, &chunk)
            .await
            .unwrap();

        assert!(cache_manager.get_chunk(&cache_key).await.is_some());
    }
}
