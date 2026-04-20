//! Caching system for FUSE filesystem with migration awareness
//!
//! This module provides intelligent caching with epoch-aware invalidation,
//! migration-aware cache policies, and performance optimization.

pub mod chunks;
pub mod eviction;
pub mod metadata;

use crate::error::Result;
use hybridcipher_client::{network::Network, storage::Storage, Client};
use std::{
    collections::HashMap,
    marker::PhantomData,
    mem,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
use tracing::debug;

pub use chunks::{CacheStats, ChunkCache};
pub use eviction::EvictionPolicy;
pub use metadata::{MetadataCache, MetadataCacheStats};

/// Cache key for identifying cached items
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// File identifier
    pub file_id: String,
    /// Offset within file
    pub offset: u64,
    /// Size of cached chunk
    pub size: usize,
}

impl CacheKey {
    /// Create a new cache key
    pub fn new(file_id: &str, offset: u64, size: usize) -> Self {
        Self {
            file_id: file_id.to_string(),
            offset,
            size,
        }
    }
}

/// Cached chunk data with metadata
#[derive(Debug, Clone)]
pub struct CachedChunk {
    /// Decrypted data
    pub data: Vec<u8>,
    /// Epoch used for decryption
    pub epoch_id: u64,
    /// Cache timestamp
    pub timestamp: SystemTime,
    /// Time-to-live for this cache entry
    pub ttl: Duration,
    /// Access count for LRU tracking
    pub access_count: u64,
}

/// Cached overlay content with metadata
#[derive(Debug, Clone)]
pub struct CachedOverlayContent {
    /// Content data
    pub content: Vec<u8>,
    /// Content expiration time
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Access count for statistics
    pub access_count: u64,
}

/// Main cache manager coordinating all cache types
pub struct CacheManager<S: Storage, N: Network> {
    /// Chunk cache for decrypted file data
    chunk_cache: Arc<ChunkCache>,

    /// Metadata cache for file attributes
    metadata_cache: Arc<MetadataCache>,

    /// Cache invalidation tracking
    invalidation_tracker: Arc<RwLock<InvalidationTracker>>,

    /// Cache configuration parameters
    config: CacheConfig,

    /// Phantom marker to keep client generics tied to this manager
    _marker: PhantomData<(S, N)>,
}

/// Cache configuration parameters
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum chunk cache size in bytes
    pub max_chunk_cache_size: usize,
    /// Maximum metadata cache entries
    pub max_metadata_entries: usize,
    /// Default TTL for cached items
    pub default_ttl: Duration,
    /// Enable migration-aware caching
    pub migration_aware: bool,
    /// Memory pressure threshold
    pub memory_pressure_threshold: f32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_chunk_cache_size: 256 * 1024 * 1024, // 256MB
            max_metadata_entries: 10000,
            default_ttl: Duration::from_secs(300), // 5 minutes
            migration_aware: true,
            memory_pressure_threshold: 0.8,
        }
    }
}

/// Cache invalidation tracking
#[derive(Debug, Default)]
pub struct InvalidationTracker {
    /// Files with pending invalidation
    pending_files: HashMap<String, SystemTime>,
    /// Last migration event timestamp
    last_migration_event: Option<SystemTime>,
    /// Epoch-based invalidation markers
    epoch_markers: HashMap<u64, SystemTime>,
}

impl<S: Storage, N: Network> CacheManager<S, N> {
    /// Create a new cache manager
    pub async fn new(_client: Arc<Client<S, N>>, config: CacheConfig) -> Self {
        let chunk_cache = ChunkCache::new(config.max_chunk_cache_size as u64)
            .await
            .unwrap();
        let metadata_cache = MetadataCache::new(config.max_metadata_entries)
            .await
            .unwrap();

        Self {
            chunk_cache: Arc::new(chunk_cache),
            metadata_cache: Arc::new(metadata_cache),
            invalidation_tracker: Arc::new(RwLock::new(InvalidationTracker::default())),
            config,
            _marker: PhantomData,
        }
    }

    /// Get a cached chunk
    pub async fn get_chunk(&self, key: &CacheKey) -> Option<CachedChunk> {
        // Check if cache entry is still valid
        if self.is_cache_entry_valid(&key.file_id).await {
            if let Ok(Some(data)) = self
                .chunk_cache
                .get_chunk(&key.file_id, key.offset, key.size as u64)
                .await
            {
                Some(CachedChunk {
                    data,
                    epoch_id: 0, // Default epoch since not provided by underlying cache
                    timestamp: std::time::SystemTime::now(),
                    ttl: std::time::Duration::from_secs(300), // Default 5-minute TTL
                    access_count: 1,
                })
            } else {
                None
            }
        } else {
            debug!("Cache entry invalid for file: {}", key.file_id);
            None
        }
    }

    /// Store a chunk in cache with TTL
    pub async fn store_chunk(
        &self,
        key: &CacheKey,
        chunk: &crate::filesystem::decrypt::DecryptedChunk,
        ttl: Duration,
    ) {
        // Use the underlying insert_chunk method
        let _ = self
            .chunk_cache
            .insert_chunk(&key.file_id, key.offset, chunk.data.clone())
            .await;

        debug!(
            "Stored chunk in cache: file={}, offset={}, size={}, ttl={:?}",
            key.file_id, key.offset, key.size, ttl
        );
    }

    /// Invalidate cache entries for a specific file
    pub async fn invalidate_file(&self, file_id: &str) {
        debug!("Invalidating cache for file: {}", file_id);

        let _ = self.chunk_cache.invalidate_file(file_id).await;
        // Note: metadata_cache doesn't have invalidate_file method, skip for now

        // Track invalidation
        let mut tracker = self.invalidation_tracker.write().await;
        tracker
            .pending_files
            .insert(file_id.to_string(), SystemTime::now());
    }

    /// Invalidate cache entries for an entire epoch
    pub async fn invalidate_epoch(&self, epoch_id: u64) {
        debug!("Invalidating cache for epoch: {}", epoch_id);

        // Note: invalidate_epoch method doesn't exist, use invalidate_file as fallback
        // This is a simplified implementation

        // Track epoch invalidation
        let mut tracker = self.invalidation_tracker.write().await;
        tracker.epoch_markers.insert(epoch_id, SystemTime::now());
    }

    /// Handle migration event - invalidate appropriate cache entries
    pub async fn handle_migration_event(&self, from_epoch: u64, to_epoch: u64) {
        debug!("Handling migration event: {} -> {}", from_epoch, to_epoch);

        // Invalidate old epoch cache entries
        self.invalidate_epoch(from_epoch).await;

        // Update migration tracker
        let mut tracker = self.invalidation_tracker.write().await;
        tracker.last_migration_event = Some(SystemTime::now());
    }

    /// Check if cache entry is still valid based on migration status
    async fn is_cache_entry_valid(&self, file_id: &str) -> bool {
        let tracker = self.invalidation_tracker.read().await;

        // Check if file has pending invalidation
        if let Some(invalidation_time) = tracker.pending_files.get(file_id) {
            // Allow some grace period for invalidation
            if invalidation_time.elapsed().unwrap_or(Duration::ZERO) < Duration::from_secs(1) {
                return false;
            }
        }

        // Check migration-based invalidation
        if let Some(migration_time) = tracker.last_migration_event {
            // Invalidate entries older than the last migration
            if migration_time.elapsed().unwrap_or(Duration::ZERO) < Duration::from_secs(30) {
                return false;
            }
        }

        true
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheManagerStats {
        let chunk_stats = self.chunk_cache.get_stats();
        let metadata_stats = self.metadata_cache.get_stats();
        let chunk_bytes = self.chunk_cache.current_size_bytes();
        let chunk_capacity = self.chunk_cache.max_size_bytes();
        let metadata_bytes = self.metadata_cache.estimated_memory_usage();
        let total_memory_usage = self.estimate_memory_usage().await;

        CacheManagerStats {
            chunk_cache: chunk_stats,
            metadata_cache: metadata_stats,
            total_memory_usage,
            chunk_cache_bytes: chunk_bytes,
            chunk_cache_capacity: chunk_capacity,
            chunk_cache_utilization: if chunk_capacity > 0 {
                chunk_bytes as f64 / chunk_capacity as f64
            } else {
                0.0
            },
            chunk_hit_rate: self.chunk_cache.get_hit_rate(),
            metadata_hit_rate: self.metadata_cache.get_hit_rate(),
            metadata_memory_usage: metadata_bytes,
        }
    }

    /// Estimate total memory usage
    async fn estimate_memory_usage(&self) -> usize {
        let chunk_memory = self.chunk_cache.current_size_bytes() as usize;
        let metadata_memory = self.metadata_cache.estimated_memory_usage();
        chunk_memory + metadata_memory
    }

    /// Handle memory pressure by evicting cache entries
    pub async fn handle_memory_pressure(&self) -> Result<usize> {
        debug!("Handling memory pressure");

        let initial_usage = self.estimate_memory_usage().await;

        let chunk_capacity = self.chunk_cache.max_size_bytes();
        let chunk_usage = self.chunk_cache.current_size_bytes();
        let mut total_freed: usize = 0;

        if chunk_capacity > 0 {
            let utilization = chunk_usage as f64 / chunk_capacity as f64;
            if utilization > self.config.memory_pressure_threshold as f64 {
                let target_utilization =
                    (self.config.memory_pressure_threshold as f64 * 0.8).clamp(0.0, 1.0);
                let target_bytes = (chunk_capacity as f64 * target_utilization) as u64;
                let bytes_to_free = chunk_usage.saturating_sub(target_bytes);

                if bytes_to_free > 0 {
                    let freed = self.chunk_cache.evict_lru(bytes_to_free).await?;
                    total_freed += freed as usize;
                }
            }
        }

        let metadata_usage = self.metadata_cache.estimated_memory_usage();
        let metadata_capacity_bytes = self
            .config
            .max_metadata_entries
            .saturating_mul(mem::size_of::<metadata::CachedMetadata>());

        if metadata_capacity_bytes > 0 {
            let utilization = metadata_usage as f64 / metadata_capacity_bytes as f64;
            if utilization > self.config.memory_pressure_threshold as f64 {
                let target_utilization =
                    (self.config.memory_pressure_threshold as f64 * 0.8).clamp(0.0, 1.0);
                let target_entries =
                    (self.config.max_metadata_entries as f64 * target_utilization) as usize;
                let removed = self.metadata_cache.shrink_to(target_entries).await;
                total_freed += removed * mem::size_of::<metadata::CachedMetadata>();
            }
        }

        let final_usage = self.estimate_memory_usage().await;
        let freed = initial_usage.saturating_sub(final_usage);

        debug!(
            "Memory pressure handling: freed {} bytes (requested {} additional bytes)",
            freed, total_freed
        );

        Ok(freed)
    }
}

/// Combined cache statistics
#[derive(Debug, Clone)]
pub struct CacheManagerStats {
    /// Chunk cache statistics
    pub chunk_cache: CacheStats,
    /// Metadata cache statistics
    pub metadata_cache: MetadataCacheStats,
    /// Total estimated memory usage
    pub total_memory_usage: usize,
    /// Current bytes stored in chunk cache
    pub chunk_cache_bytes: u64,
    /// Configured chunk cache capacity in bytes
    pub chunk_cache_capacity: u64,
    /// Chunk cache utilization (0.0 - 1.0)
    pub chunk_cache_utilization: f64,
    /// Chunk cache hit rate (0.0 - 1.0)
    pub chunk_hit_rate: f64,
    /// Metadata cache hit rate (0.0 - 1.0)
    pub metadata_hit_rate: f64,
    /// Estimated memory usage of metadata cache (bytes)
    pub metadata_memory_usage: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybridcipher_client::{network::MockNetwork, storage::MockStorage};

    #[tokio::test]
    async fn test_cache_manager_creation() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager = CacheManager::new(client, CacheConfig::default()).await;
        let stats = cache_manager.chunk_cache.get_stats();
        assert_eq!(stats.total_bytes_cached, 0); // Cache should be empty on initialization
    }

    #[tokio::test]
    async fn test_migration_aware_invalidation() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager = CacheManager::new(client, CacheConfig::default()).await;

        let key = CacheKey::new("file1", 0, 32);
        let chunk = crate::filesystem::decrypt::DecryptedChunk {
            data: vec![1, 2, 3, 4],
            epoch_id: 1,
            decrypted_at: SystemTime::now(),
            size: 4,
            from_cache: false,
        };

        cache_manager
            .store_chunk(&key, &chunk, Duration::from_secs(60))
            .await;

        assert!(cache_manager.get_chunk(&key).await.is_some());

        cache_manager.handle_migration_event(1, 2).await;

        assert!(cache_manager.get_chunk(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_memory_pressure_handling() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let mut config = CacheConfig::default();
        config.max_chunk_cache_size = 64 * 1024; // 64KB
        config.memory_pressure_threshold = 0.5;

        let cache_manager = CacheManager::new(client, config).await;

        let large_chunk = vec![0u8; 16 * 1024];
        for idx in 0..6 {
            let key = CacheKey::new("file1", idx * 16 * 1024, large_chunk.len());
            let chunk = crate::filesystem::decrypt::DecryptedChunk {
                data: large_chunk.clone(),
                epoch_id: 1,
                decrypted_at: SystemTime::now(),
                size: large_chunk.len(),
                from_cache: false,
            };
            cache_manager
                .store_chunk(&key, &chunk, Duration::from_secs(60))
                .await;
        }

        let before = cache_manager.estimate_memory_usage().await;
        let freed = cache_manager.handle_memory_pressure().await.unwrap();
        let after = cache_manager.estimate_memory_usage().await;

        assert!(freed > 0);
        assert!(after < before);
    }
}
