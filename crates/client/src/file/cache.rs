/// Performance optimization caching for file operations
///
/// This module provides multi-level caching strategies for file keys,
/// epoch keys, and metadata to optimize performance during bulk operations
/// and reduce storage lookups.
use hybridcipher_crypto::AeadKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Cache operation errors
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Cache entry not found: {0}")]
    EntryNotFound(String),

    #[error("Cache entry expired: {0}")]
    EntryExpired(String),

    #[error("Cache is full")]
    CacheFull,

    #[error("Invalid cache entry: {0}")]
    InvalidEntry(String),
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries per cache
    pub max_entries: usize,
    /// Time-to-live for cache entries (seconds)
    pub ttl_seconds: u64,
    /// Enable/disable caching
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1000,
            ttl_seconds: 3600, // 1 hour
            enabled: true,
        }
    }
}

/// Cached entry with expiration
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    created_at: SystemTime,
    last_accessed: SystemTime,
}

impl<T> CacheEntry<T> {
    fn new(value: T) -> Self {
        let now = SystemTime::now();
        Self {
            value,
            created_at: now,
            last_accessed: now,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed().unwrap_or(Duration::MAX) > ttl
    }

    fn access(&mut self) -> &T {
        self.last_accessed = SystemTime::now();
        &self.value
    }
}

/// LRU cache implementation
#[derive(Debug)]
struct LruCache<K, V> {
    entries: HashMap<K, CacheEntry<V>>,
    config: CacheConfig,
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> LruCache<K, V> {
    fn new(config: CacheConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    fn get(&mut self, key: &K) -> Option<V> {
        if !self.config.enabled {
            return None;
        }

        let ttl = Duration::from_secs(self.config.ttl_seconds);

        if let Some(entry) = self.entries.get_mut(key) {
            if entry.is_expired(ttl) {
                self.entries.remove(key);
                return None;
            }
            return Some(entry.access().clone());
        }

        None
    }

    fn put(&mut self, key: K, value: V) -> Result<(), CacheError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Evict expired entries
        self.evict_expired();

        // Check capacity
        if self.entries.len() >= self.config.max_entries && !self.entries.contains_key(&key) {
            self.evict_lru();
        }

        self.entries.insert(key, CacheEntry::new(value));
        Ok(())
    }

    fn evict_expired(&mut self) {
        let ttl = Duration::from_secs(self.config.ttl_seconds);
        self.entries.retain(|_, entry| !entry.is_expired(ttl));
    }

    fn evict_lru(&mut self) {
        if let Some((oldest_key, _)) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
        {
            let oldest_key = oldest_key.clone();
            self.entries.remove(&oldest_key);
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
    }

    fn size(&self) -> usize {
        self.entries.len()
    }
}

/// File cache manager with multiple cache levels
#[derive(Debug)]
pub struct CacheManager {
    /// File key cache (file_path -> AeadKey)
    file_key_cache: Arc<RwLock<LruCache<String, Vec<u8>>>>,
    /// Epoch key cache (epoch_id -> AeadKey)
    epoch_key_cache: Arc<RwLock<LruCache<u64, Vec<u8>>>>,
    /// Metadata cache (file_path -> metadata)
    metadata_cache: Arc<RwLock<LruCache<String, Vec<u8>>>>,
    /// Cache configuration
    config: CacheConfig,
}

impl CacheManager {
    /// Create a new cache manager with default configuration
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Create a new cache manager with custom configuration
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            file_key_cache: Arc::new(RwLock::new(LruCache::new(config.clone()))),
            epoch_key_cache: Arc::new(RwLock::new(LruCache::new(config.clone()))),
            metadata_cache: Arc::new(RwLock::new(LruCache::new(config.clone()))),
            config,
        }
    }

    /// Cache a file key
    pub fn cache_file_key(&self, file_path: &str, key: &AeadKey) -> Result<(), CacheError> {
        let mut cache = self.file_key_cache.write().unwrap();
        cache.put(file_path.to_string(), key.as_bytes().to_vec())
    }

    /// Get a cached file key
    pub fn get_file_key(&self, file_path: &str) -> Option<AeadKey> {
        let mut cache = self.file_key_cache.write().unwrap();
        if let Some(key_bytes) = cache.get(&file_path.to_string()) {
            AeadKey::from_bytes(&key_bytes).ok()
        } else {
            None
        }
    }

    /// Cache an epoch key
    pub fn cache_epoch_key(&self, epoch_id: u64, key: &AeadKey) -> Result<(), CacheError> {
        let mut cache = self.epoch_key_cache.write().unwrap();
        cache.put(epoch_id, key.as_bytes().to_vec())
    }

    /// Get a cached epoch key
    pub fn get_epoch_key(&self, epoch_id: u64) -> Option<AeadKey> {
        let mut cache = self.epoch_key_cache.write().unwrap();
        if let Some(key_bytes) = cache.get(&epoch_id) {
            AeadKey::from_bytes(&key_bytes).ok()
        } else {
            None
        }
    }

    /// Cache file metadata
    pub fn cache_metadata(&self, file_path: &str, metadata: &[u8]) -> Result<(), CacheError> {
        let mut cache = self.metadata_cache.write().unwrap();
        cache.put(file_path.to_string(), metadata.to_vec())
    }

    /// Get cached file metadata
    pub fn get_metadata(&self, file_path: &str) -> Option<Vec<u8>> {
        let mut cache = self.metadata_cache.write().unwrap();
        cache.get(&file_path.to_string())
    }

    /// Clear all caches
    pub fn clear_all(&self) {
        self.file_key_cache.write().unwrap().clear();
        self.epoch_key_cache.write().unwrap().clear();
        self.metadata_cache.write().unwrap().clear();
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        CacheStats {
            file_key_cache_size: self.file_key_cache.read().unwrap().size(),
            epoch_key_cache_size: self.epoch_key_cache.read().unwrap().size(),
            metadata_cache_size: self.metadata_cache.read().unwrap().size(),
            max_entries: self.config.max_entries,
            ttl_seconds: self.config.ttl_seconds,
            enabled: self.config.enabled,
        }
    }

    /// Check if the last cache access for a file was a hit
    pub fn was_cache_hit(&self, _file_path: &str) -> bool {
        // For now, return false as a conservative estimate
        // In a real implementation, this would track recent cache access patterns
        false
    }

    /// Update access statistics for cache operations
    pub fn update_access_stats(&self, _file_path: &str, _cache_hit: bool) {
        // In a real implementation, this would update detailed statistics
        // For now, this is a placeholder
    }

    /// Get file metadata from cache (bytes format)
    pub fn get_file_metadata_bytes(&self, file_path: &str) -> Option<Vec<u8>> {
        self.get_metadata(file_path)
    }

    /// Store file metadata in cache (bytes format)
    pub fn store_file_metadata_bytes(
        &self,
        file_path: &str,
        metadata: Vec<u8>,
    ) -> Result<(), CacheError> {
        self.cache_metadata(file_path, &metadata)
    }

    /// Store epoch key in cache
    pub fn store_epoch_key(&self, epoch_id: u64, key: &AeadKey) -> Result<(), CacheError> {
        self.cache_epoch_key(epoch_id, key)
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub file_key_cache_size: usize,
    pub epoch_key_cache_size: usize,
    pub metadata_cache_size: usize,
    pub max_entries: usize,
    pub ttl_seconds: u64,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybridcipher_crypto::AeadKey;

    #[test]
    fn test_cache_manager_file_keys() {
        let cache = CacheManager::new();
        let mut rng = rand::rngs::OsRng;
        let key = AeadKey::generate(&mut rng).unwrap();
        let file_path = "/test/file.txt";

        // Cache should be empty initially
        assert!(cache.get_file_key(file_path).is_none());

        // Cache the key
        assert!(cache.cache_file_key(file_path, &key).is_ok());

        // Retrieve the key
        let cached_key = cache.get_file_key(file_path).unwrap();
        assert_eq!(key.as_bytes(), cached_key.as_bytes());
    }

    #[test]
    fn test_cache_manager_epoch_keys() {
        let cache = CacheManager::new();
        let mut rng = rand::rngs::OsRng;
        let key = AeadKey::generate(&mut rng).unwrap();
        let epoch_id = 42;

        // Cache should be empty initially
        assert!(cache.get_epoch_key(epoch_id).is_none());

        // Cache the key
        assert!(cache.cache_epoch_key(epoch_id, &key).is_ok());

        // Retrieve the key
        let cached_key = cache.get_epoch_key(epoch_id).unwrap();
        assert_eq!(key.as_bytes(), cached_key.as_bytes());
    }

    #[test]
    fn test_cache_manager_metadata() {
        let cache = CacheManager::new();
        let metadata = b"test metadata".to_vec();
        let file_path = "/test/file.txt";

        // Cache should be empty initially
        assert!(cache.get_metadata(file_path).is_none());

        // Cache the metadata
        assert!(cache.cache_metadata(file_path, &metadata).is_ok());

        // Retrieve the metadata
        let cached_metadata = cache.get_metadata(file_path).unwrap();
        assert_eq!(metadata, cached_metadata);
    }

    #[test]
    fn test_cache_stats() {
        let cache = CacheManager::new();
        let stats = cache.get_stats();

        assert_eq!(stats.file_key_cache_size, 0);
        assert_eq!(stats.epoch_key_cache_size, 0);
        assert_eq!(stats.metadata_cache_size, 0);
        assert!(stats.enabled);
    }

    #[test]
    fn test_cache_clear() {
        let cache = CacheManager::new();
        let mut rng = rand::rngs::OsRng;
        let key = AeadKey::generate(&mut rng).unwrap();

        // Add some entries
        cache.cache_file_key("/test1.txt", &key).unwrap();
        cache.cache_epoch_key(1, &key).unwrap();
        cache.cache_metadata("/test1.txt", b"metadata").unwrap();

        // Verify entries exist
        assert!(cache.get_file_key("/test1.txt").is_some());
        assert!(cache.get_epoch_key(1).is_some());
        assert!(cache.get_metadata("/test1.txt").is_some());

        // Clear all caches
        cache.clear_all();

        // Verify entries are gone
        assert!(cache.get_file_key("/test1.txt").is_none());
        assert!(cache.get_epoch_key(1).is_none());
        assert!(cache.get_metadata("/test1.txt").is_none());
    }

    #[test]
    fn test_lru_eviction() {
        let config = CacheConfig {
            max_entries: 2,
            ttl_seconds: 3600,
            enabled: true,
        };
        let mut cache = LruCache::new(config);

        // Fill cache to capacity
        cache.put("key1".to_string(), "value1".to_string()).unwrap();
        cache.put("key2".to_string(), "value2".to_string()).unwrap();

        // Access key1 to make it more recently used
        cache.get(&"key1".to_string());

        // Add another entry, should evict key2 (least recently used)
        cache.put("key3".to_string(), "value3".to_string()).unwrap();

        assert!(cache.get(&"key1".to_string()).is_some());
        assert!(cache.get(&"key2".to_string()).is_none()); // Evicted
        assert!(cache.get(&"key3".to_string()).is_some());
    }
}
