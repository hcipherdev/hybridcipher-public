//! Metadata caching for file attributes and directory listings
//!
//! This module provides caching for file metadata to reduce
//! client round-trips and improve filesystem performance.

use anyhow::Result;
use lru::LruCache;
use parking_lot::RwLock;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::debug;

/// Cached file metadata
#[derive(Debug, Clone)]
pub struct CachedMetadata {
    pub file_id: String,
    pub size: u64,
    pub is_directory: bool,
    pub modified_time: SystemTime,
    pub access_time: SystemTime,
    pub creation_time: SystemTime,
    pub permissions: u16,
    pub epoch_id: String,
    pub cache_time: SystemTime,
    pub access_count: u64,
}

/// Metadata cache for file attributes
pub struct MetadataCache {
    /// LRU cache for metadata
    cache: Arc<RwLock<LruCache<String, CachedMetadata>>>,

    /// Cache statistics
    stats: Arc<parking_lot::Mutex<MetadataCacheStats>>,
}

/// Metadata cache statistics
#[derive(Debug, Default, Clone)]
pub struct MetadataCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    pub evictions: u64,
}

impl MetadataCache {
    /// Create a new metadata cache
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of metadata entries to cache
    ///
    /// # Returns
    ///
    /// Returns a new metadata cache instance
    pub async fn new(max_entries: usize) -> Result<Self> {
        let cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(max_entries).unwrap(),
        )));

        debug!(
            "Created metadata cache with capacity {} entries",
            max_entries
        );

        Ok(Self {
            cache,
            stats: Arc::new(parking_lot::Mutex::new(MetadataCacheStats::default())),
        })
    }

    /// Get metadata from cache
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    ///
    /// # Returns
    ///
    /// Returns cached metadata if available
    pub async fn get_metadata(&self, file_id: &str) -> Option<CachedMetadata> {
        let mut cache = self.cache.write();

        if let Some(metadata) = cache.get_mut(file_id) {
            // Update access information
            metadata.access_count += 1;
            metadata.access_time = SystemTime::now();

            // Update statistics
            {
                let mut stats = self.stats.lock();
                stats.hits += 1;
            }

            debug!("Metadata cache hit for file {}", file_id);
            Some(metadata.clone())
        } else {
            // Update miss statistics
            {
                let mut stats = self.stats.lock();
                stats.misses += 1;
            }

            debug!("Metadata cache miss for file {}", file_id);
            None
        }
    }

    /// Insert metadata into cache
    ///
    /// # Arguments
    ///
    /// * `metadata` - Metadata to cache
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if successfully cached
    pub async fn insert_metadata(&self, metadata: CachedMetadata) -> Result<()> {
        let file_id = metadata.file_id.clone();

        {
            let mut cache = self.cache.write();
            cache.put(file_id.clone(), metadata);
        }

        // Update statistics
        {
            let mut stats = self.stats.lock();
            stats.entries += 1;
        }

        debug!("Cached metadata for file {}", file_id);
        Ok(())
    }

    /// Invalidate metadata for a specific file
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file to invalidate
    ///
    /// # Returns
    ///
    /// Returns `true` if entry was found and removed
    pub async fn invalidate_metadata(&self, file_id: &str) -> bool {
        let mut cache = self.cache.write();

        if cache.pop(file_id).is_some() {
            debug!("Invalidated metadata cache for file {}", file_id);
            let mut stats = self.stats.lock();
            stats.entries = stats.entries.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> MetadataCacheStats {
        self.stats.lock().clone()
    }

    /// Get cache hit rate
    pub fn get_hit_rate(&self) -> f64 {
        let stats = self.stats.lock();
        let total_requests = stats.hits + stats.misses;

        if total_requests > 0 {
            stats.hits as f64 / total_requests as f64
        } else {
            0.0
        }
    }

    /// Estimate memory usage of cached metadata entries.
    pub fn estimated_memory_usage(&self) -> usize {
        let stats = self.stats.lock();
        stats.entries as usize * size_of::<CachedMetadata>()
    }

    /// Shrink the cache to at most `max_entries`, returning the number removed.
    pub async fn shrink_to(&self, max_entries: usize) -> usize {
        let mut removed = 0usize;
        let mut cache = self.cache.write();

        while cache.len() > max_entries {
            if cache.pop_lru().is_some() {
                removed += 1;
            } else {
                break;
            }
        }

        if removed > 0 {
            let mut stats = self.stats.lock();
            stats.entries = stats.entries.saturating_sub(removed as u64);
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metadata_cache_creation() {
        let cache = MetadataCache::new(1000).await.unwrap();
        assert_eq!(cache.get_hit_rate(), 0.0);
    }

    #[tokio::test]
    async fn test_metadata_cache_insert_and_get() {
        let cache = MetadataCache::new(1000).await.unwrap();

        let metadata = CachedMetadata {
            file_id: "test_file".to_string(),
            size: 1024,
            is_directory: false,
            modified_time: SystemTime::now(),
            access_time: SystemTime::now(),
            creation_time: SystemTime::now(),
            permissions: 0o644,
            epoch_id: "epoch1".to_string(),
            cache_time: SystemTime::now(),
            access_count: 1,
        };

        cache.insert_metadata(metadata.clone()).await.unwrap();

        let retrieved = cache.get_metadata("test_file").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().file_id, "test_file");
    }
}
