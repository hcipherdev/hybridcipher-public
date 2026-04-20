//! Chunk-based caching for file data
//!
//! This module provides efficient chunk-based caching with LRU eviction
//! and migration-aware cache invalidation.

use super::CacheKey;
use anyhow::Result;
use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::debug;

/// Cached chunk data with metadata
#[derive(Debug, Clone)]
pub struct CachedChunk {
    pub data: Vec<u8>,
    pub epoch_id: String,
    pub cache_time: std::time::SystemTime,
    pub access_count: u64,
}

/// Chunk-based file data cache
pub struct ChunkCache {
    /// LRU cache for chunk data
    cache: Arc<RwLock<LruCache<CacheKey, CachedChunk>>>,

    /// Maximum cache size in bytes
    max_size_bytes: u64,

    /// Current cache size in bytes
    current_size_bytes: Arc<parking_lot::Mutex<u64>>,

    /// Cache statistics
    stats: Arc<parking_lot::Mutex<CacheStats>>,
}

/// Cache statistics for monitoring
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub total_bytes_cached: u64,
    pub average_chunk_size: f64,
}

impl ChunkCache {
    /// Create a new chunk cache
    ///
    /// # Arguments
    ///
    /// * `max_size_bytes` - Maximum cache size in bytes
    ///
    /// # Returns
    ///
    /// Returns a new chunk cache instance
    pub async fn new(max_size_bytes: u64) -> Result<Self> {
        let cache_capacity = (max_size_bytes / (64 * 1024)).max(1000) as usize; // Estimate based on 64KB chunks

        let cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(cache_capacity).unwrap(),
        )));

        debug!(
            "Created chunk cache with capacity {} entries, max size {} bytes",
            cache_capacity, max_size_bytes
        );

        Ok(Self {
            cache,
            max_size_bytes,
            current_size_bytes: Arc::new(parking_lot::Mutex::new(0)),
            stats: Arc::new(parking_lot::Mutex::new(CacheStats::default())),
        })
    }

    /// Get chunk from cache
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    /// * `offset` - Byte offset of the chunk
    /// * `size` - Size of the chunk
    ///
    /// # Returns
    ///
    /// Returns cached chunk data if available
    pub async fn get_chunk(
        &self,
        file_id: &str,
        offset: u64,
        size: u64,
    ) -> Result<Option<Vec<u8>>> {
        // Try exact match first
        let exact_key = CacheKey::new(file_id, offset, size as usize);

        if let Some(cached) = self.get_exact_chunk(&exact_key).await? {
            return Ok(Some(cached));
        }

        // Try to find overlapping chunks
        self.get_overlapping_chunk(file_id, offset, size).await
    }

    /// Get exact chunk match from cache
    async fn get_exact_chunk(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        let mut cache = self.cache.write();

        // Check for exact match with any epoch
        for (cached_key, cached_chunk) in cache.iter() {
            if cached_key.file_id == key.file_id
                && cached_key.offset == key.offset
                && cached_chunk.data.len() as u64 >= key.size as u64
            {
                // Update access count
                let mut chunk = cached_chunk.clone();
                chunk.access_count += 1;

                // Move to front of LRU
                let key_clone = cached_key.clone();
                cache.put(key_clone, chunk.clone());

                // Update statistics
                {
                    let mut stats = self.stats.lock();
                    stats.hits += 1;
                }

                debug!(
                    "Cache hit for file {} at offset {} (exact match)",
                    key.file_id, key.offset
                );

                // Return requested portion of cached data
                let end_offset = std::cmp::min(key.size as usize, chunk.data.len());
                return Ok(Some(chunk.data[0..end_offset].to_vec()));
            }
        }

        // Update miss statistics
        {
            let mut stats = self.stats.lock();
            stats.misses += 1;
        }

        Ok(None)
    }

    /// Get overlapping chunk from cache
    async fn get_overlapping_chunk(
        &self,
        file_id: &str,
        offset: u64,
        size: u64,
    ) -> Result<Option<Vec<u8>>> {
        let cache = self.cache.read();

        for (cached_key, cached_chunk) in cache.iter() {
            if cached_key.file_id == file_id {
                let cached_start = cached_key.offset;
                let cached_end = cached_start + cached_chunk.data.len() as u64;
                let request_end = offset + size;

                // Check for overlap
                if offset < cached_end && request_end > cached_start {
                    // Calculate overlapping region
                    let overlap_start = std::cmp::max(offset, cached_start);
                    let overlap_end = std::cmp::min(request_end, cached_end);

                    if overlap_end > overlap_start {
                        let data_start = (overlap_start - cached_start) as usize;
                        let data_end = data_start + (overlap_end - overlap_start) as usize;

                        debug!(
                            "Cache partial hit for file {} at offset {} (overlap)",
                            file_id, offset
                        );

                        return Ok(Some(cached_chunk.data[data_start..data_end].to_vec()));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Insert chunk into cache
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    /// * `offset` - Byte offset of the chunk
    /// * `data` - Chunk data to cache
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if successfully cached
    pub async fn insert_chunk(&self, file_id: &str, offset: u64, data: Vec<u8>) -> Result<()> {
        let data_size = data.len() as u64;

        // Check if chunk is too large for cache
        if data_size > self.max_size_bytes / 4 {
            debug!("Chunk too large for cache: {} bytes", data_size);
            return Ok(()); // Don't cache very large chunks
        }

        // Ensure we have space
        self.ensure_cache_space(data_size).await?;

        let key = CacheKey::new(file_id, offset, data_size as usize);

        let cached_chunk = CachedChunk {
            data,
            epoch_id: "current".to_string(),
            cache_time: std::time::SystemTime::now(),
            access_count: 1,
        };

        {
            let mut cache = self.cache.write();
            cache.put(key, cached_chunk);
        }

        // Update size tracking
        {
            let mut size = self.current_size_bytes.lock();
            *size += data_size;
        }

        // Update statistics
        {
            let mut stats = self.stats.lock();
            stats.total_bytes_cached += data_size;

            // Update average chunk size
            let cache_read = self.cache.read();
            let entry_count = cache_read.len() as f64;
            if entry_count > 0.0 {
                stats.average_chunk_size = *self.current_size_bytes.lock() as f64 / entry_count;
            }
        }

        debug!(
            "Cached chunk for file {} at offset {} ({} bytes)",
            file_id, offset, data_size
        );

        Ok(())
    }

    /// Ensure sufficient cache space for new data
    async fn ensure_cache_space(&self, required_bytes: u64) -> Result<()> {
        let current_size = *self.current_size_bytes.lock();

        if current_size + required_bytes <= self.max_size_bytes {
            return Ok(()); // Sufficient space available
        }

        debug!(
            "Cache eviction needed: current={}, required={}, max={}",
            current_size, required_bytes, self.max_size_bytes
        );

        // Calculate how much space we need to free
        let target_size = (self.max_size_bytes * 3) / 4; // Keep cache at 75% after eviction
        let bytes_to_free = (current_size + required_bytes).saturating_sub(target_size);

        let _ = self.evict_chunks(bytes_to_free).await?;

        Ok(())
    }

    /// Evict chunks to free space
    async fn evict_chunks(&self, bytes_to_free: u64) -> Result<u64> {
        let mut freed_bytes = 0u64;
        let mut eviction_count = 0u64;

        {
            let mut cache = self.cache.write();

            // LRU cache automatically evicts least recently used items
            while freed_bytes < bytes_to_free && !cache.is_empty() {
                if let Some((_, chunk)) = cache.pop_lru() {
                    freed_bytes += chunk.data.len() as u64;
                    eviction_count += 1;
                }
            }
        }

        // Update size tracking
        {
            let mut size = self.current_size_bytes.lock();
            *size = size.saturating_sub(freed_bytes);
        }

        // Update statistics
        {
            let mut stats = self.stats.lock();
            stats.evictions += eviction_count;
        }

        debug!(
            "Evicted {} chunks, freed {} bytes",
            eviction_count, freed_bytes
        );

        Ok(freed_bytes)
    }

    /// Explicitly evict least recently used chunks up to the requested size.
    pub async fn evict_lru(&self, bytes_to_free: u64) -> Result<u64> {
        if bytes_to_free == 0 {
            return Ok(0);
        }
        self.evict_chunks(bytes_to_free).await
    }

    /// Invalidate cache entries for a specific file
    ///
    /// This method is used when a file is migrated or modified
    /// to ensure cache consistency.
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file to invalidate
    ///
    /// # Returns
    ///
    /// Returns number of entries invalidated
    pub async fn invalidate_file(&self, file_id: &str) -> Result<u64> {
        let mut invalidated_count = 0u64;
        let mut freed_bytes = 0u64;

        {
            let mut cache = self.cache.write();
            let keys_to_remove: Vec<CacheKey> = cache
                .iter()
                .filter_map(|(key, _)| {
                    if key.file_id == file_id {
                        Some(key.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for key in keys_to_remove {
                if let Some(chunk) = cache.pop(&key) {
                    freed_bytes += chunk.data.len() as u64;
                    invalidated_count += 1;
                }
            }
        }

        // Update size tracking
        {
            let mut size = self.current_size_bytes.lock();
            *size = size.saturating_sub(freed_bytes);
        }

        debug!(
            "Invalidated {} cache entries for file {} (freed {} bytes)",
            invalidated_count, file_id, freed_bytes
        );

        Ok(invalidated_count)
    }

    /// Get cache statistics
    ///
    /// # Returns
    ///
    /// Returns current cache statistics
    pub fn get_stats(&self) -> CacheStats {
        self.stats.lock().clone()
    }

    /// Get cache hit rate
    ///
    /// # Returns
    ///
    /// Returns cache hit rate as percentage (0.0-1.0)
    pub fn get_hit_rate(&self) -> f64 {
        let stats = self.stats.lock();
        let total_requests = stats.hits + stats.misses;

        if total_requests > 0 {
            stats.hits as f64 / total_requests as f64
        } else {
            0.0
        }
    }

    /// Get current cache utilization
    ///
    /// # Returns
    ///
    /// Returns cache utilization as percentage (0.0-1.0)
    pub fn get_utilization(&self) -> f64 {
        let current_size = *self.current_size_bytes.lock();
        current_size as f64 / self.max_size_bytes as f64
    }

    /// Report current memory usage for cached chunks.
    pub fn current_size_bytes(&self) -> u64 {
        *self.current_size_bytes.lock()
    }

    /// Report the configured capacity for the chunk cache.
    pub fn max_size_bytes(&self) -> u64 {
        self.max_size_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_chunk_cache_creation() {
        let cache = ChunkCache::new(1024 * 1024).await.unwrap();
        assert_eq!(cache.get_utilization(), 0.0);
        assert_eq!(cache.get_hit_rate(), 0.0);
    }

    #[tokio::test]
    async fn test_chunk_cache_insert_and_get() {
        let cache = ChunkCache::new(1024 * 1024).await.unwrap();
        let test_data = vec![1, 2, 3, 4, 5];

        cache
            .insert_chunk("test_file", 0, test_data.clone())
            .await
            .unwrap();

        let retrieved = cache.get_chunk("test_file", 0, 5).await.unwrap();
        assert_eq!(retrieved, Some(test_data));
    }

    #[tokio::test]
    async fn test_chunk_cache_invalidation() {
        let cache = ChunkCache::new(1024 * 1024).await.unwrap();
        let test_data = vec![1, 2, 3, 4, 5];

        cache.insert_chunk("test_file", 0, test_data).await.unwrap();

        let invalidated = cache.invalidate_file("test_file").await.unwrap();
        assert_eq!(invalidated, 1);

        let retrieved = cache.get_chunk("test_file", 0, 5).await.unwrap();
        assert_eq!(retrieved, None);
    }
}
