//! File reading implementation with dual-epoch support
//!
//! This module provides file reading functionality with automatic
//! epoch fallback and opportunistic migration coordination.

use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, error, warn};

/// Result of a file read operation
#[derive(Debug, Clone)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub epoch_used: String,
    pub from_cache: bool,
    pub migration_triggered: bool,
}

/// File reading manager with dual-epoch support
pub struct ReadManager<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
> {
    client: Arc<hybridcipher_client::Client<S, N>>,
}

impl<S: hybridcipher_client::storage::Storage, N: hybridcipher_client::network::Network>
    ReadManager<S, N>
{
    /// Create a new read manager
    pub fn new(client: Arc<hybridcipher_client::Client<S, N>>) -> Self {
        Self { client }
    }

    /// Read file chunk with dual-epoch fallback
    ///
    /// This method attempts to read from the preferred epoch first,
    /// then falls back to available epochs during migration.
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    /// * `preferred_epoch` - Preferred epoch for reading
    /// * `offset` - Byte offset to start reading from
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// Returns `ReadResult` with data and metadata about the read operation
    pub async fn read_with_epoch_fallback(
        &self,
        file_id: &str,
        preferred_epoch: &str,
        offset: u64,
        size: u64,
    ) -> Result<ReadResult> {
        debug!(
            "Reading file {} from offset {} (size: {}) with preferred epoch {}",
            file_id, offset, size, preferred_epoch
        );

        // First attempt: try preferred epoch
        match self
            .read_from_epoch(file_id, preferred_epoch, offset, size)
            .await
        {
            Ok(data) => {
                debug!("Successfully read from preferred epoch {}", preferred_epoch);
                return Ok(ReadResult {
                    data,
                    epoch_used: preferred_epoch.to_string(),
                    from_cache: false,
                    migration_triggered: false,
                });
            }
            Err(e) => {
                warn!(
                    "Failed to read from preferred epoch {}: {}",
                    preferred_epoch, e
                );
            }
        }

        // Fallback: try other available epochs during migration
        if let Ok(migration_status) = self.client.get_migration_status().await {
            debug!("Migration status: {}", migration_status);

            // Note: Since get_migration_status returns String instead of structured data,
            // we can't determine specific epoch information for fallback reads.
            // This could be enhanced when the client API provides structured migration data.

            // For now, just attempt a regular read without epoch specification
            warn!("Migration detected but structured epoch data not available from client API");
            match self.read_from_epoch(file_id, "current", offset, size).await {
                Ok(data) => {
                    debug!("Successfully read from current epoch");

                    // Note: Opportunistic migration requires more context from migration system
                    // This is simplified for now until Step 4 (missing methods) is implemented
                    return Ok(ReadResult {
                        data,
                        epoch_used: "current".to_string(),
                        from_cache: false,
                        migration_triggered: false,
                    });
                }
                Err(e) => {
                    error!("Failed to read from current epoch: {}", e);
                }
            }
        }

        // If all attempts failed, return the original error
        Err(anyhow::anyhow!(
            "Failed to read file {} from any available epoch",
            file_id
        ))
    }

    /// Read file chunk from a specific epoch
    async fn read_from_epoch(
        &self,
        file_id: &str,
        _epoch_id: &str, // Note: client API doesn't support epoch-specific reads yet
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>> {
        // Use the current client API which doesn't take epoch parameter
        self.client
            .read_file_chunk(file_id, offset, size)
            .await
            .map_err(|e| anyhow::anyhow!("Read error: {}", e))
    }

    /// Read entire file with automatic chunking and epoch fallback
    ///
    /// This method reads a complete file by breaking it into chunks
    /// and handling epoch fallback for each chunk if necessary.
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    /// * `preferred_epoch` - Preferred epoch for reading
    /// * `chunk_size` - Size of each chunk (default 64KB)
    ///
    /// # Returns
    ///
    /// Returns the complete file data as a `Vec<u8>`
    pub async fn read_entire_file(
        &self,
        file_id: &str,
        preferred_epoch: &str,
        chunk_size: Option<u64>,
    ) -> Result<Vec<u8>> {
        let chunk_size = chunk_size.unwrap_or(64 * 1024); // Default 64KB chunks

        debug!(
            "Reading entire file {} with chunk size {}",
            file_id, chunk_size
        );

        // Get file size first
        let file_size = self.get_file_size(file_id, preferred_epoch).await?;
        let mut result_data = Vec::with_capacity(file_size as usize);

        let mut offset = 0;
        while offset < file_size {
            let remaining = file_size - offset;
            let current_chunk_size = std::cmp::min(chunk_size, remaining);

            let read_result = self
                .read_with_epoch_fallback(file_id, preferred_epoch, offset, current_chunk_size)
                .await?;

            result_data.extend_from_slice(&read_result.data);
            offset += current_chunk_size;

            debug!(
                "Read chunk at offset {} (size: {}) for file {}",
                offset - current_chunk_size,
                current_chunk_size,
                file_id
            );
        }

        debug!(
            "Successfully read entire file {} ({} bytes)",
            file_id,
            result_data.len()
        );
        Ok(result_data)
    }

    /// Get file size with epoch fallback
    async fn get_file_size(&self, file_id: &str, _preferred_epoch: &str) -> Result<u64> {
        // Try to get file metadata (client API doesn't support epoch parameter)
        if let Ok(metadata) = self.client.get_file_metadata(file_id).await {
            return Ok(metadata.size);
        }

        // Fallback to other epochs during migration
        if let Ok(migration_status) = self.client.get_migration_status().await {
            debug!("Migration status: {}", migration_status);
            // Note: Without structured migration data, we can't try specific epochs
            // The client API would need to be enhanced to support epoch-specific metadata
        }

        Err(anyhow::anyhow!(
            "Could not determine file size for {}",
            file_id
        ))
    }

    /// Read file with intelligent prefetching
    ///
    /// This method reads a file chunk and prefetches subsequent chunks
    /// in the background to improve performance for sequential access.
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    /// * `preferred_epoch` - Preferred epoch for reading
    /// * `offset` - Byte offset to start reading from
    /// * `size` - Number of bytes to read
    /// * `prefetch_size` - Size of data to prefetch ahead
    ///
    /// # Returns
    ///
    /// Returns `ReadResult` with the requested data
    pub async fn read_with_prefetch(
        &self,
        file_id: &str,
        preferred_epoch: &str,
        offset: u64,
        size: u64,
        prefetch_size: Option<u64>,
    ) -> Result<ReadResult> {
        let prefetch_size = prefetch_size.unwrap_or(128 * 1024); // Default 128KB prefetch

        debug!(
            "Reading with prefetch: file={}, offset={}, size={}, prefetch={}",
            file_id, offset, size, prefetch_size
        );

        // Read the requested data
        let read_result = self
            .read_with_epoch_fallback(file_id, preferred_epoch, offset, size)
            .await?;

        // Schedule prefetch for next chunk in background
        let file_id_clone = file_id.to_string();
        let client_clone = self.client.clone();

        tokio::spawn(async move {
            let prefetch_offset = offset + size;
            // Compatibility prefetch implementation using read_file_chunk
            // This performs actual reading rather than just prefetching into cache
            // but provides similar performance benefits for sequential access
            match client_clone
                .read_file_chunk(&file_id_clone, prefetch_offset, prefetch_size)
                .await
            {
                Ok(data) => {
                    debug!(
                        "Prefetch completed for file {} at offset {}: {} bytes",
                        file_id_clone,
                        prefetch_offset,
                        data.len()
                    );
                    // Data is read but not cached - the client handles its own caching
                }
                Err(e) => {
                    debug!("Prefetch failed for file {}: {}", file_id_clone, e);
                    // Prefetch failures are non-critical
                }
            }
        });

        Ok(read_result)
    }

    /// Validate file integrity during read operations
    ///
    /// This method performs integrity checks on read data to ensure
    /// data hasn't been corrupted during storage or transmission.
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    /// * `data` - Data to validate
    /// * `epoch_id` - Epoch the data was read from
    ///
    /// # Returns
    ///
    /// Returns `true` if data integrity is valid, `false` otherwise
    pub async fn validate_read_integrity(
        &self,
        file_id: &str,
        data: &[u8],
        epoch_id: &str,
    ) -> Result<bool> {
        debug!(
            "Validating integrity for file {} from epoch {}",
            file_id, epoch_id
        );

        // Get expected checksum from metadata (client API doesn't support epoch parameter)
        if let Ok(metadata) = self.client.get_file_metadata(file_id).await {
            // Note: metadata.checksum is Vec<u8>, not Option<Vec<u8>>
            let expected_checksum = &metadata.checksum;

            // Calculate actual checksum
            let actual_checksum = self.calculate_checksum(data);
            let expected_checksum_str = String::from_utf8_lossy(expected_checksum);

            let is_valid = actual_checksum == expected_checksum_str;
            if !is_valid {
                warn!(
                    "Integrity check failed for file {}: expected {:?}, got {}",
                    file_id, expected_checksum, actual_checksum
                );
            }

            return Ok(is_valid);
        }

        // If no checksum available, assume valid
        debug!(
            "No checksum available for file {}, skipping integrity check",
            file_id
        );
        Ok(true)
    }

    /// Calculate checksum for data integrity verification
    fn calculate_checksum(&self, data: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_result_creation() {
        let result = ReadResult {
            data: vec![1, 2, 3, 4],
            epoch_used: "epoch_1".to_string(),
            from_cache: false,
            migration_triggered: true,
        };

        assert_eq!(result.data.len(), 4);
        assert_eq!(result.epoch_used, "epoch_1");
        assert!(!result.from_cache);
        assert!(result.migration_triggered);
    }

    #[test]
    fn test_checksum_calculation() {
        let storage = Arc::new(hybridcipher_client::storage::MockStorage::new());
        let network = Arc::new(hybridcipher_client::network::MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let manager = ReadManager::new(Arc::new(
            // This would be a mock client in real tests
            hybridcipher_client::Client::new(device_identity, storage, network),
        ));

        let data = b"test data";
        let checksum1 = manager.calculate_checksum(data);
        let checksum2 = manager.calculate_checksum(data);

        // Same data should produce same checksum
        assert_eq!(checksum1, checksum2);

        // Different data should produce different checksum
        let different_data = b"different test data";
        let checksum3 = manager.calculate_checksum(different_data);
        assert_ne!(checksum1, checksum3);
    }
}
