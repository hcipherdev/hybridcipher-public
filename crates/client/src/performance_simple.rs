use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
/// Simple High-Performance File Operations for HybridCipher
///
/// Provides basic optimized file operations with batching and parallel processing.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

use crate::errors::ErrorCode;
use crate::network::Network;
use crate::storage::Storage;
use crate::{Client, ClientError, EncryptedFileMetadata};

/// Configuration for high-performance operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,

    /// Thread pool size for CPU-intensive work
    pub thread_pool_size: usize,

    /// Buffer size for streaming operations
    pub buffer_size: usize,

    /// Batch size for parallel operations
    pub batch_size: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_operations: 10,
            thread_pool_size: num_cpus::get(),
            buffer_size: 64 * 1024, // 64KB
            batch_size: 50,
        }
    }
}

/// High-performance client for optimized file operations
pub struct HighPerformanceClient<S: Storage, N: Network> {
    /// Base client for cryptographic operations
    client: Arc<Client<S, N>>,

    /// Configuration
    config: PerformanceConfig,

    /// Performance metrics
    metrics: Arc<std::sync::Mutex<PerformanceMetrics>>,
}

/// Performance metrics tracking
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total operations performed
    pub total_operations: u64,

    /// Total bytes processed
    pub total_bytes_processed: u64,

    /// Operation latencies by type
    pub operation_latencies: HashMap<String, Vec<Duration>>,

    /// Throughput measurements (bytes/second)
    pub throughput_measurements: Vec<f64>,
}

impl<S: Storage, N: Network> HighPerformanceClient<S, N> {
    /// Create a new high-performance client
    pub fn new(client: Arc<Client<S, N>>, config: PerformanceConfig) -> Result<Self, ClientError> {
        Ok(Self {
            client,
            config,
            metrics: Arc::new(std::sync::Mutex::new(PerformanceMetrics::default())),
        })
    }

    /// Batch encrypt multiple files with parallel processing
    pub async fn batch_encrypt_files(
        &self,
        files: Vec<(&str, &[u8])>,
    ) -> Result<Vec<EncryptedFileMetadata>, ClientError> {
        let start_time = Instant::now();

        if files.is_empty() {
            return Ok(Vec::new());
        }

        // Process files in chunks to control memory usage
        let mut all_results = Vec::new();

        for chunk in files.chunks(self.config.batch_size) {
            let chunk_results = self.client.batch_encrypt_files(chunk.to_vec()).await?;
            all_results.extend(chunk_results);
        }

        // Update metrics
        self.update_metrics(
            "batch_encrypt_files",
            start_time,
            files.len() as u64,
            files.iter().map(|(_, data)| data.len() as u64).sum(),
        );

        Ok(all_results)
    }

    /// Batch decrypt multiple files with parallel processing  
    pub async fn batch_decrypt_files(
        &self,
        files: Vec<&EncryptedFileMetadata>,
    ) -> Result<Vec<Vec<u8>>, ClientError> {
        let start_time = Instant::now();

        if files.is_empty() {
            return Ok(Vec::new());
        }

        // Process files in chunks to control memory usage
        let mut all_results = Vec::new();

        for chunk in files.chunks(self.config.batch_size) {
            let chunk_results = self.client.batch_decrypt_files(chunk.to_vec()).await?;
            all_results.extend(chunk_results);
        }

        // Update metrics
        self.update_metrics(
            "batch_decrypt_files",
            start_time,
            files.len() as u64,
            all_results.iter().map(|data| data.len() as u64).sum(),
        );

        Ok(all_results)
    }

    /// Parallel encrypt files with controlled concurrency
    pub async fn parallel_encrypt_files(
        &self,
        files: Vec<(String, Vec<u8>)>,
    ) -> Result<Vec<EncryptedFileMetadata>, ClientError> {
        let start_time = Instant::now();

        if files.is_empty() {
            return Ok(Vec::new());
        }

        // Limit concurrent operations
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_concurrent_operations,
        ));
        let mut tasks = FuturesUnordered::new();

        for (file_path, content) in files {
            let client = self.client.clone();
            let semaphore = semaphore.clone();

            let task: JoinHandle<Result<EncryptedFileMetadata, ClientError>> =
                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.map_err(|_| {
                        ClientError::system_error(
                            ErrorCode::ResourceThreadPool,
                            "Failed to acquire permit".to_string(),
                            "parallel_encrypt_files".to_string(),
                            false,
                        )
                    })?;
                    client.encrypt_file(&file_path, &content).await
                });

            tasks.push(task);
        }

        // Collect results
        let mut results = Vec::new();
        while let Some(task_result) = tasks.next().await {
            let encrypted_file = task_result
                .map_err(|e| {
                    ClientError::system_error(
                        ErrorCode::ResourceThreadPool,
                        format!("Task failed: {}", e),
                        "parallel_encrypt_files".to_string(),
                        false,
                    )
                })?
                .map_err(|e| e)?;

            results.push(encrypted_file);
        }

        // Update metrics
        let total_bytes: u64 = results.iter().map(|f| f.content_size).sum();
        self.update_metrics(
            "parallel_encrypt_files",
            start_time,
            results.len() as u64,
            total_bytes,
        );

        Ok(results)
    }

    /// Parallel decrypt files with controlled concurrency
    pub async fn parallel_decrypt_files(
        &self,
        files: Vec<EncryptedFileMetadata>,
    ) -> Result<Vec<Vec<u8>>, ClientError> {
        let start_time = Instant::now();

        if files.is_empty() {
            return Ok(Vec::new());
        }

        // Limit concurrent operations
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_concurrent_operations,
        ));
        let mut tasks = FuturesUnordered::new();

        for encrypted_file in files {
            let client = self.client.clone();
            let semaphore = semaphore.clone();

            let task: JoinHandle<Result<Vec<u8>, ClientError>> = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.map_err(|_| {
                    ClientError::system_error(
                        ErrorCode::ResourceThreadPool,
                        "Failed to acquire permit".to_string(),
                        "parallel_decrypt_files".to_string(),
                        false,
                    )
                })?;
                client.decrypt_file(&encrypted_file).await
            });

            tasks.push(task);
        }

        // Collect results
        let mut results = Vec::new();
        while let Some(task_result) = tasks.next().await {
            let decrypted_content = task_result
                .map_err(|e| {
                    ClientError::system_error(
                        ErrorCode::ResourceThreadPool,
                        format!("Task failed: {}", e),
                        "parallel_decrypt_files".to_string(),
                        false,
                    )
                })?
                .map_err(|e| e)?;

            results.push(decrypted_content);
        }

        // Update metrics
        let total_bytes: u64 = results.iter().map(|data| data.len() as u64).sum();
        self.update_metrics(
            "parallel_decrypt_files",
            start_time,
            results.len() as u64,
            total_bytes,
        );

        Ok(results)
    }

    /// Get current performance metrics
    pub fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Reset performance metrics
    pub fn reset_metrics(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        *metrics = PerformanceMetrics::default();
    }

    /// Update performance metrics
    fn update_metrics(&self, operation: &str, start_time: Instant, operations: u64, bytes: u64) {
        let mut metrics = self.metrics.lock().unwrap();
        let duration = start_time.elapsed();

        metrics.total_operations += operations;
        metrics.total_bytes_processed += bytes;

        metrics
            .operation_latencies
            .entry(operation.to_string())
            .or_insert_with(Vec::new)
            .push(duration);

        if duration.as_secs_f64() > 0.0 {
            let throughput = bytes as f64 / duration.as_secs_f64();
            metrics.throughput_measurements.push(throughput);
        }
    }
}

// Additional utility functions for performance optimization

/// Compress data using a simple compression algorithm
pub fn compress_data(data: &[u8]) -> Result<Vec<u8>, ClientError> {
    // Simple run-length encoding for demonstration
    // In production, use a proper compression library like flate2
    let mut compressed = Vec::new();

    if data.is_empty() {
        return Ok(compressed);
    }

    let mut current_byte = data[0];
    let mut count = 1u8;

    for &byte in &data[1..] {
        if byte == current_byte && count < 255 {
            count += 1;
        } else {
            compressed.push(count);
            compressed.push(current_byte);
            current_byte = byte;
            count = 1;
        }
    }

    // Add the last run
    compressed.push(count);
    compressed.push(current_byte);

    Ok(compressed)
}

/// Decompress data using the corresponding decompression algorithm
pub fn decompress_data(compressed: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut decompressed = Vec::new();

    if compressed.len() % 2 != 0 {
        return Err(ClientError::crypto_error(
            ErrorCode::CryptoDecryption,
            "Invalid compressed data format".to_string(),
            "decompress_data".to_string(),
            false,
        ));
    }

    for chunk in compressed.chunks(2) {
        let count = chunk[0];
        let byte = chunk[1];

        for _ in 0..count {
            decompressed.push(byte);
        }
    }

    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_round_trip() {
        let data = b"aaabbbcccdddeeefffggghhhiiijjjkkklllmmmnnnooopppqqqrrrssstttuuuvvvwwwxxxyyyzzzAAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPPQQQRRRSSSTTTUUUVVVWWWXXXYYYZZZ";

        let compressed = compress_data(data).unwrap();
        let decompressed = decompress_data(&compressed).unwrap();

        assert_eq!(data.to_vec(), decompressed);
        assert!(compressed.len() < data.len()); // Should be smaller for repetitive data
    }

    #[test]
    fn test_empty_data_compression() {
        let data = b"";
        let compressed = compress_data(data).unwrap();
        let decompressed = decompress_data(&compressed).unwrap();

        assert_eq!(data.to_vec(), decompressed);
        assert_eq!(compressed.len(), 0);
    }

    #[test]
    fn test_single_byte_compression() {
        let data = b"a";
        let compressed = compress_data(data).unwrap();
        let decompressed = decompress_data(&compressed).unwrap();

        assert_eq!(data.to_vec(), decompressed);
        assert_eq!(compressed, vec![1, b'a']);
    }

    #[test]
    fn test_performance_config_default() {
        let config = PerformanceConfig::default();
        assert!(config.max_concurrent_operations > 0);
        assert!(config.thread_pool_size > 0);
        assert!(config.buffer_size > 0);
        assert!(config.batch_size > 0);
    }
}
