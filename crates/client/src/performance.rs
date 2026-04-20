/// High-Performance File Operations for HybridCipher
/// 
/// Provides optimized file encryption/decryption operations with streaming,
/// batching, and parallel processing for enterprise workloads.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::sync::Semaphore;
use lru::LruCache;
use rayon::prelude::*;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::{ClientError, Client, EncryptedFileMetadata};
use crate::storage::Storage;
use crate::network::Network;
use hybridcipher_messages::{EpochId, MemberId};
use hybridcipher_crypto::secure_memory::{SecretBytes, SecretKey};

/// High-performance client for optimized file operations
pub struct HighPerformanceClient<S: Storage, N: Network> {
    /// Base client for cryptographic operations
    client: Arc<Client<S, N>>,
    
    /// Thread pool for CPU-intensive operations
    thread_pool: rayon::ThreadPool,
    
    /// LRU cache for derived keys to avoid repeated derivation
    key_cache: Arc<Mutex<LruCache<(EpochId, String), Arc<SecretKey>>>>,
    
    /// Semaphore to limit concurrent operations
    operation_semaphore: Arc<Semaphore>,
    
    /// Configuration for performance tuning
    config: PerformanceConfig,
    
    /// Metrics collection for monitoring
    metrics: Arc<Mutex<PerformanceMetrics>>,
}

/// Configuration for performance optimization
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Size of chunks for streaming operations (default: 1MB)
    pub chunk_size: usize,
    
    /// Number of parallel chunks to process (default: 4)
    pub parallel_chunks: usize,
    
    /// Maximum number of concurrent operations (default: 10)
    pub max_concurrent_operations: usize,
    
    /// Key cache size (default: 1000 entries)
    pub key_cache_size: usize,
    
    /// Thread pool size (default: num_cpus)
    pub thread_pool_size: usize,
    
    /// Enable compression for large files
    pub enable_compression: bool,
    
    /// Minimum file size for compression (default: 1KB)
    pub compression_threshold: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024, // 1MB
            parallel_chunks: 4,
            max_concurrent_operations: 10,
            key_cache_size: 1000,
            thread_pool_size: num_cpus::get(),
            enable_compression: false, // Disabled by default for security
            compression_threshold: 1024,
        }
    }
}

/// Input specification for file operations
#[derive(Debug, Clone)]
pub struct FileInput {
    /// Unique identifier for the file
    pub file_id: Uuid,
    
    /// Original file path or name
    pub path: String,
    
    /// File content as bytes
    pub content: Vec<u8>,
    
    /// Optional metadata
    pub metadata: Option<HashMap<String, String>>,
}

/// Result of file encryption operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFile {
    /// File metadata including encryption details
    pub metadata: EncryptedFileMetadata,
    
    /// Encrypted file content
    pub encrypted_content: Vec<u8>,
    
    /// Processing time for metrics
    pub processing_time: Duration,
    
    /// Compression ratio if compression was used
    pub compression_ratio: Option<f64>,
}

/// Result of file decryption operation
#[derive(Debug, Clone)]
pub struct DecryptedFile {
    /// Original file identifier
    pub file_id: Uuid,
    
    /// Decrypted file content
    pub content: Vec<u8>,
    
    /// Original file path
    pub path: String,
    
    /// Processing time for metrics
    pub processing_time: Duration,
    
    /// Any recovered metadata
    pub metadata: Option<HashMap<String, String>>,
}

/// Performance metrics collection
#[derive(Debug, Default)]
pub struct PerformanceMetrics {
    /// Total number of operations performed
    pub total_operations: u64,
    
    /// Total bytes processed
    pub total_bytes_processed: u64,
    
    /// Total processing time
    pub total_processing_time: Duration,
    
    /// Cache hit ratio
    pub cache_hits: u64,
    pub cache_misses: u64,
    
    /// Operation latencies by type
    pub operation_latencies: HashMap<String, Vec<Duration>>,
    
    /// Error counts by type
    pub error_counts: HashMap<String, u64>,
    
    /// Throughput measurements (bytes/second)
    pub throughput_measurements: Vec<f64>,
}

impl<S: Storage, N: Network> HighPerformanceClient<S, N> {
    /// Create a new high-performance client
    pub fn new(client: Arc<Client<S, N>>, config: PerformanceConfig) -> Result<Self, ClientError> {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.thread_pool_size)
            .build()
            .map_err(|e| ClientError::SystemError(format!("Failed to create thread pool: {}", e)))?;
        
        let key_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(config.key_cache_size).unwrap()
        )));
        
        let operation_semaphore = Arc::new(Semaphore::new(config.max_concurrent_operations));
        
        Ok(Self {
            client,
            thread_pool,
            key_cache,
            operation_semaphore,
            config,
            metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
        })
    }
    
    /// Encrypt a file using streaming operations for large files
    pub async fn encrypt_file_stream<R, W>(
        &self,
        input: R,
        output: W,
        file_path: String,
        epoch_id: EpochId,
    ) -> Result<EncryptedFileMetadata, ClientError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let start_time = Instant::now();
        let _permit = self.operation_semaphore.acquire().await
            .map_err(|_| ClientError::SystemError("Failed to acquire operation permit".to_string()))?;
        
        let streaming_encryptor = StreamingEncryptor::new(
            self.config.chunk_size,
            self.config.parallel_chunks,
            self.client.clone(),
            epoch_id,
        )?;
        
        let metadata = streaming_encryptor
            .encrypt_stream(input, output, file_path)
            .await?;
        
        let processing_time = start_time.elapsed();
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.total_operations += 1;
            metrics.total_bytes_processed += metadata.original_size as u64;
            metrics.total_processing_time += processing_time;
            
            let throughput = metadata.original_size as f64 / processing_time.as_secs_f64();
            metrics.throughput_measurements.push(throughput);
            
            metrics.operation_latencies
                .entry("encrypt_file_stream".to_string())
                .or_insert_with(Vec::new)
                .push(processing_time);
        }
        
        Ok(metadata)
    }
    
    /// Decrypt a file using streaming operations
    pub async fn decrypt_file_stream<R, W>(
        &self,
        input: R,
        output: W,
        metadata: EncryptedFileMetadata,
    ) -> Result<(), ClientError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let start_time = Instant::now();
        let _permit = self.operation_semaphore.acquire().await
            .map_err(|_| ClientError::SystemError("Failed to acquire operation permit".to_string()))?;
        
        let streaming_decryptor = StreamingDecryptor::new(
            self.config.chunk_size,
            self.config.parallel_chunks,
            self.client.clone(),
        )?;
        
        streaming_decryptor
            .decrypt_stream(input, output, metadata.clone())
            .await?;
        
        let processing_time = start_time.elapsed();
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.total_operations += 1;
            metrics.total_bytes_processed += metadata.original_size as u64;
            metrics.total_processing_time += processing_time;
            
            let throughput = metadata.original_size as f64 / processing_time.as_secs_f64();
            metrics.throughput_measurements.push(throughput);
            
            metrics.operation_latencies
                .entry("decrypt_file_stream".to_string())
                .or_insert_with(Vec::new)
                .push(processing_time);
        }
        
        Ok(())
    }
    
    /// Batch encrypt multiple files with parallel processing
    pub async fn batch_encrypt_files(
        &self,
        files: Vec<FileInput>,
        epoch_id: EpochId,
    ) -> Result<Vec<EncryptedFile>, ClientError> {
        let start_time = Instant::now();
        
        if files.is_empty() {
            return Ok(Vec::new());
        }
        
        // Process files in parallel with controlled concurrency
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_operations));
        let mut tasks = FuturesUnordered::new();
        
        for file in files {
            let client = self.client.clone();
            let semaphore = semaphore.clone();
            let epoch_id = epoch_id;
            let enable_compression = self.config.enable_compression;
            let compression_threshold = self.config.compression_threshold;
            
            let task: JoinHandle<Result<EncryptedFile, ClientError>> = tokio::spawn(async move {
                let _permit = semaphore.acquire().await
                    .map_err(|_| ClientError::SystemError("Failed to acquire permit".to_string()))?;
                
                let file_start = Instant::now();
                
                // Optionally compress large files
                let content = if enable_compression && file.content.len() > compression_threshold {
                    compress_data(&file.content)?
                } else {
                    file.content.clone()
                };
                
                let metadata = client.encrypt_file(
                    &content,
                    &file.path,
                    file.file_id,
                    epoch_id,
                ).await?;
                
                let encrypted_content = client.state.read().unwrap()
                    .encrypted_files
                    .get(&file.file_id)
                    .ok_or_else(|| ClientError::FileNotFound(file.file_id.to_string()))?
                    .clone();
                
                let processing_time = file_start.elapsed();
                let compression_ratio = if enable_compression && file.content.len() > compression_threshold {
                    Some(content.len() as f64 / file.content.len() as f64)
                } else {
                    None
                };
                
                Ok(EncryptedFile {
                    metadata,
                    encrypted_content,
                    processing_time,
                    compression_ratio,
                })
            });
            
            tasks.push(task);
        }
        
        // Collect results
        let mut results = Vec::new();
        while let Some(task_result) = tasks.next().await {
            let encrypted_file = task_result
                .map_err(|e| ClientError::SystemError(format!("Task failed: {}", e)))??;
            results.push(encrypted_file);
        }
        
        let total_processing_time = start_time.elapsed();
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.total_operations += results.len() as u64;
            
            let total_bytes: u64 = results.iter()
                .map(|f| f.metadata.original_size as u64)
                .sum();
            
            metrics.total_bytes_processed += total_bytes;
            metrics.total_processing_time += total_processing_time;
            
            let throughput = total_bytes as f64 / total_processing_time.as_secs_f64();
            metrics.throughput_measurements.push(throughput);
            
            metrics.operation_latencies
                .entry("batch_encrypt_files".to_string())
                .or_insert_with(Vec::new)
                .push(total_processing_time);
        }
        
        Ok(results)
    }
    
    /// Batch decrypt multiple files with parallel processing
    pub async fn parallel_decrypt_files(
        &self,
        files: Vec<EncryptedFile>,
    ) -> Result<Vec<DecryptedFile>, ClientError> {
        let start_time = Instant::now();
        
        if files.is_empty() {
            return Ok(Vec::new());
        }
        
        // Process files in parallel with controlled concurrency
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_operations));
        let mut tasks = FuturesUnordered::new();
        
        for encrypted_file in files {
            let client = self.client.clone();
            let semaphore = semaphore.clone();
            
            let task: JoinHandle<Result<DecryptedFile, ClientError>> = tokio::spawn(async move {
                let _permit = semaphore.acquire().await
                    .map_err(|_| ClientError::SystemError("Failed to acquire permit".to_string()))?;
                
                let file_start = Instant::now();
                
                // Add encrypted file to client state for decryption
                {
                    let mut state = client.state.write().unwrap();
                    state.encrypted_files.insert(
                        encrypted_file.metadata.file_id,
                        encrypted_file.encrypted_content.clone(),
                    );
                }
                
                let decrypted_content = client.decrypt_file(&encrypted_file.metadata).await?;
                
                // Decompress if needed (check if compression was used)
                let final_content = if encrypted_file.compression_ratio.is_some() {
                    decompress_data(&decrypted_content)?
                } else {
                    decrypted_content
                };
                
                let processing_time = file_start.elapsed();
                
                Ok(DecryptedFile {
                    file_id: encrypted_file.metadata.file_id,
                    content: final_content,
                    path: encrypted_file.metadata.path,
                    processing_time,
                    metadata: None, // Could be extended to include recovered metadata
                })
            });
            
            tasks.push(task);
        }
        
        // Collect results
        let mut results = Vec::new();
        while let Some(task_result) = tasks.next().await {
            let decrypted_file = task_result
                .map_err(|e| ClientError::SystemError(format!("Task failed: {}", e)))??;
            results.push(decrypted_file);
        }
        
        let total_processing_time = start_time.elapsed();
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.total_operations += results.len() as u64;
            
            let total_bytes: u64 = results.iter()
                .map(|f| f.content.len() as u64)
                .sum();
            
            metrics.total_bytes_processed += total_bytes;
            metrics.total_processing_time += total_processing_time;
            
            let throughput = total_bytes as f64 / total_processing_time.as_secs_f64();
            metrics.throughput_measurements.push(throughput);
            
            metrics.operation_latencies
                .entry("parallel_decrypt_files".to_string())
                .or_insert_with(Vec::new)
                .push(total_processing_time);
        }
        
        Ok(results)
    }
    
    /// Get derived key from cache or derive it
    async fn get_or_derive_key(
        &self,
        epoch_id: EpochId,
        context: &str,
    ) -> Result<Arc<SecretKey>, ClientError> {
        let cache_key = (epoch_id, context.to_string());
        
        // Check cache first
        {
            let mut cache = self.key_cache.lock().unwrap();
            if let Some(key) = cache.get(&cache_key) {
                // Update metrics
                {
                    let mut metrics = self.metrics.lock().unwrap();
                    metrics.cache_hits += 1;
                }
                return Ok(key.clone());
            }
        }
        
        // Cache miss - derive key
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.cache_misses += 1;
        }
        
        // Derive key using client
        let epoch_secret = self.client.get_epoch_secret(epoch_id)
            .ok_or_else(|| ClientError::EpochNotFound(epoch_id.to_string()))?;
        
        let derived_key = epoch_secret.derive_key(context.as_bytes(), 32)
            .map_err(|e| ClientError::CryptographicError(format!("Key derivation failed: {:?}", e)))?;
        
        let key_arc = Arc::new(derived_key);
        
        // Store in cache
        {
            let mut cache = self.key_cache.lock().unwrap();
            cache.put(cache_key, key_arc.clone());
        }
        
        Ok(key_arc)
    }
    
    /// Get performance metrics
    pub fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.lock().unwrap().clone()
    }
    
    /// Reset performance metrics
    pub fn reset_metrics(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        *metrics = PerformanceMetrics::default();
    }
    
    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.key_cache.lock().unwrap();
        (cache.len(), cache.cap().into())
    }
    
    /// Calculate average throughput
    pub fn get_average_throughput(&self) -> Option<f64> {
        let metrics = self.metrics.lock().unwrap();
        if metrics.throughput_measurements.is_empty() {
            None
        } else {
            let sum: f64 = metrics.throughput_measurements.iter().sum();
            Some(sum / metrics.throughput_measurements.len() as f64)
        }
    }
}

impl Clone for PerformanceMetrics {
    fn clone(&self) -> Self {
        Self {
            total_operations: self.total_operations,
            total_bytes_processed: self.total_bytes_processed,
            total_processing_time: self.total_processing_time,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            operation_latencies: self.operation_latencies.clone(),
            error_counts: self.error_counts.clone(),
            throughput_measurements: self.throughput_measurements.clone(),
        }
    }
}

/// Streaming encryptor for large files
pub struct StreamingEncryptor<S: Storage, N: Network> {
    chunk_size: usize,
    parallel_chunks: usize,
    client: Arc<Client<S, N>>,
    epoch_id: EpochId,
}

impl<S: Storage, N: Network> StreamingEncryptor<S, N> {
    /// Create a new streaming encryptor
    pub fn new(
        chunk_size: usize,
        parallel_chunks: usize,
        client: Arc<Client<S, N>>,
        epoch_id: EpochId,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            chunk_size,
            parallel_chunks,
            client,
            epoch_id,
        })
    }
    
    /// Encrypt a stream of data
    pub async fn encrypt_stream<R, W>(
        &self,
        mut input: R,
        mut output: W,
        file_path: String,
    ) -> Result<EncryptedFileMetadata, ClientError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let file_id = Uuid::new_v4();
        let start_time = chrono::Utc::now();
        let mut total_size = 0usize;
        let mut chunk_id = 0u32;
        
        // Read and encrypt in chunks
        loop {
            let mut chunk = vec![0u8; self.chunk_size];
            let bytes_read = input.read(&mut chunk).await
                .map_err(|e| ClientError::IOError(e.to_string()))?;
            
            if bytes_read == 0 {
                break; // End of stream
            }
            
            chunk.truncate(bytes_read);
            total_size += bytes_read;
            
            // Encrypt chunk using client's encrypt_file method
            let chunk_file_id = Uuid::new_v4();
            let chunk_path = format!("{}#chunk_{}", file_path, chunk_id);
            
            let _chunk_metadata = self.client.encrypt_file(
                &chunk,
                &chunk_path,
                chunk_file_id,
                self.epoch_id,
            ).await?;
            
            // Get encrypted chunk and write to output
            let encrypted_chunk = self.client.state.read().unwrap()
                .encrypted_files
                .get(&chunk_file_id)
                .ok_or_else(|| ClientError::FileNotFound(chunk_file_id.to_string()))?
                .clone();
            
            output.write_all(&encrypted_chunk).await
                .map_err(|e| ClientError::IOError(e.to_string()))?;
            
            chunk_id += 1;
        }
        
        output.flush().await
            .map_err(|e| ClientError::IOError(e.to_string()))?;
        
        // Create metadata for the complete file
        let metadata = EncryptedFileMetadata {
            file_id,
            path: file_path,
            epoch_id: self.epoch_id,
            original_size: total_size,
            encrypted_size: total_size + (chunk_id as usize * 16), // Estimate with AEAD overhead
            created_at: start_time,
            modified_at: start_time,
        };
        
        Ok(metadata)
    }
}

/// Streaming decryptor for large files
pub struct StreamingDecryptor<S: Storage, N: Network> {
    chunk_size: usize,
    parallel_chunks: usize,
    client: Arc<Client<S, N>>,
}

impl<S: Storage, N: Network> StreamingDecryptor<S, N> {
    /// Create a new streaming decryptor
    pub fn new(
        chunk_size: usize,
        parallel_chunks: usize,
        client: Arc<Client<S, N>>,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            chunk_size,
            parallel_chunks,
            client,
        })
    }
    
    /// Decrypt a stream of data
    pub async fn decrypt_stream<R, W>(
        &self,
        mut input: R,
        mut output: W,
        metadata: EncryptedFileMetadata,
    ) -> Result<(), ClientError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut chunk_id = 0u32;
        let estimated_chunk_size = self.chunk_size + 16; // Account for AEAD overhead
        
        // Read and decrypt in chunks
        loop {
            let mut encrypted_chunk = vec![0u8; estimated_chunk_size];
            let bytes_read = input.read(&mut encrypted_chunk).await
                .map_err(|e| ClientError::IOError(e.to_string()))?;
            
            if bytes_read == 0 {
                break; // End of stream
            }
            
            encrypted_chunk.truncate(bytes_read);
            
            // Create temporary metadata for decryption  
            let chunk_metadata = EncryptedFileMetadata {
                file_id: chunk_file_id.to_string(),
                file_path: format!("chunk_{}", chunk_id),
                epoch_id: 1, // Use current epoch
                content_size: encrypted_chunk.len() as u64,
                encrypted_size: encrypted_chunk.len() as u64,
                created_at: chrono::Utc::now(),
            };
            
            // Decrypt chunk
            let decrypted_chunk = self.client.decrypt_file(&chunk_metadata).await?;
            
            output.write_all(&decrypted_chunk).await
                .map_err(|e| ClientError::IOError(e.to_string()))?;
            
            chunk_id += 1;
        }
        
        output.flush().await
            .map_err(|e| ClientError::IOError(e.to_string()))?;
        
        Ok(())
    }
}

/// Simple compression using deflate (placeholder implementation)
fn compress_data(data: &[u8]) -> Result<Vec<u8>, ClientError> {
    // For security reasons, compression is disabled in this implementation
    // Real compression would use flate2 or similar
    Ok(data.to_vec())
}

/// Simple decompression using deflate (placeholder implementation)
fn decompress_data(data: &[u8]) -> Result<Vec<u8>, ClientError> {
    // For security reasons, compression is disabled in this implementation
    // Real decompression would use flate2 or similar
    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::Cursor;
    
    #[tokio::test]
    async fn test_performance_config_default() {
        let config = PerformanceConfig::default();
        assert_eq!(config.chunk_size, 1024 * 1024);
        assert_eq!(config.parallel_chunks, 4);
        assert_eq!(config.max_concurrent_operations, 10);
        assert_eq!(config.key_cache_size, 1000);
        assert!(!config.enable_compression);
    }
    
    #[tokio::test]
    async fn test_performance_metrics_creation() {
        let metrics = PerformanceMetrics::default();
        assert_eq!(metrics.total_operations, 0);
        assert_eq!(metrics.total_bytes_processed, 0);
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 0);
    }
    
    #[tokio::test]
    async fn test_file_input_creation() {
        let file_input = FileInput {
            file_id: Uuid::new_v4(),
            path: "test.txt".to_string(),
            content: b"Hello, World!".to_vec(),
            metadata: None,
        };
        
        assert_eq!(file_input.content.len(), 13);
        assert_eq!(file_input.path, "test.txt");
    }
    
    #[tokio::test]
    async fn test_compress_decompress_data() {
        let data = b"Hello, World! This is test data for compression.";
        let compressed = compress_data(data).unwrap();
        let decompressed = decompress_data(&compressed).unwrap();
        
        assert_eq!(data, decompressed.as_slice());
    }
}
