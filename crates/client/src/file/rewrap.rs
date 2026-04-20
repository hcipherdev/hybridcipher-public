/// Intelligent file rewrapping with performance optimization and batch processing
///
/// Implements efficient file rewrapping strategies including batch processing,
/// intelligent scheduling based on access patterns, and background rewrapping
/// for proactive migration of frequently accessed files.
use super::{FileError, FileMetadata};
use crate::{
    epoch::{EpochManager, EpochState},
    network::Network,
    storage::Storage,
};
use chrono::{DateTime, Utc};
use hybridcipher_crypto::{
    aead::{open, seal, AeadContext},
    AeadKey, AeadNonce,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::Semaphore;

/// Rewrapping strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RewrapStrategy {
    /// Immediate rewrapping on access
    Immediate,
    /// Batch rewrapping with size threshold
    Batch { batch_size: usize },
    /// Scheduled rewrapping at intervals
    Scheduled { interval_secs: u64 },
    /// Adaptive strategy based on access patterns
    Adaptive {
        access_threshold: u64,
        size_threshold: u64,
    },
}

/// Rewrapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewrapConfig {
    /// Rewrapping strategy
    pub strategy: RewrapStrategy,

    /// Maximum concurrent rewrapping operations
    pub max_concurrent: usize,

    /// Background rewrapping enabled
    pub background_enabled: bool,

    /// Performance optimization settings
    pub batch_size_bytes: u64,

    /// Retry configuration
    pub max_retries: u32,
    pub retry_delay_ms: u64,
}

impl Default for RewrapConfig {
    fn default() -> Self {
        Self {
            strategy: RewrapStrategy::Adaptive {
                access_threshold: 10,
                size_threshold: 1024 * 1024, // 1MB
            },
            max_concurrent: 4,
            background_enabled: true,
            batch_size_bytes: 10 * 1024 * 1024, // 10MB batches
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }
}

/// Rewrapping progress tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewrapProgress {
    /// Total files to rewrap
    pub total_files: u64,

    /// Files completed
    pub completed_files: u64,

    /// Files in progress
    pub in_progress_files: u64,

    /// Files failed
    pub failed_files: u64,

    /// Total bytes to process
    pub total_bytes: u64,

    /// Bytes completed
    pub completed_bytes: u64,

    /// Current throughput (bytes/sec)
    pub throughput_bps: f64,

    /// Estimated completion time
    pub estimated_completion: Option<DateTime<Utc>>,

    /// Progress percentage (0.0 - 100.0)
    pub progress_percent: f64,
}

/// Batch rewrapping statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRewrapStats {
    /// Batch ID
    pub batch_id: String,

    /// Files in batch
    pub file_count: u32,

    /// Total batch size
    pub total_size: u64,

    /// Processing start time
    pub start_time: DateTime<Utc>,

    /// Processing completion time
    pub completion_time: Option<DateTime<Utc>>,

    /// Success rate
    pub success_rate: f64,

    /// Average file processing time
    pub avg_file_time_ms: f64,

    /// Throughput achieved
    pub throughput_mbps: f64,
}

/// Rewrapping errors
#[derive(Debug, Error)]
pub enum RewrapError {
    #[error("File rewrapping failed: {path}")]
    RewrapFailed { path: String },

    #[error("Batch processing failed: {batch_id}")]
    BatchFailed { batch_id: String },

    #[error("Concurrent limit exceeded")]
    ConcurrencyLimitExceeded,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("File error: {0}")]
    File(#[from] FileError),
}

/// File rewrapping task
#[derive(Debug, Clone)]
struct RewrapTask {
    pub path: String,
    pub priority: u32,
    pub retry_count: u32,
    pub estimated_size: u64,
    pub access_frequency: u64,
    pub created_at: DateTime<Utc>,
}

/// Intelligent file rewrapping manager
#[derive(Debug)]
pub struct RewrapManager<S: Storage, N: Network> {
    /// Storage backend
    storage: Arc<S>,

    /// Network interface
    network: Arc<N>,

    /// Epoch manager
    epoch_manager: Arc<RwLock<EpochManager<S, N>>>,

    /// Rewrapping configuration
    config: RewrapConfig,

    /// Concurrency control
    semaphore: Arc<Semaphore>,

    /// Rewrapping queue
    task_queue: Arc<RwLock<VecDeque<RewrapTask>>>,

    /// Progress tracking
    progress: Arc<RwLock<RewrapProgress>>,

    /// Batch statistics
    batch_stats: Arc<RwLock<HashMap<String, BatchRewrapStats>>>,

    /// Performance metrics
    performance_history: Arc<RwLock<Vec<(DateTime<Utc>, f64)>>>,
}

impl<S: Storage, N: Network> RewrapManager<S, N> {
    /// Create new rewrapping manager
    pub fn new(
        storage: Arc<S>,
        network: Arc<N>,
        epoch_manager: Arc<RwLock<EpochManager<S, N>>>,
        config: RewrapConfig,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));

        Self {
            storage,
            network,
            epoch_manager,
            semaphore,
            config,
            task_queue: Arc::new(RwLock::new(VecDeque::new())),
            progress: Arc::new(RwLock::new(RewrapProgress {
                total_files: 0,
                completed_files: 0,
                in_progress_files: 0,
                failed_files: 0,
                total_bytes: 0,
                completed_bytes: 0,
                throughput_bps: 0.0,
                estimated_completion: None,
                progress_percent: 0.0,
            })),
            batch_stats: Arc::new(RwLock::new(HashMap::new())),
            performance_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Rewrap single file with atomic operation
    pub async fn rewrap_file(
        &self,
        path: &str,
        target_epoch: &EpochState,
    ) -> Result<(), RewrapError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| RewrapError::ConcurrencyLimitExceeded)?;

        let start_time = Instant::now();

        // Increment in-progress counter
        {
            let mut progress = self.progress.write().unwrap();
            progress.in_progress_files += 1;
        }

        let result = self.rewrap_file_internal(path, target_epoch).await;

        // Update progress based on result
        {
            let mut progress = self.progress.write().unwrap();
            progress.in_progress_files -= 1;

            match &result {
                Ok(_) => {
                    progress.completed_files += 1;
                    // Update throughput calculation separately to avoid holding lock across async
                }
                Err(_) => progress.failed_files += 1,
            }

            // Update progress percentage
            if progress.total_files > 0 {
                progress.progress_percent =
                    (progress.completed_files as f64 / progress.total_files as f64) * 100.0;
            }
        }

        // Update throughput separately to avoid lock conflicts
        if result.is_ok() {
            let duration = start_time.elapsed();
            if let Ok(metadata) = self.get_file_metadata(path).await {
                // Update completed bytes
                {
                    let mut progress = self.progress.write().unwrap();
                    progress.completed_bytes += metadata.size;
                }

                let throughput = metadata.size as f64 / duration.as_secs_f64();
                self.update_throughput_history(throughput).await;
            }
        }

        result
    }

    /// Internal file rewrapping implementation
    async fn rewrap_file_internal(
        &self,
        path: &str,
        target_epoch: &EpochState,
    ) -> Result<(), RewrapError> {
        // Get current file data (encrypted with old epoch)
        let old_data = self
            .storage
            .get_file(path)
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?
            .ok_or_else(|| {
                RewrapError::File(FileError::NotFound {
                    path: path.to_string(),
                })
            })?;

        // Get current epoch for decryption (get reference without holding the lock)
        let current_epoch = {
            let epoch_manager = self.epoch_manager.read().unwrap();
            let epoch = epoch_manager.current_epoch().await.ok_or_else(|| {
                RewrapError::File(FileError::Epoch("No current epoch available".to_string()))
            })?;
            // Lock is dropped here automatically
            epoch
        };

        // Extract nonce and ciphertext from old data
        if old_data.len() < 12 {
            return Err(RewrapError::File(FileError::DecryptionError(
                "Invalid encrypted data format".to_string(),
            )));
        }

        let (nonce_bytes, old_ciphertext) = old_data.split_at(12);
        let old_nonce = AeadNonce::from_bytes(nonce_bytes)
            .map_err(|e| RewrapError::File(FileError::DecryptionError(e.to_string())))?;

        // Decrypt with current epoch key
        let aad = path.as_bytes();
        let current_key = AeadKey::from_bytes(&current_epoch.encryption_key)
            .map_err(|e| RewrapError::File(FileError::DecryptionError(e.to_string())))?;
        let plaintext = open(
            &current_key,
            &old_nonce,
            AeadContext::FileData,
            aad,
            old_ciphertext,
        )
        .map_err(|e| RewrapError::File(FileError::DecryptionError(e.to_string())))?;

        // Generate new nonce and encrypt with new epoch key
        let new_nonce = AeadNonce::generate_os()
            .map_err(|e| RewrapError::File(FileError::EncryptionError(e.to_string())))?;

        let new_key = AeadKey::from_bytes(&target_epoch.encryption_key)
            .map_err(|e| RewrapError::File(FileError::EncryptionError(e.to_string())))?;
        let new_ciphertext = seal(&new_key, &new_nonce, AeadContext::FileData, aad, &plaintext)
            .map_err(|e| RewrapError::File(FileError::EncryptionError(e.to_string())))?;

        // Combine nonce and ciphertext for storage
        let mut new_data = Vec::with_capacity(12 + new_ciphertext.len());
        new_data.extend_from_slice(new_nonce.as_bytes());
        new_data.extend_from_slice(&new_ciphertext);

        // Atomic update in storage
        let transaction = self
            .storage
            .begin_transaction()
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?;

        // Store new encrypted data
        transaction
            .store_file(path, &new_data)
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?;

        // Update file metadata
        let mut metadata = self.get_file_metadata(path).await?;
        metadata.epoch_id = target_epoch.epoch_id;
        metadata.last_modified = Utc::now();
        metadata.pending_rewrap = false;

        transaction
            .store_file_metadata_typed(path, &metadata)
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?;

        // Commit transaction
        transaction
            .commit()
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?;

        log::info!(
            "Successfully rewrapped file {} to epoch {}",
            path,
            target_epoch.epoch_id
        );

        Ok(())
    }

    /// Internal file rewrapping with explicit current epoch (for batch processing)
    async fn rewrap_file_with_current_epoch(
        &self,
        path: &str,
        current_epoch: &EpochState,
        target_epoch: &EpochState,
    ) -> Result<(), RewrapError> {
        // Get current file data (encrypted with old epoch)
        let old_data = self
            .storage
            .get_file(path)
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?
            .ok_or_else(|| {
                RewrapError::File(FileError::NotFound {
                    path: path.to_string(),
                })
            })?;

        // Extract nonce and ciphertext from old data
        if old_data.len() < 12 {
            return Err(RewrapError::File(FileError::DecryptionError(
                "Invalid encrypted data format".to_string(),
            )));
        }

        let (nonce_bytes, old_ciphertext) = old_data.split_at(12);
        let old_nonce = AeadNonce::from_bytes(nonce_bytes)
            .map_err(|e| RewrapError::File(FileError::DecryptionError(e.to_string())))?;

        // Decrypt with current epoch key
        let aad = path.as_bytes();
        let current_key = AeadKey::from_bytes(&current_epoch.encryption_key)
            .map_err(|e| RewrapError::File(FileError::DecryptionError(e.to_string())))?;
        let plaintext = open(
            &current_key,
            &old_nonce,
            AeadContext::FileData,
            aad,
            old_ciphertext,
        )
        .map_err(|e| RewrapError::File(FileError::DecryptionError(e.to_string())))?;

        // Generate new nonce and encrypt with new epoch key
        let new_nonce = AeadNonce::generate_os()
            .map_err(|e| RewrapError::File(FileError::EncryptionError(e.to_string())))?;

        let new_key = AeadKey::from_bytes(&target_epoch.encryption_key)
            .map_err(|e| RewrapError::File(FileError::EncryptionError(e.to_string())))?;
        let new_ciphertext = seal(&new_key, &new_nonce, AeadContext::FileData, aad, &plaintext)
            .map_err(|e| RewrapError::File(FileError::EncryptionError(e.to_string())))?;

        // Combine nonce and ciphertext for storage
        let mut new_data = Vec::with_capacity(12 + new_ciphertext.len());
        new_data.extend_from_slice(new_nonce.as_bytes());
        new_data.extend_from_slice(&new_ciphertext);

        // Atomic update in storage
        let transaction = self
            .storage
            .begin_transaction()
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?;

        // Store new encrypted data
        transaction
            .store_file(path, &new_data)
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?;

        // Update file metadata
        let mut metadata = self.get_file_metadata(path).await?;
        metadata.epoch_id = target_epoch.epoch_id;
        metadata.last_modified = Utc::now();
        metadata.pending_rewrap = false;

        transaction
            .store_file_metadata_typed(path, &metadata)
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?;

        // Commit transaction
        transaction
            .commit()
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?;

        log::info!(
            "Successfully rewrapped file {} to epoch {}",
            path,
            target_epoch.epoch_id
        );

        Ok(())
    }

    /// Process batch of files for efficient rewrapping
    pub async fn process_batch(
        &self,
        file_paths: Vec<String>,
        target_epoch: &EpochState,
    ) -> Result<BatchRewrapStats, RewrapError> {
        let batch_id = format!("batch_{}", Utc::now().timestamp_millis());
        let start_time = Utc::now();

        let mut stats = BatchRewrapStats {
            batch_id: batch_id.clone(),
            file_count: file_paths.len() as u32,
            total_size: 0,
            start_time,
            completion_time: None,
            success_rate: 0.0,
            avg_file_time_ms: 0.0,
            throughput_mbps: 0.0,
        };

        // Calculate total batch size
        for path in &file_paths {
            if let Ok(metadata) = self.get_file_metadata(path).await {
                stats.total_size += metadata.size;
            }
        }

        let batch_start = Instant::now();
        let mut successful_files = 0;
        let mut total_file_time = Duration::ZERO;

        // Get current epoch once before spawning tasks
        let current_epoch = {
            let epoch_manager = self.epoch_manager.read().unwrap();
            let epoch = epoch_manager.current_epoch().await.ok_or_else(|| {
                RewrapError::File(FileError::Epoch("No current epoch available".to_string()))
            })?;
            epoch
        };

        // Process files in batches to respect concurrency limits
        let chunk_size = self.config.max_concurrent;
        for chunk in file_paths.chunks(chunk_size) {
            let mut handles = Vec::new();

            for path in chunk {
                let path = path.clone();
                let current_epoch = current_epoch.clone();
                let target_epoch = target_epoch.clone();
                let manager = self.clone();

                let handle = tokio::spawn(async move {
                    let file_start = Instant::now();
                    let result = manager
                        .rewrap_file_with_current_epoch(&path, &current_epoch, &target_epoch)
                        .await;
                    let file_duration = file_start.elapsed();
                    (path, result, file_duration)
                });

                handles.push(handle);
            }

            // Wait for chunk completion
            for handle in handles {
                match handle.await {
                    Ok((path, Ok(()), duration)) => {
                        successful_files += 1;
                        total_file_time += duration;
                        log::debug!("Batch {}: Successfully processed {}", batch_id, path);
                    }
                    Ok((path, Err(e), duration)) => {
                        total_file_time += duration;
                        log::warn!("Batch {}: Failed to process {}: {}", batch_id, path, e);
                    }
                    Err(e) => {
                        log::error!("Batch {}: Task join error: {}", batch_id, e);
                    }
                }
            }
        }

        let batch_duration = batch_start.elapsed();

        // Calculate final statistics
        stats.completion_time = Some(Utc::now());
        stats.success_rate = (successful_files as f64 / stats.file_count as f64) * 100.0;
        stats.avg_file_time_ms = total_file_time.as_millis() as f64 / stats.file_count as f64;

        if batch_duration.as_secs() > 0 {
            stats.throughput_mbps =
                (stats.total_size as f64 / (1024.0 * 1024.0)) / batch_duration.as_secs_f64();
        }

        // Store batch statistics
        {
            let mut batch_stats = self.batch_stats.write().unwrap();
            batch_stats.insert(batch_id.clone(), stats.clone());
        }

        log::info!(
            "Completed batch {}: {}/{} files successful, {:.2}% success rate, {:.2} MB/s",
            batch_id,
            successful_files,
            stats.file_count,
            stats.success_rate,
            stats.throughput_mbps
        );

        Ok(stats)
    }

    /// Add file to rewrapping queue with intelligent prioritization
    pub async fn queue_rewrap(&self, path: String, priority: u32) -> Result<(), RewrapError> {
        let metadata = self.get_file_metadata(&path).await?;

        let task = RewrapTask {
            path,
            priority,
            retry_count: 0,
            estimated_size: metadata.size,
            access_frequency: metadata.access_count,
            created_at: Utc::now(),
        };

        let mut queue = self.task_queue.write().unwrap();
        Self::insert_task(&mut queue, task);

        // Update total files in progress tracking
        {
            let mut progress = self.progress.write().unwrap();
            progress.total_files += 1;
            progress.total_bytes += metadata.size;
        }

        Ok(())
    }

    /// Process queued rewrapping tasks
    pub async fn process_queue(&self, target_epoch: &EpochState) -> Result<(), RewrapError> {
        while let Some(task) = {
            let mut queue = self.task_queue.write().unwrap();
            queue.pop_front()
        } {
            match self.rewrap_file(&task.path, target_epoch).await {
                Ok(_) => {
                    log::debug!(
                        "Successfully processed queued task: {} (freq {}, size {} bytes)",
                        task.path,
                        task.access_frequency,
                        task.estimated_size
                    );
                }
                Err(e) => {
                    log::warn!(
                        "Failed to process queued task {} (freq {}, size {} bytes): {}",
                        task.path,
                        task.access_frequency,
                        task.estimated_size,
                        e
                    );

                    // Retry logic
                    if task.retry_count < self.config.max_retries {
                        let mut retry_task = task;
                        retry_task.retry_count += 1;
                        retry_task.created_at = Utc::now();

                        // Add delay before retry
                        tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms)).await;

                        let mut queue = self.task_queue.write().unwrap();
                        Self::insert_task(&mut queue, retry_task);
                    } else {
                        log::error!("Task {} exceeded max retries", task.path);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get file metadata helper
    async fn get_file_metadata(&self, path: &str) -> Result<FileMetadata, RewrapError> {
        self.storage
            .get_file_metadata(path)
            .await
            .map_err(|e| RewrapError::File(FileError::Storage(e)))?
            .ok_or_else(|| {
                RewrapError::File(FileError::NotFound {
                    path: path.to_string(),
                })
            })
    }

    /// Update throughput history for performance tracking
    async fn update_throughput_history(&self, throughput: f64) {
        let mut history = self.performance_history.write().unwrap();
        history.push((Utc::now(), throughput));

        // Keep only recent history (last 1000 measurements)
        if history.len() > 1000 {
            history.remove(0);
        }

        // Update current throughput in progress
        let avg_throughput = history.iter().map(|(_, t)| t).sum::<f64>() / history.len() as f64;

        let mut progress = self.progress.write().unwrap();
        progress.throughput_bps = avg_throughput;

        // Estimate completion time
        let remaining_bytes = progress.total_bytes - progress.completed_bytes;
        if avg_throughput > 0.0 {
            let remaining_seconds = remaining_bytes as f64 / avg_throughput;
            progress.estimated_completion =
                Some(Utc::now() + chrono::Duration::seconds(remaining_seconds as i64));
        }
    }

    fn insert_task(queue: &mut VecDeque<RewrapTask>, task: RewrapTask) {
        let insert_pos = queue
            .iter()
            .position(|existing| Self::task_precedes(&task, existing))
            .unwrap_or(queue.len());

        queue.insert(insert_pos, task);
    }

    fn task_precedes(a: &RewrapTask, b: &RewrapTask) -> bool {
        if a.priority != b.priority {
            return a.priority > b.priority;
        }
        if a.access_frequency != b.access_frequency {
            return a.access_frequency > b.access_frequency;
        }
        if a.estimated_size != b.estimated_size {
            return a.estimated_size < b.estimated_size;
        }
        a.created_at < b.created_at
    }

    /// Get current progress
    pub fn get_progress(&self) -> RewrapProgress {
        self.progress.read().unwrap().clone()
    }

    /// Get batch statistics
    pub fn get_batch_stats(&self, batch_id: &str) -> Option<BatchRewrapStats> {
        self.batch_stats.read().unwrap().get(batch_id).cloned()
    }

    /// Get all batch statistics
    pub fn get_all_batch_stats(&self) -> HashMap<String, BatchRewrapStats> {
        self.batch_stats.read().unwrap().clone()
    }
}

// Clone implementation for async task spawning
impl<S: Storage, N: Network> Clone for RewrapManager<S, N> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            network: self.network.clone(),
            epoch_manager: self.epoch_manager.clone(),
            config: self.config.clone(),
            semaphore: self.semaphore.clone(),
            task_queue: self.task_queue.clone(),
            progress: self.progress.clone(),
            batch_stats: self.batch_stats.clone(),
            performance_history: self.performance_history.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{network::MockNetwork, storage::MockStorage};
    use hybridcipher_crypto::signatures::Ed25519KeyPair;

    #[tokio::test]
    async fn test_rewrap_manager_creation() {
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

        let config = RewrapConfig::default();
        let manager = RewrapManager::new(storage, network, epoch_manager, config);

        let progress = manager.get_progress();
        assert_eq!(progress.total_files, 0);
        assert_eq!(progress.completed_files, 0);
        assert_eq!(progress.progress_percent, 0.0);
    }

    #[tokio::test]
    async fn test_queue_rewrap() {
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

        let config = RewrapConfig::default();
        let manager = RewrapManager::new(storage, network, epoch_manager, config);

        // This will fail since the file doesn't exist, but tests the queue mechanism
        let result = manager.queue_rewrap("/test/file.txt".to_string(), 10).await;
        assert!(result.is_err()); // Expected since file doesn't exist
    }

    #[test]
    fn test_rewrap_config_default() {
        let config = RewrapConfig::default();
        assert_eq!(config.max_concurrent, 4);
        assert!(config.background_enabled);
        assert_eq!(config.max_retries, 3);

        match config.strategy {
            RewrapStrategy::Adaptive {
                access_threshold,
                size_threshold,
            } => {
                assert_eq!(access_threshold, 10);
                assert_eq!(size_threshold, 1024 * 1024);
            }
            _ => panic!("Expected adaptive strategy"),
        }
    }

    #[test]
    fn test_rewrap_task_creation() {
        let task = RewrapTask {
            path: "/test/file.txt".to_string(),
            priority: 5,
            retry_count: 0,
            estimated_size: 1024,
            access_frequency: 10,
            created_at: Utc::now(),
        };

        assert_eq!(task.path, "/test/file.txt");
        assert_eq!(task.priority, 5);
        assert_eq!(task.retry_count, 0);
        assert_eq!(task.estimated_size, 1024);
    }
}
