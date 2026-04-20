use futures::stream::{FuturesUnordered, StreamExt};
use lru::LruCache;
use serde::{Deserialize, Serialize};
/// Scalable Group Management for HybridCipher
///
/// Provides optimized group operations for large groups (up to 10,000 members)
/// and high-frequency member changes with efficient memory usage and parallel processing.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

use crate::errors::ErrorCode;
use crate::group::EpochId;
use crate::network::Network;
use crate::storage::Storage;
use crate::{group::MemberId, Client, ClientError};

/// Configuration for scalable group operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalableGroupConfig {
    /// Maximum number of concurrent operations
    pub max_concurrent_operations: usize,

    /// Batch size for member operations
    pub member_batch_size: usize,

    /// Cache size for processed updates
    pub update_cache_size: usize,

    /// Rekey batch size for large groups
    pub rekey_batch_size: usize,

    /// Maximum group size to handle
    pub max_group_size: usize,
}

impl Default for ScalableGroupConfig {
    fn default() -> Self {
        Self {
            max_concurrent_operations: 50,
            member_batch_size: 100,
            update_cache_size: 1000,
            rekey_batch_size: 500,
            max_group_size: 10_000,
        }
    }
}

/// Member information for efficient indexing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    /// Member identifier
    pub member_id: MemberId,

    /// Member capabilities
    pub capabilities: Vec<String>,

    /// Join timestamp
    pub joined_at: chrono::DateTime<chrono::Utc>,

    /// Last activity timestamp
    pub last_active: chrono::DateTime<chrono::Utc>,

    /// Member status
    pub status: MemberStatus,
}

/// Member status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemberStatus {
    Active,
    Inactive,
    Pending,
    Removed,
}

/// Group update identifier for caching
pub type GroupUpdateId = uuid::Uuid;

/// Processed group update for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedUpdate {
    /// Update identifier
    pub update_id: GroupUpdateId,

    /// Processing timestamp
    pub processed_at: chrono::DateTime<chrono::Utc>,

    /// Members affected
    pub affected_members: Vec<MemberId>,

    /// Processing result
    pub result: UpdateResult,
}

/// Result of group update processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateResult {
    Success,
    PartialFailure(Vec<String>),
    Failed(String),
}

/// Large group update structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeGroupUpdate {
    /// Update identifier
    pub update_id: GroupUpdateId,

    /// Target epoch
    pub target_epoch: EpochId,

    /// Members to add
    pub members_to_add: Vec<MemberId>,

    /// Members to remove
    pub members_to_remove: Vec<MemberId>,

    /// Members to update
    pub members_to_update: Vec<(MemberId, MemberInfo)>,

    /// Update timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Welcome message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Welcome {
    /// Target member
    pub member_id: MemberId,

    /// Welcome message data
    pub message_data: Vec<u8>,

    /// Generation timestamp
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Rekey operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyResult {
    /// New epoch ID
    pub new_epoch: EpochId,

    /// Processing time
    pub processing_time: std::time::Duration,

    /// Members successfully rekeyed
    pub successful_members: Vec<MemberId>,

    /// Failed members with errors
    pub failed_members: Vec<(MemberId, String)>,

    /// Performance metrics
    pub metrics: RekeyMetrics,
}

/// Rekey performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyMetrics {
    /// Total members processed
    pub total_members: usize,

    /// Keys generated per second
    pub keys_per_second: f64,

    /// Memory peak usage (bytes)
    pub peak_memory_usage: u64,

    /// Network operations performed
    pub network_operations: u64,
}

/// Scalable group manager for high-performance group operations
pub struct ScalableGroupManager<S: Storage, N: Network> {
    /// Base client
    client: Arc<Client<S, N>>,

    /// Configuration
    config: ScalableGroupConfig,

    /// Member index for fast lookups
    member_index: Arc<Mutex<BTreeMap<MemberId, MemberInfo>>>,

    /// Processed update cache
    update_cache: Arc<Mutex<LruCache<GroupUpdateId, ProcessedUpdate>>>,

    /// Batch processor
    batch_processor: BatchProcessor,

    /// Performance metrics
    metrics: Arc<Mutex<GroupManagerMetrics>>,
}

/// Performance metrics for group management
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GroupManagerMetrics {
    /// Total group updates processed
    pub total_updates_processed: u64,

    /// Total members managed
    pub total_members_managed: u64,

    /// Average update processing time
    pub avg_update_time: std::time::Duration,

    /// Cache hit rate
    pub cache_hit_rate: f64,

    /// Batch operation statistics
    pub batch_stats: BatchStatistics,
}

/// Batch operation statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BatchStatistics {
    /// Total batch operations
    pub total_batches: u64,

    /// Average batch size
    pub avg_batch_size: f64,

    /// Average batch processing time
    pub avg_batch_time: std::time::Duration,

    /// Parallel efficiency (0.0 to 1.0)
    pub parallel_efficiency: f64,
}

impl<S: Storage, N: Network> ScalableGroupManager<S, N> {
    /// Create a new scalable group manager
    pub fn new(
        client: Arc<Client<S, N>>,
        config: ScalableGroupConfig,
    ) -> Result<Self, ClientError> {
        let member_index = Arc::new(Mutex::new(BTreeMap::new()));
        let update_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(config.update_cache_size).unwrap(),
        )));
        let batch_processor = BatchProcessor::new(&config);
        let metrics = Arc::new(Mutex::new(GroupManagerMetrics::default()));

        Ok(Self {
            client,
            config,
            member_index,
            update_cache,
            batch_processor,
            metrics,
        })
    }

    /// Process a large group update efficiently
    pub async fn process_large_group_update(
        &mut self,
        update: LargeGroupUpdate,
    ) -> Result<(), ClientError> {
        let start_time = Instant::now();

        // Check cache first
        if let Some(cached_result) = self.check_update_cache(&update.update_id).await {
            match cached_result.result {
                UpdateResult::Success => return Ok(()),
                UpdateResult::Failed(error) => {
                    return Err(ClientError::system_error(
                        ErrorCode::GroupStateConflict,
                        error,
                        "process_large_group_update".to_string(),
                        true,
                    ));
                }
                UpdateResult::PartialFailure(_) => {
                    // Proceed with reprocessing
                }
            }
        }

        // Validate group size limits
        let total_members = self.get_total_member_count().await?;
        let net_change = update.members_to_add.len() as i32 - update.members_to_remove.len() as i32;
        if (total_members as i32 + net_change) > self.config.max_group_size as i32 {
            return Err(ClientError::system_error(
                ErrorCode::GroupSizeLimitExceeded,
                format!(
                    "Group would exceed maximum size of {}",
                    self.config.max_group_size
                ),
                "process_large_group_update".to_string(),
                false,
            ));
        }

        let mut affected_members = Vec::new();
        let mut errors = Vec::new();

        // Process member additions in batches
        if !update.members_to_add.is_empty() {
            match self.batch_add_members(&update.members_to_add).await {
                Ok(added) => {
                    affected_members.extend(added);
                }
                Err(e) => {
                    errors.push(format!("Failed to add members: {}", e));
                }
            }
        }

        // Process member removals in batches
        if !update.members_to_remove.is_empty() {
            match self.batch_remove_members(&update.members_to_remove).await {
                Ok(removed) => {
                    affected_members.extend(removed);
                }
                Err(e) => {
                    errors.push(format!("Failed to remove members: {}", e));
                }
            }
        }

        // Process member updates in batches
        if !update.members_to_update.is_empty() {
            match self.batch_update_members(&update.members_to_update).await {
                Ok(updated) => {
                    affected_members.extend(updated);
                }
                Err(e) => {
                    errors.push(format!("Failed to update members: {}", e));
                }
            }
        }

        // Cache the result
        let result = if errors.is_empty() {
            UpdateResult::Success
        } else if affected_members.is_empty() {
            UpdateResult::Failed(errors.join("; "))
        } else {
            UpdateResult::PartialFailure(errors)
        };

        let processed_update = ProcessedUpdate {
            update_id: update.update_id,
            processed_at: chrono::Utc::now(),
            affected_members: affected_members.clone(),
            result: result.clone(),
        };

        self.cache_update_result(processed_update).await;

        // Update metrics
        self.update_processing_metrics(start_time, affected_members.len())
            .await;

        match result {
            UpdateResult::Success => Ok(()),
            UpdateResult::Failed(error) => Err(ClientError::system_error(
                ErrorCode::GroupStateConflict,
                error,
                "process_large_group_update".to_string(),
                true,
            )),
            UpdateResult::PartialFailure(errors) => Err(ClientError::system_error(
                ErrorCode::GroupStateConflict,
                format!("Partial failure: {}", errors.join("; ")),
                "process_large_group_update".to_string(),
                true,
            )),
        }
    }

    /// Generate welcome messages for new members in batches
    pub async fn batch_welcome_generation(
        &self,
        new_members: Vec<MemberId>,
    ) -> Result<Vec<Welcome>, ClientError> {
        let start_time = Instant::now();

        if new_members.is_empty() {
            return Ok(Vec::new());
        }

        // Process in batches to control memory usage
        let mut all_welcomes = Vec::new();

        for chunk in new_members.chunks(self.config.member_batch_size) {
            let chunk_welcomes = self
                .batch_processor
                .process_welcome_batch(chunk.to_vec(), self.client.clone())
                .await?;

            all_welcomes.extend(chunk_welcomes);
        }

        // Update metrics
        self.update_welcome_metrics(start_time, all_welcomes.len())
            .await;

        Ok(all_welcomes)
    }

    /// Perform parallel rekey operation for large groups
    pub async fn parallel_rekey_operation(
        &mut self,
        target_epoch: EpochId,
    ) -> Result<RekeyResult, ClientError> {
        let start_time = Instant::now();

        // Get all active members
        let active_members = self.get_active_members().await?;

        if active_members.is_empty() {
            return Ok(RekeyResult {
                new_epoch: target_epoch,
                processing_time: start_time.elapsed(),
                successful_members: Vec::new(),
                failed_members: Vec::new(),
                metrics: RekeyMetrics {
                    total_members: 0,
                    keys_per_second: 0.0,
                    peak_memory_usage: 0,
                    network_operations: 0,
                },
            });
        }

        let total_members = active_members.len();
        let mut successful_members = Vec::new();
        let mut failed_members = Vec::new();
        let mut network_operations = 0u64;

        // Process rekey in batches for better resource management
        for chunk in active_members.chunks(self.config.rekey_batch_size) {
            match self
                .batch_processor
                .process_rekey_batch(chunk.to_vec(), target_epoch, self.client.clone())
                .await
            {
                Ok((success, failures, ops)) => {
                    successful_members.extend(success);
                    failed_members.extend(failures);
                    network_operations += ops;
                }
                Err(e) => {
                    // Convert all members in this batch to failures
                    for member in chunk {
                        failed_members
                            .push((member.clone(), format!("Batch processing failed: {}", e)));
                    }
                }
            }
        }

        let processing_time = start_time.elapsed();
        let keys_per_second = if processing_time.as_secs_f64() > 0.0 {
            successful_members.len() as f64 / processing_time.as_secs_f64()
        } else {
            0.0
        };

        // Estimate peak memory usage (simplified calculation)
        let peak_memory_usage = (total_members * 1024) as u64; // Rough estimate

        Ok(RekeyResult {
            new_epoch: target_epoch,
            processing_time,
            successful_members,
            failed_members,
            metrics: RekeyMetrics {
                total_members,
                keys_per_second,
                peak_memory_usage,
                network_operations,
            },
        })
    }

    /// Add multiple members efficiently
    async fn batch_add_members(&self, members: &[MemberId]) -> Result<Vec<MemberId>, ClientError> {
        let mut added_members = Vec::new();

        for chunk in members.chunks(self.config.member_batch_size) {
            let chunk_results = self
                .batch_processor
                .process_add_members_batch(chunk.to_vec(), self.client.clone())
                .await?;

            added_members.extend(chunk_results);
        }

        // Update member index
        self.update_member_index_add(&added_members).await;

        Ok(added_members)
    }

    /// Remove multiple members efficiently
    async fn batch_remove_members(
        &self,
        members: &[MemberId],
    ) -> Result<Vec<MemberId>, ClientError> {
        let mut removed_members = Vec::new();

        for chunk in members.chunks(self.config.member_batch_size) {
            let chunk_results = self
                .batch_processor
                .process_remove_members_batch(chunk.to_vec(), self.client.clone())
                .await?;

            removed_members.extend(chunk_results);
        }

        // Update member index
        self.update_member_index_remove(&removed_members).await;

        Ok(removed_members)
    }

    /// Update multiple members efficiently
    async fn batch_update_members(
        &self,
        updates: &[(MemberId, MemberInfo)],
    ) -> Result<Vec<MemberId>, ClientError> {
        let mut updated_members = Vec::new();

        for chunk in updates.chunks(self.config.member_batch_size) {
            let chunk_results = self
                .batch_processor
                .process_update_members_batch(chunk.to_vec(), self.client.clone())
                .await?;

            updated_members.extend(chunk_results);
        }

        // Update member index
        self.update_member_index_update(updates).await;

        Ok(updated_members)
    }

    /// Check if update is cached
    async fn check_update_cache(&self, update_id: &GroupUpdateId) -> Option<ProcessedUpdate> {
        let mut cache = self.update_cache.lock().await;
        cache.get(update_id).cloned()
    }

    /// Cache update result
    async fn cache_update_result(&self, update: ProcessedUpdate) {
        let mut cache = self.update_cache.lock().await;
        cache.put(update.update_id, update);
    }

    /// Get total member count
    async fn get_total_member_count(&self) -> Result<usize, ClientError> {
        let index = self.member_index.lock().await;
        Ok(index.len())
    }

    /// Get all active members
    async fn get_active_members(&self) -> Result<Vec<MemberId>, ClientError> {
        let index = self.member_index.lock().await;
        Ok(index
            .iter()
            .filter(|(_, info)| matches!(info.status, MemberStatus::Active))
            .map(|(id, _)| id.clone())
            .collect())
    }

    /// Update member index with new members
    async fn update_member_index_add(&self, members: &[MemberId]) {
        let mut index = self.member_index.lock().await;
        let now = chrono::Utc::now();

        for member_id in members {
            let member_info = MemberInfo {
                member_id: member_id.clone(),
                capabilities: vec!["basic".to_string()],
                joined_at: now,
                last_active: now,
                status: MemberStatus::Active,
            };
            index.insert(member_id.clone(), member_info);
        }
    }

    /// Update member index by removing members
    async fn update_member_index_remove(&self, members: &[MemberId]) {
        let mut index = self.member_index.lock().await;

        for member_id in members {
            index.remove(member_id);
        }
    }

    /// Update member index with updated member info
    async fn update_member_index_update(&self, updates: &[(MemberId, MemberInfo)]) {
        let mut index = self.member_index.lock().await;

        for (member_id, member_info) in updates {
            index.insert(member_id.clone(), member_info.clone());
        }
    }

    /// Update processing metrics
    async fn update_processing_metrics(&self, start_time: Instant, members_affected: usize) {
        let mut metrics = self.metrics.lock().await;
        metrics.total_updates_processed += 1;
        metrics.total_members_managed += members_affected as u64;

        let processing_time = start_time.elapsed();
        let new_count = metrics.total_updates_processed;
        let old_avg = metrics.avg_update_time;

        // Update running average
        let new_avg_nanos = ((old_avg.as_nanos() * (new_count - 1) as u128)
            + processing_time.as_nanos())
            / new_count as u128;
        metrics.avg_update_time =
            std::time::Duration::from_nanos(new_avg_nanos.try_into().unwrap_or_else(|_| u64::MAX));
    }

    /// Update welcome generation metrics
    async fn update_welcome_metrics(&self, start_time: Instant, welcomes_generated: usize) {
        let mut metrics = self.metrics.lock().await;
        let processing_time = start_time.elapsed();

        metrics.batch_stats.total_batches += 1;
        let new_count = metrics.batch_stats.total_batches;
        let old_avg_size = metrics.batch_stats.avg_batch_size;
        let old_avg_time = metrics.batch_stats.avg_batch_time;

        // Update running averages
        metrics.batch_stats.avg_batch_size = ((old_avg_size * (new_count - 1) as f64)
            + welcomes_generated as f64)
            / new_count as f64;

        let new_avg_time_nanos = ((old_avg_time.as_nanos() * (new_count - 1) as u128)
            + processing_time.as_nanos())
            / new_count as u128;
        metrics.batch_stats.avg_batch_time = std::time::Duration::from_nanos(
            new_avg_time_nanos.try_into().unwrap_or_else(|_| u64::MAX),
        );
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> GroupManagerMetrics {
        self.metrics.lock().await.clone()
    }

    /// Reset performance metrics
    pub async fn reset_metrics(&self) {
        let mut metrics = self.metrics.lock().await;
        *metrics = GroupManagerMetrics::default();
    }
}

/// Batch processor for parallel operations
pub struct BatchProcessor {
    /// Semaphore for controlling concurrency
    semaphore: Arc<Semaphore>,
}

impl BatchProcessor {
    /// Create new batch processor
    pub fn new(config: &ScalableGroupConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_operations));

        Self { semaphore }
    }

    /// Process welcome message generation batch
    pub async fn process_welcome_batch<S: Storage, N: Network>(
        &self,
        members: Vec<MemberId>,
        client: Arc<Client<S, N>>,
    ) -> Result<Vec<Welcome>, ClientError> {
        let mut tasks = FuturesUnordered::new();

        for member_id in members {
            let _client = client.clone();
            let semaphore = self.semaphore.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.map_err(|_| {
                    ClientError::system_error(
                        ErrorCode::ResourceThreadPool,
                        "Failed to acquire semaphore permit".to_string(),
                        "process_welcome_batch".to_string(),
                        false,
                    )
                })?;

                // Generate welcome message (simplified)
                let welcome = Welcome {
                    member_id: member_id.clone(),
                    message_data: format!("Welcome {}", member_id).into_bytes(),
                    generated_at: chrono::Utc::now(),
                };

                Ok::<Welcome, ClientError>(welcome)
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        while let Some(task_result) = tasks.next().await {
            let welcome = task_result
                .map_err(|e| {
                    ClientError::system_error(
                        ErrorCode::ResourceThreadPool,
                        format!("Task failed: {}", e),
                        "process_welcome_batch".to_string(),
                        false,
                    )
                })?
                .map_err(|e| e)?;

            results.push(welcome);
        }

        Ok(results)
    }

    /// Process rekey operation batch
    pub async fn process_rekey_batch<S: Storage, N: Network>(
        &self,
        members: Vec<MemberId>,
        _target_epoch: EpochId,
        client: Arc<Client<S, N>>,
    ) -> Result<(Vec<MemberId>, Vec<(MemberId, String)>, u64), ClientError> {
        let mut tasks = FuturesUnordered::new();

        for member_id in members {
            let _client = client.clone();
            let semaphore = self.semaphore.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.map_err(|_| {
                    ClientError::system_error(
                        ErrorCode::ResourceThreadPool,
                        "Failed to acquire semaphore permit".to_string(),
                        "process_rekey_batch".to_string(),
                        false,
                    )
                })?;

                // Simulate rekey operation (simplified)
                if member_id.as_bytes()[0] % 10 == 0 {
                    // Simulate occasional failure
                    Err(ClientError::system_error(
                        ErrorCode::CryptoKeyGeneration,
                        "Simulated rekey failure".to_string(),
                        "rekey_member".to_string(),
                        true,
                    ))
                } else {
                    Ok(member_id)
                }
            });

            tasks.push(task);
        }

        let mut successful = Vec::new();
        let mut failed = Vec::new();
        let mut network_ops = 0u64;

        while let Some(task_result) = tasks.next().await {
            network_ops += 1;

            match task_result {
                Ok(Ok(member_id)) => {
                    successful.push(member_id);
                }
                Ok(Err(error)) => {
                    // Extract member ID from error context if possible
                    failed.push(("unknown_member".to_string(), error.to_string()));
                }
                Err(e) => {
                    failed.push(("unknown_member".to_string(), format!("Task failed: {}", e)));
                }
            }
        }

        Ok((successful, failed, network_ops))
    }

    /// Process member addition batch
    pub async fn process_add_members_batch<S: Storage, N: Network>(
        &self,
        members: Vec<MemberId>,
        _client: Arc<Client<S, N>>,
    ) -> Result<Vec<MemberId>, ClientError> {
        // Simplified implementation - in practice would integrate with actual group management
        Ok(members)
    }

    /// Process member removal batch
    pub async fn process_remove_members_batch<S: Storage, N: Network>(
        &self,
        members: Vec<MemberId>,
        _client: Arc<Client<S, N>>,
    ) -> Result<Vec<MemberId>, ClientError> {
        // Simplified implementation - in practice would integrate with actual group management
        Ok(members)
    }

    /// Process member update batch
    pub async fn process_update_members_batch<S: Storage, N: Network>(
        &self,
        updates: Vec<(MemberId, MemberInfo)>,
        _client: Arc<Client<S, N>>,
    ) -> Result<Vec<MemberId>, ClientError> {
        // Simplified implementation - in practice would integrate with actual group management
        Ok(updates.into_iter().map(|(id, _)| id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalable_group_config_default() {
        let config = ScalableGroupConfig::default();
        assert!(config.max_concurrent_operations > 0);
        assert!(config.member_batch_size > 0);
        assert!(config.update_cache_size > 0);
        assert!(config.rekey_batch_size > 0);
        assert_eq!(config.max_group_size, 10_000);
    }

    #[test]
    fn test_member_info_creation() {
        let member_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let member_info = MemberInfo {
            member_id: member_id.clone(),
            capabilities: vec!["basic".to_string()],
            joined_at: now,
            last_active: now,
            status: MemberStatus::Active,
        };

        assert_eq!(member_info.member_id, member_id);
        assert!(matches!(member_info.status, MemberStatus::Active));
    }

    #[test]
    fn test_large_group_update_structure() {
        let update = LargeGroupUpdate {
            update_id: uuid::Uuid::new_v4(),
            target_epoch: 1,
            members_to_add: vec![uuid::Uuid::new_v4().to_string()],
            members_to_remove: vec![uuid::Uuid::new_v4().to_string()],
            members_to_update: vec![],
            timestamp: chrono::Utc::now(),
        };

        assert!(!update.members_to_add.is_empty());
        assert!(!update.members_to_remove.is_empty());
        assert!(update.members_to_update.is_empty());
    }
}
