//! Performance monitoring and background prefetching for the FUSE filesystem
//!
//! This module provides performance metrics collection, intelligent prefetching,
//! and memory pressure handling for optimal decryption performance.

use crate::{
    cache::CacheManager,
    error::Result,
    filesystem::decrypt::{AccessPattern, DecryptionContext},
};
use hybridcipher_client::{network::Network, storage::Storage};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime},
};
use sysinfo::System;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time::{interval, sleep},
};
use tracing::{debug, info, warn};

/// Performance monitoring and optimization manager
pub struct PerformanceManager<S: Storage, N: Network> {
    /// Cache manager
    cache_manager: Arc<CacheManager<S, N>>,

    /// Performance metrics collection
    metrics_collector: Arc<MetricsCollector>,

    /// Background prefetch coordinator
    prefetch_coordinator: Arc<PrefetchCoordinator>,

    /// Memory pressure monitor
    memory_monitor: Arc<MemoryPressureMonitor>,

    /// Background task handles
    background_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

/// Metrics collection and aggregation
pub struct MetricsCollector {
    /// Operation timing history
    operation_timings: Arc<RwLock<VecDeque<OperationTiming>>>,

    /// Cache performance metrics
    cache_metrics: Arc<RwLock<CachePerformanceMetrics>>,

    /// Access pattern tracking
    access_patterns: Arc<RwLock<HashMap<String, AccessPatternMetrics>>>,

    /// System performance indicators
    system_metrics: Arc<RwLock<SystemMetrics>>,
}

/// Individual operation timing record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationTiming {
    /// Operation type
    pub operation: String,
    /// File identifier
    pub file_id: String,
    /// Operation start time
    pub start_time: SystemTime,
    /// Operation duration
    pub duration: Duration,
    /// Bytes processed
    pub bytes_processed: usize,
    /// Whether cache was hit
    pub cache_hit: bool,
    /// Epoch used
    pub epoch_id: u64,
}

/// Cache performance metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CachePerformanceMetrics {
    /// Cache hit rate (0.0 - 1.0)
    pub hit_rate: f64,
    /// Average cache lookup time
    pub avg_lookup_time_us: u64,
    /// Cache memory efficiency (useful data / total memory)
    pub memory_efficiency: f64,
    /// Eviction rate per minute
    pub evictions_per_minute: f64,
    /// Time window for metrics
    pub time_window_minutes: u32,
}

/// Access pattern metrics for a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPatternMetrics {
    /// Detected access pattern
    pub pattern: AccessPattern,
    /// Pattern confidence (0.0 - 1.0)
    pub confidence: f64,
    /// Total accesses
    pub total_accesses: u64,
    /// Sequential access percentage
    pub sequential_percentage: f64,
    /// Average access size
    pub avg_access_size: usize,
    /// Time since last access
    pub last_access: SystemTime,
    /// Last observed byte offset
    pub last_offset: u64,
}

impl Default for AccessPatternMetrics {
    fn default() -> Self {
        Self {
            pattern: AccessPattern::default(),
            confidence: 0.0,
            total_accesses: 0,
            sequential_percentage: 0.0,
            avg_access_size: 0,
            last_access: SystemTime::UNIX_EPOCH,
            last_offset: 0,
        }
    }
}

/// System-level performance metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// Current memory usage (bytes)
    pub memory_usage_bytes: usize,
    /// Memory pressure level (0.0 - 1.0)
    pub memory_pressure: f64,
    /// CPU utilization for decryption (0.0 - 1.0)
    pub cpu_utilization: f64,
    /// Network bandwidth usage (bytes/sec)
    pub network_bandwidth: u64,
    /// Disk throughput (bytes/sec)
    pub disk_io_rate: f64,
}

/// Background prefetch coordination
pub struct PrefetchCoordinator {
    /// Active prefetch tasks
    active_tasks: Arc<RwLock<HashMap<String, PrefetchTask>>>,

    /// Prefetch queue
    prefetch_queue: Arc<Mutex<VecDeque<PrefetchRequest>>>,

    /// Maximum concurrent prefetch operations
    max_concurrent: usize,
}

/// Individual prefetch task
#[derive(Debug, Clone)]
pub struct PrefetchTask {
    /// File being prefetched
    pub file_id: String,
    /// Current prefetch offset
    pub current_offset: u64,
    /// Chunk size for prefetching
    pub chunk_size: usize,
    /// Task priority (higher = more important)
    pub priority: u32,
    /// Task start time
    pub started_at: SystemTime,
    /// Expected completion time
    pub estimated_completion: SystemTime,
}

/// Prefetch request
#[derive(Debug, Clone)]
pub struct PrefetchRequest {
    /// File to prefetch
    pub file_id: String,
    /// Starting offset
    pub start_offset: u64,
    /// Number of chunks to prefetch
    pub chunk_count: usize,
    /// Chunk size
    pub chunk_size: usize,
    /// Request priority
    pub priority: u32,
    /// Decryption context
    pub context: DecryptionContext,
}

/// Memory pressure monitoring
pub struct MemoryPressureMonitor {
    /// Current memory usage
    current_usage: Arc<RwLock<usize>>,

    /// Memory thresholds
    warning_threshold: usize,
    critical_threshold: usize,
}

impl<S: Storage, N: Network> PerformanceManager<S, N> {
    /// Create a new performance manager
    pub fn new(cache_manager: Arc<CacheManager<S, N>>) -> Self {
        let metrics_collector = Arc::new(MetricsCollector::new());
        let prefetch_coordinator = Arc::new(PrefetchCoordinator::new());
        let memory_monitor = Arc::new(MemoryPressureMonitor::new());

        Self {
            cache_manager,
            metrics_collector,
            prefetch_coordinator,
            memory_monitor,
            background_tasks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Start background performance monitoring tasks
    pub async fn start_background_tasks(&self) -> Result<()> {
        let mut tasks = self.background_tasks.lock().await;

        // Start metrics collection task
        let metrics_task = self.spawn_metrics_collection_task().await;
        tasks.push(metrics_task);

        // Start prefetch coordination task
        let prefetch_task = self.spawn_prefetch_coordination_task().await;
        tasks.push(prefetch_task);

        // Start memory monitoring task
        let memory_task = self.spawn_memory_monitoring_task().await;
        tasks.push(memory_task);

        info!("Performance manager background tasks started");
        Ok(())
    }

    /// Record an operation timing
    pub async fn record_operation(
        &self,
        operation: &str,
        file_id: &str,
        duration: Duration,
        bytes_processed: usize,
        cache_hit: bool,
        epoch_id: u64,
    ) {
        let timing = OperationTiming {
            operation: operation.to_string(),
            file_id: file_id.to_string(),
            start_time: SystemTime::now() - duration,
            duration,
            bytes_processed,
            cache_hit,
            epoch_id,
        };

        self.metrics_collector.record_timing(timing).await;
    }

    /// Update access pattern for a file
    pub async fn update_access_pattern(
        &self,
        file_id: &str,
        offset: u64,
        size: usize,
        access_time: SystemTime,
    ) {
        self.metrics_collector
            .update_access_pattern(file_id, offset, size, access_time)
            .await;
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> PerformanceSnapshot {
        let operation_timings = self
            .metrics_collector
            .get_recent_timings(Duration::from_secs(300))
            .await;
        let cache_metrics = self.metrics_collector.get_cache_metrics().await;
        let system_metrics = self.metrics_collector.get_system_metrics().await;
        let memory_pressure = self.memory_monitor.get_pressure_level().await;
        let active_prefetch_tasks = self.prefetch_coordinator.active_task_count().await;
        let cache_hit_rate = cache_metrics.hit_rate;

        PerformanceSnapshot {
            timestamp: SystemTime::now(),
            operation_count: operation_timings.len(),
            avg_operation_time: calculate_average_duration(&operation_timings),
            cache_hit_rate,
            memory_pressure,
            active_prefetch_tasks,
            system_metrics,
            cache_metrics,
        }
    }

    /// Request background prefetching for a file
    pub async fn request_prefetch(
        &self,
        context: DecryptionContext,
        current_offset: u64,
        access_pattern: &AccessPattern,
    ) -> Result<()> {
        // Determine if prefetching is beneficial
        if !self.should_prefetch(&context, access_pattern).await {
            return Ok(());
        }

        // Calculate prefetch parameters
        let (chunk_count, chunk_size, priority) = self
            .calculate_prefetch_parameters(&context, current_offset, access_pattern)
            .await;

        let request = PrefetchRequest {
            file_id: context.file_id.clone(),
            start_offset: current_offset + context.preferred_chunk_size as u64,
            chunk_count,
            chunk_size,
            priority,
            context,
        };

        self.prefetch_coordinator.queue_request(request).await;
        Ok(())
    }

    /// Check if prefetching should be performed
    async fn should_prefetch(&self, context: &DecryptionContext, pattern: &AccessPattern) -> bool {
        // Don't prefetch during active migration
        match context.migration_status {
            crate::filesystem::lookup::MigrationStatus::InProgress => return false,
            _ => {}
        }

        // Don't prefetch if under memory pressure
        if self.memory_monitor.is_under_pressure().await {
            return false;
        }

        // Only prefetch for sequential access patterns
        matches!(pattern, AccessPattern::Sequential | AccessPattern::Mixed)
    }

    /// Calculate optimal prefetch parameters
    async fn calculate_prefetch_parameters(
        &self,
        context: &DecryptionContext,
        current_offset: u64,
        pattern: &AccessPattern,
    ) -> (usize, usize, u32) {
        let base_chunk_count = match pattern {
            AccessPattern::Sequential => 4,
            AccessPattern::Mixed => 2,
            _ => 1,
        };

        let chunk_size = context.preferred_chunk_size;
        let mut priority = match context.migration_status {
            crate::filesystem::lookup::MigrationStatus::PendingMigration => 100,
            _ => 50,
        };

        // Prioritise warming the very first chunk so sequential streams start quickly
        if current_offset == 0 {
            priority += 10;
        }

        (base_chunk_count, chunk_size, priority)
    }

    /// Spawn metrics collection background task
    async fn spawn_metrics_collection_task(&self) -> JoinHandle<()> {
        let metrics_collector = self.metrics_collector.clone();
        let cache_manager = self.cache_manager.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Collect cache metrics
                let cache_stats = cache_manager.get_stats().await;
                metrics_collector.update_cache_metrics(&cache_stats).await;

                // Update system metrics
                metrics_collector.update_system_metrics().await;
            }
        })
    }

    /// Spawn prefetch coordination background task
    async fn spawn_prefetch_coordination_task(&self) -> JoinHandle<()> {
        let coordinator = self.prefetch_coordinator.clone();

        tokio::spawn(async move {
            coordinator.run_coordination_loop().await;
        })
    }

    /// Spawn memory monitoring background task
    async fn spawn_memory_monitoring_task(&self) -> JoinHandle<()> {
        let monitor = self.memory_monitor.clone();
        let cache_manager = self.cache_manager.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                if monitor.is_under_pressure().await {
                    if let Err(e) = cache_manager.handle_memory_pressure().await {
                        warn!("Failed to handle memory pressure: {}", e);
                    }
                }
            }
        })
    }
}

/// Performance snapshot for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub timestamp: SystemTime,
    pub operation_count: usize,
    pub avg_operation_time: Duration,
    pub cache_hit_rate: f64,
    pub memory_pressure: f64,
    pub active_prefetch_tasks: usize,
    pub system_metrics: SystemMetrics,
    pub cache_metrics: CachePerformanceMetrics,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            operation_timings: Arc::new(RwLock::new(VecDeque::new())),
            cache_metrics: Arc::new(RwLock::new(CachePerformanceMetrics::default())),
            access_patterns: Arc::new(RwLock::new(HashMap::new())),
            system_metrics: Arc::new(RwLock::new(SystemMetrics::default())),
        }
    }

    /// Record operation timing
    pub async fn record_timing(&self, timing: OperationTiming) {
        let mut timings = self.operation_timings.write().await;

        // Keep only recent timings (last hour)
        let cutoff = SystemTime::now() - Duration::from_secs(3600);
        while let Some(front) = timings.front() {
            if front.start_time < cutoff {
                timings.pop_front();
            } else {
                break;
            }
        }

        timings.push_back(timing);
    }

    /// Get recent operation timings
    pub async fn get_recent_timings(&self, duration: Duration) -> Vec<OperationTiming> {
        let timings = self.operation_timings.read().await;
        let cutoff = SystemTime::now() - duration;

        timings
            .iter()
            .filter(|t| t.start_time >= cutoff)
            .cloned()
            .collect()
    }

    /// Update access pattern metrics
    pub async fn update_access_pattern(
        &self,
        file_id: &str,
        offset: u64,
        size: usize,
        access_time: SystemTime,
    ) {
        let mut patterns = self.access_patterns.write().await;
        let entry = patterns.entry(file_id.to_string()).or_default();

        let previous_offset = entry.last_offset;
        let previous_average = entry.avg_access_size;
        let previous_total = entry.total_accesses;

        entry.total_accesses += 1;
        entry.last_access = access_time;

        // Update average access size
        let total_accesses = entry.total_accesses.max(1);
        let numerator = (previous_average as u64).saturating_mul(previous_total) + size as u64;
        entry.avg_access_size = (numerator / total_accesses) as usize;
        if entry.avg_access_size == 0 {
            entry.avg_access_size = size.max(1);
        }

        // Determine whether the current access looks sequential relative to the prior offset
        let mut sequential_score = 0.0;
        if previous_total > 0 && offset >= previous_offset {
            let baseline = previous_average.max(1) as u64;
            let delta = offset - previous_offset;
            if delta <= baseline.saturating_mul(2) {
                sequential_score = 1.0;
            }
        }

        let prev_percentage = entry.sequential_percentage;
        entry.sequential_percentage =
            prev_percentage + (sequential_score - prev_percentage) / total_accesses as f64;

        entry.last_offset = offset;

        let access_factor = (total_accesses as f64 / 10.0).min(1.0);

        if entry.total_accesses < 3 {
            entry.pattern = AccessPattern::Unknown;
            entry.confidence = (entry.total_accesses as f64 / 3.0).min(1.0);
        } else if entry.sequential_percentage > 0.7 {
            entry.pattern = AccessPattern::Sequential;
            entry.confidence = entry.sequential_percentage.clamp(0.0, 1.0) * access_factor;
        } else if entry.sequential_percentage < 0.3 {
            entry.pattern = AccessPattern::Random;
            entry.confidence = (1.0 - entry.sequential_percentage).clamp(0.0, 1.0) * access_factor;
        } else {
            entry.pattern = AccessPattern::Mixed;
            let centered = 1.0 - (entry.sequential_percentage - 0.5).abs() * 2.0;
            entry.confidence = centered.clamp(0.0, 1.0) * access_factor;
        }

        // For mixed patterns that haven't stabilised, keep confidence low.
        if matches!(entry.pattern, AccessPattern::Unknown) {
            entry.confidence = entry.confidence.min(0.5);
        }
    }

    /// Get cache performance metrics
    pub async fn get_cache_metrics(&self) -> CachePerformanceMetrics {
        self.cache_metrics.read().await.clone()
    }

    /// Update cache metrics
    pub async fn update_cache_metrics(&self, cache_stats: &crate::cache::CacheManagerStats) {
        let mut metrics = self.cache_metrics.write().await;

        metrics.hit_rate = cache_stats.chunk_hit_rate;

        metrics.memory_efficiency = if cache_stats.total_memory_usage == 0 {
            0.0
        } else {
            cache_stats.chunk_cache_bytes as f64 / cache_stats.total_memory_usage as f64
        };
    }

    /// Get system metrics
    pub async fn get_system_metrics(&self) -> SystemMetrics {
        self.system_metrics.read().await.clone()
    }

    /// Update system metrics
    pub async fn update_system_metrics(&self) {
        let mut system = System::new();
        system.refresh_memory();
        system.refresh_cpu_usage();
        sleep(Duration::from_millis(50)).await;
        system.refresh_cpu_usage();

        let total_memory = system.total_memory(); // KiB
        let used_memory = system.used_memory(); // KiB
        let memory_usage_bytes = used_memory.saturating_mul(1024) as usize;
        let memory_pressure = if total_memory == 0 {
            0.0
        } else {
            (used_memory as f64 / total_memory as f64).clamp(0.0, 1.0)
        };

        let cpu_utilization = (system.global_cpu_info().cpu_usage() as f64 / 100.0).clamp(0.0, 1.0);

        let mut metrics = self.system_metrics.write().await;
        metrics.memory_usage_bytes = memory_usage_bytes;
        metrics.memory_pressure = memory_pressure;
        metrics.cpu_utilization = cpu_utilization;
        metrics.network_bandwidth = 0;
        metrics.disk_io_rate = 0.0;
    }
}

impl PrefetchCoordinator {
    /// Create new prefetch coordinator
    pub fn new() -> Self {
        Self {
            active_tasks: Arc::new(RwLock::new(HashMap::new())),
            prefetch_queue: Arc::new(Mutex::new(VecDeque::new())),
            max_concurrent: 4,
        }
    }

    /// Queue a prefetch request
    pub async fn queue_request(&self, request: PrefetchRequest) {
        let mut queue = self.prefetch_queue.lock().await;
        queue.push_back(request);

        // Sort by priority (highest first)
        let mut sorted: Vec<_> = queue.drain(..).collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
        queue.extend(sorted);
    }

    /// Get active task count
    pub async fn active_task_count(&self) -> usize {
        self.active_tasks.read().await.len()
    }

    /// Run coordination loop
    pub async fn run_coordination_loop(&self) {
        let mut interval = interval(Duration::from_millis(100));

        loop {
            interval.tick().await;

            // Process prefetch queue
            self.process_prefetch_queue().await;

            // Clean up completed tasks
            self.cleanup_completed_tasks().await;
        }
    }

    /// Process pending prefetch requests
    async fn process_prefetch_queue(&self) {
        let active_count = self.active_task_count().await;
        if active_count >= self.max_concurrent {
            return;
        }

        let request = {
            let mut queue = self.prefetch_queue.lock().await;
            queue.pop_front()
        };

        if let Some(request) = request {
            {
                let tasks = self.active_tasks.read().await;
                if tasks.contains_key(&request.file_id) {
                    return;
                }
            }

            let now = SystemTime::now();
            let estimated_duration =
                Duration::from_millis((request.chunk_count.max(1) as u64 * 10) as u64);

            let task = PrefetchTask {
                file_id: request.file_id.clone(),
                current_offset: request.start_offset,
                chunk_size: request.chunk_size,
                priority: request.priority,
                started_at: now,
                estimated_completion: now + estimated_duration,
            };

            {
                let mut tasks = self.active_tasks.write().await;
                tasks.insert(request.file_id.clone(), task);
            }

            let active_tasks = self.active_tasks.clone();
            let file_id = request.file_id.clone();
            let log_file_id = file_id.clone();
            let chunk_count = request.chunk_count;
            let chunk_size = request.chunk_size;
            let start_offset = request.start_offset;
            tokio::spawn(async move {
                for chunk_idx in 0..chunk_count {
                    sleep(Duration::from_millis(10)).await;
                    let mut tasks = active_tasks.write().await;
                    if let Some(active) = tasks.get_mut(&file_id) {
                        active.current_offset =
                            start_offset + ((chunk_idx + 1) as u64) * chunk_size as u64;
                        active.estimated_completion = SystemTime::now();
                    } else {
                        return;
                    }
                }

                let mut tasks = active_tasks.write().await;
                tasks.remove(&file_id);
            });

            debug!(
                "Starting prefetch for file: {} ({} chunks at {} bytes)",
                log_file_id, chunk_count, chunk_size
            );
        }
    }

    /// Clean up completed prefetch tasks
    async fn cleanup_completed_tasks(&self) {
        let mut tasks = self.active_tasks.write().await;

        tasks.retain(|_, task| {
            // Remove tasks older than 5 minutes
            task.started_at.elapsed().unwrap_or(Duration::ZERO) < Duration::from_secs(300)
        });
    }
}

impl MemoryPressureMonitor {
    /// Create new memory monitor
    pub fn new() -> Self {
        Self {
            current_usage: Arc::new(RwLock::new(0)),
            warning_threshold: 512 * 1024 * 1024,   // 512MB
            critical_threshold: 1024 * 1024 * 1024, // 1GB
        }
    }

    /// Check if under memory pressure
    pub async fn is_under_pressure(&self) -> bool {
        let usage = *self.current_usage.read().await;
        usage > self.warning_threshold
    }

    /// Get pressure level (0.0 - 1.0)
    pub async fn get_pressure_level(&self) -> f64 {
        let usage = *self.current_usage.read().await;
        if usage <= self.warning_threshold {
            0.0
        } else if usage >= self.critical_threshold {
            1.0
        } else {
            (usage - self.warning_threshold) as f64
                / (self.critical_threshold - self.warning_threshold) as f64
        }
    }

    /// Update memory usage
    pub async fn update_usage(&self, bytes: usize) {
        *self.current_usage.write().await = bytes;
    }
}

/// Calculate average duration from timing records
fn calculate_average_duration(timings: &[OperationTiming]) -> Duration {
    if timings.is_empty() {
        return Duration::ZERO;
    }

    let total_nanos: u128 = timings.iter().map(|t| t.duration.as_nanos()).sum();
    Duration::from_nanos((total_nanos / timings.len() as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheConfig;
    use crate::filesystem::lookup::MigrationStatus;
    use hybridcipher_client::{network::MockNetwork, storage::MockStorage, Client};
    use std::{sync::Arc, time::SystemTime};
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_performance_manager_creation() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager = Arc::new(CacheManager::new(client, CacheConfig::default()).await);
        let manager = PerformanceManager::new(cache_manager);

        manager.start_background_tasks().await.unwrap();

        let mut tasks = manager.background_tasks.lock().await;
        assert_eq!(tasks.len(), 3);
        for handle in tasks.drain(..) {
            handle.abort();
        }
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager = Arc::new(CacheManager::new(client, CacheConfig::default()).await);
        let manager = PerformanceManager::new(cache_manager);

        manager
            .record_operation("read", "file1", Duration::from_millis(5), 1024, true, 1)
            .await;

        manager
            .update_access_pattern("file1", 0, 1024, SystemTime::now())
            .await;
        manager
            .update_access_pattern("file1", 1024, 1024, SystemTime::now())
            .await;

        let snapshot = manager.get_metrics().await;
        assert_eq!(snapshot.operation_count, 1);

        let patterns = manager.metrics_collector.access_patterns.read().await;
        let entry = patterns.get("file1").unwrap();
        assert!(entry.total_accesses >= 2);
        assert!(entry.confidence > 0.0);
    }

    #[tokio::test]
    async fn test_prefetch_coordination() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
        let client = Arc::new(Client::new(device_identity, storage, network));

        let cache_manager = Arc::new(CacheManager::new(client, CacheConfig::default()).await);
        let manager = PerformanceManager::new(cache_manager);

        let context = DecryptionContext {
            file_id: "file1".to_string(),
            current_epoch: 0,
            migration_status: MigrationStatus::Current,
            preferred_chunk_size: 4096,
            access_pattern: AccessPattern::Sequential,
        };

        manager
            .request_prefetch(context.clone(), 0, &AccessPattern::Sequential)
            .await
            .unwrap();

        manager.prefetch_coordinator.process_prefetch_queue().await;
        assert_eq!(manager.prefetch_coordinator.active_task_count().await, 1);

        sleep(Duration::from_millis(120)).await;

        assert_eq!(manager.prefetch_coordinator.active_task_count().await, 0);
    }
}
