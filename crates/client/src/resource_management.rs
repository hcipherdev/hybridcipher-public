use futures::future::join_all;
use serde::{Deserialize, Serialize};
/// System Resource Management for HybridCipher
///
/// Provides optimized resource allocation and management for memory, CPU, and I/O operations.
/// Implements memory pools, thread pools, and I/O scheduling for enterprise-scale performance.
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::{errors::ErrorCode, ClientError};

/// Configuration for resource management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    /// Maximum memory pool size in bytes
    pub max_memory_pool_size: usize,

    /// Thread pool size for CPU-intensive operations
    pub cpu_thread_pool_size: usize,

    /// Maximum concurrent I/O operations
    pub max_concurrent_io: usize,

    /// Memory allocation alignment
    pub memory_alignment: usize,

    /// I/O queue depth for scheduling
    pub io_queue_depth: usize,

    /// CPU cache line size optimization
    pub cpu_cache_line_size: usize,

    /// Minimum threshold for memory pool allocation
    pub min_pool_allocation: usize,

    /// Maximum threshold for memory pool allocation  
    pub max_pool_allocation: usize,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            max_memory_pool_size: 512 * 1024 * 1024, // 512MB
            cpu_thread_pool_size: num_cpus::get() * 2,
            max_concurrent_io: 256,
            memory_alignment: 64, // 64-byte alignment for cache optimization
            io_queue_depth: 128,
            cpu_cache_line_size: 64,
            min_pool_allocation: 1024,             // 1KB
            max_pool_allocation: 64 * 1024 * 1024, // 64MB
        }
    }
}

/// Secure memory buffer with automatic zeroization
pub struct SecureBuffer {
    data: Box<[u8]>,
    size: usize,
}

impl SecureBuffer {
    /// Create new secure buffer with specified size and alignment
    pub fn new(size: usize, alignment: usize) -> Result<Self, ResourceError> {
        if size == 0 {
            return Err(ResourceError::InvalidSize { size });
        }

        // Ensure requested allocation can be represented before constructing buffer
        std::alloc::Layout::from_size_align(size, alignment)
            .map_err(|_| ResourceError::AllocationFailed { size, alignment })?;

        let data = vec![0u8; size].into_boxed_slice();

        Ok(Self { data, size })
    }

    /// Get mutable slice to buffer data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get immutable slice to buffer data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get buffer size
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Securely zero memory on drop
        for byte in self.data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Memory pool for efficient allocation and reuse
pub struct MemoryPool {
    /// Configuration
    config: ResourceConfig,

    /// Available memory blocks by size
    available_blocks: Arc<Mutex<HashMap<usize, VecDeque<SecureBuffer>>>>,

    /// Total allocated memory
    total_allocated: Arc<Mutex<usize>>,

    /// Allocation statistics
    stats: Arc<Mutex<MemoryPoolStats>>,
}

/// Memory pool statistics
#[derive(Debug, Clone, Default)]
pub struct MemoryPoolStats {
    /// Total allocations performed
    pub total_allocations: u64,

    /// Total deallocations performed
    pub total_deallocations: u64,

    /// Cache hits (reused allocations)
    pub cache_hits: u64,

    /// Cache misses (new allocations)
    pub cache_misses: u64,

    /// Peak memory usage
    pub peak_memory_usage: usize,

    /// Current memory usage
    pub current_memory_usage: usize,
}

impl MemoryPool {
    /// Create new memory pool
    pub fn new(config: ResourceConfig) -> Self {
        Self {
            config,
            available_blocks: Arc::new(Mutex::new(HashMap::new())),
            total_allocated: Arc::new(Mutex::new(0)),
            stats: Arc::new(Mutex::new(MemoryPoolStats::default())),
        }
    }

    /// Allocate secure memory buffer
    pub fn allocate(&self, size: usize) -> Result<SecureBuffer, ResourceError> {
        // Round up to next power of 2 for efficient pooling
        let pool_size = self.round_up_to_power_of_2(size.max(self.config.min_pool_allocation));

        // Check pool size limits
        if pool_size > self.config.max_pool_allocation {
            return Err(ResourceError::AllocationTooLarge { size: pool_size });
        }

        let mut stats = self.stats.lock().unwrap();
        stats.total_allocations += 1;

        // Try to reuse from pool first
        if let Some(buffer) = self.try_reuse_from_pool(pool_size) {
            stats.cache_hits += 1;
            return Ok(buffer);
        }

        // Check total memory limits
        {
            let mut total_allocated = self.total_allocated.lock().unwrap();
            if *total_allocated + pool_size > self.config.max_memory_pool_size {
                return Err(ResourceError::OutOfMemory {
                    requested: pool_size,
                    available: self
                        .config
                        .max_memory_pool_size
                        .saturating_sub(*total_allocated),
                });
            }
            *total_allocated += pool_size;
        }

        // Allocate new buffer
        stats.cache_misses += 1;
        stats.current_memory_usage += pool_size;
        if stats.current_memory_usage > stats.peak_memory_usage {
            stats.peak_memory_usage = stats.current_memory_usage;
        }

        SecureBuffer::new(pool_size, self.config.memory_alignment)
    }

    /// Deallocate memory buffer back to pool
    pub fn deallocate(&self, buffer: SecureBuffer) {
        let size = buffer.size();

        let mut stats = self.stats.lock().unwrap();
        stats.total_deallocations += 1;
        stats.current_memory_usage = stats.current_memory_usage.saturating_sub(size);

        // Return to pool for reuse
        let mut available_blocks = self.available_blocks.lock().unwrap();
        available_blocks
            .entry(size)
            .or_insert_with(VecDeque::new)
            .push_back(buffer);
    }

    /// Try to reuse buffer from pool
    fn try_reuse_from_pool(&self, size: usize) -> Option<SecureBuffer> {
        let mut available_blocks = self.available_blocks.lock().unwrap();
        available_blocks.get_mut(&size)?.pop_front()
    }

    /// Round up to next power of 2
    fn round_up_to_power_of_2(&self, size: usize) -> usize {
        if size <= 1 {
            return 1;
        }

        let mut result = 1;
        while result < size {
            result <<= 1;
        }
        result
    }

    /// Get memory pool statistics
    pub fn get_stats(&self) -> MemoryPoolStats {
        self.stats.lock().unwrap().clone()
    }
}

/// Thread pool for CPU-intensive operations
pub struct ThreadPool {
    /// Semaphore for controlling concurrency
    semaphore: Arc<Semaphore>,

    /// Thread pool statistics
    stats: Arc<Mutex<ThreadPoolStats>>,
}

/// Thread pool statistics
#[derive(Debug, Clone, Default)]
pub struct ThreadPoolStats {
    /// Total tasks executed
    pub total_tasks: u64,

    /// Currently running tasks
    pub active_tasks: u64,

    /// Average task execution time
    pub avg_execution_time: Duration,

    /// Peak concurrent tasks
    pub peak_concurrent_tasks: u64,
}

impl ThreadPool {
    /// Create new thread pool
    pub fn new(config: &ResourceConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.cpu_thread_pool_size)),
            stats: Arc::new(Mutex::new(ThreadPoolStats::default())),
        }
    }

    /// Schedule CPU-intensive task
    pub async fn schedule_task<T>(
        &self,
        task: impl FnOnce() -> T + Send + 'static,
    ) -> Result<JoinHandle<T>, ResourceError>
    where
        T: Send + 'static,
    {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ResourceError::ThreadPoolOverloaded)?;

        let stats = self.stats.clone();

        // Update statistics
        {
            let mut stats_guard = stats.lock().unwrap();
            stats_guard.total_tasks += 1;
            stats_guard.active_tasks += 1;
            if stats_guard.active_tasks > stats_guard.peak_concurrent_tasks {
                stats_guard.peak_concurrent_tasks = stats_guard.active_tasks;
            }
        }

        let handle = tokio::task::spawn_blocking(move || {
            let start_time = Instant::now();
            let result = task();
            let execution_time = start_time.elapsed();

            // Update execution time statistics
            {
                let mut stats_guard = stats.lock().unwrap();
                stats_guard.active_tasks -= 1;

                // Update average execution time
                let total_tasks = stats_guard.total_tasks;
                let old_avg = stats_guard.avg_execution_time;
                let new_avg_nanos = ((old_avg.as_nanos() * (total_tasks - 1) as u128)
                    + execution_time.as_nanos())
                    / total_tasks as u128;
                stats_guard.avg_execution_time =
                    Duration::from_nanos(new_avg_nanos.try_into().unwrap_or_else(|_| u64::MAX));
            }

            drop(permit); // Release semaphore permit
            result
        });

        Ok(handle)
    }

    /// Get thread pool statistics
    pub fn get_stats(&self) -> ThreadPoolStats {
        self.stats.lock().unwrap().clone()
    }
}

/// I/O operation types
#[derive(Debug, Clone)]
pub enum IoOperation {
    /// Read operation
    Read {
        path: String,
        offset: u64,
        size: usize,
        priority: u8,
    },

    /// Write operation
    Write {
        path: String,
        offset: u64,
        data: Vec<u8>,
        priority: u8,
    },

    /// Sync operation
    Sync { path: String, priority: u8 },
}

impl IoOperation {
    /// Get operation priority
    pub fn priority(&self) -> u8 {
        match self {
            IoOperation::Read { priority, .. } => *priority,
            IoOperation::Write { priority, .. } => *priority,
            IoOperation::Sync { priority, .. } => *priority,
        }
    }

    /// Get operation path
    pub fn path(&self) -> &str {
        match self {
            IoOperation::Read { path, .. } => path,
            IoOperation::Write { path, .. } => path,
            IoOperation::Sync { path, .. } => path,
        }
    }
}

/// I/O scheduler for optimizing disk operations
pub struct IoScheduler {
    /// Pending operations queue
    queue: Arc<Mutex<VecDeque<IoOperation>>>,

    /// Semaphore for controlling concurrency
    semaphore: Arc<Semaphore>,

    /// I/O statistics
    stats: Arc<Mutex<IoStats>>,
}

/// I/O statistics
#[derive(Debug, Clone, Default)]
pub struct IoStats {
    /// Total I/O operations
    pub total_operations: u64,

    /// Read operations
    pub read_operations: u64,

    /// Write operations
    pub write_operations: u64,

    /// Sync operations
    pub sync_operations: u64,

    /// Total bytes read
    pub bytes_read: u64,

    /// Total bytes written
    pub bytes_written: u64,

    /// Average I/O time
    pub avg_io_time: Duration,
}

impl IoScheduler {
    /// Create new I/O scheduler
    pub fn new(config: &ResourceConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_io)),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(Mutex::new(IoStats::default())),
        }
    }

    /// Schedule I/O operation
    pub async fn schedule_io(&self, operation: IoOperation) -> Result<(), ResourceError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| ResourceError::IoQueueFull)?;

        let mut queue = self.queue.lock().unwrap();
        queue.push_back(operation);

        Ok(())
    }

    /// Optimize I/O operations for better performance
    pub fn optimize_operations(&self, mut operations: Vec<IoOperation>) -> Vec<IoOperation> {
        // Sort by priority (higher priority first) and then by path for locality
        operations.sort_by(|a, b| {
            b.priority()
                .cmp(&a.priority())
                .then_with(|| a.path().cmp(b.path()))
        });

        // Group sequential operations on the same file
        let mut optimized = Vec::new();
        let mut current_group = Vec::new();
        let mut current_path = String::new();

        for op in operations {
            if op.path() != current_path && !current_group.is_empty() {
                // Merge sequential operations in current group
                optimized
                    .extend(self.merge_sequential_operations(std::mem::take(&mut current_group)));
            }
            current_group.push(op);
            current_path = current_group.last().unwrap().path().to_string();
        }

        // Handle last group
        if !current_group.is_empty() {
            optimized.extend(self.merge_sequential_operations(current_group));
        }

        optimized
    }

    /// Merge sequential operations on the same file
    fn merge_sequential_operations(&self, operations: Vec<IoOperation>) -> Vec<IoOperation> {
        // For now, return as-is. In a full implementation, we would merge
        // sequential reads/writes to reduce I/O overhead
        operations
    }

    /// Process queued I/O operations
    pub async fn process_queue(&self) -> Result<(), ResourceError> {
        let operations = {
            let mut queue = self.queue.lock().unwrap();
            let ops: Vec<IoOperation> = queue.drain(..).collect();
            ops
        };

        if operations.is_empty() {
            return Ok(());
        }

        let optimized_ops = self.optimize_operations(operations);

        // Execute operations with controlled concurrency
        let semaphore = &self.semaphore;
        let stats = &self.stats;

        let tasks: Vec<_> = optimized_ops
            .into_iter()
            .map(|op| {
                let semaphore = semaphore.clone();
                let stats = stats.clone();

                tokio::spawn(async move {
                    let _permit = semaphore
                        .acquire()
                        .await
                        .map_err(|_| ResourceError::IoQueueFull)?;
                    let start_time = Instant::now();

                    // Execute the I/O operation (simplified)
                    let result: Result<(), ResourceError> = match &op {
                        IoOperation::Read { size, .. } => {
                            // Simulate read operation
                            tokio::time::sleep(Duration::from_micros(10)).await;

                            let mut stats_guard = stats.lock().unwrap();
                            stats_guard.read_operations += 1;
                            stats_guard.bytes_read += *size as u64;
                            Ok(())
                        }
                        IoOperation::Write { data, .. } => {
                            // Simulate write operation
                            tokio::time::sleep(Duration::from_micros(20)).await;

                            let mut stats_guard = stats.lock().unwrap();
                            stats_guard.write_operations += 1;
                            stats_guard.bytes_written += data.len() as u64;
                            Ok(())
                        }
                        IoOperation::Sync { .. } => {
                            // Simulate sync operation
                            tokio::time::sleep(Duration::from_micros(100)).await;

                            let mut stats_guard = stats.lock().unwrap();
                            stats_guard.sync_operations += 1;
                            Ok(())
                        }
                    };

                    let io_time = start_time.elapsed();

                    // Update timing statistics
                    {
                        let mut stats_guard = stats.lock().unwrap();
                        stats_guard.total_operations += 1;

                        let total_ops = stats_guard.total_operations;
                        let old_avg = stats_guard.avg_io_time;
                        let new_avg_nanos = ((old_avg.as_nanos() * (total_ops - 1) as u128)
                            + io_time.as_nanos())
                            / total_ops as u128;
                        stats_guard.avg_io_time = Duration::from_nanos(
                            new_avg_nanos.try_into().unwrap_or_else(|_| u64::MAX),
                        );
                    }

                    result
                })
            })
            .collect();

        let results = join_all(tasks).await;

        // Check for any failures
        for result in results {
            if let Err(e) = result {
                return Err(ResourceError::IoExecutionFailed {
                    details: format!("Task execution failed: {}", e),
                });
            }
        }

        Ok(())
    }

    /// Get I/O statistics
    pub fn get_stats(&self) -> IoStats {
        self.stats.lock().unwrap().clone()
    }
}

/// Main resource manager
pub struct ResourceManager {
    /// Memory pool for efficient allocation
    pub memory_pool: MemoryPool,

    /// Thread pool for CPU-intensive operations
    pub thread_pool: ThreadPool,

    /// I/O scheduler for disk operations
    pub io_scheduler: IoScheduler,

    /// Configuration
    config: ResourceConfig,
}

impl ResourceManager {
    /// Create new resource manager
    pub fn new(config: ResourceConfig) -> Self {
        let memory_pool = MemoryPool::new(config.clone());
        let thread_pool = ThreadPool::new(&config);
        let io_scheduler = IoScheduler::new(&config);

        Self {
            memory_pool,
            thread_pool,
            io_scheduler,
            config,
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(ResourceConfig::default())
    }

    /// Allocate secure memory
    pub fn allocate_secure_memory(&mut self, size: usize) -> Result<SecureBuffer, ResourceError> {
        self.memory_pool.allocate(size)
    }

    /// Schedule CPU-intensive task
    pub async fn schedule_cpu_intensive_task<T>(
        &self,
        task: impl FnOnce() -> T + Send + 'static,
    ) -> Result<JoinHandle<T>, ResourceError>
    where
        T: Send + 'static,
    {
        self.thread_pool.schedule_task(task).await
    }

    /// Optimize I/O operations
    pub fn optimize_io_operations(&self, operations: Vec<IoOperation>) -> Vec<IoOperation> {
        self.io_scheduler.optimize_operations(operations)
    }

    /// Schedule I/O operation
    pub async fn schedule_io_operation(&self, operation: IoOperation) -> Result<(), ResourceError> {
        self.io_scheduler.schedule_io(operation).await
    }

    /// Get comprehensive resource statistics
    pub fn get_resource_stats(&self) -> ResourceStats {
        ResourceStats {
            memory_stats: self.memory_pool.get_stats(),
            thread_stats: self.thread_pool.get_stats(),
            io_stats: self.io_scheduler.get_stats(),
            config: self.config.clone(),
        }
    }
}

/// Comprehensive resource statistics
#[derive(Debug, Clone)]
pub struct ResourceStats {
    /// Memory pool statistics
    pub memory_stats: MemoryPoolStats,

    /// Thread pool statistics
    pub thread_stats: ThreadPoolStats,

    /// I/O statistics
    pub io_stats: IoStats,

    /// Configuration
    pub config: ResourceConfig,
}

/// Resource management errors
#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("Invalid buffer size: {size}")]
    InvalidSize { size: usize },

    #[error("Memory allocation failed: size={size}, alignment={alignment}")]
    AllocationFailed { size: usize, alignment: usize },

    #[error("Allocation too large: {size} bytes")]
    AllocationTooLarge { size: usize },

    #[error("Out of memory: requested={requested}, available={available}")]
    OutOfMemory { requested: usize, available: usize },

    #[error("Thread pool overloaded")]
    ThreadPoolOverloaded,

    #[error("I/O queue full")]
    IoQueueFull,

    #[error("I/O execution failed: {details}")]
    IoExecutionFailed { details: String },
}

impl From<ResourceError> for ClientError {
    fn from(error: ResourceError) -> Self {
        ClientError::system_error(
            ErrorCode::ResourceManagementFailed,
            error.to_string(),
            "resource_management".to_string(),
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_allocation() {
        let buffer = SecureBuffer::new(1024, 64).unwrap();
        assert_eq!(buffer.size(), 1024);
        assert_eq!(buffer.as_slice().len(), 1024);
    }

    #[test]
    fn test_memory_pool_allocation_reuse() {
        let config = ResourceConfig::default();
        let pool = MemoryPool::new(config);

        // Allocate and deallocate
        let buffer1 = pool.allocate(1024).unwrap();
        let size = buffer1.size();
        assert_eq!(size, 1024);
        pool.deallocate(buffer1);

        // Should reuse from pool
        let stats_before = pool.get_stats();
        let _buffer2 = pool.allocate(1024).unwrap();
        let stats_after = pool.get_stats();

        assert_eq!(stats_after.cache_hits, stats_before.cache_hits + 1);
    }

    #[tokio::test]
    async fn test_thread_pool_task_execution() {
        let config = ResourceConfig {
            cpu_thread_pool_size: 2,
            ..Default::default()
        };
        let pool = ThreadPool::new(&config);

        let handle = pool
            .schedule_task(|| {
                std::thread::sleep(Duration::from_millis(10));
                42
            })
            .await
            .unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, 42);

        let stats = pool.get_stats();
        assert_eq!(stats.total_tasks, 1);
    }

    #[tokio::test]
    async fn test_io_scheduler_optimization() {
        let config = ResourceConfig::default();
        let scheduler = IoScheduler::new(&config);

        let operations = vec![
            IoOperation::Read {
                path: "file2.txt".to_string(),
                offset: 0,
                size: 1024,
                priority: 1,
            },
            IoOperation::Read {
                path: "file1.txt".to_string(),
                offset: 0,
                size: 1024,
                priority: 2,
            },
            IoOperation::Write {
                path: "file1.txt".to_string(),
                offset: 1024,
                data: vec![0; 512],
                priority: 1,
            },
        ];

        let optimized = scheduler.optimize_operations(operations);

        // Should be sorted by priority first
        assert_eq!(optimized[0].priority(), 2);
        assert_eq!(optimized[0].path(), "file1.txt");
    }

    #[tokio::test]
    async fn test_resource_manager_integration() {
        let mut manager = ResourceManager::new_default();

        // Test memory allocation
        let buffer = manager.allocate_secure_memory(2048).unwrap();
        assert!(buffer.size() >= 2048);

        // Test CPU task scheduling
        let handle = manager
            .schedule_cpu_intensive_task(|| "test_result".to_string())
            .await
            .unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, "test_result");

        // Test I/O operation scheduling
        let io_op = IoOperation::Read {
            path: "test.txt".to_string(),
            offset: 0,
            size: 1024,
            priority: 1,
        };

        manager.schedule_io_operation(io_op).await.unwrap();

        let stats = manager.get_resource_stats();
        assert!(stats.memory_stats.total_allocations > 0);
        assert!(stats.thread_stats.total_tasks > 0);
    }
}
