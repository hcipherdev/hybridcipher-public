//! Migration tracking and coordination module for mount crate.
//!
//! This module provides functionality for tracking file migration status,
//! progress monitoring, epoch coordination, and opportunistic migration scheduling.

use anyhow::Result;
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Migration progress information
#[derive(Debug, Clone)]
pub struct MigrationProgress {
    pub file_id: String,
    pub from_epoch: String,
    pub to_epoch: String,
    pub progress_percentage: f32,
    pub bytes_migrated: u64,
    pub total_bytes: u64,
    pub started_at: SystemTime,
    pub estimated_completion: Option<SystemTime>,
}

/// Migration statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct MigrationStats {
    pub total_files: u64,
    pub migrated_files: u64,
    pub failed_files: u64,
    pub bytes_migrated: u64,
    pub total_bytes: u64,
    pub migration_rate_bps: f64,
    pub estimated_time_remaining: Option<Duration>,
}

/// File migration status
#[derive(Debug, Clone, PartialEq)]
pub enum FileMigrationStatus {
    NotStarted,
    Queued,
    InProgress,
    Completed,
    Failed(String),
}

/// Migration event for notifications
#[derive(Debug, Clone)]
pub enum MigrationEvent {
    FileQueued { file_id: String },
    FileStarted { file_id: String },
    FileProgress { file_id: String, progress: f32 },
    FileCompleted { file_id: String },
    FileFailed { file_id: String, error: String },
    MigrationCompleted,
}

/// Main migration tracker for FUSE operations
///
/// This struct coordinates migration activities across the FUSE filesystem,
/// providing progress monitoring, opportunistic migration scheduling, and
/// statistics collection for user visibility.
pub struct MigrationTracker<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
> {
    /// HybridCipher client for migration operations
    client: Arc<hybridcipher_client::Client<S, N>>,

    /// Currently active migration information
    active_migration: Arc<RwLock<Option<MigrationInfo>>>,

    /// Per-file migration progress tracking
    file_progress: Arc<DashMap<String, MigrationProgress>>,

    /// Overall migration statistics
    stats: Arc<RwLock<MigrationStats>>,

    /// Migration event broadcaster
    event_sender: mpsc::UnboundedSender<MigrationEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<MigrationEvent>>>>,

    /// Opportunistic migration queue
    opportunistic_queue: Arc<DashMap<String, OpportunisticMigrationRequest>>,

    /// Migration rate limiter
    rate_limiter: Arc<RateLimiter>,
}

/// Active migration information
#[derive(Debug, Clone)]
pub struct MigrationInfo {
    pub from_epoch: String,
    pub to_epoch: String,
    pub started_at: SystemTime,
    pub total_files: u64,
}

/// Opportunistic migration request
#[derive(Debug, Clone)]
struct OpportunisticMigrationRequest {
    file_id: String,
    from_epoch: String,
    to_epoch: String,
    priority: u8,
}

/// Rate limiter for migration operations
#[derive(Debug)]
struct RateLimiter {
    tokens: Arc<parking_lot::Mutex<f64>>,
    last_refill: Arc<parking_lot::Mutex<SystemTime>>,
    tokens_per_second: f64,
    max_tokens: f64,
}

impl<S, N> MigrationTracker<S, N>
where
    S: hybridcipher_client::storage::Storage + Send + Sync + 'static,
    N: hybridcipher_client::network::Network + Send + Sync + 'static,
{
    /// Create a new migration tracker
    ///
    /// # Arguments
    ///
    /// * `client` - HybridCipher client for migration operations
    ///
    /// # Returns
    ///
    /// Returns a new migration tracker instance
    pub async fn new(client: Arc<hybridcipher_client::Client<S, N>>) -> Result<Self> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let tracker = Self {
            client,
            active_migration: Arc::new(RwLock::new(None)),
            file_progress: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(MigrationStats::default())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            opportunistic_queue: Arc::new(DashMap::new()),
            rate_limiter: Arc::new(RateLimiter::new(1024.0 * 1024.0, 10.0 * 1024.0 * 1024.0)), // 1MB/s, 10MB burst
        };

        // Initialize migration state from client
        tracker.sync_migration_state().await?;

        // Start background tasks
        tracker.start_background_tasks().await;

        info!("Migration tracker initialized successfully");
        Ok(tracker)
    }

    /// Sync migration state with the client
    async fn sync_migration_state(&self) -> Result<()> {
        debug!("Syncing migration state with client");

        if let Some(state) = self.client.migration_state_snapshot().await {
            debug!(
                "Active migration detected: from {} to {} ({:?})",
                state.from_epoch, state.to_epoch, state.phase
            );

            let migration_info = MigrationInfo {
                from_epoch: state.from_epoch.to_string(),
                to_epoch: state.to_epoch.to_string(),
                started_at: state.started_at.into(),
                total_files: state.total_files,
            };

            *self.active_migration.write() = Some(migration_info);

            self.file_progress.clear();

            for file_id in &state.migrated_files {
                self.file_progress.insert(
                    file_id.clone(),
                    MigrationProgress {
                        file_id: file_id.clone(),
                        from_epoch: state.from_epoch.to_string(),
                        to_epoch: state.to_epoch.to_string(),
                        progress_percentage: 100.0,
                        bytes_migrated: 0,
                        total_bytes: 0,
                        started_at: state.started_at.into(),
                        estimated_completion: Some(SystemTime::now()),
                    },
                );
            }

            for file_id in &state.failed_files {
                self.file_progress.insert(
                    file_id.clone(),
                    MigrationProgress {
                        file_id: file_id.clone(),
                        from_epoch: state.from_epoch.to_string(),
                        to_epoch: state.to_epoch.to_string(),
                        progress_percentage: 0.0,
                        bytes_migrated: 0,
                        total_bytes: 0,
                        started_at: state.started_at.into(),
                        estimated_completion: None,
                    },
                );
            }

            let mut stats = self.stats.write();
            stats.total_files = state.total_files;
            stats.migrated_files = state.migrated_files.len() as u64;
            stats.failed_files = state.failed_files.len() as u64;
            stats.bytes_migrated = 0;
            stats.total_bytes = 0;
            stats.migration_rate_bps = 0.0;
            stats.estimated_time_remaining = state.estimated_completion.and_then(|deadline| {
                let now = Utc::now();
                (deadline > now)
                    .then_some((deadline - now).to_std().ok())
                    .flatten()
            });

            debug!("Migration state synchronized using structured snapshot");
        } else {
            self.file_progress.clear();
            *self.active_migration.write() = None;
            *self.stats.write() = MigrationStats::default();
            debug!("No active migration found");
        }

        Ok(())
    }

    /// Start background tasks for migration coordination
    async fn start_background_tasks(&self) {
        let tracker_clone = self.clone_for_tasks();

        // Start statistics update task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                if let Err(e) = tracker_clone.update_statistics().await {
                    warn!("Failed to update migration statistics: {}", e);
                }
            }
        });

        let tracker_clone = self.clone_for_tasks();

        // Start opportunistic migration processor
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                tracker_clone.process_opportunistic_queue().await;
            }
        });
    }

    /// Clone tracker for background tasks (simplified for async tasks)
    fn clone_for_tasks(&self) -> Self {
        Self {
            client: self.client.clone(),
            active_migration: self.active_migration.clone(),
            file_progress: self.file_progress.clone(),
            stats: self.stats.clone(),
            event_sender: self.event_sender.clone(),
            event_receiver: self.event_receiver.clone(),
            opportunistic_queue: self.opportunistic_queue.clone(),
            rate_limiter: self.rate_limiter.clone(),
        }
    }

    /// Get preferred epoch for a file
    ///
    /// This method determines which epoch should be used for file access
    /// based on migration status and availability.
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    ///
    /// # Returns
    ///
    /// Returns the preferred epoch ID for file access
    pub async fn get_preferred_epoch_for_file(&self, file_id: &str) -> Result<String> {
        debug!("Getting preferred epoch for file {}", file_id);

        // Check if file has been migrated
        if let Ok(migrated) = self.client.is_file_migrated(file_id).await {
            if migrated {
                // File has been migrated, use current epoch
                if let Some(migration) = self.active_migration.read().as_ref() {
                    return Ok(migration.to_epoch.clone());
                }
            }
        }

        // Check if migration is in progress for this file
        if let Some(progress) = self.file_progress.get(file_id) {
            if progress.progress_percentage < 1.0 {
                // Migration in progress, use source epoch
                return Ok(progress.from_epoch.clone());
            } else {
                // Migration completed, use target epoch
                return Ok(progress.to_epoch.clone());
            }
        }

        // Default to current epoch from client
        Ok(self.client.current_epoch().await.to_string())
    }

    /// Get fallback epoch for a file during errors
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    ///
    /// # Returns
    ///
    /// Returns fallback epoch ID if available
    pub async fn get_fallback_epoch_for_file(&self, file_id: &str) -> Result<Option<String>> {
        debug!("Getting fallback epoch for file {}", file_id);

        if let Some(migration) = self.active_migration.read().as_ref() {
            // During migration, fallback is typically the source epoch
            Ok(Some(migration.from_epoch.clone()))
        } else {
            // No migration active, no fallback available
            Ok(None)
        }
    }

    /// Schedule opportunistic rewrapping for a file
    ///
    /// This method queues a file for opportunistic migration when it's
    /// accessed and found to be in an old epoch.
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    /// * `from_epoch` - Source epoch ID
    /// * `to_epoch` - Target epoch ID
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if successfully scheduled
    pub async fn schedule_opportunistic_rewrap(
        &self,
        file_id: String,
        from_epoch: String,
        to_epoch: String,
    ) -> Result<()> {
        debug!(
            "Scheduling opportunistic rewrap for file {} from {} to {}",
            file_id, from_epoch, to_epoch
        );

        // Check if already queued or in progress
        if self.opportunistic_queue.contains_key(&file_id)
            || self.file_progress.contains_key(&file_id)
        {
            debug!(
                "File {} already queued or in progress for migration",
                file_id
            );
            return Ok(());
        }

        let request = OpportunisticMigrationRequest {
            file_id: file_id.clone(),
            from_epoch,
            to_epoch,
            priority: 1, // Low priority for opportunistic migrations
        };

        self.opportunistic_queue.insert(file_id.clone(), request);

        // Send event notification
        let _ = self
            .event_sender
            .send(MigrationEvent::FileQueued { file_id });

        debug!("Opportunistic rewrap scheduled successfully");
        Ok(())
    }

    /// Process opportunistic migration queue
    async fn process_opportunistic_queue(&self) {
        if self.opportunistic_queue.is_empty() {
            return;
        }

        // Check rate limiting
        if !self.rate_limiter.acquire_token().await {
            return; // Rate limited, try again later
        }

        // Find highest priority item
        let mut best_request: Option<(String, OpportunisticMigrationRequest)> = None;

        for entry in self.opportunistic_queue.iter() {
            let (file_id, request) = entry.pair();

            if best_request.is_none()
                || request.priority > best_request.as_ref().unwrap().1.priority
            {
                best_request = Some((file_id.clone(), request.clone()));
            }
        }

        if let Some((file_id, request)) = best_request {
            // Remove from queue and start migration
            self.opportunistic_queue.remove(&file_id);

            debug!("Starting opportunistic migration for file {}", file_id);

            if let Err(e) = self.start_file_migration(request).await {
                warn!(
                    "Failed to start opportunistic migration for file {}: {}",
                    file_id, e
                );
                let _ = self.event_sender.send(MigrationEvent::FileFailed {
                    file_id,
                    error: e.to_string(),
                });
            }
        }
    }

    /// Start migration for a specific file
    async fn start_file_migration(&self, request: OpportunisticMigrationRequest) -> Result<()> {
        let progress = MigrationProgress {
            file_id: request.file_id.clone(),
            from_epoch: request.from_epoch.clone(),
            to_epoch: request.to_epoch.clone(),
            progress_percentage: 0.0,
            bytes_migrated: 0,
            total_bytes: 0, // Will be updated when file size is known
            started_at: SystemTime::now(),
            estimated_completion: None,
        };

        self.file_progress.insert(request.file_id.clone(), progress);

        // Send start event
        let _ = self.event_sender.send(MigrationEvent::FileStarted {
            file_id: request.file_id.clone(),
        });

        // Start actual migration via client
        let client = self.client.clone();
        let file_id = request.file_id.clone();
        let from_epoch = request.from_epoch;
        let to_epoch = request.to_epoch;
        let progress_map = self.file_progress.clone();
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            match client
                .rewrap_file_header_only(&file_id, &from_epoch, &to_epoch)
                .await
            {
                Ok(_) => {
                    // Update progress to completed
                    if let Some(mut progress) = progress_map.get_mut(&file_id) {
                        progress.progress_percentage = 1.0;
                    }

                    let _ = event_sender.send(MigrationEvent::FileCompleted { file_id });
                }
                Err(e) => {
                    // Remove from progress and send failure event
                    progress_map.remove(&file_id);
                    let _ = event_sender.send(MigrationEvent::FileFailed {
                        file_id,
                        error: e.to_string(),
                    });
                }
            }
        });

        Ok(())
    }

    /// Update migration statistics
    async fn update_statistics(&self) -> Result<()> {
        if let Ok(migration) = self.client.get_migration_status().await {
            // Migration status is just a string, so we can't extract detailed stats
            // Update state to indicate migration is active
            debug!("Migration active: {}", migration);
        }

        Ok(())
    }

    /// Get current migration statistics
    ///
    /// # Returns
    ///
    /// Returns current migration statistics
    pub fn get_migration_stats(&self) -> MigrationStats {
        self.stats.read().clone()
    }

    /// Get migration progress for a specific file
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    ///
    /// # Returns
    ///
    /// Returns migration progress if available
    pub fn get_file_migration_progress(&self, file_id: &str) -> Option<MigrationProgress> {
        self.file_progress.get(file_id).map(|p| p.clone())
    }

    /// Check if migration is currently active
    ///
    /// # Returns
    ///
    /// Returns `true` if migration is active, `false` otherwise
    pub fn is_migration_active(&self) -> bool {
        self.active_migration.read().is_some()
    }

    /// Get active migration information
    ///
    /// # Returns
    ///
    /// Returns active migration info if available
    pub fn get_active_migration(&self) -> Option<MigrationInfo> {
        self.active_migration.read().clone()
    }
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    ///
    /// * `tokens_per_second` - Rate of token generation
    /// * `max_tokens` - Maximum token bucket size
    ///
    /// # Returns
    ///
    /// Returns a new rate limiter instance
    fn new(tokens_per_second: f64, max_tokens: f64) -> Self {
        Self {
            tokens: Arc::new(parking_lot::Mutex::new(max_tokens)),
            last_refill: Arc::new(parking_lot::Mutex::new(SystemTime::now())),
            tokens_per_second,
            max_tokens,
        }
    }

    /// Attempt to acquire a token from the rate limiter
    ///
    /// # Returns
    ///
    /// Returns `true` if token was acquired, `false` if rate limited
    async fn acquire_token(&self) -> bool {
        let now = SystemTime::now();

        // Refill tokens based on elapsed time
        {
            let mut last_refill = self.last_refill.lock();
            if let Ok(elapsed) = now.duration_since(*last_refill) {
                let tokens_to_add = elapsed.as_secs_f64() * self.tokens_per_second;

                let mut tokens = self.tokens.lock();
                *tokens = (*tokens + tokens_to_add).min(self.max_tokens);
                *last_refill = now;
            }
        }

        // Try to acquire a token
        let mut tokens = self.tokens.lock();
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_progress_creation() {
        let progress = MigrationProgress {
            file_id: "test_file".to_string(),
            from_epoch: "epoch1".to_string(),
            to_epoch: "epoch2".to_string(),
            progress_percentage: 0.5,
            bytes_migrated: 512,
            total_bytes: 1024,
            started_at: SystemTime::now(),
            estimated_completion: None,
        };

        assert_eq!(progress.file_id, "test_file");
        assert_eq!(progress.progress_percentage, 0.5);
        assert_eq!(progress.bytes_migrated, 512);
    }

    #[test]
    fn test_file_migration_status() {
        assert_eq!(
            FileMigrationStatus::NotStarted,
            FileMigrationStatus::NotStarted
        );
        assert_ne!(FileMigrationStatus::NotStarted, FileMigrationStatus::Queued);

        match FileMigrationStatus::Failed("test error".to_string()) {
            FileMigrationStatus::Failed(msg) => assert_eq!(msg, "test error"),
            _ => panic!("Expected Failed status"),
        }
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(1.0, 1.0); // 1 token per second, max 1 token

        // Should be able to acquire initial token
        assert!(limiter.acquire_token().await);

        // Should not be able to acquire another immediately
        assert!(!limiter.acquire_token().await);
    }
}
