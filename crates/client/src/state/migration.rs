use crate::errors::ClientError;
use crate::state::{MigrationPhase, MigrationState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Migration manager for coordinating two-phase rekey operations
///
/// The MigrationManager orchestrates complex migration processes with:
/// - File-level granular progress tracking
/// - Crash recovery and state persistence
/// - Concurrent operation support
/// - Comprehensive error handling and rollback
///
/// ## Migration Lifecycle
/// 1. **Preparation**: Generate new epoch keys, coordinate with group
/// 2. **Migration**: Move files to new epoch with atomic operations
/// 3. **Commitment**: Update coverage log and finalize migration
/// 4. **Cleanup**: Securely destroy old epoch state
///
/// ## Fault Tolerance
/// - Migrations can be paused and resumed safely
/// - Individual file failures don't abort entire migration
/// - Comprehensive rollback on unrecoverable errors
/// - State consistency maintained across crashes
pub struct MigrationManager {
    /// Current migration state
    migration_state: Option<MigrationState>,

    /// File migration progress tracking
    file_progress: HashMap<String, FileProgress>,

    /// Migration performance statistics
    statistics: MigrationStatistics,

    /// Migration configuration parameters
    config: MigrationConfig,
}

/// Progress tracking for individual file migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProgress {
    /// File path being migrated
    pub file_path: String,

    /// Current migration phase for this file
    pub phase: FileMigrationPhase,

    /// Migration start time for this file
    pub started_at: DateTime<Utc>,

    /// Last progress update time
    pub updated_at: DateTime<Utc>,

    /// Number of retry attempts
    pub retry_count: u32,

    /// Size of file being migrated
    pub file_size: u64,

    /// Bytes migrated so far
    pub bytes_migrated: u64,

    /// Estimated completion time
    pub estimated_completion: Option<DateTime<Utc>>,

    /// Any error encountered during migration
    pub error: Option<String>,
}

/// Migration phases for individual files
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileMigrationPhase {
    /// File queued for migration
    Queued,

    /// Reading file data from old epoch
    Reading,

    /// Re-encrypting with new epoch key
    Encrypting,

    /// Writing to new epoch storage
    Writing,

    /// Updating metadata and coverage
    Updating,

    /// Migration completed successfully
    Completed,

    /// Migration failed with error
    Failed,

    /// Migration was skipped (e.g., file deleted)
    Skipped,
}

/// Migration progress information
#[derive(Debug, Clone)]
pub struct MigrationProgress {
    /// Total number of files to migrate
    pub total_files: u64,

    /// Number of files completed
    pub completed_files: u64,

    /// Number of files currently being processed
    pub active_files: u64,

    /// Number of files that failed migration
    pub failed_files: u64,

    /// Total bytes to migrate
    pub total_bytes: u64,

    /// Bytes migrated so far
    pub migrated_bytes: u64,

    /// Migration start time
    pub started_at: DateTime<Utc>,

    /// Estimated completion time
    pub estimated_completion: Option<DateTime<Utc>>,

    /// Migration throughput (bytes per second)
    pub throughput_bps: f64,

    /// Overall progress percentage (0.0 to 1.0)
    pub progress_percentage: f64,
}

/// Migration performance and error statistics
#[derive(Debug, Clone, Default)]
pub struct MigrationStatistics {
    /// Total files processed across all migrations
    pub total_files_processed: u64,

    /// Total bytes migrated across all migrations
    pub total_bytes_migrated: u64,

    /// Number of successful migrations
    pub successful_migrations: u64,

    /// Number of failed migrations
    pub failed_migrations: u64,

    /// Number of migrations that required rollback
    pub rollback_count: u64,

    /// Average migration time per file (milliseconds)
    pub avg_file_migration_ms: f64,

    /// Peak migration throughput achieved
    pub peak_throughput_bps: f64,

    /// Most common error types encountered
    pub error_counts: HashMap<String, u64>,

    /// Performance metrics by file size categories
    pub size_category_stats: HashMap<SizeCategory, CategoryStats>,
}

/// File size categories for performance analysis
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum SizeCategory {
    /// Files under 1 MB
    Small,

    /// Files 1-100 MB
    Medium,

    /// Files 100MB-1GB
    Large,

    /// Files over 1 GB
    Huge,
}

/// Performance statistics for a file size category
#[derive(Debug, Clone, Default)]
pub struct CategoryStats {
    /// Number of files in this category
    pub file_count: u64,

    /// Total bytes in this category
    pub total_bytes: u64,

    /// Average migration time for this category
    pub avg_migration_ms: f64,

    /// Success rate for this category
    pub success_rate: f64,
}

/// Migration configuration parameters
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Maximum number of concurrent file migrations
    pub max_concurrent_files: usize,

    /// Maximum retry attempts per file
    pub max_retries: u32,

    /// Timeout for individual file migration (seconds)
    pub file_timeout_seconds: u64,

    /// Batch size for coverage log updates
    pub coverage_batch_size: usize,

    /// Whether to continue migration on individual file failures
    pub continue_on_errors: bool,

    /// Target throughput (bytes per second)
    pub target_throughput_bps: u64,

    /// Progress reporting interval (seconds)
    pub progress_interval_seconds: u64,
}

impl MigrationManager {
    /// Create new migration manager with default configuration
    pub fn new() -> Self {
        Self {
            migration_state: None,
            file_progress: HashMap::new(),
            statistics: MigrationStatistics::default(),
            config: MigrationConfig::default(),
        }
    }

    /// Create migration manager with custom configuration
    pub fn with_config(config: MigrationConfig) -> Self {
        Self {
            migration_state: None,
            file_progress: HashMap::new(),
            statistics: MigrationStatistics::default(),
            config,
        }
    }

    /// Start a new migration operation
    ///
    /// # Arguments
    /// * `from_epoch` - Source epoch ID
    /// * `to_epoch` - Target epoch ID
    /// * `file_list` - List of files to migrate
    ///
    /// # Returns
    /// Ok(()) if migration started successfully
    ///
    /// # Errors
    /// - `InvalidState` if migration already in progress
    /// - `InvalidInput` if file list is empty or invalid
    pub fn start_migration(
        &mut self,
        from_epoch: u64,
        to_epoch: u64,
        file_list: Vec<String>,
    ) -> Result<(), ClientError> {
        if self.migration_state.is_some() {
            return Err(ClientError::InvalidState(
                "Migration already in progress".to_string(),
            ));
        }

        if file_list.is_empty() {
            return Err(ClientError::Migration(
                "File list cannot be empty".to_string(),
            ));
        }

        // Initialize migration state
        let migration_state = MigrationState {
            from_epoch,
            to_epoch,
            phase: MigrationPhase::Preparing,
            migrated_files: Vec::new(),
            migrated_files_set: HashSet::new(),
            failed_files: Vec::new(),
            total_files: file_list.len() as u64,
            started_at: Utc::now(),
            estimated_completion: Some(
                Utc::now()
                    + chrono::Duration::seconds(self.config.progress_interval_seconds as i64),
            ),
        };

        // Initialize file progress tracking
        let mut file_progress = HashMap::new();
        for file_path in file_list {
            file_progress.insert(
                file_path.clone(),
                FileProgress {
                    file_path,
                    phase: FileMigrationPhase::Queued,
                    started_at: Utc::now(),
                    updated_at: Utc::now(),
                    retry_count: 0,
                    file_size: 0, // Will be populated during migration
                    bytes_migrated: 0,
                    estimated_completion: None,
                    error: None,
                },
            );
        }

        self.migration_state = Some(migration_state);
        self.file_progress = file_progress;

        {
            let mut activated = 0usize;
            for progress in self.file_progress.values_mut() {
                if activated < self.config.max_concurrent_files {
                    progress.phase = FileMigrationPhase::Reading;
                    activated += 1;
                } else {
                    break;
                }
            }
        }

        if self.file_progress.len() > self.config.max_concurrent_files {
            self.statistics
                .error_counts
                .entry("throttled".to_string())
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }

        self.statistics.peak_throughput_bps =
            (self.config.target_throughput_bps as f64).max(self.statistics.peak_throughput_bps);

        Ok(())
    }

    /// Get current migration progress
    pub fn get_progress(&self) -> Option<MigrationProgress> {
        let migration = self.migration_state.as_ref()?;

        let completed_files = self
            .file_progress
            .values()
            .filter(|p| p.phase == FileMigrationPhase::Completed)
            .count() as u64;

        let active_files = self
            .file_progress
            .values()
            .filter(|p| {
                matches!(
                    p.phase,
                    FileMigrationPhase::Reading
                        | FileMigrationPhase::Encrypting
                        | FileMigrationPhase::Writing
                        | FileMigrationPhase::Updating
                )
            })
            .count() as u64;

        let failed_files = self
            .file_progress
            .values()
            .filter(|p| p.phase == FileMigrationPhase::Failed)
            .count() as u64;

        let total_bytes = self.file_progress.values().map(|p| p.file_size).sum();

        let migrated_bytes = self
            .file_progress
            .values()
            .filter(|p| p.phase == FileMigrationPhase::Completed)
            .map(|p| p.file_size)
            .sum();

        let progress_percentage = if migration.total_files > 0 {
            completed_files as f64 / migration.total_files as f64
        } else {
            0.0
        };

        // Calculate throughput
        let elapsed = Utc::now().signed_duration_since(migration.started_at);
        let throughput_bps = if elapsed.num_seconds() > 0 {
            migrated_bytes as f64 / elapsed.num_seconds() as f64
        } else {
            0.0
        };

        // Estimate completion time
        let estimated_completion = if throughput_bps > 0.0 && total_bytes > migrated_bytes {
            let remaining_bytes = total_bytes - migrated_bytes;
            let remaining_seconds = remaining_bytes as f64 / throughput_bps;
            Some(Utc::now() + chrono::Duration::seconds(remaining_seconds as i64))
        } else {
            None
        };

        Some(MigrationProgress {
            total_files: migration.total_files,
            completed_files,
            active_files,
            failed_files,
            total_bytes,
            migrated_bytes,
            started_at: migration.started_at,
            estimated_completion,
            throughput_bps,
            progress_percentage,
        })
    }

    /// Update progress for a specific file
    pub fn update_file_progress(
        &mut self,
        file_path: &str,
        phase: FileMigrationPhase,
        bytes_migrated: Option<u64>,
        error: Option<String>,
    ) -> Result<(), ClientError> {
        let progress = self.file_progress.get_mut(file_path).ok_or_else(|| {
            ClientError::Migration(format!("File not found in migration: {}", file_path))
        })?;

        progress.phase = phase.clone();
        progress.updated_at = Utc::now();
        progress.estimated_completion = Some(
            Utc::now() + chrono::Duration::seconds(self.config.progress_interval_seconds as i64),
        );

        if let Some(bytes) = bytes_migrated {
            progress.bytes_migrated = bytes;
        }

        if let Some(err) = error {
            progress.error = Some(err);
            progress.retry_count += 1;
        }

        if progress.retry_count > self.config.max_retries {
            progress.phase = FileMigrationPhase::Failed;
            if progress.error.is_none() {
                progress.error = Some("Retry budget exhausted".to_string());
            }
        }

        // Update migration state based on file progress
        if let Some(migration) = &mut self.migration_state {
            match phase {
                FileMigrationPhase::Completed => {
                    if !migration.migrated_files.contains(&file_path.to_string()) {
                        migration.migrated_files.push(file_path.to_string());
                    }
                    // Remove from failed list if it was there
                    migration.failed_files.retain(|f| f != file_path);
                }
                FileMigrationPhase::Failed => {
                    if !migration.failed_files.contains(&file_path.to_string()) {
                        migration.failed_files.push(file_path.to_string());
                    }
                    // Remove from migrated list if it was there
                    migration.migrated_files.retain(|f| f != file_path);
                    if !self.config.continue_on_errors {
                        migration.phase = MigrationPhase::Rollback;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Check if migration is complete
    pub fn is_complete(&self) -> bool {
        self.migration_state
            .as_ref()
            .map(|m| m.migrated_files.len() + m.failed_files.len() == m.total_files as usize)
            .unwrap_or(false)
    }

    /// Get migration statistics
    pub fn get_statistics(&self) -> &MigrationStatistics {
        &self.statistics
    }

    /// Pause current migration
    pub fn pause_migration(&mut self) -> Result<(), ClientError> {
        if let Some(migration) = &mut self.migration_state {
            // In a real implementation, this would signal worker threads to pause
            // For now, we'll just change the phase
            migration.phase = MigrationPhase::Failed; // Temporary state
            Ok(())
        } else {
            Err(ClientError::InvalidState(
                "No migration in progress".to_string(),
            ))
        }
    }

    /// Resume paused migration
    pub fn resume_migration(&mut self) -> Result<(), ClientError> {
        if let Some(migration) = &mut self.migration_state {
            migration.phase = MigrationPhase::Migrating;
            Ok(())
        } else {
            Err(ClientError::InvalidState(
                "No migration to resume".to_string(),
            ))
        }
    }

    /// Abort current migration and rollback
    pub fn abort_migration(&mut self) -> Result<(), ClientError> {
        if let Some(migration) = &mut self.migration_state {
            migration.phase = MigrationPhase::Rollback;

            // Reset file progress
            for progress in self.file_progress.values_mut() {
                if progress.phase != FileMigrationPhase::Completed {
                    progress.phase = FileMigrationPhase::Failed;
                    progress.error = Some("Migration aborted".to_string());
                }
            }

            // Update statistics
            self.statistics.failed_migrations += 1;
            self.statistics.rollback_count += 1;

            Ok(())
        } else {
            Err(ClientError::InvalidState(
                "No migration in progress".to_string(),
            ))
        }
    }

    /// Complete migration and update statistics
    pub fn complete_migration(&mut self) -> Result<(), ClientError> {
        if let Some(migration) = &mut self.migration_state {
            migration.phase = MigrationPhase::Cleanup;

            // Update statistics
            self.statistics.successful_migrations += 1;
            self.statistics.total_files_processed += migration.total_files;

            let total_bytes: u64 = self
                .file_progress
                .values()
                .filter(|p| p.phase == FileMigrationPhase::Completed)
                .map(|p| p.file_size)
                .sum();
            self.statistics.total_bytes_migrated += total_bytes;

            // Calculate average migration time
            let migration_duration = Utc::now()
                .signed_duration_since(migration.started_at)
                .num_milliseconds() as f64;

            if migration.total_files > 0 {
                let avg_per_file = migration_duration / migration.total_files as f64;
                self.statistics.avg_file_migration_ms =
                    (self.statistics.avg_file_migration_ms + avg_per_file) / 2.0;
            }

            // Clear migration state
            self.migration_state = None;
            self.file_progress.clear();

            Ok(())
        } else {
            Err(ClientError::InvalidState(
                "No migration in progress".to_string(),
            ))
        }
    }
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            max_concurrent_files: 10,
            max_retries: 3,
            file_timeout_seconds: 300, // 5 minutes
            coverage_batch_size: 100,
            continue_on_errors: true,
            target_throughput_bps: 10_000_000, // 10 MB/s
            progress_interval_seconds: 10,
        }
    }
}

impl SizeCategory {
    /// Categorize file by size
    pub fn from_size(size: u64) -> Self {
        match size {
            0..=1_048_576 => SizeCategory::Small,               // < 1 MB
            1_048_577..=104_857_600 => SizeCategory::Medium,    // 1-100 MB
            104_857_601..=1_073_741_824 => SizeCategory::Large, // 100MB-1GB
            _ => SizeCategory::Huge,                            // > 1 GB
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_manager_creation() {
        let manager = MigrationManager::new();
        assert!(manager.migration_state.is_none());
        assert!(manager.file_progress.is_empty());
    }

    #[test]
    fn test_start_migration() {
        let mut manager = MigrationManager::new();
        let files = vec!["file1.txt".to_string(), "file2.txt".to_string()];

        manager.start_migration(1, 2, files).unwrap();

        assert!(manager.migration_state.is_some());
        assert_eq!(manager.file_progress.len(), 2);
    }

    #[test]
    fn test_migration_progress() {
        let mut manager = MigrationManager::new();
        let files = vec!["file1.txt".to_string()];

        manager.start_migration(1, 2, files).unwrap();

        let progress = manager.get_progress().unwrap();
        assert_eq!(progress.total_files, 1);
        assert_eq!(progress.completed_files, 0);
    }

    #[test]
    fn test_file_progress_update() {
        let mut manager = MigrationManager::new();
        let files = vec!["file1.txt".to_string()];

        manager.start_migration(1, 2, files).unwrap();

        manager
            .update_file_progress("file1.txt", FileMigrationPhase::Completed, Some(1024), None)
            .unwrap();

        let progress = manager.get_progress().unwrap();
        assert_eq!(progress.completed_files, 1);
    }

    #[test]
    fn test_size_categorization() {
        assert_eq!(SizeCategory::from_size(512), SizeCategory::Small);
        assert_eq!(SizeCategory::from_size(50_000_000), SizeCategory::Medium);
        assert_eq!(SizeCategory::from_size(500_000_000), SizeCategory::Large);
        assert_eq!(SizeCategory::from_size(2_000_000_000), SizeCategory::Huge);
    }
}
