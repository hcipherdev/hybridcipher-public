//! File attributes with migration status awareness
//!
//! This module provides file attribute management with integration
//! of migration status and epoch information.

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// File attributes enhanced with migration information
#[derive(Debug, Clone)]
pub struct MigrationAwareAttr {
    pub size: u64,
    pub permissions: u16,
    pub modified_time: SystemTime,
    pub access_time: SystemTime,
    pub creation_time: SystemTime,
    pub is_directory: bool,
    pub migration_status: MigrationAttrStatus,
    pub epoch_info: EpochInfo,
}

/// Migration status encoded in file attributes
#[derive(Debug, Clone, PartialEq)]
pub enum MigrationAttrStatus {
    /// File is current and up-to-date
    Current,
    /// File needs migration (encoded in nanoseconds field)
    PendingMigration,
    /// File is being migrated (encoded in nanoseconds field)
    InProgress,
    /// File migration completed (encoded in nanoseconds field)
    Completed,
}

/// Epoch information for file attributes
#[derive(Debug, Clone)]
pub struct EpochInfo {
    pub current_epoch: String,
    pub source_epoch: Option<String>,
    pub migration_progress: Option<f32>,
}

impl MigrationAwareAttr {
    /// Create new migration-aware attributes
    ///
    /// # Arguments
    ///
    /// * `size` - File size in bytes
    /// * `permissions` - File permissions (Unix-style)
    /// * `modified_time` - Last modification time
    /// * `access_time` - Last access time
    /// * `creation_time` - File creation time
    /// * `is_directory` - Whether this is a directory
    /// * `migration_status` - Current migration status
    /// * `epoch_info` - Epoch information
    ///
    /// # Returns
    ///
    /// Returns a new `MigrationAwareAttr` instance
    pub fn new(
        size: u64,
        permissions: u16,
        modified_time: SystemTime,
        access_time: SystemTime,
        creation_time: SystemTime,
        is_directory: bool,
        migration_status: MigrationAttrStatus,
        epoch_info: EpochInfo,
    ) -> Self {
        Self {
            size,
            permissions,
            modified_time,
            access_time,
            creation_time,
            is_directory,
            migration_status,
            epoch_info,
        }
    }

    /// Convert to FUSE FileAttr with migration status encoding
    ///
    /// Migration status is encoded in the nanoseconds field of the
    /// modification time to provide visibility without breaking
    /// standard filesystem semantics.
    ///
    /// # Arguments
    ///
    /// * `inode` - Inode number for the file
    ///
    /// # Returns
    ///
    /// Returns a FUSE `FileAttr` with encoded migration information
    pub fn to_fuse_attr(&self, inode: u64) -> fuser::FileAttr {
        // Encode migration status in nanoseconds field
        let encoded_mtime = self.encode_migration_status_in_time(self.modified_time);

        let file_type = if self.is_directory {
            fuser::FileType::Directory
        } else {
            fuser::FileType::RegularFile
        };

        debug!(
            "Converting to FUSE attr: inode={}, size={}, migration_status={:?}",
            inode, self.size, self.migration_status
        );

        fuser::FileAttr {
            ino: inode,
            size: self.size,
            blocks: (self.size + 511) / 512, // 512-byte blocks
            atime: self.access_time,
            mtime: encoded_mtime,
            ctime: self.creation_time,
            crtime: self.creation_time,
            kind: file_type,
            perm: self.permissions,
            nlink: if self.is_directory { 2 } else { 1 },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    /// Encode migration status in timestamp nanoseconds field
    ///
    /// This method uses the nanoseconds field of the modification time
    /// to encode migration status information in a way that's visible
    /// to tools that examine detailed file attributes.
    ///
    /// Encoding scheme:
    /// - 0-99: Current (no migration)
    /// - 100-199: Pending migration
    /// - 200-299: Migration in progress
    /// - 300-399: Migration completed
    ///
    /// # Arguments
    ///
    /// * `base_time` - Base timestamp to encode status into
    ///
    /// # Returns
    ///
    /// Returns timestamp with encoded migration status
    fn encode_migration_status_in_time(&self, base_time: SystemTime) -> SystemTime {
        let encoded_nanos = match self.migration_status {
            MigrationAttrStatus::Current => 0,
            MigrationAttrStatus::PendingMigration => 100,
            MigrationAttrStatus::InProgress => {
                // Encode progress percentage in 200-299 range
                200 + (self.epoch_info.migration_progress.unwrap_or(0.0) * 99.0) as u32
            }
            MigrationAttrStatus::Completed => 300,
        };

        // Create a new timestamp with encoded nanoseconds
        if let Ok(duration) = base_time.duration_since(UNIX_EPOCH) {
            let secs = duration.as_secs();
            let new_duration = std::time::Duration::new(secs, encoded_nanos);
            UNIX_EPOCH + new_duration
        } else {
            base_time // Fallback to original time if encoding fails
        }
    }

    /// Decode migration status from timestamp nanoseconds field
    ///
    /// This method reverses the encoding performed by `encode_migration_status_in_time`
    /// to extract migration status information from file attributes.
    ///
    /// # Arguments
    ///
    /// * `encoded_time` - Timestamp with encoded migration status
    ///
    /// # Returns
    ///
    /// Returns decoded migration status and progress information
    pub fn decode_migration_status_from_time(
        encoded_time: SystemTime,
    ) -> (MigrationAttrStatus, Option<f32>) {
        if let Ok(duration) = encoded_time.duration_since(UNIX_EPOCH) {
            let nanos = duration.subsec_nanos();

            match nanos {
                0..=99 => (MigrationAttrStatus::Current, None),
                100..=199 => (MigrationAttrStatus::PendingMigration, None),
                200..=299 => {
                    let progress = (nanos - 200) as f32 / 99.0;
                    (MigrationAttrStatus::InProgress, Some(progress))
                }
                300..=399 => (MigrationAttrStatus::Completed, None),
                _ => (MigrationAttrStatus::Current, None), // Default fallback
            }
        } else {
            (MigrationAttrStatus::Current, None)
        }
    }

    /// Update access time while preserving migration status encoding
    ///
    /// This method updates the access time without disturbing the
    /// migration status encoding in the modification time.
    ///
    /// # Arguments
    ///
    /// * `new_access_time` - New access time to set
    pub fn update_access_time(&mut self, new_access_time: SystemTime) {
        self.access_time = new_access_time;
        debug!(
            "Updated access time for file with migration status {:?}",
            self.migration_status
        );
    }

    /// Update migration status and re-encode in timestamp
    ///
    /// This method updates the migration status and ensures it's
    /// properly encoded in the file attributes.
    ///
    /// # Arguments
    ///
    /// * `new_status` - New migration status to set
    /// * `progress` - Optional progress percentage for in-progress migrations
    pub fn update_migration_status(
        &mut self,
        new_status: MigrationAttrStatus,
        progress: Option<f32>,
    ) {
        debug!(
            "Updating migration status from {:?} to {:?}",
            self.migration_status, new_status
        );

        self.migration_status = new_status;
        if let Some(p) = progress {
            self.epoch_info.migration_progress = Some(p);
        }

        // Re-encode the status in the modification time
        self.modified_time = self.encode_migration_status_in_time(self.modified_time);
    }

    /// Get human-readable migration status string
    ///
    /// This method provides a user-friendly representation of the
    /// current migration status for logging and debugging.
    ///
    /// # Returns
    ///
    /// Returns a string describing the current migration status
    pub fn migration_status_string(&self) -> String {
        match &self.migration_status {
            MigrationAttrStatus::Current => "Current".to_string(),
            MigrationAttrStatus::PendingMigration => "Pending Migration".to_string(),
            MigrationAttrStatus::InProgress => {
                if let Some(progress) = self.epoch_info.migration_progress {
                    format!("Migrating ({:.1}%)", progress * 100.0)
                } else {
                    "Migrating".to_string()
                }
            }
            MigrationAttrStatus::Completed => "Migration Completed".to_string(),
        }
    }

    /// Check if file needs migration
    ///
    /// # Returns
    ///
    /// Returns `true` if the file requires migration, `false` otherwise
    pub fn needs_migration(&self) -> bool {
        matches!(
            self.migration_status,
            MigrationAttrStatus::PendingMigration | MigrationAttrStatus::InProgress
        )
    }

    /// Get effective file size considering migration status
    ///
    /// During migration, file size might need adjustment based on
    /// compression or encryption changes between epochs.
    ///
    /// # Returns
    ///
    /// Returns the effective file size for filesystem operations
    pub fn effective_size(&self) -> u64 {
        // For now, return actual size
        // In future versions, this could account for size changes during migration
        self.size
    }
}

impl EpochInfo {
    /// Create new epoch information
    ///
    /// # Arguments
    ///
    /// * `current_epoch` - Current epoch identifier
    /// * `source_epoch` - Optional source epoch for migrations
    /// * `migration_progress` - Optional migration progress (0.0-1.0)
    ///
    /// # Returns
    ///
    /// Returns a new `EpochInfo` instance
    pub fn new(
        current_epoch: String,
        source_epoch: Option<String>,
        migration_progress: Option<f32>,
    ) -> Self {
        Self {
            current_epoch,
            source_epoch,
            migration_progress,
        }
    }

    /// Check if this represents a migration scenario
    ///
    /// # Returns
    ///
    /// Returns `true` if migration information is present
    pub fn is_migration_active(&self) -> bool {
        self.source_epoch.is_some() || self.migration_progress.is_some()
    }

    /// Get migration progress as percentage string
    ///
    /// # Returns
    ///
    /// Returns formatted progress string or "N/A" if not available
    pub fn progress_string(&self) -> String {
        if let Some(progress) = self.migration_progress {
            format!("{:.1}%", progress * 100.0)
        } else {
            "N/A".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn test_migration_status_encoding_decoding() {
        let base_time = UNIX_EPOCH + std::time::Duration::from_secs(1000000);

        let attr = MigrationAwareAttr::new(
            1024,
            0o644,
            base_time,
            base_time,
            base_time,
            false,
            MigrationAttrStatus::InProgress,
            EpochInfo::new("epoch2".to_string(), Some("epoch1".to_string()), Some(0.5)),
        );

        let encoded_time = attr.encode_migration_status_in_time(base_time);
        let (decoded_status, progress) =
            MigrationAwareAttr::decode_migration_status_from_time(encoded_time);

        assert_eq!(decoded_status, MigrationAttrStatus::InProgress);
        assert!(progress.is_some());
        assert!((progress.unwrap() - 0.5).abs() < 0.1); // Allow some encoding precision loss
    }

    #[test]
    fn test_migration_status_string() {
        let epoch_info = EpochInfo::new("epoch1".to_string(), None, None);

        let current_attr = MigrationAwareAttr::new(
            1024,
            0o644,
            SystemTime::now(),
            SystemTime::now(),
            SystemTime::now(),
            false,
            MigrationAttrStatus::Current,
            epoch_info.clone(),
        );
        assert_eq!(current_attr.migration_status_string(), "Current");

        let mut pending_attr = current_attr.clone();
        pending_attr.migration_status = MigrationAttrStatus::PendingMigration;
        assert_eq!(pending_attr.migration_status_string(), "Pending Migration");

        let mut progress_attr = current_attr.clone();
        progress_attr.migration_status = MigrationAttrStatus::InProgress;
        progress_attr.epoch_info.migration_progress = Some(0.75);
        assert_eq!(progress_attr.migration_status_string(), "Migrating (75.0%)");
    }

    #[test]
    fn test_needs_migration() {
        let epoch_info = EpochInfo::new("epoch1".to_string(), None, None);

        let current_attr = MigrationAwareAttr::new(
            1024,
            0o644,
            SystemTime::now(),
            SystemTime::now(),
            SystemTime::now(),
            false,
            MigrationAttrStatus::Current,
            epoch_info.clone(),
        );
        assert!(!current_attr.needs_migration());

        let mut pending_attr = current_attr.clone();
        pending_attr.migration_status = MigrationAttrStatus::PendingMigration;
        assert!(pending_attr.needs_migration());

        let mut progress_attr = current_attr.clone();
        progress_attr.migration_status = MigrationAttrStatus::InProgress;
        assert!(progress_attr.needs_migration());

        let mut completed_attr = current_attr.clone();
        completed_attr.migration_status = MigrationAttrStatus::Completed;
        assert!(!completed_attr.needs_migration());
    }

    #[test]
    fn test_epoch_info_migration_detection() {
        let no_migration = EpochInfo::new("epoch1".to_string(), None, None);
        assert!(!no_migration.is_migration_active());

        let with_source = EpochInfo::new("epoch2".to_string(), Some("epoch1".to_string()), None);
        assert!(with_source.is_migration_active());

        let with_progress = EpochInfo::new("epoch1".to_string(), None, Some(0.5));
        assert!(with_progress.is_migration_active());
    }
}
