//! Virtual filesystem tree for migration status overlay
//!
//! This module manages the virtual filesystem tree that overlays
//! migration status information onto the regular filesystem.

use super::{OverlayFile, VirtualFileInfo};
use crate::filesystem::hybridcipher::FileInfo;
use anyhow::Result;
use std::collections::HashMap;
use std::time::SystemTime;
use tracing::debug;

/// Virtual filesystem tree manager
pub struct VirtualTree {
    /// Root directory virtual files
    root_files: HashMap<String, VirtualFileInfo>,

    /// Last update time
    last_update: SystemTime,
}

impl VirtualTree {
    /// Create a new virtual tree
    pub fn new() -> Self {
        Self {
            root_files: HashMap::new(),
            last_update: SystemTime::now(),
        }
    }

    /// Initialize the virtual tree with root directory
    pub fn initialize_root(&mut self) -> Result<()> {
        debug!("Initializing virtual filesystem tree");

        // Create migration status file
        self.create_migration_status_file()?;

        // Create pending files list
        self.create_pending_files_list()?;

        // Create coverage log status
        self.create_coverage_log_file()?;

        // Create rekey history
        self.create_rekey_history_file()?;

        // Create performance metrics view
        self.create_performance_metrics_file()?;

        // Create cache statistics view
        self.create_cache_statistics_file()?;

        self.last_update = SystemTime::now();
        debug!(
            "Virtual filesystem tree initialized with {} files",
            self.root_files.len()
        );

        Ok(())
    }

    /// Create migration status virtual file
    fn create_migration_status_file(&mut self) -> Result<()> {
        let mut virtual_file = VirtualFileInfo::new_file(
            ".migration-status".to_string(),
            Vec::new(),
            0o444, // Read-only
        );
        virtual_file.overlay_type = Some(OverlayFile::MigrationStatus);
        let default_content = b"Migration status: idle\n".to_vec();
        virtual_file.size = default_content.len() as u64;
        virtual_file.content = default_content;

        self.root_files
            .insert(".migration-status".to_string(), virtual_file);
        debug!("Created .migration-status virtual file");

        Ok(())
    }

    /// Create pending files list virtual file
    fn create_pending_files_list(&mut self) -> Result<()> {
        let mut virtual_file = VirtualFileInfo::new_file(
            ".pending-files".to_string(),
            Vec::new(),
            0o444, // Read-only
        );
        virtual_file.overlay_type = Some(OverlayFile::PendingFiles);
        virtual_file.size = 0;

        self.root_files
            .insert(".pending-files".to_string(), virtual_file);
        debug!("Created .pending-files virtual file");

        Ok(())
    }

    /// Create coverage log virtual file
    fn create_coverage_log_file(&mut self) -> Result<()> {
        let mut virtual_file = VirtualFileInfo::new_file(
            ".coverage-log".to_string(),
            Vec::new(),
            0o444, // Read-only
        );
        virtual_file.overlay_type = Some(OverlayFile::CoverageLog);
        virtual_file.size = 0;

        self.root_files
            .insert(".coverage-log".to_string(), virtual_file);
        debug!("Created .coverage-log virtual file");

        Ok(())
    }

    /// Create rekey history virtual file
    fn create_rekey_history_file(&mut self) -> Result<()> {
        let mut virtual_file = VirtualFileInfo::new_file(
            ".rekey-history".to_string(),
            Vec::new(),
            0o444, // Read-only
        );
        virtual_file.overlay_type = Some(OverlayFile::RekeyHistory);
        virtual_file.size = 0;

        self.root_files
            .insert(".rekey-history".to_string(), virtual_file);
        debug!("Created .rekey-history virtual file");

        Ok(())
    }

    /// Create performance metrics virtual file
    fn create_performance_metrics_file(&mut self) -> Result<()> {
        let mut virtual_file =
            VirtualFileInfo::new_file(".performance-metrics".to_string(), Vec::new(), 0o444);
        virtual_file.overlay_type = Some(OverlayFile::PerformanceMetrics);
        virtual_file.size = 0;

        self.root_files
            .insert(".performance-metrics".to_string(), virtual_file);
        debug!("Created .performance-metrics virtual file");

        Ok(())
    }

    /// Create cache statistics virtual file
    fn create_cache_statistics_file(&mut self) -> Result<()> {
        let mut virtual_file =
            VirtualFileInfo::new_file(".cache-statistics".to_string(), Vec::new(), 0o444);
        virtual_file.overlay_type = Some(OverlayFile::CacheStatistics);
        virtual_file.size = 0;

        self.root_files
            .insert(".cache-statistics".to_string(), virtual_file);
        debug!("Created .cache-statistics virtual file");

        Ok(())
    }

    /// Lookup virtual file by name
    ///
    /// # Arguments
    ///
    /// * `parent_inode` - Parent directory inode
    /// * `filename` - Name of the virtual file
    ///
    /// # Returns
    ///
    /// Returns virtual file info if found
    pub fn lookup_virtual_file(
        &self,
        parent_inode: u64,
        filename: &str,
    ) -> Result<Option<FileInfo>> {
        // Only serve virtual files from root directory
        if parent_inode != 1 {
            return Ok(None);
        }

        if let Some(virtual_file) = self.root_files.get(filename) {
            debug!("Found virtual file: {}", filename);
            Ok(Some(virtual_file.clone().into()))
        } else {
            Ok(None)
        }
    }

    /// Get all virtual entries for directory listing
    ///
    /// # Returns
    ///
    /// Returns list of virtual file entries
    pub fn get_virtual_entries(&self) -> Vec<(String, FileInfo)> {
        self.root_files
            .iter()
            .map(|(name, virtual_file)| (name.clone(), virtual_file.clone().into()))
            .collect()
    }

    /// Update virtual files with latest migration information
    ///
    /// This method refreshes the content of virtual files with
    /// current migration status and progress.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if successfully updated
    pub async fn update_virtual_files(&mut self) -> Result<()> {
        debug!("Updating virtual files with latest information");

        self.last_update = SystemTime::now();
        Ok(())
    }

    /// Read content from a virtual file
    ///
    /// # Arguments
    ///
    /// * `filename` - Name of the virtual file
    /// * `offset` - Byte offset to start reading from
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// Returns file content if found
    pub async fn read_virtual_file(
        &self,
        filename: &str,
        offset: u64,
        size: u64,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(virtual_file) = self.root_files.get(filename) {
            let start = offset as usize;
            let end = std::cmp::min(start + size as usize, virtual_file.content.len());

            if start < virtual_file.content.len() {
                debug!(
                    "Reading {} bytes from virtual file {} at offset {}",
                    end - start,
                    filename,
                    offset
                );
                Ok(Some(virtual_file.content[start..end].to_vec()))
            } else {
                Ok(Some(Vec::new())) // EOF
            }
        } else {
            Ok(None)
        }
    }

    /// Check if refresh is needed based on age
    ///
    /// # Returns
    ///
    /// Returns `true` if virtual files should be refreshed
    pub fn needs_refresh(&self) -> bool {
        if let Ok(elapsed) = SystemTime::now().duration_since(self.last_update) {
            elapsed.as_secs() > 5 // Refresh every 5 seconds
        } else {
            true
        }
    }

    /// Get the number of virtual files
    ///
    /// # Returns
    ///
    /// Returns count of virtual files
    pub fn file_count(&self) -> usize {
        self.root_files.len()
    }

    pub fn overlay_type_for(&self, filename: &str) -> Option<OverlayFile> {
        self.root_files
            .get(filename)
            .and_then(|entry| entry.overlay_type.clone())
    }

    pub fn update_content(&mut self, filename: &str, data: Vec<u8>) {
        if let Some(entry) = self.root_files.get_mut(filename) {
            entry.size = data.len() as u64;
            entry.content = data;
            entry.last_modified = SystemTime::now();
            entry.access_time = entry.last_modified;
        }
        self.last_update = SystemTime::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_tree_creation() {
        let mut tree = VirtualTree::new();
        assert_eq!(tree.file_count(), 0);

        tree.initialize_root().unwrap();
        assert!(tree.file_count() > 0);
    }

    #[test]
    fn test_virtual_file_lookup() {
        let mut tree = VirtualTree::new();
        tree.initialize_root().unwrap();

        // Should find virtual files in root directory
        let result = tree.lookup_virtual_file(1, ".migration-status").unwrap();
        assert!(result.is_some());

        // Should not find virtual files in other directories
        let result = tree.lookup_virtual_file(2, ".migration-status").unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_virtual_file_reading() {
        let mut tree = VirtualTree::new();
        tree.initialize_root().unwrap();

        let content = tree
            .read_virtual_file(".migration-status", 0, 100)
            .await
            .unwrap();
        assert!(content.is_some());
        assert!(!content.unwrap().is_empty());
    }
}
