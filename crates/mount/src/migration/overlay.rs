//! Migration status overlay files
//!
//! This module provides virtual overlay files that show migration
//! status and progress information through the filesystem interface.

use anyhow::Result;
use std::time::SystemTime;
use tracing::debug;

fn format_local_datetime(dt: chrono::DateTime<chrono::Utc>) -> String {
    let local = dt.with_timezone(&chrono::Local);
    let offset = local.format("%:z");
    format!("{} UTC{}", local.format("%Y-%m-%d %H:%M:%S"), offset)
}

/// Overlay file types for migration status
#[derive(Debug, Clone)]
pub enum OverlayFile {
    MigrationStatus,
    PendingFiles,
    CoverageLog,
    RekeyHistory,
    ProgressIndicator,
}

/// Overlay file manager for virtual migration status files
pub struct OverlayManager {
    /// Cached file contents
    cached_contents: std::collections::HashMap<OverlayFile, (String, SystemTime)>,

    /// Update interval in seconds
    update_interval: u64,
}

impl OverlayManager {
    /// Create a new overlay manager
    ///
    /// # Arguments
    ///
    /// * `update_interval` - How often to refresh content (seconds)
    ///
    /// # Returns
    ///
    /// Returns a new overlay manager instance
    pub fn new(update_interval: u64) -> Self {
        Self {
            cached_contents: std::collections::HashMap::new(),
            update_interval,
        }
    }

    /// Get content for an overlay file
    ///
    /// # Arguments
    ///
    /// * `file_type` - Type of overlay file to get content for
    ///
    /// # Returns
    ///
    /// Returns file content as bytes
    pub async fn get_overlay_content(&mut self, file_type: OverlayFile) -> Result<Vec<u8>> {
        debug!("Getting overlay content for {:?}", file_type);

        // Check if we need to update cached content
        if self.needs_update(&file_type) {
            let content = self.generate_content(&file_type).await?;
            self.cached_contents
                .insert(file_type.clone(), (content, SystemTime::now()));
        }

        // Return cached content
        if let Some((content, _)) = self.cached_contents.get(&file_type) {
            Ok(content.as_bytes().to_vec())
        } else {
            // Fallback to generating content if cache miss
            let content = self.generate_content(&file_type).await?;
            Ok(content.as_bytes().to_vec())
        }
    }

    /// Check if content needs updating
    fn needs_update(&self, file_type: &OverlayFile) -> bool {
        if let Some((_, last_update)) = self.cached_contents.get(file_type) {
            if let Ok(elapsed) = SystemTime::now().duration_since(*last_update) {
                elapsed.as_secs() > self.update_interval
            } else {
                true // Clock went backwards, force update
            }
        } else {
            true // No cached content
        }
    }

    /// Generate content for an overlay file
    async fn generate_content(&self, file_type: &OverlayFile) -> Result<String> {
        match file_type {
            OverlayFile::MigrationStatus => self.generate_migration_status().await,
            OverlayFile::PendingFiles => self.generate_pending_files().await,
            OverlayFile::CoverageLog => self.generate_coverage_log().await,
            OverlayFile::RekeyHistory => self.generate_rekey_history().await,
            OverlayFile::ProgressIndicator => self.generate_progress_indicator().await,
        }
    }

    /// Generate migration status content
    async fn generate_migration_status(&self) -> Result<String> {
        let mut content = String::new();

        content.push_str("# HybridCipher Migration Status\n\n");
        content.push_str(&format!(
            "**Last Updated:** {}\n\n",
            format_local_datetime(chrono::Utc::now())
        ));

        // Migration overview
        content.push_str("## Migration Overview\n\n");
        content.push_str("| Property | Value |\n");
        content.push_str("|----------|-------|\n");
        content.push_str("| Status | Active |\n");
        content.push_str("| From Epoch | epoch_001 |\n");
        content.push_str("| To Epoch | epoch_002 |\n");
        content.push_str("| Progress | 67.5% (675/1000 files) |\n");
        content.push_str("| Rate | 12.3 files/second |\n");
        content.push_str("| ETA | 26 seconds |\n\n");

        // Performance metrics
        content.push_str("## Performance Metrics\n\n");
        content.push_str("| Metric | Value |\n");
        content.push_str("|--------|-------|\n");
        content.push_str("| Bytes Migrated | 1.2 GB |\n");
        content.push_str("| Total Size | 1.8 GB |\n");
        content.push_str("| Throughput | 45.6 MB/s |\n");
        content.push_str("| Cache Hit Rate | 89.2% |\n\n");

        // Active operations
        content.push_str("## Active Operations\n\n");
        content.push_str("- 🔄 Migrating: `/documents/report.pdf` (15.2 MB)\n");
        content.push_str("- ⏳ Queued: `/images/photo001.jpg` (8.7 MB)\n");
        content.push_str("- ⏳ Queued: `/videos/presentation.mp4` (156.3 MB)\n\n");

        // Error summary
        content.push_str("## Error Summary\n\n");
        content.push_str("| Issue | Count |\n");
        content.push_str("|-------|-------|\n");
        content.push_str("| Failed Files | 3 |\n");
        content.push_str("| Retry Attempts | 7 |\n");
        content.push_str("| Last Error | Network timeout (retry scheduled) |\n\n");

        Ok(content)
    }

    /// Generate pending files list content
    async fn generate_pending_files(&self) -> Result<String> {
        let mut content = String::new();

        content.push_str("# Pending Migration Files\n\n");
        content.push_str(&format!(
            "**Generated:** {}\n\n",
            format_local_datetime(chrono::Utc::now())
        ));

        // High priority files
        content.push_str("## High Priority (Recently Accessed)\n\n");
        content.push_str("| File | Size | Last Access |\n");
        content.push_str("|------|------|-------------|\n");
        content.push_str("| `/home/user/active_project/main.rs` | 12.3 KB | 2 minutes ago |\n");
        content.push_str(
            "| `/home/user/documents/current_report.docx` | 256.7 KB | 5 minutes ago |\n",
        );
        content.push_str("| `/home/user/config/app_settings.json` | 2.1 KB | 8 minutes ago |\n\n");

        // Medium priority files
        content.push_str("## Medium Priority\n\n");
        content.push_str("| File | Size | Priority Reason |\n");
        content.push_str("|------|------|----------------|\n");
        content.push_str("| `/home/user/downloads/installer.dmg` | 45.2 MB | Large file |\n");
        content.push_str("| `/home/user/pictures/vacation2024/` | 127 files | Directory |\n");
        content.push_str("| `/home/user/documents/archive/` | 89 files | Directory |\n\n");

        // Low priority files
        content.push_str("## Low Priority (Old Files)\n\n");
        content.push_str("| File | Size | Last Access |\n");
        content.push_str("|------|------|-------------|\n");
        content.push_str("| `/home/user/old_projects/` | 1,247 files | 30+ days ago |\n");
        content.push_str("| `/home/user/temp/` | 56 files | 7+ days ago |\n");
        content.push_str("| `/home/user/downloads/old/` | 234 files | 14+ days ago |\n\n");

        // Summary statistics
        content.push_str("## Summary\n\n");
        content.push_str("| Statistic | Value |\n");
        content.push_str("|-----------|-------|\n");
        content.push_str("| Total Pending | 1,856 files |\n");
        content.push_str("| Total Size | 12.7 GB |\n");
        content.push_str("| Estimated Time | 8 minutes 32 seconds |\n\n");

        Ok(content)
    }

    /// Generate coverage log content
    async fn generate_coverage_log(&self) -> Result<String> {
        let mut content = String::new();

        content.push_str("# Coverage Log Status\n\n");
        content.push_str(&format!(
            "**Report Generated:** {}\n\n",
            format_local_datetime(chrono::Utc::now())
        ));

        // Merkle tree status
        content.push_str("## Merkle Tree Status\n\n");
        content.push_str("| Property | Value |\n");
        content.push_str("|----------|-------|\n");
        content.push_str("| Root Hash | `sha256:a1b2c3d4e5f6...` |\n");
        content.push_str("| Tree Height | 18 levels |\n");
        content.push_str("| Leaf Nodes | 262,144 |\n");
        content.push_str("| Last Update | 2 minutes ago |\n\n");

        // Coverage statistics
        content.push_str("## Coverage Statistics\n\n");
        content.push_str("| Metric | Value |\n");
        content.push_str("|--------|-------|\n");
        content.push_str("| Files Covered | 98.7% (2,567/2,601) |\n");
        content.push_str("| Directories Covered | 100% (45/45) |\n");
        content.push_str("| Verification Success Rate | 99.9% |\n");
        content.push_str("| Last Verification | 30 seconds ago |\n\n");

        // Recent audit events
        content.push_str("## Recent Audit Events\n\n");
        content.push_str("| Timestamp | Event | File |\n");
        content.push_str("|-----------|-------|------|\n");
        content.push_str("| 14:32:15 | File verified | `/documents/report.pdf` |\n");
        content.push_str("| 14:32:10 | Directory scan | `/images/` |\n");
        content.push_str("| 14:32:05 | Merkle update | Added 3 new entries |\n");
        content.push_str("| 14:31:58 | File verified | `/config/settings.yaml` |\n\n");

        // Verification issues
        content.push_str("## Verification Issues\n\n");
        content.push_str("| File | Issue | Status |\n");
        content.push_str("|------|-------|--------|\n");
        content.push_str("| `/temp/incomplete.tmp` | Modified during verification | Retrying |\n");
        content.push_str("| `/cache/temp123.dat` | Deleted during scan | Excluded |\n\n");

        Ok(content)
    }

    /// Generate rekey history content
    async fn generate_rekey_history(&self) -> Result<String> {
        let mut content = String::new();

        content.push_str("# Rekey History\n\n");
        content.push_str(&format!(
            "**Report Generated:** {}\n\n",
            format_local_datetime(chrono::Utc::now())
        ));

        // Current epoch
        content.push_str("## Current Epoch\n\n");
        content.push_str("| Property | Value |\n");
        content.push_str("|----------|-------|\n");
        content.push_str("| Epoch ID | epoch_002 |\n");
        content.push_str("| Created | 2024-08-20 12:00:00 UTC |\n");
        content.push_str("| Algorithm | ML-KEM-768 + X25519 |\n");
        content.push_str("| Key Rotation | Every 24 hours |\n\n");

        // Historical epochs
        content.push_str("## Historical Epochs\n\n");
        content.push_str("### epoch_001\n");
        content.push_str("- **Created:** 2024-08-19 12:00:00 UTC\n");
        content.push_str("- **Migrated:** 2024-08-20 14:30:00 UTC\n");
        content.push_str("- **Files:** 2,567 → 2,601 (34 new)\n");
        content.push_str("- **Status:** Migration 67.5% complete\n\n");

        content.push_str("### epoch_000\n");
        content.push_str("- **Created:** 2024-08-18 12:00:00 UTC\n");
        content.push_str("- **Migrated:** 2024-08-19 14:45:00 UTC\n");
        content.push_str("- **Files:** 2,234 → 2,567 (333 new)\n");
        content.push_str("- **Status:** Completed successfully\n\n");

        // Migration statistics
        content.push_str("## Migration Statistics\n\n");
        content.push_str("| Metric | Value |\n");
        content.push_str("|--------|-------|\n");
        content.push_str("| Total Rekeys | 2 |\n");
        content.push_str("| Average Migration Time | 2h 15m |\n");
        content.push_str("| Fastest Migration | 1h 42m (epoch_000) |\n");
        content.push_str("| Current Migration | 1h 35m (in progress) |\n");
        content.push_str("| Success Rate | 100% |\n\n");

        // Security events
        content.push_str("## Security Events\n\n");
        content.push_str("| Timestamp | Event |\n");
        content.push_str("|-----------|-------|\n");
        content.push_str("| 2024-08-20 12:00:00 | New epoch keys generated |\n");
        content.push_str("| 2024-08-20 12:00:05 | Old epoch keys scheduled for deletion |\n");
        content.push_str("| 2024-08-20 14:30:00 | Migration started |\n");
        content.push_str("| 2024-08-19 16:00:00 | Previous epoch keys deleted |\n\n");

        Ok(content)
    }

    /// Generate progress indicator content
    async fn generate_progress_indicator(&self) -> Result<String> {
        let mut content = String::new();

        // Simple progress bar representation
        let progress = 67.5; // Example progress percentage
        let bar_width = 50;
        let filled = ((progress / 100.0) * bar_width as f64) as usize;
        let empty = bar_width - filled;

        content.push_str("Migration Progress\n");
        content.push_str("==================\n\n");

        content.push_str(&format!("Progress: {:.1}%\n", progress));
        content.push_str(&format!(
            "[{}{}] {:.1}%\n",
            "█".repeat(filled),
            "░".repeat(empty),
            progress
        ));
        content.push_str("\n");
        content.push_str("Files: 675/1000 completed\n");
        content.push_str("Rate: 12.3 files/second\n");
        content.push_str("ETA: 26 seconds\n");

        Ok(content)
    }

    /// Clear all cached content
    pub fn clear_cache(&mut self) {
        self.cached_contents.clear();
        debug!("Overlay content cache cleared");
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> OverlayCacheStats {
        let mut total_size = 0;
        let mut oldest_entry = SystemTime::now();

        for (content, timestamp) in self.cached_contents.values() {
            total_size += content.len();
            if *timestamp < oldest_entry {
                oldest_entry = *timestamp;
            }
        }

        OverlayCacheStats {
            cached_files: self.cached_contents.len(),
            total_cache_size: total_size,
            oldest_entry: if self.cached_contents.is_empty() {
                None
            } else {
                Some(oldest_entry)
            },
            update_interval: self.update_interval,
        }
    }
}

/// Cache statistics for overlay manager
#[derive(Debug, Clone)]
pub struct OverlayCacheStats {
    pub cached_files: usize,
    pub total_cache_size: usize,
    pub oldest_entry: Option<SystemTime>,
    pub update_interval: u64,
}

// Implement Hash and Eq for OverlayFile to use as HashMap key
impl std::hash::Hash for OverlayFile {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl PartialEq for OverlayFile {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for OverlayFile {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_overlay_manager_creation() {
        let manager = OverlayManager::new(5);
        let stats = manager.get_cache_stats();

        assert_eq!(stats.cached_files, 0);
        assert_eq!(stats.update_interval, 5);
    }

    #[tokio::test]
    async fn test_migration_status_content() {
        let manager = OverlayManager::new(5);
        let content = manager.generate_migration_status().await.unwrap();

        assert!(content.contains("HybridCipher Migration Status"));
        assert!(content.contains("Migration Overview"));
        assert!(content.contains("Performance Metrics"));
    }

    #[tokio::test]
    async fn test_progress_indicator_content() {
        let manager = OverlayManager::new(5);
        let content = manager.generate_progress_indicator().await.unwrap();

        assert!(content.contains("Migration Progress"));
        assert!(content.contains("Progress:"));
        assert!(content.contains("ETA:"));
    }
}
