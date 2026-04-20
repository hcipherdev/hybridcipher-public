use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Differentiates between folder-based scopes and single-file roots.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoverageRootKind {
    /// Tracks every managed file under a directory tree.
    Folder,
    /// Tracks a single file (used for one-off adoption flows).
    SingleFile,
}

/// Lifecycle state for an enrolled root.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoverageRootState {
    /// Root is actively managed and counts toward coverage.
    Active,
    /// Root has been unenrolled and no longer factors into coverage.
    Unenrolled,
}

/// Metadata describing a folder (or single file) enrolled for coverage tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRoot {
    /// Stable identifier assigned at enrollment time.
    pub root_id: Uuid,
    /// Canonical, absolute filesystem path.
    pub path: PathBuf,
    /// Owning group for this enrolled root.
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// Differentiates directory roots from one-off files.
    pub kind: CoverageRootKind,
    /// Current lifecycle state.
    pub state: CoverageRootState,
    /// Timestamp when the root was enrolled.
    pub created_at: DateTime<Utc>,
    /// Timestamp for the most recent state change.
    pub updated_at: DateTime<Utc>,
    /// Timestamp of the last successful scan covering this root.
    pub last_scan: Option<DateTime<Utc>>,
}

/// Per-file coverage record derived from enrolled roots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileCoverageState {
    /// File is tracked and counts toward coverage ratios.
    Tracked,
    /// File moved out of an enrolled root and must be adopted or removed.
    Orphaned,
    /// File was intentionally removed from coverage (delete/decrypt).
    Tombstoned,
    /// File exists but is not part of any enrolled root.
    Unmanaged,
}

/// Additional context for why a file is orphaned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileOrphanKind {
    /// Metadata exists but references an epoch that is no longer valid for the active group.
    WrongEpoch,
    /// Metadata exists but the corresponding ciphertext is missing on disk.
    MissingFile,
    /// Ciphertext exists and has a HybridCipher header, but no metadata is available locally.
    MissingMetadata,
    /// Ciphertext belongs to a different group than the active one.
    Outcast,
}

/// Index entry describing a managed file within a root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndexEntry {
    /// Stable identifier for the file.
    pub file_uuid: Uuid,
    /// File identifier from the encrypted metadata header, if available.
    #[serde(default)]
    pub file_id: Option<String>,
    /// Identifier of the parent root.
    pub root_id: Uuid,
    /// Relative path within the enrolled root.
    pub relative_path: String,
    /// Size in bytes recorded during the last scan.
    pub size: u64,
    /// Last epoch that successfully protected the file.
    pub last_epoch: u64,
    /// Optional checksum hint (e.g., BLAKE3 chunk hash) for integrity.
    pub checksum_hint: Option<String>,
    /// Timestamp when this file was last observed on disk.
    pub last_seen: DateTime<Utc>,
    /// Current coverage state.
    pub state: FileCoverageState,
    /// Optional reason explaining why the file is orphaned.
    #[serde(default)]
    pub orphan_kind: Option<FileOrphanKind>,
}
