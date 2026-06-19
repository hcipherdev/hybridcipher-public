pub mod mount_runner;

use std::io::{BufRead, Read, Seek, Write};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, NaiveDateTime, Utc};
use filetime::{set_file_times, FileTime};
use hybridcipher_client::{
    config_loader::config_file_candidates,
    file::encrypt::{
        chunked_encrypted_size, normalize_file_identifier, write_encrypted_file, MacOsFileMetadata,
        PlatformFileMetadata, PlatformXattr, SerializedEncryptedHeader, SparseExtent,
        SparseFileMetadata, CHUNKED_HEADER_VERSION,
    },
    storage::{AccessControlData, FileMetadataData},
    ClientError, EncryptedFileMetadata,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(target_os = "macos")]
use std::{
    ffi::{CStr, CString, OsString},
    mem::size_of,
    os::unix::ffi::{OsStrExt, OsStringExt},
};
use sysinfo::Disks;
use thiserror::Error;
use tracing::{debug, info, warn};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
#[cfg(unix)]
use xattr;

#[cfg(target_os = "macos")]
const FILE_ID_XATTR: &str = "com.hybridcipher.file_id";
#[cfg(all(unix, not(target_os = "macos")))]
const FILE_ID_XATTR: &str = "user.hybridcipher.file_id";
#[cfg(target_os = "windows")]
const FILE_ID_STREAM: &str = "hybridcipher.file_id";
#[cfg(target_os = "macos")]
const ORIGINAL_NAME_XATTR: &str = "com.hybridcipher.original_name";
#[cfg(all(unix, not(target_os = "macos")))]
const ORIGINAL_NAME_XATTR: &str = "user.hybridcipher.original_name";
#[cfg(target_os = "windows")]
const ORIGINAL_NAME_STREAM: &str = "hybridcipher.original_name";
#[cfg(target_os = "macos")]
const LOCAL_ONLY_REASON_XATTR: &str = "com.hybridcipher.local_only_reason";
#[cfg(all(unix, not(target_os = "macos")))]
const LOCAL_ONLY_REASON_XATTR: &str = "user.hybridcipher.local_only_reason";
#[cfg(target_os = "windows")]
const LOCAL_ONLY_REASON_STREAM: &str = "hybridcipher.local_only_reason";
#[cfg(target_os = "macos")]
const CONFLICT_ID_XATTR: &str = "com.hybridcipher.conflict_id";
#[cfg(all(unix, not(target_os = "macos")))]
const CONFLICT_ID_XATTR: &str = "user.hybridcipher.conflict_id";
#[cfg(target_os = "windows")]
const CONFLICT_ID_STREAM: &str = "hybridcipher.conflict_id";
#[cfg(target_os = "macos")]
const CONFLICT_LIVE_PATH_XATTR: &str = "com.hybridcipher.conflict_live_path";
#[cfg(all(unix, not(target_os = "macos")))]
const CONFLICT_LIVE_PATH_XATTR: &str = "user.hybridcipher.conflict_live_path";
#[cfg(target_os = "windows")]
const CONFLICT_LIVE_PATH_STREAM: &str = "hybridcipher.conflict_live_path";
#[cfg(target_os = "macos")]
const CONFLICT_KIND_XATTR: &str = "com.hybridcipher.conflict_kind";
#[cfg(all(unix, not(target_os = "macos")))]
const CONFLICT_KIND_XATTR: &str = "user.hybridcipher.conflict_kind";
#[cfg(target_os = "windows")]
const CONFLICT_KIND_STREAM: &str = "hybridcipher.conflict_kind";

const TEMP_FILE_GRACE_SECS: u64 = 30;
const SPARSE_SKIP_SIZE_BYTES: u64 = 512 * 1024 * 1024;
const STREAM_THRESHOLD_BYTES: u64 = 1024 * 1024 * 1024;
const STREAM_CHUNK_SIZE_BYTES: u64 = 4 * 1024 * 1024;
const STREAM_STABILITY_AGE_SECS: u64 = 5;
const STARTUP_LOCAL_DELETE_MAX_ACTIONS: usize = 20;
const ENCRYPTED_TMP_CLEANUP_AGE_SECS: u64 = 300;
const ENCRYPTED_TMP_DIR_NAME: &str = ".hybridcipher-tmp";
const LOW_SPACE_WARNING_RESERVE_BYTES: u64 = 256 * 1024 * 1024;
const LOW_SPACE_JOURNAL_RESERVE_BYTES: u64 = 256 * 1024;
const LOW_SPACE_ATOMIC_WRITE_OVERHEAD_BYTES: u64 = 4 * 1024 * 1024;
const LOW_SPACE_DIRECTORY_CREATE_BYTES: u64 = 4096;
const DIRECTORY_METADATA_FILE_NAME: &str = ".hybridcipher_dir.encrypted";
const MAX_OPEN_UNLINKED_PATHS_IN_STATUS: usize = 16;
const MAX_CONFLICT_PATHS_IN_STATUS: usize = 16;
const MAX_RECOVERED_PENDING_PATHS_IN_STATUS: usize = 16;
const MAX_OPEN_UNLINKED_OWNERS: usize = 8;
const CONFLICT_TEXT_PREVIEW_MAX_BYTES: usize = 1024 * 1024;
const TRANSACTIONAL_DATABASE_EXTENSIONS: &[&str] = &["db", "db3", "sqlite", "sqlite3", "sqlitedb"];
const TRANSACTIONAL_PACKAGE_EXTENSIONS: &[&str] = &[
    "app",
    "bundle",
    "pkg",
    "pages",
    "numbers",
    "key",
    "rtfd",
    "playground",
    "xcodeproj",
    "xcworkspace",
    "photoslibrary",
    "photolibrary",
    "aplibrary",
    "band",
    "logicx",
];

#[cfg(target_os = "macos")]
type MacOsAcl = *mut libc::c_void;
#[cfg(target_os = "macos")]
type MacOsAclType = libc::c_int;
#[cfg(target_os = "macos")]
const MACOS_ACL_TYPE_EXTENDED: MacOsAclType = 0x0000_0100;
#[cfg(target_os = "macos")]
const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;
#[cfg(target_os = "macos")]
const PROC_PIDTBSDINFO_SIZE: libc::c_int = size_of::<libc::proc_bsdinfo>() as libc::c_int;
#[cfg(target_os = "macos")]
const PROC_PIDFDVNODEPATHINFO_SIZE: libc::c_int =
    size_of::<MacOsVnodeFdInfoWithPath>() as libc::c_int;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_get_file(path_p: *const libc::c_char, type_: MacOsAclType) -> MacOsAcl;
    fn acl_set_file(path_p: *const libc::c_char, type_: MacOsAclType, acl: MacOsAcl)
        -> libc::c_int;
    fn acl_from_text(buf_p: *const libc::c_char) -> MacOsAcl;
    fn acl_to_text(acl: MacOsAcl, len_p: *mut libc::ssize_t) -> *mut libc::c_char;
    fn acl_free(obj_p: *mut libc::c_void) -> libc::c_int;
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacOsProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: libc::off_t,
    fi_type: i32,
    fi_guardflags: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacOsVinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: libc::uid_t,
    vst_gid: libc::gid_t,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: libc::off_t,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacOsVnodeInfo {
    vi_stat: MacOsVinfoStat,
    vi_type: libc::c_int,
    vi_pad: libc::c_int,
    vi_fsid: libc::fsid_t,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacOsVnodeInfoPath {
    vip_vi: MacOsVnodeInfo,
    vip_path: [libc::c_char; libc::MAXPATHLEN as usize],
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacOsVnodeFdInfoWithPath {
    pfi: MacOsProcFileInfo,
    pvip: MacOsVnodeInfoPath,
}

const EMBEDDED_CLIENT_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../client/resources/client_config.toml"
));

#[derive(Debug, Error)]
pub enum MountSyncError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Format error: {0}")]
    Format(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Unstable file during sync: {0}")]
    UnstableFile(String),
    #[error("Path excluded from encryption: {0}")]
    PathExcluded(String),
    #[error("Invalid path: {0}")]
    InvalidPath(PathBuf),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowSpaceMode {
    #[default]
    Healthy,
    Warning,
    RefreshDegraded,
    WritebackDegraded,
    FullyDegraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MountSafetyReason {
    PendingWriteback {
        count: usize,
        oldest_age_ms: u64,
        #[serde(default)]
        sample_paths: Vec<String>,
        #[serde(default)]
        last_error: Option<String>,
    },
    PendingRefresh {
        count: usize,
    },
    Conflict {
        count: usize,
        edited_count: usize,
        sample_paths: Vec<String>,
    },
    DeletedOpen {
        count: usize,
        sample_paths: Vec<String>,
    },
    TransactionalBlocked {
        count: usize,
        sample_paths: Vec<String>,
    },
    HardLinkBlocked {
        count: usize,
        sample_paths: Vec<String>,
    },
    LowSpaceDegraded {
        mode: LowSpaceMode,
        count: usize,
        sample_paths: Vec<String>,
    },
    RecoveryCopiesPresent {
        count: usize,
        sample_paths: Vec<String>,
    },
}

impl MountSafetyReason {
    pub fn is_auto_drainable(&self) -> bool {
        match self {
            MountSafetyReason::PendingWriteback { last_error, .. } => {
                !pending_writeback_error_is_terminal(last_error.as_deref())
            }
            MountSafetyReason::PendingRefresh { .. } => true,
            _ => false,
        }
    }

    fn summary(&self) -> String {
        match self {
            MountSafetyReason::PendingWriteback {
                count,
                oldest_age_ms,
                sample_paths,
                last_error,
            } => {
                let mut message = format!(
                    "{count} pending encrypted commit(s) still need to finish before the newest local changes are protected. Oldest pending commit age: {}s.",
                    oldest_age_ms / 1000
                );
                if let Some(path) = sample_paths.first() {
                    message.push_str(&format!(" Example: {path}"));
                }
                if let Some(error) = last_error
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                {
                    message.push_str(&format!(" Last error: {error}"));
                }
                message
            }
            MountSafetyReason::PendingRefresh { count } => format!(
                "{count} pending plaintext refresh(es) are still rebuilding the local mount state."
            ),
            MountSafetyReason::Conflict {
                count,
                edited_count,
                sample_paths,
            } => {
                let mut message = format!(
                    "{count} unresolved conflict file(s) remain local-only until they are resolved or merged back."
                );
                if let Some(path) = sample_paths.first() {
                    message.push_str(&format!(" Example: {path}"));
                }
                if *edited_count > 0 {
                    message.push_str(&format!(
                        " {edited_count} conflict file(s) were edited locally and are still not protected by encrypted sync."
                    ));
                }
                message
            }
            MountSafetyReason::DeletedOpen {
                count,
                sample_paths,
            } => {
                let mut message = format!("{count} deleted-open path(s) are still active.");
                if let Some(path) = sample_paths.first() {
                    message.push_str(&format!(" Example: {path}"));
                }
                message
            }
            MountSafetyReason::TransactionalBlocked {
                count,
                sample_paths,
            } => {
                let mut message = format!(
                    "{count} transactional path(s) are blocked because sync mount does not provide atomic-set guarantees for databases, packages, or bundle-style formats."
                );
                if let Some(path) = sample_paths.first() {
                    message.push_str(&format!(" Example: {path}"));
                }
                message
            }
            MountSafetyReason::HardLinkBlocked {
                count,
                sample_paths,
            } => {
                let mut message = format!(
                    "{count} hard-linked file(s) are blocked because sync mount does not preserve hard-link semantics."
                );
                if let Some(path) = sample_paths.first() {
                    message.push_str(&format!(" Example: {path}"));
                }
                message.push_str(
                    " Break the hard link or replace it with an independent copy to resume protected sync.",
                );
                message
            }
            MountSafetyReason::LowSpaceDegraded {
                mode,
                count,
                sample_paths,
            } => {
                let mut message = if *count > 0 {
                    format!("Low-space degraded mode ({mode:?}) is active for {count} path(s).")
                } else {
                    format!("Low-space degraded mode ({mode:?}) is active.")
                };
                if let Some(path) = sample_paths.first() {
                    message.push_str(&format!(" Example: {path}"));
                }
                message
            }
            MountSafetyReason::RecoveryCopiesPresent {
                count,
                sample_paths,
            } => {
                let mut message = format!(
                    "{count} recovered pending-work file(s) were recreated as local-only read-only copies after an unclean mount restart."
                );
                if let Some(path) = sample_paths.first() {
                    message.push_str(&format!(" Example: {path}"));
                }
                message
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSyncRuntimeStatus {
    pub safe_to_unmount: bool,
    pub pending_writeback_count: usize,
    #[serde(default)]
    pub pending_writeback_oldest_age_ms: Option<u64>,
    #[serde(default)]
    pub pending_writeback_paths: Vec<String>,
    pub pending_refresh_count: usize,
    pub pending_open_unlinked_count: usize,
    #[serde(default)]
    pub pending_conflict_count: usize,
    #[serde(default)]
    pub edited_conflict_count: usize,
    #[serde(default)]
    pub recovered_pending_copy_count: usize,
    pub pending_low_space_path_count: usize,
    pub low_space_mode: LowSpaceMode,
    pub low_space_paths: Vec<String>,
    pub open_unlinked_paths: Vec<String>,
    #[serde(default)]
    pub conflict_paths: Vec<String>,
    #[serde(default)]
    pub edited_conflict_paths: Vec<String>,
    #[serde(default)]
    pub recovered_pending_copy_paths: Vec<String>,
    #[serde(default)]
    pub unsafe_reasons: Vec<MountSafetyReason>,
    pub preflight_warnings: Vec<String>,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl Default for MountSyncRuntimeStatus {
    fn default() -> Self {
        Self {
            safe_to_unmount: false,
            pending_writeback_count: 0,
            pending_writeback_oldest_age_ms: None,
            pending_writeback_paths: Vec::new(),
            pending_refresh_count: 0,
            pending_open_unlinked_count: 0,
            pending_conflict_count: 0,
            edited_conflict_count: 0,
            recovered_pending_copy_count: 0,
            pending_low_space_path_count: 0,
            low_space_mode: LowSpaceMode::Healthy,
            low_space_paths: Vec::new(),
            open_unlinked_paths: Vec::new(),
            conflict_paths: Vec::new(),
            edited_conflict_paths: Vec::new(),
            recovered_pending_copy_paths: Vec::new(),
            unsafe_reasons: Vec::new(),
            preflight_warnings: Vec::new(),
            last_error: None,
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    DecryptCollision,
    DeletedOpenRecovery,
    /// Both local and remote modified the same file while disconnected
    LocalRemoteBothModified,
    /// Local edited a file that was deleted remotely
    LocalEditRemoteDelete,
    /// Local deleted a file that was edited remotely
    LocalDeleteRemoteEdit,
}

/// Policy for resolving conflicts during sync mount recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictPolicy {
    /// Default resolution strategy
    pub default_resolution: ConflictPolicyResolution,
    /// If timestamps differ by less than this, always keep both
    pub timestamp_threshold_secs: u64,
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        Self {
            default_resolution: ConflictPolicyResolution::KeepBoth,
            timestamp_threshold_secs: 5,
        }
    }
}

/// Resolution strategy for conflict policy (distinct from ConflictResolutionAction which is user-driven)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicyResolution {
    /// Keep both versions: original + .conflict-<timestamp> copy (default, like Dropbox)
    #[default]
    KeepBoth,
    /// Newer timestamp wins, older becomes conflict copy
    NewerWins,
    /// Local always wins
    LocalWins,
    /// Remote always wins (legacy behavior)
    RemoteWins,
}

/// Action determined during per-file reconciliation on unclean remount
#[derive(Debug, Clone)]
pub enum ReconciliationAction {
    /// File unchanged - no action needed
    Unchanged { path: PathBuf },
    /// Local file modified, no remote change - queue for encryption
    LocalModified { mount_path: PathBuf },
    /// New local file not present in encrypted - queue for encryption
    LocalCreated { mount_path: PathBuf },
    /// Local file deleted - queue encrypted deletion
    LocalDeleted {
        mount_path: PathBuf,
        encrypted_path: PathBuf,
    },
    /// Remote changed, local unchanged - decrypt fresh (current behavior)
    RemoteModified {
        mount_path: PathBuf,
        encrypted_path: PathBuf,
    },
    /// Both modified - conflict requiring resolution
    Conflict {
        mount_path: PathBuf,
        encrypted_path: PathBuf,
        kind: ConflictKind,
    },
}

/// Summary of reconciliation results for reporting
#[derive(Debug, Clone, Default)]
pub struct ReconciliationSummary {
    pub unchanged_count: usize,
    pub local_modified: Vec<PathBuf>,
    pub local_created: Vec<PathBuf>,
    pub local_deleted: Vec<PathBuf>,
    pub remote_modified: Vec<PathBuf>,
    pub conflicts: Vec<(PathBuf, ConflictKind)>,
}

impl ConflictKind {
    fn local_only_reason(self) -> &'static str {
        match self {
            ConflictKind::DecryptCollision => "conflict",
            ConflictKind::DeletedOpenRecovery => "deleted_open_recovery",
            ConflictKind::LocalRemoteBothModified => "both_modified_conflict",
            ConflictKind::LocalEditRemoteDelete => "local_edit_remote_delete",
            ConflictKind::LocalDeleteRemoteEdit => "local_delete_remote_edit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConflictRecord {
    pub id: Uuid,
    pub kind: ConflictKind,
    pub live_relative_path: PathBuf,
    pub conflict_relative_path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub edited: bool,
    pub live_exists: bool,
    pub text_merge_supported: bool,
    pub live_size_bytes: Option<u64>,
    pub conflict_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConflictPreview {
    pub record: MountConflictRecord,
    pub live_path: PathBuf,
    pub conflict_path: PathBuf,
    pub live_text: Option<String>,
    pub conflict_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolutionAction {
    KeepMountedFile,
    UseConflictCopy,
    MergeText,
    SaveConflictAsNew,
    ArchiveAndDismiss,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResolutionRequest {
    pub request_id: Uuid,
    pub conflict_id: Uuid,
    pub action: ConflictResolutionAction,
    #[serde(default)]
    pub merged_text: Option<String>,
    #[serde(default)]
    pub destination_path: Option<PathBuf>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResolutionResult {
    pub resolved_conflict_id: Uuid,
    pub archive_paths: Vec<PathBuf>,
    pub live_path: Option<PathBuf>,
    pub requires_writeback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResolutionResponse {
    pub request_id: Uuid,
    pub success: bool,
    #[serde(default)]
    pub result: Option<ConflictResolutionResult>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountRecoveryCopyRecord {
    pub recovery_relative_path: PathBuf,
    pub live_relative_path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub live_exists: bool,
    pub text_preview_supported: bool,
    pub live_size_bytes: Option<u64>,
    pub recovery_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountRecoveryCopyPreview {
    pub record: MountRecoveryCopyRecord,
    pub live_path: PathBuf,
    pub recovery_path: PathBuf,
    pub live_text: Option<String>,
    pub recovery_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCopyResolutionAction {
    ReplaceMountedFile,
    SaveAsNew,
    ArchiveAndDismiss,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCopyResolutionRequest {
    pub request_id: Uuid,
    pub recovery_relative_path: PathBuf,
    pub action: RecoveryCopyResolutionAction,
    #[serde(default)]
    pub destination_path: Option<PathBuf>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCopyResolutionResult {
    pub resolved_recovery_relative_path: PathBuf,
    pub archive_paths: Vec<PathBuf>,
    pub live_path: Option<PathBuf>,
    pub requires_writeback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCopyResolutionResponse {
    pub request_id: Uuid,
    pub success: bool,
    #[serde(default)]
    pub result: Option<RecoveryCopyResolutionResult>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StreamingEncryptedFile {
    pub metadata: EncryptedFileMetadata,
    pub integrity_hash: [u8; 32],
}

impl From<ClientError> for MountSyncError {
    fn from(value: ClientError) -> Self {
        match value {
            ClientError::PathExcluded(path) => MountSyncError::PathExcluded(path),
            other => MountSyncError::Crypto(other.to_string()),
        }
    }
}

#[async_trait]
pub trait MountCrypto: Send + Sync {
    async fn decrypt_file(
        &self,
        encrypted_path: &Path,
        metadata: &EncryptedFileMetadata,
    ) -> Result<Vec<u8>, MountSyncError>;

    async fn decrypt_file_streaming(
        &self,
        encrypted_path: &Path,
        output_path: &Path,
        metadata: &EncryptedFileMetadata,
    ) -> Result<(), MountSyncError>;

    async fn encrypt_file(
        &self,
        relative_path: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedFileMetadata, MountSyncError>;

    async fn encrypt_file_with_id(
        &self,
        relative_path: &str,
        plaintext: &[u8],
        file_id: &str,
    ) -> Result<EncryptedFileMetadata, MountSyncError>;

    async fn encrypt_file_streaming(
        &self,
        relative_path: &str,
        plaintext_path: &Path,
        output_path: &Path,
        original_name: Option<&str>,
        platform_metadata: Option<&PlatformFileMetadata>,
        chunk_size: usize,
    ) -> Result<StreamingEncryptedFile, MountSyncError>;

    async fn encrypt_file_streaming_with_id(
        &self,
        relative_path: &str,
        plaintext_path: &Path,
        output_path: &Path,
        original_name: Option<&str>,
        platform_metadata: Option<&PlatformFileMetadata>,
        file_id: &str,
        chunk_size: usize,
    ) -> Result<StreamingEncryptedFile, MountSyncError>;

    async fn coverage_store_metadata(
        &self,
        metadata: FileMetadataData,
    ) -> Result<(), MountSyncError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FileSignature {
    modified_ns: u128,
    ctime_ns: u128,
    len: u64,
}

impl FileSignature {
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        let len = metadata.len();
        let modified_ns = metadata
            .modified()
            .ok()
            .map(system_time_to_ns)
            .unwrap_or_default();
        let ctime_ns = metadata_change_time_ns(metadata);
        Self {
            modified_ns,
            ctime_ns,
            len,
        }
    }

    fn content_signature_eq(&self, other: &Self) -> bool {
        self.modified_ns == other.modified_ns && self.len == other.len
    }

    fn ctime_only_change(&self, other: &Self) -> bool {
        self.content_signature_eq(other) && self.ctime_ns != other.ctime_ns
    }
}

const ZERO_SIGNATURE: FileSignature = FileSignature {
    modified_ns: 0,
    ctime_ns: 0,
    len: 0,
};

fn system_time_to_ns(time: SystemTime) -> u128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            (duration.as_secs() as u128) * 1_000_000_000u128 + duration.subsec_nanos() as u128
        }
        Err(_) => 0,
    }
}

fn metadata_change_time_ns(metadata: &fs::Metadata) -> u128 {
    #[cfg(unix)]
    {
        let secs = metadata.ctime();
        let nsecs = metadata.ctime_nsec();
        if secs < 0 || nsecs < 0 {
            0
        } else {
            (secs as u128) * 1_000_000_000u128 + (nsecs as u128)
        }
    }
    #[cfg(not(unix))]
    {
        metadata
            .modified()
            .ok()
            .map(system_time_to_ns)
            .unwrap_or_default()
    }
}

// Two-phase deletion configuration (can be overridden via config)
#[derive(Debug, Clone)]
pub struct DeletionConfig {
    pub min_consecutive_missing_scans: u32,
    pub rapid_scan_total_duration_ms: u64,
    pub retention_days: u32,
    /// Path to retention folder where deleted files are moved before permanent deletion
    pub retention_folder: Option<PathBuf>,
}

impl Default for DeletionConfig {
    fn default() -> Self {
        Self {
            min_consecutive_missing_scans: 7,
            rapid_scan_total_duration_ms: 2718, // 2.71828 seconds
            retention_days: 7,
            retention_folder: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MountSyncConfig {
    pub deletion: DeletionConfig,
    pub sparse_skip_size_bytes: u64,
    pub stream_threshold_bytes: u64,
    pub stream_chunk_size_bytes: u64,
    pub stream_stability_age_secs: u64,
    pub startup_local_delete_max_actions: usize,
}

impl Default for MountSyncConfig {
    fn default() -> Self {
        Self {
            deletion: DeletionConfig::default(),
            sparse_skip_size_bytes: SPARSE_SKIP_SIZE_BYTES,
            stream_threshold_bytes: STREAM_THRESHOLD_BYTES,
            stream_chunk_size_bytes: STREAM_CHUNK_SIZE_BYTES,
            stream_stability_age_secs: STREAM_STABILITY_AGE_SECS,
            startup_local_delete_max_actions: STARTUP_LOCAL_DELETE_MAX_ACTIONS,
        }
    }
}

impl DeletionConfig {
    pub fn rapid_scan_interval_ms(&self) -> u64 {
        self.rapid_scan_total_duration_ms / self.min_consecutive_missing_scans as u64
    }

    /// Set the retention folder path based on user config directory
    pub fn with_retention_folder(mut self, user_config_dir: &Path) -> Self {
        let retention_path = user_config_dir.join("retention");
        self.retention_folder = Some(retention_path);
        self
    }
}

fn apply_mount_config_from_str(contents: &str, source: &str, config: &mut MountSyncConfig) -> bool {
    let parsed: toml::Value = match toml::from_str(contents) {
        Ok(val) => val,
        Err(err) => {
            debug!("Failed to parse {} for mount config: {}", source, err);
            return false;
        }
    };

    let mount = match parsed.get("mount") {
        Some(section) => section,
        None => return false,
    };

    if let Some(deletion) = mount.get("deletion") {
        if let Some(scans) = deletion.get("min_consecutive_missing_scans") {
            if let Some(val) = scans.as_integer() {
                if val > 0 {
                    config.deletion.min_consecutive_missing_scans = val as u32;
                }
            }
        }

        if let Some(duration) = deletion.get("rapid_scan_total_duration_ms") {
            if let Some(val) = duration.as_integer() {
                if val > 0 {
                    config.deletion.rapid_scan_total_duration_ms = val as u64;
                }
            }
        }

        if let Some(retention) = deletion.get("retention_days") {
            if let Some(val) = retention.as_integer() {
                if val > 0 {
                    config.deletion.retention_days = val as u32;
                }
            }
        }
    }

    if let Some(size) = mount.get("sparse_skip_size_bytes") {
        if let Some(val) = size.as_integer() {
            if val >= 0 {
                config.sparse_skip_size_bytes = val as u64;
            }
        }
    }

    if let Some(size) = mount.get("stream_threshold_bytes") {
        if let Some(val) = size.as_integer() {
            if val >= 0 {
                config.stream_threshold_bytes = val as u64;
            }
        }
    }

    if let Some(size) = mount.get("stream_chunk_size_bytes") {
        if let Some(val) = size.as_integer() {
            if val > 0 {
                config.stream_chunk_size_bytes = val as u64;
            }
        }
    }

    if let Some(value) = mount.get("stream_stability_age_secs") {
        if let Some(val) = value.as_integer() {
            if val >= 0 {
                config.stream_stability_age_secs = val as u64;
            }
        }
    }

    if let Some(value) = mount.get("startup_local_delete_max_actions") {
        if let Some(val) = value.as_integer() {
            if val > 0 {
                config.startup_local_delete_max_actions = val as usize;
            }
        }
    }

    debug!("Applied mount config from {}", source);
    true
}

#[derive(Debug, Clone, Default)]
enum ScanHealth {
    #[default]
    Healthy,
    #[allow(dead_code)]
    Unhealthy { reason: String },
}

#[derive(Debug, Clone)]
struct PendingDeletion {
    /// Path to the mount file that was deleted (used for verification)
    mount_path: PathBuf,
    /// When the file was first detected as missing (used for retention timeout cleanup)
    #[allow(dead_code)]
    first_missing_time: Instant,
    consecutive_missing_scans: u32,
    had_healthy_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingDeletionRecord {
    encrypted_path: PathBuf,
    mount_path: PathBuf,
    consecutive_missing_scans: u32,
    had_healthy_scan: bool,
}

#[derive(Debug, Clone)]
struct PendingOrphan {
    encrypted_path: PathBuf,
    consecutive_missing_scans: u32,
    had_healthy_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingOrphanRecord {
    mount_path: PathBuf,
    encrypted_path: PathBuf,
    consecutive_missing_scans: u32,
    had_healthy_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingWriteback {
    encrypted_path: PathBuf,
    last_error: Option<String>,
    low_space: bool,
    first_observed_at: DateTime<Utc>,
    last_observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingWritebackRecord {
    mount_path: PathBuf,
    encrypted_path: PathBuf,
    last_error: Option<String>,
    low_space: bool,
    #[serde(default = "pending_writeback_default_timestamp")]
    first_observed_at: DateTime<Utc>,
    #[serde(default = "pending_writeback_default_timestamp")]
    last_observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRefresh {
    encrypted_path: PathBuf,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRefreshRecord {
    mount_path: PathBuf,
    encrypted_path: PathBuf,
    last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OpenUnlinkedOwner {
    pid: i32,
    name: String,
}

#[derive(Debug, Clone)]
struct PendingOpenUnlinked {
    encrypted_path: Option<PathBuf>,
    encrypted_version_exists: bool,
    had_unsynced_local_writeback: bool,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    owners: Vec<OpenUnlinkedOwner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingOpenUnlinkedRecord {
    mount_path: PathBuf,
    encrypted_path: Option<PathBuf>,
    encrypted_version_exists: bool,
    had_unsynced_local_writeback: bool,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    owners: Vec<OpenUnlinkedOwner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingMetadataRecord {
    encrypted_path: PathBuf,
    metadata: FileMetadataData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncBaselineRecord {
    encrypted_signatures: Vec<SyncBaselineEncryptedSignatureRecord>,
    decrypted_signatures: Vec<SyncBaselineDecryptedSignatureRecord>,
    path_mappings: Vec<SyncBaselinePathMappingRecord>,
    file_id_mappings: Vec<SyncBaselineFileIdMappingRecord>,
    decrypted_hashes: Vec<SyncBaselineHashRecord>,
    decrypted_metadata_hashes: Vec<SyncBaselineHashRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncBaselineEncryptedSignatureRecord {
    encrypted_path: PathBuf,
    signature: FileSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncBaselineDecryptedSignatureRecord {
    mount_path: PathBuf,
    signature: FileSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncBaselinePathMappingRecord {
    encrypted_path: PathBuf,
    mount_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncBaselineFileIdMappingRecord {
    file_id: String,
    mount_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncBaselineHashRecord {
    mount_path: PathBuf,
    hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RetentionMetadata {
    deleted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
struct StableEntry {
    signature: FileSignature,
    first_seen: Instant,
}

#[derive(Debug, Clone)]
struct ConflictBaseline {
    id: Uuid,
    live_path: PathBuf,
    kind: ConflictKind,
    created_at: DateTime<Utc>,
    signature: FileSignature,
    content_hash: Option<[u8; 32]>,
    edited: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConflictRegistryRecord {
    id: Uuid,
    kind: ConflictKind,
    live_relative_path: PathBuf,
    conflict_relative_path: PathBuf,
    created_at: DateTime<Utc>,
    edited: bool,
    live_exists: bool,
    text_merge_supported: bool,
    live_size_bytes: Option<u64>,
    conflict_size_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct SpaceWarningState {
    mount_low: bool,
    encrypted_low: bool,
    journal_low: bool,
}

impl SpaceWarningState {
    fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.mount_low {
            warnings.push("mount volume below reserve".to_string());
        }
        if self.encrypted_low {
            warnings.push("encrypted volume below reserve".to_string());
        }
        if self.journal_low {
            warnings.push("journal volume below reserve".to_string());
        }
        warnings
    }

    fn any(&self) -> bool {
        self.mount_low || self.encrypted_low || self.journal_low
    }
}

enum DecryptOutcome {
    Ready(PathBuf),
    DeferredLowSpace(PathBuf),
}

fn normalize_relative_path(relative: &Path) -> String {
    let label = relative.to_string_lossy().replace('\\', "/");
    let trimmed = label.trim_matches('/');
    if trimmed.is_empty() {
        relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown_file")
            .to_string()
    } else {
        trimmed.to_string()
    }
}

fn truncate_to_char_boundary(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }

    let mut end = 0;
    for (idx, _) in value.char_indices() {
        if idx > max_len {
            break;
        }
        end = idx;
    }
    value[..end].to_string()
}

fn safe_name_with_suffix(name: &str, marker: &str, file_id: &str) -> String {
    let suffix_len = 12.min(file_id.len());
    let suffix = &file_id[..suffix_len];
    let marker = format!(".{}-", marker);
    let max_component_len = 240usize;
    let available = max_component_len.saturating_sub(marker.len() + suffix.len());
    let base = truncate_to_char_boundary(name, available);
    format!("{}{}{}", base, marker, suffix)
}

fn collision_safe_name(name: &str, file_id: &str) -> String {
    safe_name_with_suffix(name, "collision", file_id)
}

fn sanitized_safe_name(name: &str, file_id: &str) -> String {
    safe_name_with_suffix(name, "sanitized", file_id)
}

fn collision_safe_path(target: &Path, file_id: &str) -> PathBuf {
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("collision");
    let new_name = collision_safe_name(file_name, file_id);
    match target.parent() {
        Some(parent) => parent.join(new_name),
        None => PathBuf::from(new_name),
    }
}

fn pending_writeback_default_timestamp() -> DateTime<Utc> {
    Utc::now()
}

fn sanitize_mount_file_name(name: &str, file_id: &str) -> (String, bool) {
    let mut sanitized = name.replace('/', "_");
    let mut changed = sanitized != name;

    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        sanitized = "unnamed".to_string();
        changed = true;
    }

    let max_component_len = 240usize;
    if sanitized.len() > max_component_len {
        sanitized = sanitized_safe_name(&sanitized, file_id);
        changed = true;
    }

    (sanitized, changed)
}

fn is_temp_like_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    if name.starts_with("~$")
        || name.starts_with(".#")
        || name.starts_with('~')
        || name.starts_with(".~lock.")
        || (name.starts_with('#') && name.ends_with('#'))
    {
        return true;
    }

    if name.starts_with(".___jb_tmp___") || name.starts_with(".goutputstream-") {
        return true;
    }

    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), ".ds_store" | ".trashes" | ".temporaryitems")
        || lower.ends_with(".swp")
        || lower.ends_with(".swo")
        || lower.ends_with(".swx")
        || lower.ends_with(".bak")
        || lower.ends_with(".tmp")
        || lower.ends_with(".temp")
        || lower.ends_with(".part")
        || lower.ends_with('~')
}

fn is_directory_metadata_file(path: &Path) -> bool {
    path.file_name().and_then(|value| value.to_str()) == Some(DIRECTORY_METADATA_FILE_NAME)
}

fn encrypted_directory_metadata_path_for(
    encrypted_root: &Path,
    mount_root: &Path,
    directory_path: &Path,
) -> Result<PathBuf, MountSyncError> {
    let relative = directory_path.strip_prefix(mount_root).map_err(|_| {
        MountSyncError::Format(format!(
            "Directory {} is outside mount root",
            directory_path.display()
        ))
    })?;

    Ok(encrypted_root
        .join(relative)
        .join(DIRECTORY_METADATA_FILE_NAME))
}

fn decrypted_directory_target_path(
    encrypted_root: &Path,
    encrypted_path: &Path,
    mount_root: &Path,
) -> Result<PathBuf, MountSyncError> {
    let relative = encrypted_path.strip_prefix(encrypted_root).map_err(|_| {
        MountSyncError::Format("Encrypted directory metadata is outside the selected root".into())
    })?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    Ok(mount_root.join(parent))
}

fn is_transactional_package_name(name: &str) -> bool {
    let Some(ext) = Path::new(name).extension().and_then(|value| value.to_str()) else {
        return false;
    };

    TRANSACTIONAL_PACKAGE_EXTENSIONS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(ext))
}

fn directory_has_existing_encrypted_state(
    encrypted_root: &Path,
    mount_root: &Path,
    directory_path: &Path,
) -> bool {
    let Ok(relative) = directory_path.strip_prefix(mount_root) else {
        return false;
    };
    let encrypted_dir = encrypted_root.join(relative);
    if !encrypted_dir.exists() {
        return false;
    }

    let mut stack = vec![encrypted_dir];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) == Some(ENCRYPTED_TMP_DIR_NAME) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if is_directory_metadata_file(&path)
                || path.extension().and_then(|value| value.to_str()) == Some("encrypted")
            {
                return true;
            }
        }
    }

    false
}

fn directory_is_empty(path: &Path) -> Result<bool, MountSyncError> {
    let mut entries = fs::read_dir(path)?;
    Ok(entries.next().is_none())
}

fn known_transactional_database_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let path = Path::new(&lower);
    if let Some(ext) = path.extension().and_then(|ext| ext.to_str()) {
        if TRANSACTIONAL_DATABASE_EXTENSIONS.contains(&ext) {
            return true;
        }
    }

    for suffix in ["-wal", "-shm", "-journal"] {
        if !lower.ends_with(suffix) {
            continue;
        }
        let base = &lower[..lower.len().saturating_sub(suffix.len())];
        let Some(ext) = Path::new(base).extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if TRANSACTIONAL_DATABASE_EXTENSIONS.contains(&ext) {
            return true;
        }
    }

    false
}

fn transactional_package_ancestor(relative: &Path) -> Option<String> {
    for ancestor in relative.ancestors().skip(1) {
        let Some(name) = ancestor.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(ext) = Path::new(name).extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if TRANSACTIONAL_PACKAGE_EXTENSIONS
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(ext))
        {
            return Some(name.to_string());
        }
    }

    None
}

fn transactional_format_reason(mount_root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(mount_root).ok()?;
    if let Some(package_name) = transactional_package_ancestor(relative) {
        return Some(format!(
            "package-like directory {} requires atomic-set sync",
            package_name
        ));
    }

    let file_name = path.file_name().and_then(|value| value.to_str())?;
    if known_transactional_database_name(file_name) {
        return Some(format!(
            "database/journal file {} requires atomic-set sync",
            file_name
        ));
    }

    None
}

fn should_cleanup_encrypted_temp(metadata: &fs::Metadata) -> bool {
    match metadata.modified() {
        Ok(modified) => SystemTime::now()
            .duration_since(modified)
            .map(|age| age.as_secs() >= ENCRYPTED_TMP_CLEANUP_AGE_SECS)
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn cleanup_encrypted_tmp_dir(path: &Path) {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) => {
            warn!(
                "Failed to read encrypted temp dir {}: {}",
                path.display(),
                err
            );
            return;
        }
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                warn!(
                    "Failed to stat encrypted temp file {}: {}",
                    entry_path.display(),
                    err
                );
                continue;
            }
        };

        if metadata.is_dir() {
            continue;
        }

        if should_cleanup_encrypted_temp(&metadata) {
            if let Err(err) = fs::remove_file(&entry_path) {
                if err.kind() != io::ErrorKind::NotFound {
                    warn!(
                        "Failed to remove stale encrypted temp file {}: {}",
                        entry_path.display(),
                        err
                    );
                }
            }
        }
    }
}

#[cfg(unix)]
#[allow(dead_code)]
fn sparse_metrics(metadata: &fs::Metadata) -> Option<(u64, u64)> {
    let logical = metadata.len();
    let blocks = metadata.blocks();
    if logical == 0 || blocks == 0 {
        return None;
    }
    let physical = blocks.saturating_mul(512);
    Some((logical, physical))
}

#[cfg(not(unix))]
fn sparse_metrics(_metadata: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn sparse_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<Option<SparseFileMetadata>, MountSyncError> {
    let logical_size = metadata.len();
    if logical_size == 0 {
        return Ok(None);
    }

    let file = fs::File::open(path)?;
    let fd = file.as_raw_fd();
    let mut extents = Vec::new();
    let mut cursor = 0u64;

    while cursor < logical_size {
        let data = unsafe { libc::lseek(fd, cursor as libc::off_t, libc::SEEK_DATA) };
        if data < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == libc::ENXIO => break,
                Some(code) if code == libc::EINVAL => return Ok(None),
                _ => return Err(MountSyncError::Io(err)),
            }
        }

        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == libc::EINVAL => return Ok(None),
                _ => return Err(MountSyncError::Io(err)),
            }
        }

        let offset = data as u64;
        let hole = hole as u64;
        if hole > offset {
            extents.push(SparseExtent {
                offset,
                length: hole - offset,
            });
        }
        cursor = hole;
    }

    let sparse = SparseFileMetadata {
        logical_size,
        extents,
    };
    if !sparse.is_effectively_sparse() {
        return Ok(None);
    }

    Ok(Some(sparse))
}

#[cfg(not(unix))]
fn sparse_file_metadata(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<Option<SparseFileMetadata>, MountSyncError> {
    Ok(None)
}

#[cfg(unix)]
fn should_skip_sparse_update(
    _metadata: &fs::Metadata,
    _encrypted_exists: bool,
    _sparse_skip_size_bytes: u64,
) -> bool {
    false
}

#[cfg(not(unix))]
fn should_skip_sparse_update(
    metadata: &fs::Metadata,
    encrypted_exists: bool,
    sparse_skip_size_bytes: u64,
) -> bool {
    if sparse_skip_size_bytes == 0 {
        return false;
    }
    if !encrypted_exists {
        return false;
    }
    let (logical, physical) = match sparse_metrics(metadata) {
        Some(values) => values,
        None => return false,
    };
    if logical < sparse_skip_size_bytes {
        return false;
    }
    physical.saturating_mul(2) < logical
}

fn copy_sparse_extents_to_dense_file(
    source_path: &Path,
    packed_path: &Path,
    sparse_metadata: &SparseFileMetadata,
) -> Result<(), MountSyncError> {
    let parent = packed_path.parent().ok_or_else(|| {
        MountSyncError::Format(format!(
            "Packed sparse temp path {} has no parent directory",
            packed_path.display()
        ))
    })?;
    fs::create_dir_all(parent)?;

    let mut input = fs::File::open(source_path)?;
    let mut output = fs::File::create(packed_path)?;
    let mut buffer = vec![0u8; 1024 * 1024];

    for extent in &sparse_metadata.extents {
        input.seek(io::SeekFrom::Start(extent.offset))?;
        let mut remaining = extent.length;
        while remaining > 0 {
            let read_len =
                usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = input.read(&mut buffer[..read_len])?;
            if read == 0 {
                return Err(MountSyncError::Format(format!(
                    "Unexpected EOF while packing sparse extent from {}",
                    source_path.display()
                )));
            }
            output.write_all(&buffer[..read])?;
            remaining = remaining.saturating_sub(read as u64);
        }
    }

    output.sync_all()?;
    Ok(())
}

fn rewrite_encrypted_file_atomic_from_ciphertext(
    source_path: &Path,
    destination_path: &Path,
    header: &SerializedEncryptedHeader<'_>,
) -> Result<(), MountSyncError> {
    let parent = destination_path.parent().ok_or_else(|| {
        MountSyncError::Format(format!(
            "Encrypted file path {} has no parent directory",
            destination_path.display()
        ))
    })?;
    let file_name = destination_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "encrypted".to_string());
    let tmp_dir = parent.join(ENCRYPTED_TMP_DIR_NAME);
    fs::create_dir_all(&tmp_dir)?;
    let tmp_name = format!("tmp-{}.{}", Uuid::new_v4(), file_name);
    let tmp_path = tmp_dir.join(tmp_name);

    let mut source = io::BufReader::new(fs::File::open(source_path)?);
    let mut line = Vec::new();
    loop {
        line.clear();
        let bytes = source.read_until(b'\n', &mut line)?;
        if bytes == 0 {
            return Err(MountSyncError::Format(format!(
                "Encrypted header separator not found in {}",
                source_path.display()
            )));
        }
        if line == b"---ENCRYPTED_DATA---\n" || line == b"---ENCRYPTED_DATA---" {
            break;
        }
    }

    let header_bytes = hybridcipher_client::file::encrypt::serialize_encrypted_header(header)
        .map_err(|err| MountSyncError::Format(err.to_string()))?;
    let mut tmp = io::BufWriter::new(fs::File::create(&tmp_path)?);
    tmp.write_all(&header_bytes)?;
    io::copy(&mut source, &mut tmp)?;
    tmp.flush()?;

    let tmp_file = tmp.into_inner().map_err(|err| {
        MountSyncError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Failed to finalize sparse ciphertext rewrite {}: {}",
                tmp_path.display(),
                err
            ),
        ))
    })?;
    tmp_file.sync_all()?;

    #[cfg(target_os = "windows")]
    {
        if destination_path.exists() {
            fs::remove_file(destination_path)?;
        }
    }

    if let Err(err) = fs::rename(&tmp_path, destination_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(MountSyncError::Io(err));
    }

    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

#[cfg(unix)]
fn hash_sparse_file(
    path: &Path,
    sparse_metadata: &SparseFileMetadata,
) -> Result<[u8; 32], MountSyncError> {
    let mut reader = io::BufReader::new(fs::File::open(path).map_err(MountSyncError::Io)?);
    let mut hasher = Sha256::new();
    let zero_buf = [0u8; 8192];
    let mut data_buf = vec![0u8; 1024 * 1024];
    let mut cursor = 0u64;

    let hash_zero_run = |remaining: u64, hasher: &mut Sha256| {
        let mut left = remaining;
        while left > 0 {
            let chunk_len =
                usize::try_from(left.min(zero_buf.len() as u64)).unwrap_or(zero_buf.len());
            hasher.update(&zero_buf[..chunk_len]);
            left = left.saturating_sub(chunk_len as u64);
        }
    };

    for extent in &sparse_metadata.extents {
        if extent.offset > cursor {
            hash_zero_run(extent.offset - cursor, &mut hasher);
        }

        reader.seek(io::SeekFrom::Start(extent.offset))?;
        let mut remaining = extent.length;
        while remaining > 0 {
            let read_len =
                usize::try_from(remaining.min(data_buf.len() as u64)).unwrap_or(data_buf.len());
            let read = reader.read(&mut data_buf[..read_len])?;
            if read == 0 {
                return Err(MountSyncError::Format(format!(
                    "Unexpected EOF while hashing sparse extent from {}",
                    path.display()
                )));
            }
            hasher.update(&data_buf[..read]);
            remaining = remaining.saturating_sub(read as u64);
        }

        cursor = extent.offset.saturating_add(extent.length);
    }

    if sparse_metadata.logical_size > cursor {
        hash_zero_run(sparse_metadata.logical_size - cursor, &mut hasher);
    }

    Ok(hasher.finalize().into())
}

fn hash_file(path: &Path) -> Result<[u8; 32], MountSyncError> {
    #[cfg(unix)]
    {
        let metadata = fs::metadata(path).map_err(MountSyncError::Io)?;
        if let Some(sparse_metadata) = sparse_file_metadata(path, &metadata)? {
            return hash_sparse_file(path, &sparse_metadata);
        }
    }

    let file = fs::File::open(path).map_err(MountSyncError::Io)?;
    let mut reader = io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read = reader.read(&mut buffer).map_err(MountSyncError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

fn mount_collision_key(mount_root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(mount_root).ok()?;
    let label = normalize_relative_path(relative);
    let normalized: String = label.nfc().collect();
    Some(normalized.to_lowercase())
}

fn timestamped_local_only_path(path: &Path, marker: &str, fallback_name: &str) -> PathBuf {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| fallback_name.to_string());
    let base_name = format!("{}.{}-{}", file_name, marker, timestamp);
    let parent = path.parent();
    let mut candidate = parent
        .map(|parent| parent.join(&base_name))
        .unwrap_or_else(|| PathBuf::from(&base_name));
    if !candidate.exists() {
        return candidate;
    }
    for index in 1..1000 {
        let collision_name = format!("{}-{}", base_name, index);
        candidate = parent
            .map(|parent| parent.join(&collision_name))
            .unwrap_or_else(|| PathBuf::from(&collision_name));
        if !candidate.exists() {
            return candidate;
        }
    }
    candidate
}

fn has_timestamped_local_only_marker(path: &Path, marker: &str) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(value) => value,
        None => return false,
    };
    let marker = format!(".{}-", marker);
    let idx = match name.rfind(&marker) {
        Some(pos) => pos + marker.len(),
        None => return false,
    };
    let suffix = &name[idx..];
    if suffix.len() < 15 {
        return false;
    }
    let ts = &suffix[..15];
    let bytes = ts.as_bytes();
    if bytes.len() != 15 {
        return false;
    }
    for (pos, ch) in bytes.iter().enumerate() {
        if pos == 8 {
            if *ch != b'_' {
                return false;
            }
        } else if !ch.is_ascii_digit() {
            return false;
        }
    }
    true
}

pub(crate) fn conflict_path_for(path: &Path) -> PathBuf {
    timestamped_local_only_path(path, "conflict", "conflict")
}

fn is_conflict_file(path: &Path) -> bool {
    has_timestamped_local_only_marker(path, "conflict")
}

fn recovered_pending_path_for(path: &Path) -> PathBuf {
    timestamped_local_only_path(path, "recovered-pending", "recovered-pending")
}

fn is_recovered_pending_file(path: &Path) -> bool {
    has_timestamped_local_only_marker(path, "recovered-pending")
}

#[cfg(unix)]
fn set_local_only_file_readonly(path: &Path) -> Result<(), MountSyncError> {
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    let readonly_mode = mode & !0o222;
    if readonly_mode != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(readonly_mode))?;
    }
    Ok(())
}

#[cfg(windows)]
fn set_local_only_file_readonly(path: &Path) -> Result<(), MountSyncError> {
    let mut permissions = fs::metadata(path)?.permissions();
    if !permissions.readonly() {
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn set_local_only_file_readonly(_path: &Path) -> Result<(), MountSyncError> {
    Ok(())
}

fn set_conflict_file_readonly(path: &Path) -> Result<(), MountSyncError> {
    set_local_only_file_readonly(path)
}

fn set_recovered_pending_file_readonly(path: &Path) -> Result<(), MountSyncError> {
    set_local_only_file_readonly(path)
}

#[cfg(unix)]
fn hard_link_block_reason(path: &Path, metadata: &fs::Metadata) -> Option<String> {
    if !metadata.is_file() {
        return None;
    }

    let link_count = metadata.nlink();
    if link_count <= 1 {
        return None;
    }

    Some(format!(
        "hard-linked file {} has {} links; sync mount does not preserve hard-link semantics",
        path.display(),
        link_count
    ))
}

#[cfg(not(unix))]
fn hard_link_block_reason(_path: &Path, _metadata: &fs::Metadata) -> Option<String> {
    None
}

#[cfg(unix)]
fn set_local_only_file_writable(path: &Path) -> Result<(), MountSyncError> {
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    let writable_mode = mode | 0o200;
    if writable_mode != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(writable_mode))?;
    }
    Ok(())
}

#[cfg(windows)]
fn set_local_only_file_writable(path: &Path) -> Result<(), MountSyncError> {
    let mut permissions = fs::metadata(path)?.permissions();
    if permissions.readonly() {
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn set_local_only_file_writable(_path: &Path) -> Result<(), MountSyncError> {
    Ok(())
}

fn timestamped_local_only_suffix(path: &Path, marker: &str) -> Option<String> {
    let name = path.file_name().and_then(|n| n.to_str())?;
    let marker = format!(".{}-", marker);
    let idx = name.rfind(&marker)? + marker.len();
    Some(name[idx..].to_string())
}

fn parse_local_only_timestamp(path: &Path, marker: &str) -> Option<DateTime<Utc>> {
    let suffix = timestamped_local_only_suffix(path, marker)?;
    let timestamp = suffix.split('-').next()?;
    let naive = NaiveDateTime::parse_from_str(timestamp, "%Y%m%d_%H%M%S").ok()?;
    Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

fn derive_live_path_from_conflict_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("conflict");
    let marker = ".conflict-";
    let base_name = file_name
        .rfind(marker)
        .map(|idx| &file_name[..idx])
        .unwrap_or(file_name);
    match path.parent() {
        Some(parent) => parent.join(base_name),
        None => PathBuf::from(base_name),
    }
}

fn derive_live_path_from_recovered_pending_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("recovered");
    let marker = ".recovered-pending-";
    let base_name = file_name
        .rfind(marker)
        .map(|idx| &file_name[..idx])
        .unwrap_or(file_name);
    match path.parent() {
        Some(parent) => parent.join(base_name),
        None => PathBuf::from(base_name),
    }
}

#[cfg(unix)]
fn read_named_string_attr(path: &Path, attr_name: &str) -> Option<String> {
    match xattr::get(path, attr_name) {
        Ok(Some(value)) => {
            let decoded = String::from_utf8(value).ok()?;
            let trimmed = decoded.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Ok(None) => None,
        Err(err) => {
            debug!(
                "Failed to read xattr {} from {}: {}",
                attr_name,
                path.display(),
                err
            );
            None
        }
    }
}

#[cfg(target_os = "windows")]
fn read_named_string_attr(path: &Path, stream_name: &str) -> Option<String> {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(stream_name);
    let stream_path = PathBuf::from(stream);
    match fs::read(&stream_path) {
        Ok(value) => {
            let decoded = String::from_utf8(value).ok()?;
            let trimmed = decoded.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(
                    "Failed to read stream {} from {}: {}",
                    stream_name,
                    path.display(),
                    err
                );
            }
            None
        }
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn read_named_string_attr(_path: &Path, _name: &str) -> Option<String> {
    None
}

#[cfg(unix)]
fn write_named_string_attr(
    path: &Path,
    attr_name: &str,
    value: &str,
) -> Result<(), MountSyncError> {
    xattr::set(path, attr_name, value.as_bytes()).map_err(MountSyncError::Io)
}

#[cfg(target_os = "windows")]
fn write_named_string_attr(
    path: &Path,
    stream_name: &str,
    value: &str,
) -> Result<(), MountSyncError> {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(stream_name);
    let stream_path = PathBuf::from(stream);
    fs::write(&stream_path, value.as_bytes()).map_err(MountSyncError::Io)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn write_named_string_attr(_path: &Path, _name: &str, _value: &str) -> Result<(), MountSyncError> {
    Ok(())
}

#[cfg(unix)]
fn is_missing_xattr_error(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::NotFound {
        return true;
    }

    match err.raw_os_error() {
        #[cfg(target_os = "macos")]
        Some(code) if code == libc::ENOATTR => true,
        #[cfg(not(target_os = "macos"))]
        Some(code) if code == libc::ENODATA => true,
        _ => false,
    }
}

#[cfg(unix)]
fn clear_named_string_attr(path: &Path, attr_name: &str) -> Result<(), MountSyncError> {
    match xattr::remove(path, attr_name) {
        Ok(()) => Ok(()),
        Err(err) if is_missing_xattr_error(&err) => Ok(()),
        Err(err) => Err(MountSyncError::Io(err)),
    }
}

#[cfg(target_os = "windows")]
fn clear_named_string_attr(path: &Path, stream_name: &str) -> Result<(), MountSyncError> {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(stream_name);
    let stream_path = PathBuf::from(stream);
    match fs::remove_file(&stream_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(MountSyncError::Io(err)),
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn clear_named_string_attr(_path: &Path, _name: &str) -> Result<(), MountSyncError> {
    Ok(())
}

fn read_local_only_reason(path: &Path) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        return read_named_string_attr(path, LOCAL_ONLY_REASON_STREAM);
    }
    #[cfg(not(target_os = "windows"))]
    {
        read_named_string_attr(path, LOCAL_ONLY_REASON_XATTR)
    }
}

fn write_local_only_reason(path: &Path, reason: &str) -> Result<(), MountSyncError> {
    #[cfg(target_os = "windows")]
    {
        return write_named_string_attr(path, LOCAL_ONLY_REASON_STREAM, reason);
    }
    #[cfg(not(target_os = "windows"))]
    {
        write_named_string_attr(path, LOCAL_ONLY_REASON_XATTR, reason)
    }
}

fn clear_local_only_reason(path: &Path) -> Result<(), MountSyncError> {
    #[cfg(target_os = "windows")]
    {
        return clear_named_string_attr(path, LOCAL_ONLY_REASON_STREAM);
    }
    #[cfg(not(target_os = "windows"))]
    {
        clear_named_string_attr(path, LOCAL_ONLY_REASON_XATTR)
    }
}

fn read_conflict_id_attr(path: &Path) -> Option<Uuid> {
    let raw = {
        #[cfg(target_os = "windows")]
        {
            read_named_string_attr(path, CONFLICT_ID_STREAM)
        }
        #[cfg(not(target_os = "windows"))]
        {
            read_named_string_attr(path, CONFLICT_ID_XATTR)
        }
    }?;
    Uuid::parse_str(raw.trim()).ok()
}

fn write_conflict_id_attr(path: &Path, id: Uuid) -> Result<(), MountSyncError> {
    #[cfg(target_os = "windows")]
    {
        return write_named_string_attr(path, CONFLICT_ID_STREAM, &id.to_string());
    }
    #[cfg(not(target_os = "windows"))]
    {
        write_named_string_attr(path, CONFLICT_ID_XATTR, &id.to_string())
    }
}

fn clear_conflict_id_attr(path: &Path) -> Result<(), MountSyncError> {
    #[cfg(target_os = "windows")]
    {
        return clear_named_string_attr(path, CONFLICT_ID_STREAM);
    }
    #[cfg(not(target_os = "windows"))]
    {
        clear_named_string_attr(path, CONFLICT_ID_XATTR)
    }
}

fn read_conflict_live_path_attr(path: &Path) -> Option<PathBuf> {
    let raw = {
        #[cfg(target_os = "windows")]
        {
            read_named_string_attr(path, CONFLICT_LIVE_PATH_STREAM)
        }
        #[cfg(not(target_os = "windows"))]
        {
            read_named_string_attr(path, CONFLICT_LIVE_PATH_XATTR)
        }
    }?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn write_conflict_live_path_attr(path: &Path, live_path: &Path) -> Result<(), MountSyncError> {
    let value = live_path.to_string_lossy().to_string();
    #[cfg(target_os = "windows")]
    {
        return write_named_string_attr(path, CONFLICT_LIVE_PATH_STREAM, &value);
    }
    #[cfg(not(target_os = "windows"))]
    {
        write_named_string_attr(path, CONFLICT_LIVE_PATH_XATTR, &value)
    }
}

fn clear_conflict_live_path_attr(path: &Path) -> Result<(), MountSyncError> {
    #[cfg(target_os = "windows")]
    {
        return clear_named_string_attr(path, CONFLICT_LIVE_PATH_STREAM);
    }
    #[cfg(not(target_os = "windows"))]
    {
        clear_named_string_attr(path, CONFLICT_LIVE_PATH_XATTR)
    }
}

fn read_conflict_kind_attr(path: &Path) -> Option<ConflictKind> {
    let raw = {
        #[cfg(target_os = "windows")]
        {
            read_named_string_attr(path, CONFLICT_KIND_STREAM)
        }
        #[cfg(not(target_os = "windows"))]
        {
            read_named_string_attr(path, CONFLICT_KIND_XATTR)
        }
    }?;
    serde_json::from_str(&format!("\"{}\"", raw.trim())).ok()
}

fn write_conflict_kind_attr(path: &Path, kind: ConflictKind) -> Result<(), MountSyncError> {
    let value = match kind {
        ConflictKind::DecryptCollision => "decrypt_collision",
        ConflictKind::DeletedOpenRecovery => "deleted_open_recovery",
        ConflictKind::LocalRemoteBothModified => "both_modified_conflict",
        ConflictKind::LocalEditRemoteDelete => "local_edit_remote_delete",
        ConflictKind::LocalDeleteRemoteEdit => "local_delete_remote_edit",
    };
    #[cfg(target_os = "windows")]
    {
        return write_named_string_attr(path, CONFLICT_KIND_STREAM, value);
    }
    #[cfg(not(target_os = "windows"))]
    {
        write_named_string_attr(path, CONFLICT_KIND_XATTR, value)
    }
}

fn clear_conflict_kind_attr(path: &Path) -> Result<(), MountSyncError> {
    #[cfg(target_os = "windows")]
    {
        return clear_named_string_attr(path, CONFLICT_KIND_STREAM);
    }
    #[cfg(not(target_os = "windows"))]
    {
        clear_named_string_attr(path, CONFLICT_KIND_XATTR)
    }
}

fn stamp_conflict_file_metadata(
    conflict_path: &Path,
    live_path: &Path,
    kind: ConflictKind,
) -> Result<Uuid, MountSyncError> {
    let id = read_conflict_id_attr(conflict_path).unwrap_or_else(Uuid::new_v4);
    write_local_only_reason(conflict_path, kind.local_only_reason())?;
    write_conflict_id_attr(conflict_path, id)?;
    write_conflict_live_path_attr(conflict_path, live_path)?;
    write_conflict_kind_attr(conflict_path, kind)?;
    Ok(id)
}

fn clear_local_only_conflict_metadata(path: &Path) -> Result<(), MountSyncError> {
    clear_local_only_reason(path)?;
    clear_conflict_id_attr(path)?;
    clear_conflict_live_path_attr(path)?;
    clear_conflict_kind_attr(path)?;
    Ok(())
}

fn stamp_recovered_pending_file_metadata(path: &Path) -> Result<(), MountSyncError> {
    write_local_only_reason(path, "recovered_pending")
}

fn clear_local_only_recovery_metadata(path: &Path) -> Result<(), MountSyncError> {
    clear_local_only_reason(path)
}

fn sample_paths<I>(paths: I, limit: usize) -> Vec<String>
where
    I: IntoIterator<Item = PathBuf>,
{
    let mut values = paths
        .into_iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    values.sort();
    values.truncate(limit);
    values
}

pub fn sync_mount_conflict_registry_path(state_dir: &Path, root_id: &str) -> PathBuf {
    state_dir.join(format!("mount_conflicts_{}.json", root_id))
}

pub fn sync_mount_conflict_action_requests_dir(state_dir: &Path, root_id: &str) -> PathBuf {
    state_dir.join(format!("mount_conflict_requests_{}", root_id))
}

pub fn sync_mount_conflict_action_results_dir(state_dir: &Path, root_id: &str) -> PathBuf {
    state_dir.join(format!("mount_conflict_results_{}", root_id))
}

pub fn sync_mount_recovery_registry_path(state_dir: &Path, root_id: &str) -> PathBuf {
    state_dir.join(format!("mount_recovery_copies_{}.json", root_id))
}

pub fn sync_mount_recovery_action_requests_dir(state_dir: &Path, root_id: &str) -> PathBuf {
    state_dir.join(format!("mount_recovery_requests_{}", root_id))
}

pub fn sync_mount_recovery_action_results_dir(state_dir: &Path, root_id: &str) -> PathBuf {
    state_dir.join(format!("mount_recovery_results_{}", root_id))
}

pub fn load_mount_conflict_registry(
    path: &Path,
) -> Result<Vec<MountConflictRecord>, MountSyncError> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(MountSyncError::Io(err)),
    };
    let records: Vec<MountConflictRecord> = serde_json::from_slice(&data).map_err(|err| {
        MountSyncError::Format(format!("Failed to parse mount conflict registry: {}", err))
    })?;
    Ok(records)
}

pub fn load_mount_recovery_registry(
    path: &Path,
) -> Result<Vec<MountRecoveryCopyRecord>, MountSyncError> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(MountSyncError::Io(err)),
    };
    let records: Vec<MountRecoveryCopyRecord> = serde_json::from_slice(&data).map_err(|err| {
        MountSyncError::Format(format!("Failed to parse mount recovery registry: {}", err))
    })?;
    Ok(records)
}

fn decode_conflict_preview_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    if bytes.contains(&0) {
        return None;
    }
    if let Ok(text) = String::from_utf8(bytes.to_vec()) {
        return Some(text);
    }
    if bytes.len() >= 2 && bytes.len() % 2 == 0 {
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let units = bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            if let Ok(text) = String::from_utf16(&units) {
                return Some(text);
            }
        }
        if bytes.starts_with(&[0xFE, 0xFF]) {
            let units = bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            if let Ok(text) = String::from_utf16(&units) {
                return Some(text);
            }
        }
    }
    None
}

pub fn read_conflict_preview_text(path: &Path) -> Result<Option<String>, MountSyncError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() as usize > CONFLICT_TEXT_PREVIEW_MAX_BYTES {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    Ok(decode_conflict_preview_text(&bytes))
}

fn pending_writeback_error_is_retryable(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("unstable file")
        || normalized.contains("changed during read")
        || normalized.contains("mid-write")
}

fn pending_writeback_error_is_terminal(message: Option<&str>) -> bool {
    match message {
        Some(message) if !message.trim().is_empty() => {
            !pending_writeback_error_is_retryable(message)
        }
        _ => false,
    }
}

fn pending_writeback_oldest_age_ms_from<'a, I>(pending: I, now: DateTime<Utc>) -> Option<u64>
where
    I: IntoIterator<Item = &'a PendingWriteback>,
{
    pending
        .into_iter()
        .map(|entry| {
            now.signed_duration_since(entry.first_observed_at)
                .num_milliseconds()
                .max(0) as u64
        })
        .max()
}

fn should_fast_drain_pending_writeback(pending: &PendingWriteback) -> bool {
    !pending.low_space && !pending_writeback_error_is_terminal(pending.last_error.as_deref())
}

fn error_message_is_low_space(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("no space left on device")
        || normalized.contains("not enough space on the disk")
        || normalized.contains("disk full")
        || normalized.contains("storage full")
        || normalized.contains("enospc")
}

fn is_low_space_io_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(28 | 112)) || error_message_is_low_space(&err.to_string())
}

fn is_low_space_error(err: &MountSyncError) -> bool {
    match err {
        MountSyncError::Io(err) => is_low_space_io_error(err),
        MountSyncError::Format(message)
        | MountSyncError::Crypto(message)
        | MountSyncError::UnstableFile(message) => error_message_is_low_space(message),
        MountSyncError::PathExcluded(_) | MountSyncError::InvalidPath(_) => false,
    }
}

fn low_space_budget_error(
    operation: &str,
    path: &Path,
    required_bytes: u64,
    reserve_bytes: u64,
    available_bytes: u64,
) -> MountSyncError {
    MountSyncError::Format(format!(
        "No space left on device for {} at {}: need {} bytes plus {} bytes reserve, only {} bytes available",
        operation,
        path.display(),
        required_bytes,
        reserve_bytes,
        available_bytes
    ))
}

fn low_space_readonly_error(path: &Path) -> MountSyncError {
    MountSyncError::Format(format!(
        "No space left on device: sync mount is in read-only degraded mode for {}",
        path.display()
    ))
}

fn ensure_space_budget(
    path: &Path,
    required_bytes: u64,
    reserve_bytes: u64,
    operation: &str,
) -> Result<(), MountSyncError> {
    let Some(available) = available_space_for_path(path) else {
        return Ok(());
    };
    let budget = required_bytes.saturating_add(reserve_bytes);
    if available < budget {
        return Err(low_space_budget_error(
            operation,
            path,
            required_bytes,
            reserve_bytes,
            available,
        ));
    }
    Ok(())
}

fn volume_below_reserve(path: &Path, reserve_bytes: u64) -> bool {
    available_space_for_path(path)
        .map(|available| available < reserve_bytes)
        .unwrap_or(false)
}

fn available_space_for_path(path: &Path) -> Option<u64> {
    let existing_path = existing_ancestor(path)?;
    let canonical = fs::canonicalize(&existing_path).unwrap_or(existing_path);
    let disks = Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|disk| canonical.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(|disk| disk.available_space())
}

fn existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            return Some(current);
        }
        let parent = current.parent()?.to_path_buf();
        current = parent;
    }
}

fn format_open_unlinked_owners(owners: &[OpenUnlinkedOwner]) -> String {
    let mut labels = Vec::new();
    for owner in owners.iter().take(3) {
        if owner.name.is_empty() {
            labels.push(format!("pid {}", owner.pid));
        } else {
            labels.push(format!("{} ({})", owner.name, owner.pid));
        }
    }
    if owners.len() > 3 {
        labels.push(format!("+{} more", owners.len() - 3));
    }
    labels.join(", ")
}

#[cfg(target_os = "macos")]
fn c_char_buffer_to_os_string(buffer: &[libc::c_char]) -> Option<OsString> {
    let len = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    if len == 0 {
        return None;
    }
    let bytes = buffer[..len]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    Some(OsString::from_vec(bytes))
}

#[cfg(target_os = "macos")]
fn proc_name_from_bsdinfo(info: &libc::proc_bsdinfo) -> String {
    c_char_buffer_to_os_string(&info.pbi_name)
        .or_else(|| c_char_buffer_to_os_string(&info.pbi_comm))
        .map(|value| value.to_string_lossy().trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("pid {}", info.pbi_pid))
}

#[cfg(target_os = "macos")]
fn deleted_open_candidate_path(
    observed_path: &Path,
    mount_root: &Path,
    canonical_mount_root: Option<&Path>,
) -> Option<PathBuf> {
    if observed_path.starts_with(mount_root) {
        return Some(observed_path.to_path_buf());
    }

    let canonical_mount_root = canonical_mount_root?;
    let relative = observed_path.strip_prefix(canonical_mount_root).ok()?;
    Some(mount_root.join(relative))
}

#[cfg(target_os = "macos")]
fn detect_deleted_open_mount_paths(
    mount_root: &Path,
    candidate_paths: &HashSet<PathBuf>,
) -> Result<HashMap<PathBuf, Vec<OpenUnlinkedOwner>>, MountSyncError> {
    if candidate_paths.is_empty() {
        return Ok(HashMap::new());
    }

    let canonical_mount_root = fs::canonicalize(mount_root).ok();
    let current_uid = unsafe { libc::geteuid() };

    let mut pid_capacity = 512usize;
    let pids = loop {
        let mut buffer = vec![0i32; pid_capacity];
        let count = unsafe {
            libc::proc_listallpids(
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                (buffer.len() * size_of::<i32>()) as libc::c_int,
            )
        };
        if count < 0 {
            return Err(MountSyncError::Io(io::Error::last_os_error()));
        }
        let count = count as usize;
        if count < buffer.len() {
            buffer.truncate(count);
            break buffer;
        }
        pid_capacity = pid_capacity.saturating_mul(2);
        if pid_capacity > 32768 {
            buffer.truncate(count.min(buffer.len()));
            break buffer;
        }
    };

    let mut observed = HashMap::<PathBuf, Vec<OpenUnlinkedOwner>>::new();

    for pid in pids.into_iter().filter(|pid| *pid > 0) {
        let mut process_info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let info_size = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                process_info.as_mut_ptr().cast::<libc::c_void>(),
                PROC_PIDTBSDINFO_SIZE,
            )
        };
        if info_size != PROC_PIDTBSDINFO_SIZE {
            continue;
        }
        let process_info = unsafe { process_info.assume_init() };
        if process_info.pbi_uid != current_uid {
            continue;
        }

        let owner = OpenUnlinkedOwner {
            pid,
            name: proc_name_from_bsdinfo(&process_info),
        };

        let fd_capacity = process_info.pbi_nfiles.saturating_add(8) as usize;
        if fd_capacity == 0 {
            continue;
        }

        let mut fd_buffer = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            fd_capacity
        ];
        let fd_bytes = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fd_buffer.as_mut_ptr().cast::<libc::c_void>(),
                (fd_buffer.len() * size_of::<libc::proc_fdinfo>()) as libc::c_int,
            )
        };
        if fd_bytes <= 0 {
            continue;
        }
        let fd_count = (fd_bytes as usize) / size_of::<libc::proc_fdinfo>();

        for fd in fd_buffer.into_iter().take(fd_count) {
            if fd.proc_fdtype != libc::PROX_FDTYPE_VNODE as u32 {
                continue;
            }

            let mut vnode_info = std::mem::MaybeUninit::<MacOsVnodeFdInfoWithPath>::zeroed();
            let vnode_size = unsafe {
                libc::proc_pidfdinfo(
                    pid,
                    fd.proc_fd,
                    PROC_PIDFDVNODEPATHINFO,
                    vnode_info.as_mut_ptr().cast::<libc::c_void>(),
                    PROC_PIDFDVNODEPATHINFO_SIZE,
                )
            };
            if vnode_size != PROC_PIDFDVNODEPATHINFO_SIZE {
                continue;
            }
            let vnode_info = unsafe { vnode_info.assume_init() };
            if vnode_info.pvip.vip_vi.vi_stat.vst_nlink != 0 {
                continue;
            }

            let Some(raw_path) = c_char_buffer_to_os_string(&vnode_info.pvip.vip_path) else {
                continue;
            };
            let Some(candidate_path) = deleted_open_candidate_path(
                Path::new(&raw_path),
                mount_root,
                canonical_mount_root.as_deref(),
            ) else {
                continue;
            };
            if !candidate_paths.contains(&candidate_path) {
                continue;
            }

            let owners = observed.entry(candidate_path).or_default();
            if owners.iter().all(|existing| existing.pid != owner.pid)
                && owners.len() < MAX_OPEN_UNLINKED_OWNERS
            {
                owners.push(owner.clone());
            }
        }
    }

    Ok(observed)
}

#[cfg(not(target_os = "macos"))]
fn detect_deleted_open_mount_paths(
    _mount_root: &Path,
    _candidate_paths: &HashSet<PathBuf>,
) -> Result<HashMap<PathBuf, Vec<OpenUnlinkedOwner>>, MountSyncError> {
    Ok(HashMap::new())
}

#[cfg(unix)]
fn read_file_id_xattr(path: &Path) -> Option<String> {
    match xattr::get(path, FILE_ID_XATTR) {
        Ok(Some(value)) => {
            let decoded = String::from_utf8(value).ok()?;
            let trimmed = decoded.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Ok(None) => None,
        Err(err) => {
            debug!(
                "Failed to read file_id xattr from {}: {}",
                path.display(),
                err
            );
            None
        }
    }
}

#[cfg(target_os = "windows")]
fn read_file_id_xattr(path: &Path) -> Option<String> {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(FILE_ID_STREAM);
    let stream_path = PathBuf::from(stream);
    match fs::read(&stream_path) {
        Ok(value) => {
            let decoded = String::from_utf8(value).ok()?;
            let trimmed = decoded.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(
                    "Failed to read file_id stream from {}: {}",
                    path.display(),
                    err
                );
            }
            None
        }
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn read_file_id_xattr(_path: &Path) -> Option<String> {
    None
}

#[cfg(unix)]
fn write_file_id_xattr(path: &Path, file_id: &str) -> Result<(), MountSyncError> {
    xattr::set(path, FILE_ID_XATTR, file_id.as_bytes()).map_err(MountSyncError::Io)
}

#[cfg(target_os = "windows")]
fn write_file_id_xattr(path: &Path, file_id: &str) -> Result<(), MountSyncError> {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(FILE_ID_STREAM);
    let stream_path = PathBuf::from(stream);
    fs::write(&stream_path, file_id.as_bytes()).map_err(MountSyncError::Io)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn write_file_id_xattr(_path: &Path, _file_id: &str) -> Result<(), MountSyncError> {
    Ok(())
}

#[cfg(unix)]
fn clear_file_id_xattr(path: &Path) -> Result<(), MountSyncError> {
    match xattr::remove(path, FILE_ID_XATTR) {
        Ok(()) => Ok(()),
        Err(err) if is_missing_xattr_error(&err) => Ok(()),
        Err(err) => Err(MountSyncError::Io(err)),
    }
}

#[cfg(target_os = "windows")]
fn clear_file_id_xattr(path: &Path) -> Result<(), MountSyncError> {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(FILE_ID_STREAM);
    let stream_path = PathBuf::from(stream);
    match fs::remove_file(&stream_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(MountSyncError::Io(err)),
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn clear_file_id_xattr(_path: &Path) -> Result<(), MountSyncError> {
    Ok(())
}

#[cfg(unix)]
fn read_original_name_xattr(path: &Path) -> Option<String> {
    match xattr::get(path, ORIGINAL_NAME_XATTR) {
        Ok(Some(value)) => {
            let decoded = String::from_utf8(value).ok()?;
            let trimmed = decoded.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Ok(None) => None,
        Err(err) => {
            debug!(
                "Failed to read original_name xattr from {}: {}",
                path.display(),
                err
            );
            None
        }
    }
}

#[cfg(target_os = "windows")]
fn read_original_name_xattr(path: &Path) -> Option<String> {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(ORIGINAL_NAME_STREAM);
    let stream_path = PathBuf::from(stream);
    match fs::read(&stream_path) {
        Ok(value) => {
            let decoded = String::from_utf8(value).ok()?;
            let trimmed = decoded.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(
                    "Failed to read original_name stream from {}: {}",
                    path.display(),
                    err
                );
            }
            None
        }
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn read_original_name_xattr(_path: &Path) -> Option<String> {
    None
}

#[cfg(unix)]
fn write_original_name_xattr(path: &Path, original_name: &str) -> Result<(), MountSyncError> {
    xattr::set(path, ORIGINAL_NAME_XATTR, original_name.as_bytes()).map_err(MountSyncError::Io)
}

#[cfg(target_os = "windows")]
fn write_original_name_xattr(path: &Path, original_name: &str) -> Result<(), MountSyncError> {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(ORIGINAL_NAME_STREAM);
    let stream_path = PathBuf::from(stream);
    fs::write(&stream_path, original_name.as_bytes()).map_err(MountSyncError::Io)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn write_original_name_xattr(_path: &Path, _original_name: &str) -> Result<(), MountSyncError> {
    Ok(())
}

#[cfg(unix)]
fn capture_unix_mode(path: &Path) -> Option<u32> {
    fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode())
}

#[cfg(not(unix))]
fn capture_unix_mode(_path: &Path) -> Option<u32> {
    None
}

fn capture_platform_metadata(path: &Path) -> Option<PlatformFileMetadata> {
    let metadata = PlatformFileMetadata {
        unix_mode: capture_unix_mode(path),
        #[cfg(target_os = "macos")]
        macos: capture_macos_file_metadata(path),
        #[cfg(not(target_os = "macos"))]
        macos: None,
    };

    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

fn hash_platform_metadata(metadata: &PlatformFileMetadata) -> Option<[u8; 32]> {
    let serialized = serde_json::to_vec(metadata).ok()?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Sha256::digest(&serialized));
    Some(hash)
}

fn capture_platform_metadata_hash(path: &Path) -> Option<[u8; 32]> {
    let metadata = capture_platform_metadata(path)?;
    hash_platform_metadata(&metadata)
}

fn apply_platform_metadata(
    path: &Path,
    platform_metadata: &PlatformFileMetadata,
) -> Result<(), MountSyncError> {
    #[cfg(unix)]
    if let Some(mode) = platform_metadata.unix_mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(MountSyncError::Io)?;
    }

    #[cfg(target_os = "macos")]
    if let Some(macos) = platform_metadata.macos.as_ref() {
        apply_macos_file_metadata(path, macos)?;
    }

    Ok(())
}

#[cfg(unix)]
fn collect_mount_paths_for_permission_flip(root: &Path) -> Result<Vec<PathBuf>, MountSyncError> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut paths = vec![root.to_path_buf()];
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            paths.push(path.clone());
            if file_type.is_dir() {
                stack.push(path);
            }
        }
    }

    paths.sort_by(|left, right| {
        let left_depth = left.components().count();
        let right_depth = right.components().count();
        right_depth.cmp(&left_depth).then_with(|| left.cmp(right))
    });
    Ok(paths)
}

#[cfg(unix)]
fn apply_mount_readonly_permissions(
    mount_root: &Path,
) -> Result<HashMap<PathBuf, u32>, MountSyncError> {
    let paths = collect_mount_paths_for_permission_flip(mount_root)?;
    let mut restore_modes = HashMap::new();
    for path in paths {
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(MountSyncError::Io(err)),
        };
        let mode = metadata.permissions().mode();
        restore_modes.insert(path.clone(), mode);
        let readonly_mode = mode & !0o222;
        if readonly_mode != mode {
            fs::set_permissions(&path, fs::Permissions::from_mode(readonly_mode))?;
        }
    }
    Ok(restore_modes)
}

#[cfg(not(unix))]
fn apply_mount_readonly_permissions(
    _mount_root: &Path,
) -> Result<HashMap<PathBuf, u32>, MountSyncError> {
    Ok(HashMap::new())
}

#[cfg(unix)]
fn restore_mount_permissions(restore_modes: &HashMap<PathBuf, u32>) -> Result<(), MountSyncError> {
    let mut paths: Vec<_> = restore_modes.keys().cloned().collect();
    paths.sort();
    for path in paths {
        let Some(mode) = restore_modes.get(&path).copied() else {
            continue;
        };
        if !path.exists() {
            continue;
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_mount_permissions(_restore_modes: &HashMap<PathBuf, u32>) -> Result<(), MountSyncError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn capture_macos_file_metadata(path: &Path) -> Option<MacOsFileMetadata> {
    let mut xattrs = Vec::new();
    match xattr::list(path) {
        Ok(names) => {
            for name in names {
                let Some(name) = name.to_str() else {
                    continue;
                };
                if should_skip_embedded_xattr(name) {
                    continue;
                }
                match xattr::get(path, name) {
                    Ok(Some(value)) => xattrs.push(PlatformXattr::from_bytes(name, &value)),
                    Ok(None) => {}
                    Err(err) => {
                        debug!(
                            "Failed to read xattr {} from {}: {}",
                            name,
                            path.display(),
                            err
                        );
                    }
                }
            }
        }
        Err(err) => {
            debug!("Failed to list xattrs for {}: {}", path.display(), err);
        }
    }
    xattrs.sort_by(|left, right| left.name.cmp(&right.name));

    let metadata = MacOsFileMetadata {
        xattrs,
        acl_text: capture_macos_acl_text(path),
    };
    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

#[cfg(target_os = "macos")]
fn should_skip_embedded_xattr(name: &str) -> bool {
    name == FILE_ID_XATTR || name == ORIGINAL_NAME_XATTR || name.starts_with("com.hybridcipher.")
}

#[cfg(target_os = "macos")]
fn capture_macos_acl_text(path: &Path) -> Option<String> {
    let path_bytes = path.as_os_str().as_bytes();
    let c_path = CString::new(path_bytes).ok()?;
    let acl = unsafe { acl_get_file(c_path.as_ptr(), MACOS_ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return None;
    }

    let acl_text_ptr = unsafe { acl_to_text(acl, std::ptr::null_mut()) };
    if acl_text_ptr.is_null() {
        unsafe {
            acl_free(acl);
        }
        return None;
    }

    let acl_text = unsafe { CStr::from_ptr(acl_text_ptr) }
        .to_string_lossy()
        .into_owned();

    unsafe {
        acl_free(acl_text_ptr as *mut libc::c_void);
        acl_free(acl);
    }

    let trimmed = acl_text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_file_metadata(
    path: &Path,
    metadata: &MacOsFileMetadata,
) -> Result<(), MountSyncError> {
    for xattr_entry in &metadata.xattrs {
        let Some(value) = xattr_entry.decode_value() else {
            debug!(
                "Skipping malformed base64 xattr {} for {}",
                xattr_entry.name,
                path.display()
            );
            continue;
        };
        xattr::set(path, &xattr_entry.name, &value).map_err(MountSyncError::Io)?;
    }

    if let Some(acl_text) = metadata.acl_text.as_deref() {
        apply_macos_acl_text(path, acl_text)?;
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_macos_acl_text(path: &Path, acl_text: &str) -> Result<(), MountSyncError> {
    let acl_text = acl_text.trim();
    if acl_text.is_empty() {
        return Ok(());
    }

    let path_bytes = path.as_os_str().as_bytes();
    let c_path = CString::new(path_bytes).map_err(|err| {
        MountSyncError::Format(format!(
            "Invalid macOS metadata path {}: {}",
            path.display(),
            err
        ))
    })?;
    let c_acl_text = CString::new(acl_text).map_err(|err| {
        MountSyncError::Format(format!("Invalid ACL text for {}: {}", path.display(), err))
    })?;

    let acl = unsafe { acl_from_text(c_acl_text.as_ptr()) };
    if acl.is_null() {
        return Err(MountSyncError::Io(io::Error::last_os_error()));
    }

    let result = unsafe { acl_set_file(c_path.as_ptr(), MACOS_ACL_TYPE_EXTENDED, acl) };
    let outcome = if result == 0 {
        Ok(())
    } else {
        Err(MountSyncError::Io(io::Error::last_os_error()))
    };

    unsafe {
        acl_free(acl);
    }

    outcome
}

#[derive(Default)]
pub struct SyncTracker {
    encrypted_signatures: HashMap<PathBuf, FileSignature>,
    encrypted_directory_signatures: HashMap<PathBuf, FileSignature>,
    decrypted_signatures: HashMap<PathBuf, FileSignature>,
    decrypted_directory_signatures: HashMap<PathBuf, FileSignature>,
    decrypted_hashes: HashMap<PathBuf, [u8; 32]>,
    decrypted_metadata_hashes: HashMap<PathBuf, [u8; 32]>,
    decrypted_directory_metadata_hashes: HashMap<PathBuf, [u8; 32]>,
    // Cache mapping from encrypted path to decrypted path to avoid re-parsing
    path_mapping: HashMap<PathBuf, PathBuf>,
    // Track which file_ids have been successfully decrypted to mount paths
    // This enables proper restoration detection: if file_id is tracked but mount file is missing,
    // it means the user deleted it (don't re-decrypt). If file_id is not tracked, decrypt it.
    file_id_to_mount_path: HashMap<String, PathBuf>,
    // Two-phase deletion tracking: encrypted files marked for deletion pending verification
    // Key is encrypted_path (not mount_path) - only encrypted files tracked
    pending_deletions: HashMap<PathBuf, PendingDeletion>,
    // Encrypted-side disappearance tracking: plaintext files stay pending until verified
    pending_orphans: HashMap<PathBuf, PendingOrphan>,
    // Local plaintext changes observed but not yet durably committed to encrypted storage
    pending_writebacks: HashMap<PathBuf, PendingWriteback>,
    // Encrypted changes that could not be refreshed into plaintext due to low space
    pending_refreshes: HashMap<PathBuf, PendingRefresh>,
    // Mount paths deleted while still open by another process on macOS
    pending_open_unlinked: HashMap<PathBuf, PendingOpenUnlinked>,
    // Coverage metadata writes that must be retried before deletion is allowed
    pending_metadata: HashMap<PathBuf, FileMetadataData>,
    // Local paths blocked because sync mount cannot safely publish them as atomic sets
    unsupported_transactional_paths: HashMap<PathBuf, String>,
    // Local paths blocked because sync mount does not preserve hard-link semantics
    unsupported_hard_link_paths: HashMap<PathBuf, String>,
    // Collision keys for case-insensitive and Unicode-normalized mount paths
    mount_collision_keys: HashMap<String, PathBuf>,
    // Temp-like files awaiting stable persistence before encryption
    pending_temp: HashMap<PathBuf, Instant>,
    // Sparse files that are skipped to avoid densification
    pending_sparse: HashSet<PathBuf>,
    // Conflict files that remain local-only until the user resolves them
    conflict_baselines: HashMap<PathBuf, ConflictBaseline>,
    // Recovery copies recreated from quarantined stale plaintext after an unclean restart
    recovered_pending_paths: HashSet<PathBuf>,
    // Pending deletion journal path
    pending_deletion_path: Option<PathBuf>,
    pending_deletions_dirty: bool,
    pending_orphan_path: Option<PathBuf>,
    pending_orphans_dirty: bool,
    pending_writeback_path: Option<PathBuf>,
    pending_writebacks_dirty: bool,
    pending_refresh_path: Option<PathBuf>,
    pending_refreshes_dirty: bool,
    pending_open_unlinked_path: Option<PathBuf>,
    pending_open_unlinked_dirty: bool,
    pending_metadata_path: Option<PathBuf>,
    pending_metadata_dirty: bool,
    sync_baseline_path: Option<PathBuf>,
    conflict_registry_path: Option<PathBuf>,
    conflict_registry_dirty: bool,
    recovery_registry_path: Option<PathBuf>,
    recovery_registry_dirty: bool,
    last_open_unlinked_warning: Option<String>,
    mount_readonly_active: bool,
    mount_readonly_restore_modes: HashMap<PathBuf, u32>,
    hard_link_block_restore_modes: HashMap<PathBuf, u32>,
    // Track files that need two stable scans before encryption
    pending_stable: HashMap<PathBuf, StableEntry>,
    // Current scan health state
    scan_health: ScanHealth,
    space_warnings: SpaceWarningState,
    // Deletion configuration
    deletion_config: DeletionConfig,
    sparse_skip_size_bytes: u64,
    stream_threshold_bytes: u64,
    stream_chunk_size_bytes: u64,
    stream_stability_age_secs: u64,
    // Exclusion patterns from client config — files matching these are invisible to sync
    excluded_patterns: Vec<glob::Pattern>,
    // Bidirectional sync: local files created while unmounted, pending encryption
    pending_local_creates: Vec<PathBuf>,
    // Bidirectional sync: local deletions while unmounted, pending encrypted-side removal
    pending_local_deletes: Vec<PathBuf>,
    // One-shot startup guard: skip inferring local deletions from a just-mounted empty view.
    suppress_deletion_inference: bool,
    // One-shot startup guard: skip executing pending deletion/orphan processing.
    suppress_deletion_processing: bool,
    // Conflict policy for reconciliation
    conflict_policy: ConflictPolicy,
}

impl SyncTracker {
    pub fn new() -> Self {
        Self {
            scan_health: ScanHealth::Healthy,
            deletion_config: DeletionConfig::default(),
            sparse_skip_size_bytes: SPARSE_SKIP_SIZE_BYTES,
            stream_threshold_bytes: STREAM_THRESHOLD_BYTES,
            stream_chunk_size_bytes: STREAM_CHUNK_SIZE_BYTES,
            stream_stability_age_secs: STREAM_STABILITY_AGE_SECS,
            ..Self::default()
        }
    }

    pub fn set_pending_deletion_path(&mut self, path: PathBuf) {
        self.pending_deletion_path = Some(path);
        if let Err(err) = self.load_pending_deletions() {
            warn!("Failed to load pending deletions: {}", err);
        }
    }

    pub fn set_pending_orphan_path(&mut self, path: PathBuf) {
        self.pending_orphan_path = Some(path);
        if let Err(err) = self.load_pending_orphans() {
            warn!("Failed to load pending orphans: {}", err);
        }
    }

    pub fn set_pending_writeback_path(&mut self, path: PathBuf) {
        self.pending_writeback_path = Some(path);
        if let Err(err) = self.load_pending_writebacks() {
            warn!("Failed to load pending writebacks: {}", err);
        }
    }

    pub fn set_pending_refresh_path(&mut self, path: PathBuf) {
        self.pending_refresh_path = Some(path);
        if let Err(err) = self.load_pending_refreshes() {
            warn!("Failed to load pending refreshes: {}", err);
        }
    }

    pub fn set_pending_open_unlinked_path(&mut self, path: PathBuf) {
        self.pending_open_unlinked_path = Some(path);
        if let Err(err) = self.load_pending_open_unlinked() {
            warn!("Failed to load pending deleted-open journal: {}", err);
        }
    }

    pub fn set_pending_metadata_path(&mut self, path: PathBuf) {
        self.pending_metadata_path = Some(path);
        if let Err(err) = self.load_pending_metadata() {
            warn!("Failed to load pending metadata: {}", err);
        }
    }

    pub fn set_sync_baseline_path(&mut self, path: PathBuf) {
        self.sync_baseline_path = Some(path);
        if let Err(err) = self.load_sync_baseline() {
            warn!("Failed to load sync baseline: {}", err);
        }
    }

    pub fn set_conflict_registry_path(&mut self, path: PathBuf) {
        self.conflict_registry_path = Some(path);
        self.conflict_registry_dirty = true;
    }

    pub fn set_recovery_registry_path(&mut self, path: PathBuf) {
        self.recovery_registry_path = Some(path);
        self.recovery_registry_dirty = true;
    }

    /// Set deletion configuration (called from config file)
    /// Preserves existing retention_folder if the new config doesn't have one set
    pub fn set_deletion_config(&mut self, config: DeletionConfig) {
        // Preserve existing retention folder if new config doesn't have one
        let existing_retention_folder = self.deletion_config.retention_folder.clone();
        let retention_folder = if config.retention_folder.is_some() {
            config.retention_folder.clone()
        } else {
            existing_retention_folder
        };

        // Create a new config with preserved retention folder
        let mut final_config = config;
        final_config.retention_folder = retention_folder;

        // Ensure retention folder exists if configured
        if let Some(ref folder) = final_config.retention_folder {
            if let Err(e) = fs::create_dir_all(folder) {
                warn!(
                    "Failed to create retention folder {}: {}",
                    folder.display(),
                    e
                );
            } else {
                info!("Retention folder ready: {}", folder.display());
            }
        }
        self.deletion_config = final_config;
    }

    pub fn set_sparse_skip_size_bytes(&mut self, sparse_skip_size_bytes: u64) {
        self.sparse_skip_size_bytes = sparse_skip_size_bytes;
    }

    pub fn set_stream_threshold_bytes(&mut self, stream_threshold_bytes: u64) {
        self.stream_threshold_bytes = stream_threshold_bytes;
    }

    pub fn set_stream_chunk_size_bytes(&mut self, stream_chunk_size_bytes: u64) {
        self.stream_chunk_size_bytes = stream_chunk_size_bytes;
    }

    pub fn set_stream_stability_age_secs(&mut self, stream_stability_age_secs: u64) {
        self.stream_stability_age_secs = stream_stability_age_secs;
    }

    pub fn set_excluded_patterns(&mut self, raw_patterns: Vec<String>) {
        self.excluded_patterns = raw_patterns
            .iter()
            .filter_map(|raw| match glob::Pattern::new(raw) {
                Ok(p) => Some(p),
                Err(err) => {
                    warn!("Ignoring invalid exclusion pattern '{}': {}", raw, err);
                    None
                }
            })
            .collect();
    }

    /// Set the conflict policy for reconciliation
    pub fn set_conflict_policy(&mut self, policy: ConflictPolicy) {
        self.conflict_policy = policy;
    }

    /// Get the current conflict policy
    pub fn conflict_policy(&self) -> &ConflictPolicy {
        &self.conflict_policy
    }

    /// Get a snapshot of decrypted (mount) file signatures for reconciliation
    pub fn decrypted_signatures_snapshot(&self) -> HashMap<PathBuf, FileSignature> {
        self.decrypted_signatures.clone()
    }

    /// Get a snapshot of encrypted file signatures for reconciliation
    pub fn encrypted_signatures_snapshot(&self) -> HashMap<PathBuf, FileSignature> {
        self.encrypted_signatures.clone()
    }

    /// Get mapping from mount paths to encrypted paths using tracked file_ids
    pub fn mount_to_encrypted_mapping(&self) -> HashMap<PathBuf, PathBuf> {
        // Invert the path_mapping (encrypted -> mount) to get mount -> encrypted
        self.path_mapping
            .iter()
            .map(|(enc, mount)| (mount.clone(), enc.clone()))
            .collect()
    }

    /// Queue a local file for background encryption (new or modified while unmounted)
    pub fn queue_local_create(&mut self, mount_path: PathBuf) {
        if !self.pending_local_creates.contains(&mount_path) {
            info!(
                "Queuing local file for background encryption: {}",
                mount_path.display()
            );
            self.pending_local_creates.push(mount_path);
        }
    }

    /// Queue an encrypted file for background deletion (local file was deleted while unmounted)
    pub fn queue_local_delete(&mut self, encrypted_path: PathBuf) {
        if !self.pending_local_deletes.contains(&encrypted_path) {
            info!(
                "Queuing encrypted file for background deletion: {}",
                encrypted_path.display()
            );
            self.pending_local_deletes.push(encrypted_path);
        }
    }

    /// Get pending local creates for background processing
    pub fn pending_local_creates(&self) -> &[PathBuf] {
        &self.pending_local_creates
    }

    /// Get pending local deletes for background processing
    pub fn pending_local_deletes(&self) -> &[PathBuf] {
        &self.pending_local_deletes
    }

    /// Clear a processed local create
    pub fn complete_local_create(&mut self, mount_path: &Path) {
        self.pending_local_creates.retain(|p| p != mount_path);
    }

    /// Clear a processed local delete
    pub fn complete_local_delete(&mut self, encrypted_path: &Path) {
        self.pending_local_deletes.retain(|p| p != encrypted_path);
    }

    /// Check if there are pending background operations
    pub fn has_pending_background_ops(&self) -> bool {
        !self.pending_local_creates.is_empty() || !self.pending_local_deletes.is_empty()
    }

    /// Enter one-shot startup rehydrate mode.
    ///
    /// Used after consuming a clean marker (and empty-mount startup guard) so first sync
    /// rebuilds plaintext state from encrypted files without inferring or executing deletions.
    pub fn enter_startup_rehydrate_mode(&mut self) {
        self.decrypted_signatures.clear();
        self.decrypted_hashes.clear();
        self.decrypted_metadata_hashes.clear();
        self.file_id_to_mount_path.clear();
        self.path_mapping.clear();
        self.clear_pending_deletions();
        self.suppress_deletion_inference = true;
        self.suppress_deletion_processing = true;
    }

    /// Exit one-shot startup rehydrate mode after first successful sync pass.
    pub fn exit_startup_rehydrate_mode(&mut self) {
        self.suppress_deletion_inference = false;
        self.suppress_deletion_processing = false;
    }

    /// Process pending local creates (encrypt files created while unmounted)
    /// This is called from the sync loop after mount is ready.
    /// Returns the number of files successfully processed.
    pub async fn process_pending_local_creates<C: MountCrypto + ?Sized>(
        &mut self,
        _crypto: &C,
        _encrypted_root: &Path,
        mount_root: &Path,
    ) -> Result<usize, MountSyncError> {
        if self.pending_local_creates.is_empty() {
            return Ok(0);
        }

        let mut processed = 0;
        let creates_to_process: Vec<PathBuf> = self.pending_local_creates.clone();

        for mount_path in creates_to_process {
            if !mount_path.exists() {
                // File was deleted since queued, just remove from queue
                self.complete_local_create(&mount_path);
                continue;
            }

            // Check if file is excluded
            if self.is_path_excluded(&mount_path) {
                info!(
                    "Skipping excluded file from local create queue: {}",
                    mount_path.display()
                );
                self.complete_local_create(&mount_path);
                continue;
            }

            // Verify path is under mount root
            let _relative = match mount_path.strip_prefix(mount_root) {
                Ok(rel) => rel,
                Err(_) => {
                    warn!(
                        "Local create path {} not under mount root {}",
                        mount_path.display(),
                        mount_root.display()
                    );
                    self.complete_local_create(&mount_path);
                    continue;
                }
            };

            // Get metadata for the file
            let metadata = match fs::metadata(&mount_path) {
                Ok(m) => m,
                Err(err) => {
                    warn!(
                        "Failed to get metadata for local create {}: {}",
                        mount_path.display(),
                        err
                    );
                    self.complete_local_create(&mount_path);
                    continue;
                }
            };

            if !metadata.is_file() {
                self.complete_local_create(&mount_path);
                continue;
            }

            // Check stability - don't encrypt files that are still being written
            let sig = FileSignature::from_metadata(&metadata);
            if let Some(stored_sig) = self.decrypted_signatures.get(&mount_path) {
                if sig != *stored_sig {
                    // File changed since we queued it, wait for it to stabilize
                    debug!(
                        "Local create {} changed since queued, waiting for stability",
                        mount_path.display()
                    );
                    continue;
                }
            }

            // Encrypt the file using the sync mechanism
            // This will be handled by the normal sync pass - just mark as needing encryption
            info!(
                "Processing local create for encryption: {}",
                mount_path.display()
            );

            // Update tracking so the next sync picks it up as a dirty file
            self.decrypted_signatures.insert(mount_path.clone(), sig);
            self.refresh_decrypted_metadata_hash(&mount_path);

            // Mark as complete - the normal sync will handle actual encryption
            self.complete_local_create(&mount_path);
            processed += 1;
        }

        Ok(processed)
    }

    /// Process pending local deletes (remove encrypted files for files deleted while unmounted)
    /// Returns the number of files successfully processed.
    pub async fn process_pending_local_deletes<C: MountCrypto + ?Sized>(
        &mut self,
        _crypto: &C,
        encrypted_root: &Path,
    ) -> Result<usize, MountSyncError> {
        if self.pending_local_deletes.is_empty() {
            return Ok(0);
        }

        let mut processed = 0;
        let deletes_to_process: Vec<PathBuf> = self.pending_local_deletes.clone();

        for encrypted_path in deletes_to_process {
            if !encrypted_path.exists() {
                // Already deleted, just clean up tracking
                self.complete_local_delete(&encrypted_path);
                processed += 1;
                continue;
            }

            // Use the existing deletion mechanism with retention
            info!(
                "Processing local delete - removing encrypted file: {}",
                encrypted_path.display()
            );

            // Apply deletion with retention policy if configured
            match self.apply_encrypted_deletion(&encrypted_path, encrypted_root) {
                Ok(_) => {
                    // Clean up tracking for this file
                    self.encrypted_signatures.remove(&encrypted_path);
                    if let Some(mount_path) = self.path_mapping.remove(&encrypted_path) {
                        self.decrypted_signatures.remove(&mount_path);
                        self.decrypted_hashes.remove(&mount_path);
                        self.decrypted_metadata_hashes.remove(&mount_path);
                    }
                    self.complete_local_delete(&encrypted_path);
                    processed += 1;
                }
                Err(err) => {
                    warn!(
                        "Failed to delete encrypted file {}: {}",
                        encrypted_path.display(),
                        err
                    );
                    // Keep in queue for retry
                }
            }
        }

        Ok(processed)
    }

    /// Apply encrypted file deletion, respecting retention policy
    fn apply_encrypted_deletion(
        &self,
        encrypted_path: &Path,
        _encrypted_root: &Path,
    ) -> Result<(), MountSyncError> {
        if let Some(ref retention_folder) = self.deletion_config.retention_folder {
            // Move to retention folder instead of deleting
            let file_name = encrypted_path
                .file_name()
                .ok_or_else(|| MountSyncError::InvalidPath(encrypted_path.to_path_buf()))?;

            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let retention_name = format!("{}_{}", timestamp, file_name.to_string_lossy());
            let retention_path = retention_folder.join(retention_name);

            fs::rename(encrypted_path, &retention_path)?;
            info!(
                "Moved encrypted file to retention: {} -> {}",
                encrypted_path.display(),
                retention_path.display()
            );
        } else {
            // Direct deletion
            fs::remove_file(encrypted_path)?;
            info!("Deleted encrypted file: {}", encrypted_path.display());
        }

        Ok(())
    }

    // Test helper methods for injecting state
    #[cfg(test)]
    pub fn inject_decrypted_signature(&mut self, path: PathBuf, sig: FileSignature) {
        self.decrypted_signatures.insert(path, sig);
    }

    #[cfg(test)]
    pub fn inject_encrypted_signature(&mut self, path: PathBuf, sig: FileSignature) {
        self.encrypted_signatures.insert(path, sig);
    }

    #[cfg(test)]
    pub fn inject_path_mapping(&mut self, encrypted_path: PathBuf, mount_path: PathBuf) {
        self.path_mapping.insert(encrypted_path, mount_path);
    }

    pub fn is_path_excluded(&self, path: &Path) -> bool {
        if self.excluded_patterns.is_empty() {
            return false;
        }

        let path_candidates = exclusion_path_candidates(path);
        let file_name = path.file_name().and_then(|n| n.to_str());
        self.excluded_patterns.iter().any(|pattern| {
            pattern.matches_path(path)
                || path_candidates
                    .iter()
                    .any(|candidate| pattern.matches(candidate))
                || file_name.map(|name| pattern.matches(name)).unwrap_or(false)
        })
    }

    fn should_stream_file(&self, size_bytes: u64) -> bool {
        if self.stream_threshold_bytes == 0 {
            return false;
        }
        size_bytes >= self.stream_threshold_bytes
    }

    fn stream_chunk_size(&self) -> Option<usize> {
        if self.stream_chunk_size_bytes == 0 {
            return None;
        }
        usize::try_from(self.stream_chunk_size_bytes).ok()
    }

    /// Set the retention folder path
    pub fn set_retention_folder(&mut self, user_config_dir: &Path) {
        let retention_path = user_config_dir.join("retention");
        if let Err(e) = fs::create_dir_all(&retention_path) {
            warn!(
                "Failed to create retention folder {}: {}",
                retention_path.display(),
                e
            );
            // Don't set retention folder if we can't create it
            return;
        }
        self.deletion_config.retention_folder = Some(retention_path.clone());
        info!(
            "Retention folder initialized: {} (retention_days: {})",
            retention_path.display(),
            self.deletion_config.retention_days
        );
    }

    /// Load mount configuration from config file
    pub fn load_mount_config_from_file(config_path: Option<&Path>) -> MountSyncConfig {
        let mut candidates = config_file_candidates();

        // Check explicit config path
        if let Some(path) = config_path {
            let path_buf = path.to_path_buf();
            if path_buf.exists() && !candidates.contains(&path_buf) {
                candidates.push(path_buf);
            }
        }

        let mut config = MountSyncConfig::default();
        let mut saw_any = false;

        if apply_mount_config_from_str(
            EMBEDDED_CLIENT_CONFIG,
            "embedded client_config.toml",
            &mut config,
        ) {
            saw_any = true;
        }

        // Try to load config from files
        for path in candidates {
            if let Ok(contents) = fs::read_to_string(&path) {
                if apply_mount_config_from_str(&contents, &path.display().to_string(), &mut config)
                {
                    saw_any = true;
                }
            }
        }

        if saw_any {
            debug!(
                "Loaded mount config: scans={}, duration_ms={}, retention_days={}, sparse_skip_size_bytes={}, stream_threshold_bytes={}, stream_chunk_size_bytes={}, stream_stability_age_secs={}, startup_local_delete_max_actions={}",
                config.deletion.min_consecutive_missing_scans,
                config.deletion.rapid_scan_total_duration_ms,
                config.deletion.retention_days,
                config.sparse_skip_size_bytes,
                config.stream_threshold_bytes,
                config.stream_chunk_size_bytes,
                config.stream_stability_age_secs,
                config.startup_local_delete_max_actions
            );
        } else {
            debug!("Using default mount config");
        }
        config
    }

    /// Load deletion configuration from config file (legacy helper)
    pub fn load_deletion_config_from_file(config_path: Option<&Path>) -> DeletionConfig {
        Self::load_mount_config_from_file(config_path).deletion
    }

    /// Explicitly clear all pending deletions and flush the journal.
    pub fn clear_pending_deletions(&mut self) {
        if !self.pending_deletions.is_empty() {
            info!(
                "Clearing {} pending deletions",
                self.pending_deletions.len()
            );
            self.pending_deletions.clear();
            self.pending_deletions_dirty = true;
            self.flush_pending_deletions();
        }
    }

    pub fn clear_pending_writebacks(&mut self) {
        if !self.pending_writebacks.is_empty() {
            info!(
                "Clearing {} pending writebacks",
                self.pending_writebacks.len()
            );
            self.pending_writebacks.clear();
            self.pending_writebacks_dirty = true;
            self.flush_pending_writebacks();
        }
    }

    pub fn pending_writeback_mount_paths(&self) -> Vec<PathBuf> {
        self.pending_writebacks.keys().cloned().collect()
    }

    pub fn has_fast_drain_work(&self) -> bool {
        !self.pending_stable.is_empty()
            || self
                .pending_writebacks
                .values()
                .any(should_fast_drain_pending_writeback)
    }

    /// Pre-populate the stability entry for a file that has been fully written
    /// to the cache (e.g. by the File Provider writeback path).  The next
    /// sync() pass will see the matching signature and encrypt immediately
    /// instead of deferring for a second stability scan.
    pub fn preseed_stable(&mut self, path: &Path) {
        if let Ok(metadata) = fs::metadata(path) {
            let signature = FileSignature::from_metadata(&metadata);
            self.pending_stable.insert(
                path.to_path_buf(),
                StableEntry {
                    signature,
                    first_seen: Instant::now(),
                },
            );
        }
    }

    pub fn clear_pending_refreshes(&mut self) {
        if !self.pending_refreshes.is_empty() {
            info!(
                "Clearing {} pending refreshes",
                self.pending_refreshes.len()
            );
            self.pending_refreshes.clear();
            self.pending_refreshes_dirty = true;
            self.flush_pending_refreshes();
        }
    }

    pub fn can_cleanup_mountpoint(&self) -> bool {
        if !matches!(self.scan_health, ScanHealth::Healthy) {
            return false;
        }
        if !self.pending_open_unlinked.is_empty() {
            return false;
        }
        if !self.unsupported_transactional_paths.is_empty() {
            return false;
        }
        if !self.unsupported_hard_link_paths.is_empty() {
            return false;
        }
        if !self.pending_refreshes.is_empty() {
            return false;
        }
        if !self.pending_writebacks.is_empty() {
            return false;
        }
        if !self.pending_orphans.is_empty() {
            return false;
        }
        if !self.pending_stable.is_empty() {
            return false;
        }
        if !self.pending_temp.is_empty() {
            return false;
        }
        if !self.conflict_baselines.is_empty() {
            return false;
        }
        if !self.recovered_pending_paths.is_empty() {
            return false;
        }
        true
    }

    pub fn prepare_mountpoint_cleanup(&mut self) -> Result<(), MountSyncError> {
        if !self.mount_readonly_active {
            return Ok(());
        }

        restore_mount_permissions(&self.mount_readonly_restore_modes)?;
        self.mount_readonly_restore_modes.clear();
        self.mount_readonly_active = false;
        Ok(())
    }

    fn low_space_readonly_required(&self) -> bool {
        self.space_warnings.any()
            || !self.pending_refreshes.is_empty()
            || self
                .pending_writebacks
                .values()
                .any(|pending| pending.low_space)
    }

    pub fn refresh_low_space_mount_mode(
        &mut self,
        encrypted_root: &Path,
        mount_root: &Path,
    ) -> Result<(), MountSyncError> {
        self.refresh_space_warnings(encrypted_root, mount_root);
        self.enforce_low_space_mount_mode(mount_root)
    }

    pub fn enforce_low_space_mount_mode(
        &mut self,
        mount_root: &Path,
    ) -> Result<(), MountSyncError> {
        let should_enable = self.low_space_readonly_required();
        if should_enable == self.mount_readonly_active {
            return Ok(());
        }

        if should_enable {
            self.mount_readonly_restore_modes = apply_mount_readonly_permissions(mount_root)?;
            self.mount_readonly_active = true;
            warn!(
                "Mountpoint {} switched to read-only degraded mode due to low-space conditions",
                mount_root.display()
            );
        } else {
            restore_mount_permissions(&self.mount_readonly_restore_modes)?;
            self.mount_readonly_restore_modes.clear();
            self.mount_readonly_active = false;
            info!(
                "Mountpoint {} restored to writable mode after low-space recovery",
                mount_root.display()
            );
        }

        Ok(())
    }

    pub fn runtime_status(&self) -> MountSyncRuntimeStatus {
        let now = Utc::now();
        let pending_refresh_count = self.pending_refreshes.len();
        let pending_writeback_count = self.pending_writebacks.len();
        let pending_writeback_oldest_age_ms =
            pending_writeback_oldest_age_ms_from(self.pending_writebacks.values(), now);
        let mut pending_writeback_paths = self
            .pending_writebacks
            .keys()
            .map(|path| path.display().to_string())
            .take(16)
            .collect::<Vec<_>>();
        pending_writeback_paths.sort();
        let pending_open_unlinked_count = self.pending_open_unlinked.len();
        let pending_conflict_count = self.conflict_baselines.len();
        let edited_conflict_count = self
            .conflict_baselines
            .values()
            .filter(|baseline| baseline.edited)
            .count();
        let recovered_pending_copy_count = self.recovered_pending_paths.len();
        let transactional_warnings = self.transactional_format_warnings();
        let hard_link_warnings = self.hard_link_warnings();
        let conflict_warnings = self.conflict_warnings();
        let recovery_copy_warnings = self.recovered_pending_copy_warnings();
        let open_unlinked_warnings = self.open_unlinked_warnings();
        let pending_low_space_path_count = self
            .pending_writebacks
            .values()
            .filter(|pending| pending.low_space)
            .count()
            + self.pending_refreshes.len();

        let low_space_mode = if self.pending_refreshes.is_empty()
            && self
                .pending_writebacks
                .values()
                .all(|pending| !pending.low_space)
        {
            if self.space_warnings.any() {
                LowSpaceMode::Warning
            } else {
                LowSpaceMode::Healthy
            }
        } else if !self.pending_refreshes.is_empty()
            && self
                .pending_writebacks
                .values()
                .any(|pending| pending.low_space)
        {
            LowSpaceMode::FullyDegraded
        } else if !self.pending_refreshes.is_empty() {
            LowSpaceMode::RefreshDegraded
        } else {
            LowSpaceMode::WritebackDegraded
        };

        let low_space_paths: Vec<String> = self
            .pending_writebacks
            .iter()
            .filter_map(|(path, pending)| pending.low_space.then(|| path.display().to_string()))
            .chain(
                self.pending_refreshes
                    .keys()
                    .map(|path| path.display().to_string()),
            )
            .take(16)
            .collect();

        let mut open_unlinked_paths = self
            .pending_open_unlinked
            .keys()
            .map(|path| path.display().to_string())
            .take(MAX_OPEN_UNLINKED_PATHS_IN_STATUS)
            .collect::<Vec<_>>();
        open_unlinked_paths.sort();
        let mut conflict_paths = self
            .conflict_baselines
            .keys()
            .map(|path| path.display().to_string())
            .take(MAX_CONFLICT_PATHS_IN_STATUS)
            .collect::<Vec<_>>();
        conflict_paths.sort();
        let mut recovered_pending_copy_paths = self
            .recovered_pending_paths
            .iter()
            .map(|path| path.display().to_string())
            .take(MAX_RECOVERED_PENDING_PATHS_IN_STATUS)
            .collect::<Vec<_>>();
        recovered_pending_copy_paths.sort();
        let mut edited_conflict_paths = self
            .conflict_baselines
            .iter()
            .filter(|(_, baseline)| baseline.edited)
            .map(|(path, _)| path.display().to_string())
            .take(MAX_CONFLICT_PATHS_IN_STATUS)
            .collect::<Vec<_>>();
        edited_conflict_paths.sort();

        let last_error = self
            .pending_writebacks
            .values()
            .filter_map(|pending| pending.last_error.clone())
            .next()
            .or_else(|| {
                self.pending_refreshes
                    .values()
                    .filter_map(|pending| pending.last_error.clone())
                    .next()
            })
            .or_else(|| self.last_open_unlinked_warning.clone())
            .or_else(|| conflict_warnings.first().cloned())
            .or_else(|| recovery_copy_warnings.first().cloned())
            .or_else(|| open_unlinked_warnings.first().cloned())
            .or_else(|| hard_link_warnings.first().cloned())
            .or_else(|| transactional_warnings.first().cloned())
            .or_else(|| self.space_warnings.warnings().first().cloned());

        let mut unsafe_reasons = Vec::new();
        if pending_writeback_count > 0 {
            unsafe_reasons.push(MountSafetyReason::PendingWriteback {
                count: pending_writeback_count,
                oldest_age_ms: pending_writeback_oldest_age_ms.unwrap_or(0),
                sample_paths: pending_writeback_paths.iter().take(3).cloned().collect(),
                last_error: self
                    .pending_writebacks
                    .values()
                    .filter_map(|pending| pending.last_error.clone())
                    .next(),
            });
        }
        if pending_refresh_count > 0 {
            unsafe_reasons.push(MountSafetyReason::PendingRefresh {
                count: pending_refresh_count,
            });
        }
        if pending_conflict_count > 0 {
            unsafe_reasons.push(MountSafetyReason::Conflict {
                count: pending_conflict_count,
                edited_count: edited_conflict_count,
                sample_paths: sample_paths(self.conflict_baselines.keys().cloned(), 3),
            });
        }
        if pending_open_unlinked_count > 0 {
            unsafe_reasons.push(MountSafetyReason::DeletedOpen {
                count: pending_open_unlinked_count,
                sample_paths: sample_paths(self.pending_open_unlinked.keys().cloned(), 3),
            });
        }
        if !self.unsupported_transactional_paths.is_empty() {
            unsafe_reasons.push(MountSafetyReason::TransactionalBlocked {
                count: self.unsupported_transactional_paths.len(),
                sample_paths: sample_paths(self.unsupported_transactional_paths.keys().cloned(), 3),
            });
        }
        if !self.unsupported_hard_link_paths.is_empty() {
            unsafe_reasons.push(MountSafetyReason::HardLinkBlocked {
                count: self.unsupported_hard_link_paths.len(),
                sample_paths: sample_paths(self.unsupported_hard_link_paths.keys().cloned(), 3),
            });
        }
        if !matches!(low_space_mode, LowSpaceMode::Healthy) {
            unsafe_reasons.push(MountSafetyReason::LowSpaceDegraded {
                mode: low_space_mode,
                count: pending_low_space_path_count,
                sample_paths: low_space_paths.iter().take(3).cloned().collect(),
            });
        }
        if recovered_pending_copy_count > 0 {
            unsafe_reasons.push(MountSafetyReason::RecoveryCopiesPresent {
                count: recovered_pending_copy_count,
                sample_paths: sample_paths(self.recovered_pending_paths.iter().cloned(), 3),
            });
        }

        let mut preflight_warnings = unsafe_reasons
            .iter()
            .map(MountSafetyReason::summary)
            .collect::<Vec<_>>();
        preflight_warnings.extend(open_unlinked_warnings);
        preflight_warnings.extend(hard_link_warnings);
        preflight_warnings.extend(transactional_warnings);
        preflight_warnings.extend(recovery_copy_warnings);
        if self.mount_readonly_active {
            preflight_warnings
                .push("mount forced read-only due to low-space degraded mode".to_string());
        }
        preflight_warnings.extend(self.space_warnings.warnings());
        let mut seen_warnings = HashSet::new();
        preflight_warnings.retain(|warning| seen_warnings.insert(warning.clone()));

        MountSyncRuntimeStatus {
            safe_to_unmount: self.can_cleanup_mountpoint(),
            pending_writeback_count,
            pending_writeback_oldest_age_ms,
            pending_writeback_paths,
            pending_refresh_count,
            pending_open_unlinked_count,
            pending_conflict_count,
            edited_conflict_count,
            recovered_pending_copy_count,
            pending_low_space_path_count,
            low_space_mode,
            low_space_paths,
            open_unlinked_paths,
            conflict_paths,
            edited_conflict_paths,
            recovered_pending_copy_paths,
            unsafe_reasons,
            preflight_warnings,
            last_error,
            updated_at: now,
        }
    }

    fn refresh_space_warnings(&mut self, encrypted_root: &Path, mount_root: &Path) {
        self.space_warnings = SpaceWarningState {
            mount_low: volume_below_reserve(mount_root, LOW_SPACE_WARNING_RESERVE_BYTES),
            encrypted_low: volume_below_reserve(encrypted_root, LOW_SPACE_WARNING_RESERVE_BYTES),
            journal_low: self
                .journal_budget_path()
                .map(|path| volume_below_reserve(path, LOW_SPACE_WARNING_RESERVE_BYTES))
                .unwrap_or(false),
        };
    }

    fn journal_budget_path(&self) -> Option<&Path> {
        self.pending_writeback_path
            .as_deref()
            .or(self.pending_refresh_path.as_deref())
            .or(self.pending_open_unlinked_path.as_deref())
            .or(self.pending_metadata_path.as_deref())
            .or(self.pending_orphan_path.as_deref())
            .or(self.pending_deletion_path.as_deref())
    }

    fn ensure_space_budget(
        &self,
        path: &Path,
        required_bytes: u64,
        reserve_bytes: u64,
        operation: &str,
    ) -> Result<(), MountSyncError> {
        ensure_space_budget(path, required_bytes, reserve_bytes, operation)
    }

    fn remember_decrypted_metadata_hash(
        &mut self,
        path: &Path,
        platform_metadata: Option<&PlatformFileMetadata>,
    ) {
        let hash = platform_metadata.and_then(hash_platform_metadata);
        if let Some(hash) = hash {
            self.decrypted_metadata_hashes
                .insert(path.to_path_buf(), hash);
        } else {
            self.decrypted_metadata_hashes.remove(path);
        }
    }

    fn remember_decrypted_directory_metadata_hash(
        &mut self,
        path: &Path,
        platform_metadata: Option<&PlatformFileMetadata>,
    ) {
        let hash = platform_metadata.and_then(hash_platform_metadata);
        if let Some(hash) = hash {
            self.decrypted_directory_metadata_hashes
                .insert(path.to_path_buf(), hash);
        } else {
            self.decrypted_directory_metadata_hashes.remove(path);
        }
    }

    fn record_unsupported_transactional_path(&mut self, path: &Path, reason: &str) {
        let reason_string = reason.to_string();
        let changed = self
            .unsupported_transactional_paths
            .get(path)
            .map(|existing| existing != &reason_string)
            .unwrap_or(true);

        self.unsupported_transactional_paths
            .insert(path.to_path_buf(), reason_string);

        if changed {
            warn!(
                "Blocking transactional-format sync for {}: {}",
                path.display(),
                reason
            );
        }
    }

    fn record_unsupported_hard_link_path(
        &mut self,
        path: &Path,
        reason: &str,
    ) -> Result<(), MountSyncError> {
        let reason_string = reason.to_string();
        let changed = self
            .unsupported_hard_link_paths
            .get(path)
            .map(|existing| existing != &reason_string)
            .unwrap_or(true);

        #[cfg(unix)]
        {
            let metadata = fs::metadata(path)?;
            let current_mode = metadata.permissions().mode();
            let restore_mode = if self.mount_readonly_active {
                self.mount_readonly_restore_modes
                    .get(path)
                    .copied()
                    .unwrap_or(current_mode)
            } else {
                current_mode
            };
            self.hard_link_block_restore_modes
                .entry(path.to_path_buf())
                .or_insert(restore_mode);
            let readonly_mode = current_mode & !0o222;
            if readonly_mode != current_mode {
                fs::set_permissions(path, fs::Permissions::from_mode(readonly_mode))?;
            }
        }

        self.unsupported_hard_link_paths
            .insert(path.to_path_buf(), reason_string);
        self.pending_stable.remove(path);
        self.pending_temp.remove(path);
        self.pending_sparse.remove(path);
        self.clear_pending_writeback(path);
        self.clear_pending_refresh(path);
        self.file_id_to_mount_path
            .retain(|_file_id, mount_path| mount_path != path);

        if changed {
            warn!(
                "Blocking hard-linked file from sync for {}: {}",
                path.display(),
                reason
            );
        }

        Ok(())
    }

    fn clear_unsupported_hard_link_path(&mut self, path: &Path) -> Result<(), MountSyncError> {
        let removed = self.unsupported_hard_link_paths.remove(path).is_some();
        let restore_mode = self.hard_link_block_restore_modes.remove(path);

        #[cfg(unix)]
        if let Some(mode) = restore_mode {
            if path.exists() {
                if self.mount_readonly_active {
                    self.mount_readonly_restore_modes
                        .insert(path.to_path_buf(), mode);
                } else {
                    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
                }
            }
        }

        if removed {
            debug!("Cleared hard-link block for {}", path.display());
        }

        Ok(())
    }

    fn transactional_format_warnings(&self) -> Vec<String> {
        if self.unsupported_transactional_paths.is_empty() {
            return Vec::new();
        }

        let mut warnings = Vec::new();
        warnings.push(format!(
            "{} transactional path(s) blocked; sync mount does not provide atomic-set guarantees for databases, packages, or bundle-style formats",
            self.unsupported_transactional_paths.len()
        ));

        for path in self.unsupported_transactional_paths.keys().take(3) {
            warnings.push(format!("Transactional sync blocked: {}", path.display()));
        }

        warnings
    }

    fn hard_link_warnings(&self) -> Vec<String> {
        if self.unsupported_hard_link_paths.is_empty() {
            return Vec::new();
        }

        let mut warnings = Vec::new();
        warnings.push(format!(
            "{} hard-linked file(s) blocked; sync mount does not preserve hard-link semantics",
            self.unsupported_hard_link_paths.len()
        ));

        for path in self.unsupported_hard_link_paths.keys().take(3) {
            warnings.push(format!(
                "Hard-link sync blocked: {}. Break the hard link or replace it with an independent copy to resume protected sync.",
                path.display()
            ));
        }

        warnings
    }

    fn conflict_warnings(&self) -> Vec<String> {
        if self.conflict_baselines.is_empty() {
            return Vec::new();
        }

        let mut warnings = Vec::new();
        warnings.push(format!(
            "{} unresolved conflict file(s) remain local-only until they are resolved or merged back",
            self.conflict_baselines.len()
        ));

        let edited_count = self
            .conflict_baselines
            .values()
            .filter(|baseline| baseline.edited)
            .count();
        if edited_count > 0 {
            warnings.push(format!(
                "{} conflict file(s) were edited locally and are still not protected by encrypted sync",
                edited_count
            ));
        }

        let mut conflict_paths = self
            .conflict_baselines
            .keys()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        conflict_paths.sort();
        for path in conflict_paths.into_iter().take(3) {
            warnings.push(format!("Conflict file still unresolved: {}", path));
        }

        warnings
    }

    fn recovered_pending_copy_warnings(&self) -> Vec<String> {
        if self.recovered_pending_paths.is_empty() {
            return Vec::new();
        }

        let mut warnings = Vec::new();
        warnings.push(format!(
            "{} recovered pending-work file(s) were recreated as local-only read-only copies after an unclean mount restart",
            self.recovered_pending_paths.len()
        ));

        let mut paths = self
            .recovered_pending_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths.into_iter().take(3) {
            warnings.push(format!("Recovered pending work copy: {}", path));
        }

        warnings
    }

    fn conflict_record_for_path(
        &self,
        mount_root: &Path,
        conflict_path: &Path,
        baseline: &ConflictBaseline,
    ) -> Option<MountConflictRecord> {
        let conflict_relative_path = conflict_path.strip_prefix(mount_root).ok()?.to_path_buf();
        let live_relative_path = baseline
            .live_path
            .strip_prefix(mount_root)
            .ok()?
            .to_path_buf();
        let conflict_size_bytes = fs::metadata(conflict_path).ok()?.len();
        let live_size_bytes = fs::metadata(&baseline.live_path)
            .ok()
            .map(|meta| meta.len());
        let text_merge_supported = baseline.live_path.exists()
            && read_conflict_preview_text(conflict_path)
                .ok()
                .flatten()
                .is_some()
            && read_conflict_preview_text(&baseline.live_path)
                .ok()
                .flatten()
                .is_some();
        Some(MountConflictRecord {
            id: baseline.id,
            kind: baseline.kind,
            live_relative_path,
            conflict_relative_path,
            created_at: baseline.created_at,
            edited: baseline.edited,
            live_exists: baseline.live_path.exists(),
            text_merge_supported,
            live_size_bytes,
            conflict_size_bytes,
        })
    }

    pub fn conflict_records(&self, mount_root: &Path) -> Vec<MountConflictRecord> {
        let mut records = self
            .conflict_baselines
            .iter()
            .filter_map(|(path, baseline)| {
                self.conflict_record_for_path(mount_root, path, baseline)
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.live_relative_path
                .cmp(&right.live_relative_path)
                .then_with(|| {
                    left.conflict_relative_path
                        .cmp(&right.conflict_relative_path)
                })
        });
        records
    }

    fn recovery_copy_record_for_path(
        &self,
        mount_root: &Path,
        recovery_path: &Path,
    ) -> Option<MountRecoveryCopyRecord> {
        let recovery_relative_path = recovery_path.strip_prefix(mount_root).ok()?.to_path_buf();
        let live_path = derive_live_path_from_recovered_pending_path(recovery_path);
        let live_relative_path = live_path.strip_prefix(mount_root).ok()?.to_path_buf();
        let recovery_size_bytes = fs::metadata(recovery_path).ok()?.len();
        let live_size_bytes = fs::metadata(&live_path).ok().map(|meta| meta.len());
        let text_preview_supported = read_conflict_preview_text(recovery_path)
            .ok()
            .flatten()
            .is_some()
            && live_path.exists()
            && read_conflict_preview_text(&live_path)
                .ok()
                .flatten()
                .is_some();
        Some(MountRecoveryCopyRecord {
            recovery_relative_path,
            live_relative_path,
            created_at: parse_local_only_timestamp(recovery_path, "recovered-pending")
                .unwrap_or_else(Utc::now),
            live_exists: live_path.exists(),
            text_preview_supported,
            live_size_bytes,
            recovery_size_bytes,
        })
    }

    pub fn recovery_copy_records(&self, mount_root: &Path) -> Vec<MountRecoveryCopyRecord> {
        let mut records = self
            .recovered_pending_paths
            .iter()
            .filter_map(|path| self.recovery_copy_record_for_path(mount_root, path))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.live_relative_path
                .cmp(&right.live_relative_path)
                .then_with(|| {
                    left.recovery_relative_path
                        .cmp(&right.recovery_relative_path)
                })
        });
        records
    }

    fn flush_conflict_registry(&mut self, mount_root: &Path) {
        if !self.conflict_registry_dirty {
            return;
        }
        match self.persist_conflict_registry(mount_root) {
            Ok(()) => {
                self.conflict_registry_dirty = false;
            }
            Err(err) => {
                warn!("Failed to persist conflict registry: {}", err);
            }
        }
    }

    fn persist_conflict_registry(&self, mount_root: &Path) -> Result<(), MountSyncError> {
        let path = match self.conflict_registry_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let records: Vec<ConflictRegistryRecord> = self
            .conflict_records(mount_root)
            .into_iter()
            .map(|record| ConflictRegistryRecord {
                id: record.id,
                kind: record.kind,
                live_relative_path: record.live_relative_path,
                conflict_relative_path: record.conflict_relative_path,
                created_at: record.created_at,
                edited: record.edited,
                live_exists: record.live_exists,
                text_merge_supported: record.text_merge_supported,
                live_size_bytes: record.live_size_bytes,
                conflict_size_bytes: record.conflict_size_bytes,
            })
            .collect();
        let data = serde_json::to_vec_pretty(&records).map_err(|err| {
            MountSyncError::Format(format!("Failed to serialize conflict registry: {}", err))
        })?;
        Self::write_atomic_bytes(path, &data)?;
        Ok(())
    }

    fn flush_recovery_registry(&mut self, mount_root: &Path) {
        if !self.recovery_registry_dirty {
            return;
        }
        match self.persist_recovery_registry(mount_root) {
            Ok(()) => {
                self.recovery_registry_dirty = false;
            }
            Err(err) => {
                warn!("Failed to persist recovery registry: {}", err);
            }
        }
    }

    fn persist_recovery_registry(&self, mount_root: &Path) -> Result<(), MountSyncError> {
        let path = match self.recovery_registry_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let records = self.recovery_copy_records(mount_root);
        let data = serde_json::to_vec_pretty(&records).map_err(|err| {
            MountSyncError::Format(format!("Failed to serialize recovery registry: {}", err))
        })?;
        Self::write_atomic_bytes(path, &data)?;
        Ok(())
    }

    fn update_conflict_file_tracking_with_kind(
        &mut self,
        path: &Path,
        signature: FileSignature,
        kind_override: Option<ConflictKind>,
    ) {
        if let Err(err) = set_conflict_file_readonly(path) {
            warn!(
                "Failed to force conflict file {} read-only: {}",
                path.display(),
                err
            );
        }

        let live_path = read_conflict_live_path_attr(path)
            .unwrap_or_else(|| derive_live_path_from_conflict_path(path));
        let kind = kind_override
            .or_else(|| read_conflict_kind_attr(path))
            .or_else(|| match read_local_only_reason(path).as_deref() {
                Some("deleted_open_recovery") => Some(ConflictKind::DeletedOpenRecovery),
                Some("conflict") => Some(ConflictKind::DecryptCollision),
                _ => None,
            })
            .unwrap_or(ConflictKind::DecryptCollision);
        let id = match stamp_conflict_file_metadata(path, &live_path, kind) {
            Ok(id) => id,
            Err(err) => {
                warn!(
                    "Failed to stamp conflict metadata for {}: {}",
                    path.display(),
                    err
                );
                read_conflict_id_attr(path).unwrap_or_else(Uuid::new_v4)
            }
        };
        let created_at = parse_local_only_timestamp(path, "conflict").unwrap_or_else(Utc::now);

        let current_hash = match hash_file(path) {
            Ok(hash) => Some(hash),
            Err(err) => {
                debug!("Failed to hash conflict file {}: {}", path.display(), err);
                None
            }
        };

        match self.conflict_baselines.get_mut(path) {
            Some(existing) => {
                let content_changed = match (existing.content_hash, current_hash) {
                    (Some(previous), Some(current)) => previous != current,
                    (Some(_), None) => true,
                    (None, Some(_)) => existing.signature != signature,
                    (None, None) => existing.signature != signature,
                };
                if content_changed {
                    existing.edited = true;
                }
                existing.live_path = live_path.clone();
                existing.kind = kind;
                existing.signature = signature;
                if existing.content_hash.is_none() {
                    existing.content_hash = current_hash;
                }
            }
            None => {
                self.conflict_baselines.insert(
                    path.to_path_buf(),
                    ConflictBaseline {
                        id,
                        live_path,
                        kind,
                        created_at,
                        signature,
                        content_hash: current_hash,
                        edited: false,
                    },
                );
            }
        }
        self.conflict_registry_dirty = true;
    }

    fn update_conflict_file_tracking(&mut self, path: &Path, signature: FileSignature) {
        self.update_conflict_file_tracking_with_kind(path, signature, None);
    }

    fn prune_conflict_tracking(&mut self, current_conflicts: &HashSet<PathBuf>) {
        let previous = self.conflict_baselines.len();
        self.conflict_baselines
            .retain(|path, _| current_conflicts.contains(path) && path.exists());
        if self.conflict_baselines.len() != previous {
            self.conflict_registry_dirty = true;
        }
    }

    fn note_recovered_pending_copy(&mut self, path: &Path, signature: FileSignature) {
        if let Err(err) = set_recovered_pending_file_readonly(path) {
            warn!(
                "Failed to force recovered pending copy {} read-only: {}",
                path.display(),
                err
            );
        }
        if let Err(err) = stamp_recovered_pending_file_metadata(path) {
            warn!(
                "Failed to stamp recovery-copy metadata for {}: {}",
                path.display(),
                err
            );
        }

        self.recovered_pending_paths.insert(path.to_path_buf());
        self.decrypted_signatures
            .insert(path.to_path_buf(), signature);
        self.refresh_decrypted_metadata_hash(path);
        self.decrypted_hashes.remove(path);
        self.pending_stable.remove(path);
        self.recovery_registry_dirty = true;
    }

    fn prune_recovered_pending_tracking(&mut self, current_recovered: &HashSet<PathBuf>) {
        let previous = self.recovered_pending_paths.len();
        self.recovered_pending_paths
            .retain(|path| current_recovered.contains(path) && path.exists());
        if self.recovered_pending_paths.len() != previous {
            self.recovery_registry_dirty = true;
        }
    }

    pub fn materialize_recovered_pending_copies(
        &mut self,
        quarantined_mount_root: &Path,
        live_mount_root: &Path,
        mount_paths: &[PathBuf],
    ) -> Result<Vec<PathBuf>, MountSyncError> {
        let mut created = Vec::new();

        for mount_path in mount_paths {
            let Ok(relative) = mount_path.strip_prefix(live_mount_root) else {
                continue;
            };
            let source_path = quarantined_mount_root.join(relative);
            if !source_path.is_file() {
                continue;
            }

            let target_path = recovered_pending_path_for(&live_mount_root.join(relative));
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            match fs::rename(&source_path, &target_path) {
                Ok(()) => {}
                Err(_) => {
                    fs::copy(&source_path, &target_path)?;
                }
            }

            let metadata = fs::metadata(&target_path)?;
            let signature = FileSignature::from_metadata(&metadata);
            self.note_recovered_pending_copy(&target_path, signature);
            created.push(target_path);
        }

        Ok(created)
    }

    pub fn materialize_existing_recovered_pending_copies(
        &mut self,
        quarantined_mount_root: &Path,
        live_mount_root: &Path,
    ) -> Result<Vec<PathBuf>, MountSyncError> {
        if !quarantined_mount_root.exists() {
            return Ok(Vec::new());
        }

        let mut created = Vec::new();
        let mut stack = vec![quarantined_mount_root.to_path_buf()];
        while let Some(current_dir) = stack.pop() {
            let entries = match fs::read_dir(&current_dir) {
                Ok(entries) => entries,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(MountSyncError::Io(err)),
            };
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !file_type.is_file() || !is_recovered_pending_file(&path) {
                    continue;
                }
                if self.is_path_excluded(&path) {
                    continue;
                }

                let Ok(relative) = path.strip_prefix(quarantined_mount_root) else {
                    continue;
                };
                let mut target_path = live_mount_root.join(relative);
                if target_path.exists() {
                    let live_path = derive_live_path_from_recovered_pending_path(&target_path);
                    target_path = recovered_pending_path_for(&live_path);
                }
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                match fs::rename(&path, &target_path) {
                    Ok(()) => {}
                    Err(_) => {
                        fs::copy(&path, &target_path)?;
                    }
                }

                let metadata = fs::metadata(&target_path)?;
                let signature = FileSignature::from_metadata(&metadata);
                self.note_recovered_pending_copy(&target_path, signature);
                created.push(target_path);
            }
        }

        Ok(created)
    }

    pub fn materialize_conflict_copies(
        &mut self,
        quarantined_mount_root: &Path,
        live_mount_root: &Path,
    ) -> Result<Vec<PathBuf>, MountSyncError> {
        if !quarantined_mount_root.exists() {
            return Ok(Vec::new());
        }

        let mut created = Vec::new();
        let mut stack = vec![quarantined_mount_root.to_path_buf()];
        while let Some(current_dir) = stack.pop() {
            let entries = match fs::read_dir(&current_dir) {
                Ok(entries) => entries,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(MountSyncError::Io(err)),
            };
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !file_type.is_file() || !is_conflict_file(&path) {
                    continue;
                }

                let Ok(relative) = path.strip_prefix(quarantined_mount_root) else {
                    continue;
                };
                let mut target_path = live_mount_root.join(relative);
                if target_path.exists() {
                    let live_path = derive_live_path_from_conflict_path(&target_path);
                    target_path = conflict_path_for(&live_path);
                }
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                match fs::rename(&path, &target_path) {
                    Ok(()) => {}
                    Err(_) => {
                        fs::copy(&path, &target_path)?;
                    }
                }

                let metadata = fs::metadata(&target_path)?;
                let signature = FileSignature::from_metadata(&metadata);
                self.decrypted_signatures
                    .insert(target_path.clone(), signature);
                self.refresh_decrypted_metadata_hash(&target_path);
                self.update_conflict_file_tracking(&target_path, signature);
                created.push(target_path);
            }
        }

        Ok(created)
    }

    fn conflict_archive_root(&self) -> Result<PathBuf, MountSyncError> {
        let retention_root = self
            .deletion_config
            .retention_folder
            .as_ref()
            .ok_or_else(|| MountSyncError::Format("Retention folder is not configured".into()))?;
        let archive_root = retention_root.join("conflicts");
        fs::create_dir_all(&archive_root)?;
        Ok(archive_root)
    }

    fn conflict_archive_dir(&self, conflict_id: Uuid) -> Result<PathBuf, MountSyncError> {
        let root = self.conflict_archive_root()?;
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let dir = root.join(format!("{}_{}", timestamp, conflict_id));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn recovery_archive_root(&self) -> Result<PathBuf, MountSyncError> {
        let retention_root = self
            .deletion_config
            .retention_folder
            .as_ref()
            .ok_or_else(|| MountSyncError::Format("Retention folder is not configured".into()))?;
        let archive_root = retention_root.join("recovery_copies");
        fs::create_dir_all(&archive_root)?;
        Ok(archive_root)
    }

    fn recovery_archive_dir(&self, request_id: Uuid) -> Result<PathBuf, MountSyncError> {
        let root = self.recovery_archive_root()?;
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let dir = root.join(format!("{}_{}", timestamp, request_id));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn archive_conflict_source(
        &self,
        source_path: &Path,
        archive_dir: &Path,
        label: &str,
    ) -> Result<PathBuf, MountSyncError> {
        let file_name = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown");
        let archive_name = format!("{}_{}", label, file_name);
        let archive_path = archive_dir.join(archive_name);
        fs::copy(source_path, &archive_path)?;
        if let Some(platform_metadata) = capture_platform_metadata(source_path).as_ref() {
            let _ = apply_platform_metadata(&archive_path, platform_metadata);
        }
        if let Ok(meta) = fs::metadata(source_path) {
            if let Ok(modified) = meta.modified() {
                let ft = FileTime::from_system_time(modified);
                let _ = set_file_times(&archive_path, ft, ft);
            }
        }
        Ok(archive_path)
    }

    fn replace_file_from_source(
        source_path: &Path,
        destination_path: &Path,
    ) -> Result<(), MountSyncError> {
        let parent = destination_path.parent().ok_or_else(|| {
            MountSyncError::Format(format!(
                "Conflict destination {} has no parent directory",
                destination_path.display()
            ))
        })?;
        fs::create_dir_all(parent)?;
        let file_name = destination_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("resolved");
        let tmp_path = parent.join(format!("{}.resolve-{}", file_name, Uuid::new_v4()));
        {
            let mut reader = io::BufReader::new(fs::File::open(source_path)?);
            let mut writer = io::BufWriter::new(fs::File::create(&tmp_path)?);
            io::copy(&mut reader, &mut writer)?;
            writer.flush()?;
            writer
                .into_inner()
                .map_err(|err| {
                    MountSyncError::Io(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "Failed to finalize conflict resolution temp file {}: {}",
                            tmp_path.display(),
                            err
                        ),
                    ))
                })?
                .sync_all()?;
        }

        #[cfg(target_os = "windows")]
        if destination_path.exists() {
            fs::remove_file(destination_path)?;
        }

        if let Err(err) = fs::rename(&tmp_path, destination_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(MountSyncError::Io(err));
        }

        if let Some(platform_metadata) = capture_platform_metadata(source_path).as_ref() {
            let _ = apply_platform_metadata(destination_path, platform_metadata);
        }
        if let Ok(meta) = fs::metadata(source_path) {
            if let Ok(modified) = meta.modified() {
                let ft = FileTime::from_system_time(modified);
                let _ = set_file_times(destination_path, ft, ft);
            }
        }
        Ok(())
    }

    fn write_text_resolution(
        &self,
        destination_path: &Path,
        merged_text: &str,
        metadata_source: Option<&Path>,
    ) -> Result<(), MountSyncError> {
        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Self::write_atomic_bytes(destination_path, merged_text.as_bytes())?;
        if let Some(source_path) = metadata_source {
            if let Some(platform_metadata) = capture_platform_metadata(source_path).as_ref() {
                let _ = apply_platform_metadata(destination_path, platform_metadata);
            }
            if let Ok(meta) = fs::metadata(source_path) {
                if let Ok(modified) = meta.modified() {
                    let ft = FileTime::from_system_time(modified);
                    let _ = set_file_times(destination_path, ft, ft);
                }
            }
        }
        Ok(())
    }

    fn conflict_by_id(&self, conflict_id: Uuid) -> Option<(PathBuf, ConflictBaseline)> {
        self.conflict_baselines.iter().find_map(|(path, baseline)| {
            (baseline.id == conflict_id).then(|| (path.clone(), baseline.clone()))
        })
    }

    fn recovery_copy_by_relative_path(
        &self,
        mount_root: &Path,
        recovery_relative_path: &Path,
    ) -> Option<PathBuf> {
        let recovery_path = mount_root.join(recovery_relative_path);
        (self.recovered_pending_paths.contains(&recovery_path) && recovery_path.exists())
            .then_some(recovery_path)
    }

    pub fn resolve_conflict_action(
        &mut self,
        mount_root: &Path,
        request: &ConflictResolutionRequest,
    ) -> Result<ConflictResolutionResult, MountSyncError> {
        let (conflict_path, baseline) =
            self.conflict_by_id(request.conflict_id).ok_or_else(|| {
                MountSyncError::Format(format!("Conflict {} was not found", request.conflict_id))
            })?;
        let live_path = baseline.live_path.clone();
        let archive_dir = self.conflict_archive_dir(baseline.id)?;
        let mut archive_paths = Vec::new();
        let mut requires_writeback = false;
        let mut resolved_live_path: Option<PathBuf> = None;

        match request.action {
            ConflictResolutionAction::KeepMountedFile => {
                archive_paths.push(self.archive_conflict_source(
                    &conflict_path,
                    &archive_dir,
                    "conflict",
                )?);
                fs::remove_file(&conflict_path)?;
            }
            ConflictResolutionAction::UseConflictCopy => {
                let live_platform_metadata = if live_path.exists() {
                    capture_platform_metadata(&live_path)
                } else {
                    None
                };
                if live_path.exists() {
                    archive_paths.push(self.archive_conflict_source(
                        &live_path,
                        &archive_dir,
                        "live",
                    )?);
                }
                Self::replace_file_from_source(&conflict_path, &live_path)?;
                if let Some(platform_metadata) = live_platform_metadata.as_ref() {
                    let _ = apply_platform_metadata(&live_path, platform_metadata);
                }
                let _ = set_local_only_file_writable(&live_path);
                clear_local_only_conflict_metadata(&live_path)?;
                let _ = set_local_only_file_writable(&live_path);
                fs::remove_file(&conflict_path)?;
                requires_writeback = true;
                resolved_live_path = Some(live_path.clone());
            }
            ConflictResolutionAction::MergeText => {
                let merged_text = request.merged_text.as_deref().ok_or_else(|| {
                    MountSyncError::Format("Merged text is required for merge_text".into())
                })?;
                if !baseline.live_path.exists() {
                    return Err(MountSyncError::Format(
                        "Cannot merge text because the mounted file no longer exists".into(),
                    ));
                }
                archive_paths.push(self.archive_conflict_source(
                    &live_path,
                    &archive_dir,
                    "live",
                )?);
                archive_paths.push(self.archive_conflict_source(
                    &conflict_path,
                    &archive_dir,
                    "conflict",
                )?);
                self.write_text_resolution(&live_path, merged_text, Some(&live_path))?;
                fs::remove_file(&conflict_path)?;
                requires_writeback = true;
                resolved_live_path = Some(live_path.clone());
            }
            ConflictResolutionAction::SaveConflictAsNew => {
                let destination_relative = request.destination_path.as_ref().ok_or_else(|| {
                    MountSyncError::Format(
                        "Destination path is required for save_conflict_as_new".into(),
                    )
                })?;
                let destination_path = mount_root.join(destination_relative);
                if destination_path.exists() {
                    return Err(MountSyncError::Format(format!(
                        "Destination {} already exists",
                        destination_path.display()
                    )));
                }
                Self::replace_file_from_source(&conflict_path, &destination_path)?;
                let _ = set_local_only_file_writable(&destination_path);
                clear_local_only_conflict_metadata(&destination_path)?;
                let _ = set_local_only_file_writable(&destination_path);
                archive_paths.push(self.archive_conflict_source(
                    &conflict_path,
                    &archive_dir,
                    "conflict",
                )?);
                fs::remove_file(&conflict_path)?;
                requires_writeback = true;
                resolved_live_path = Some(destination_path);
            }
            ConflictResolutionAction::ArchiveAndDismiss => {
                if live_path.exists() {
                    return Err(MountSyncError::Format(
                        "archive_and_dismiss is only allowed when the mounted file is absent"
                            .into(),
                    ));
                }
                archive_paths.push(self.archive_conflict_source(
                    &conflict_path,
                    &archive_dir,
                    "conflict",
                )?);
                fs::remove_file(&conflict_path)?;
            }
        }

        self.decrypted_signatures.remove(&conflict_path);
        self.decrypted_hashes.remove(&conflict_path);
        self.decrypted_metadata_hashes.remove(&conflict_path);
        self.pending_stable.remove(&conflict_path);
        self.conflict_baselines.remove(&conflict_path);
        self.conflict_registry_dirty = true;

        Ok(ConflictResolutionResult {
            resolved_conflict_id: baseline.id,
            archive_paths,
            live_path: resolved_live_path,
            requires_writeback,
        })
    }

    pub fn resolve_recovery_copy_action(
        &mut self,
        mount_root: &Path,
        request: &RecoveryCopyResolutionRequest,
    ) -> Result<RecoveryCopyResolutionResult, MountSyncError> {
        let recovery_path = self
            .recovery_copy_by_relative_path(mount_root, &request.recovery_relative_path)
            .ok_or_else(|| {
                MountSyncError::Format(format!(
                    "Recovery copy {} was not found",
                    request.recovery_relative_path.display()
                ))
            })?;
        let live_path = derive_live_path_from_recovered_pending_path(&recovery_path);
        let archive_dir = self.recovery_archive_dir(request.request_id)?;
        let mut archive_paths = Vec::new();
        let mut requires_writeback = false;
        let mut resolved_live_path = None;

        match request.action {
            RecoveryCopyResolutionAction::ReplaceMountedFile => {
                let live_platform_metadata = if live_path.exists() {
                    capture_platform_metadata(&live_path)
                } else {
                    None
                };
                if live_path.exists() {
                    archive_paths.push(self.archive_conflict_source(
                        &live_path,
                        &archive_dir,
                        "live",
                    )?);
                }
                Self::replace_file_from_source(&recovery_path, &live_path)?;
                if let Some(platform_metadata) = live_platform_metadata.as_ref() {
                    let _ = apply_platform_metadata(&live_path, platform_metadata);
                }
                let _ = set_local_only_file_writable(&live_path);
                clear_local_only_recovery_metadata(&live_path)?;
                let _ = set_local_only_file_writable(&live_path);
                archive_paths.push(self.archive_conflict_source(
                    &recovery_path,
                    &archive_dir,
                    "recovery",
                )?);
                fs::remove_file(&recovery_path)?;
                requires_writeback = true;
                resolved_live_path = Some(live_path.clone());
            }
            RecoveryCopyResolutionAction::SaveAsNew => {
                let destination_relative = request.destination_path.as_ref().ok_or_else(|| {
                    MountSyncError::Format("Destination path is required for save_as_new".into())
                })?;
                let destination_path = mount_root.join(destination_relative);
                if destination_path.exists() {
                    return Err(MountSyncError::Format(format!(
                        "Destination {} already exists",
                        destination_path.display()
                    )));
                }
                Self::replace_file_from_source(&recovery_path, &destination_path)?;
                let _ = set_local_only_file_writable(&destination_path);
                clear_local_only_recovery_metadata(&destination_path)?;
                let _ = set_local_only_file_writable(&destination_path);
                archive_paths.push(self.archive_conflict_source(
                    &recovery_path,
                    &archive_dir,
                    "recovery",
                )?);
                fs::remove_file(&recovery_path)?;
                requires_writeback = true;
                resolved_live_path = Some(destination_path);
            }
            RecoveryCopyResolutionAction::ArchiveAndDismiss => {
                archive_paths.push(self.archive_conflict_source(
                    &recovery_path,
                    &archive_dir,
                    "recovery",
                )?);
                fs::remove_file(&recovery_path)?;
            }
        }

        self.decrypted_signatures.remove(&recovery_path);
        self.decrypted_hashes.remove(&recovery_path);
        self.decrypted_metadata_hashes.remove(&recovery_path);
        self.pending_stable.remove(&recovery_path);
        self.recovered_pending_paths.remove(&recovery_path);
        self.recovery_registry_dirty = true;

        Ok(RecoveryCopyResolutionResult {
            resolved_recovery_relative_path: request.recovery_relative_path.clone(),
            archive_paths,
            live_path: resolved_live_path,
            requires_writeback,
        })
    }

    fn open_unlinked_warnings(&self) -> Vec<String> {
        if self.pending_open_unlinked.is_empty() {
            return Vec::new();
        }

        let mut entries = self
            .pending_open_unlinked
            .iter()
            .map(|(path, pending)| (path.display().to_string(), pending))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut warnings = Vec::with_capacity(entries.len().min(4) + 1);
        warnings.push(format!(
            "{} deleted-open path(s) blocking unmount; HybridCipher is preserving the last encrypted version until those handles close",
            entries.len()
        ));

        for (path, pending) in entries.into_iter().take(3) {
            let owners = format_open_unlinked_owners(&pending.owners);
            if owners.is_empty() {
                warnings.push(format!("Deleted-open file still active: {}", path));
            } else {
                warnings.push(format!(
                    "Deleted-open file still active: {} [{}]",
                    path, owners
                ));
            }
        }

        warnings
    }

    fn clear_pending_open_unlinked_entry(&mut self, mount_path: &Path) {
        if self.pending_open_unlinked.remove(mount_path).is_some() {
            self.pending_open_unlinked_dirty = true;
            self.flush_pending_open_unlinked();
        }
    }

    fn record_pending_open_unlinked(
        &mut self,
        mount_path: &Path,
        encrypted_path: Option<PathBuf>,
        encrypted_version_exists: bool,
        had_unsynced_local_writeback: bool,
        owners: Vec<OpenUnlinkedOwner>,
    ) {
        let now = Utc::now();
        let owners = owners
            .into_iter()
            .take(MAX_OPEN_UNLINKED_OWNERS)
            .collect::<Vec<_>>();
        let changed = match self.pending_open_unlinked.get_mut(mount_path) {
            Some(pending) => {
                let previous = pending.clone();
                if encrypted_path.is_some() {
                    pending.encrypted_path = encrypted_path;
                }
                pending.encrypted_version_exists |= encrypted_version_exists;
                pending.had_unsynced_local_writeback |= had_unsynced_local_writeback;
                pending.last_seen_at = now;
                pending.owners = owners;
                previous.encrypted_path != pending.encrypted_path
                    || previous.encrypted_version_exists != pending.encrypted_version_exists
                    || previous.had_unsynced_local_writeback != pending.had_unsynced_local_writeback
                    || previous.owners != pending.owners
            }
            None => {
                self.pending_open_unlinked.insert(
                    mount_path.to_path_buf(),
                    PendingOpenUnlinked {
                        encrypted_path,
                        encrypted_version_exists,
                        had_unsynced_local_writeback,
                        first_seen_at: now,
                        last_seen_at: now,
                        owners,
                    },
                );
                true
            }
        };

        if changed {
            self.pending_open_unlinked_dirty = true;
            self.flush_pending_open_unlinked();
        }
    }

    fn collect_deleted_open_probe_candidates(&self, mount_root: &Path) -> HashSet<PathBuf> {
        let mut candidates = HashSet::new();

        for path in self.decrypted_signatures.keys() {
            if !is_conflict_file(path) && !path.exists() && path.starts_with(mount_root) {
                candidates.insert(path.clone());
            }
        }

        for path in self.pending_writebacks.keys() {
            if !path.exists() && path.starts_with(mount_root) {
                candidates.insert(path.clone());
            }
        }

        for pending in self.pending_deletions.values() {
            if !pending.mount_path.exists() && pending.mount_path.starts_with(mount_root) {
                candidates.insert(pending.mount_path.clone());
            }
        }

        candidates.extend(self.pending_open_unlinked.keys().cloned());
        candidates
    }

    async fn refresh_pending_open_unlinked<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        encrypted_root: &Path,
        mount_root: &Path,
    ) -> Result<(), MountSyncError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = crypto;
            let _ = encrypted_root;
            let _ = mount_root;
            return Ok(());
        }

        let candidates = self.collect_deleted_open_probe_candidates(mount_root);
        if candidates.is_empty() && self.pending_open_unlinked.is_empty() {
            return Ok(());
        }

        let observed = detect_deleted_open_mount_paths(mount_root, &candidates)?;
        self.reconcile_pending_open_unlinked(crypto, encrypted_root, mount_root, observed)
            .await
    }

    async fn reconcile_pending_open_unlinked<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        encrypted_root: &Path,
        mount_root: &Path,
        mut observed: HashMap<PathBuf, Vec<OpenUnlinkedOwner>>,
    ) -> Result<(), MountSyncError> {
        self.last_open_unlinked_warning = None;

        let existing_paths = self
            .pending_open_unlinked
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for mount_path in existing_paths {
            if mount_path.exists() {
                self.clear_pending_open_unlinked_entry(&mount_path);
                continue;
            }

            if let Some(owners) = observed.remove(&mount_path) {
                let mut encrypted_path = self
                    .pending_open_unlinked
                    .get(&mount_path)
                    .and_then(|pending| pending.encrypted_path.clone())
                    .or_else(|| encrypted_path_for(encrypted_root, mount_root, &mount_path).ok());
                let mut encrypted_version_exists = encrypted_path
                    .as_ref()
                    .map(|path| path.exists())
                    .unwrap_or(false);
                let mut had_unsynced_local_writeback = self
                    .pending_open_unlinked
                    .get(&mount_path)
                    .map(|pending| pending.had_unsynced_local_writeback)
                    .unwrap_or(false);

                if self.pending_writebacks.remove(&mount_path).is_some() {
                    self.pending_writebacks_dirty = true;
                    had_unsynced_local_writeback = true;
                }

                if let Some(path) = encrypted_path.as_ref() {
                    if self.pending_deletions.remove(path).is_some() {
                        self.pending_deletions_dirty = true;
                    }
                    encrypted_version_exists |= path.exists();
                }

                self.record_pending_open_unlinked(
                    &mount_path,
                    encrypted_path.take(),
                    encrypted_version_exists,
                    had_unsynced_local_writeback,
                    owners,
                );
                continue;
            }

            let Some(pending) = self.pending_open_unlinked.get(&mount_path).cloned() else {
                continue;
            };

            if pending.encrypted_version_exists {
                let Some(encrypted_path) = pending.encrypted_path.clone() else {
                    self.last_open_unlinked_warning = Some(format!(
                        "Deleted-open file {} closed after unlink, but HybridCipher no longer knows which encrypted file to recover",
                        mount_path.display()
                    ));
                    self.clear_pending_open_unlinked_entry(&mount_path);
                    continue;
                };

                if !encrypted_path.exists() {
                    self.last_open_unlinked_warning = Some(format!(
                        "Deleted-open file {} closed after unlink, but the preserved encrypted version is no longer present at {}",
                        mount_path.display(),
                        encrypted_path.display()
                    ));
                    self.clear_pending_open_unlinked_entry(&mount_path);
                    continue;
                }

                match self
                    .recover_deleted_open_conflict(crypto, &encrypted_path, &mount_path)
                    .await
                {
                    Ok(conflict_path) => {
                        self.last_open_unlinked_warning = Some(
                            if pending.had_unsynced_local_writeback {
                                format!(
                                "Recovered the last encrypted version of deleted-open file {} to {}. Later unlinked local writes from the other process were not recoverable.",
                                mount_path.display(),
                                conflict_path.display()
                            )
                            } else {
                                format!(
                                "Recovered the last encrypted version of deleted-open file {} to {} after the foreign handle closed.",
                                mount_path.display(),
                                conflict_path.display()
                            )
                            },
                        );
                        self.clear_pending_open_unlinked_entry(&mount_path);
                    }
                    Err(err) if is_low_space_error(&err) => {
                        self.last_open_unlinked_warning = Some(format!(
                            "Deleted-open recovery for {} is waiting for space before HybridCipher can materialize a conflict copy of the preserved encrypted version",
                            mount_path.display()
                        ));
                    }
                    Err(err) => return Err(err),
                }
            } else {
                self.last_open_unlinked_warning = Some(format!(
                    "Deleted-open file {} closed after unlink, but HybridCipher could not recover it because no encrypted version had been committed yet",
                    mount_path.display()
                ));
                self.clear_pending_open_unlinked_entry(&mount_path);
            }
        }

        for (mount_path, owners) in observed {
            if mount_path.exists() {
                continue;
            }

            let encrypted_path = encrypted_path_for(encrypted_root, mount_root, &mount_path).ok();
            let encrypted_version_exists = encrypted_path
                .as_ref()
                .map(|path| path.exists())
                .unwrap_or(false);
            let had_unsynced_local_writeback =
                self.pending_writebacks.remove(&mount_path).is_some();
            if had_unsynced_local_writeback {
                self.pending_writebacks_dirty = true;
            }
            if let Some(path) = encrypted_path.as_ref() {
                if self.pending_deletions.remove(path).is_some() {
                    self.pending_deletions_dirty = true;
                }
            }
            self.record_pending_open_unlinked(
                &mount_path,
                encrypted_path,
                encrypted_version_exists,
                had_unsynced_local_writeback,
                owners,
            );
        }

        Ok(())
    }

    async fn recover_deleted_open_conflict<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        encrypted_path: &Path,
        mount_path: &Path,
    ) -> Result<PathBuf, MountSyncError> {
        let parsed = parse_encrypted_file(encrypted_path)?;
        let conflict_path = conflict_path_for(mount_path);

        if self.mount_readonly_active {
            return Err(low_space_readonly_error(&conflict_path));
        }

        let plaintext_budget = parsed
            .metadata
            .content_size
            .saturating_add(LOW_SPACE_ATOMIC_WRITE_OVERHEAD_BYTES);
        self.ensure_space_budget(
            &conflict_path,
            plaintext_budget,
            LOW_SPACE_WARNING_RESERVE_BYTES,
            "deleted-open conflict recovery",
        )?;

        if let Some(parent) = conflict_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if parsed.metadata.content_chunk_size.is_some() {
            crypto
                .decrypt_file_streaming(encrypted_path, &conflict_path, &parsed.metadata)
                .await?;
        } else {
            let decrypted = crypto
                .decrypt_file(encrypted_path, &parsed.metadata)
                .await?;
            Self::write_atomic_bytes(&conflict_path, &decrypted)?;
        }

        if let Some(platform_metadata) = parsed.metadata.platform_metadata.as_ref() {
            if let Err(err) = apply_platform_metadata(&conflict_path, platform_metadata) {
                debug!(
                    "Failed to restore platform metadata for deleted-open recovery {}: {}",
                    conflict_path.display(),
                    err
                );
            }
        }

        if let Ok(enc_meta) = encrypted_path.metadata() {
            if let Ok(modified) = enc_meta.modified() {
                let ft = FileTime::from_system_time(modified);
                let _ = set_file_times(&conflict_path, ft, ft);
            }
        }

        if let Ok(meta) = fs::metadata(&conflict_path) {
            let signature = FileSignature::from_metadata(&meta);
            self.decrypted_signatures
                .insert(conflict_path.clone(), signature);
            self.refresh_decrypted_metadata_hash(&conflict_path);
            self.update_conflict_file_tracking_with_kind(
                &conflict_path,
                signature,
                Some(ConflictKind::DeletedOpenRecovery),
            );
        }
        self.decrypted_hashes.remove(&conflict_path);
        self.pending_stable.remove(&conflict_path);

        Ok(conflict_path)
    }

    fn refresh_decrypted_metadata_hash(&mut self, path: &Path) {
        let hash = capture_platform_metadata_hash(path);
        if let Some(hash) = hash {
            self.decrypted_metadata_hashes
                .insert(path.to_path_buf(), hash);
        } else {
            self.decrypted_metadata_hashes.remove(path);
        }
    }

    fn refresh_decrypted_directory_metadata_hash(&mut self, path: &Path) {
        let hash = capture_platform_metadata_hash(path);
        if let Some(hash) = hash {
            self.decrypted_directory_metadata_hashes
                .insert(path.to_path_buf(), hash);
        } else {
            self.decrypted_directory_metadata_hashes.remove(path);
        }
    }

    fn clear_decrypted_tracking(&mut self, path: &Path) {
        self.decrypted_signatures.remove(path);
        self.decrypted_hashes.remove(path);
        self.decrypted_metadata_hashes.remove(path);
        if self.conflict_baselines.remove(path).is_some() {
            self.conflict_registry_dirty = true;
        }
        if self.recovered_pending_paths.remove(path) {
            self.recovery_registry_dirty = true;
        }
    }

    fn clear_decrypted_directory_tracking(&mut self, path: &Path) {
        self.decrypted_directory_signatures.remove(path);
        self.decrypted_directory_metadata_hashes.remove(path);
    }

    fn is_local_mount_directory_dirty(&self, path: &Path) -> bool {
        let current_hash = capture_platform_metadata_hash(path);
        match (
            self.decrypted_directory_metadata_hashes.get(path),
            current_hash.as_ref(),
        ) {
            (None, None) => false,
            (Some(previous), Some(current)) => previous != current,
            _ => true,
        }
    }

    fn should_sync_directory_metadata(
        &self,
        encrypted_root: &Path,
        mount_root: &Path,
        directory_path: &Path,
    ) -> bool {
        if directory_path == mount_root {
            return false;
        }

        if self.is_path_excluded(directory_path) {
            return false;
        }

        let Ok(relative) = directory_path.strip_prefix(mount_root) else {
            return false;
        };

        let self_name_is_package = directory_path
            .file_name()
            .and_then(|value| value.to_str())
            .map(is_transactional_package_name)
            .unwrap_or(false);
        let package_ancestor = transactional_package_ancestor(relative).is_some();

        if self_name_is_package || package_ancestor {
            return directory_has_existing_encrypted_state(
                encrypted_root,
                mount_root,
                directory_path,
            );
        }

        true
    }

    fn build_metadata_record(
        file_path: String,
        file_id: String,
        group_id: Option<Uuid>,
        epoch_id: u64,
        header_version: Option<u32>,
        wrapped_file_key: Option<Vec<u8>>,
        key_wrap_nonce: Option<Vec<u8>>,
        key_wrap_aad_hash: Option<Vec<u8>>,
        content_nonce: Option<Vec<u8>>,
        content_chunk_size: Option<u64>,
        file_size: u64,
        integrity_hash: [u8; 32],
        encrypted_size: u64,
    ) -> FileMetadataData {
        FileMetadataData {
            file_path,
            file_id: Some(file_id),
            group_id,
            epoch_id,
            header_version,
            wrapped_file_key,
            key_wrap_nonce,
            key_wrap_aad_hash,
            content_nonce,
            content_chunk_size,
            algorithm: "chacha20poly1305".to_string(),
            file_size,
            modified_at: Utc::now(),
            integrity_hash,
            permissions: AccessControlData {
                readers: Vec::new(),
                writers: Vec::new(),
                is_public: false,
            },
            version: 1,
            chunks: Vec::new(),
            encrypted_size,
            encrypted_at: Utc::now(),
        }
    }

    /// Seed the tracker with a previously-known decrypted file so the next
    /// sync can skip redundant decrypt work.
    pub fn seed_file(
        &mut self,
        encrypted_path: PathBuf,
        decrypted_path: PathBuf,
        encrypted_signature: FileSignature,
        decrypted_signature: FileSignature,
    ) {
        self.encrypted_signatures
            .insert(encrypted_path.clone(), encrypted_signature);
        self.decrypted_signatures
            .insert(decrypted_path.clone(), decrypted_signature);
        self.path_mapping.insert(encrypted_path, decrypted_path);
    }

    /// Seed signatures for existing mount files so we don't treat them as dirty on first sync.
    pub fn seed_mountpoint_signatures(&mut self, mount_root: &Path) -> Result<(), MountSyncError> {
        if !mount_root.exists() {
            return Ok(());
        }

        let mut stack = vec![mount_root.to_path_buf()];
        while let Some(current) = stack.pop() {
            let entries = fs::read_dir(&current)?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;

                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    if self.is_path_excluded(&path) {
                        continue;
                    }
                    let metadata = entry.metadata()?;
                    let signature = FileSignature::from_metadata(&metadata);
                    self.decrypted_directory_signatures
                        .insert(path.clone(), signature);
                    self.refresh_decrypted_directory_metadata_hash(&path);
                    stack.push(path);
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }

                if self.is_path_excluded(&path) {
                    continue;
                }

                let metadata = entry.metadata()?;
                let signature = FileSignature::from_metadata(&metadata);
                self.decrypted_signatures.insert(path.clone(), signature);
                self.refresh_decrypted_metadata_hash(&path);
                if is_conflict_file(&path) {
                    self.update_conflict_file_tracking(&path, signature);
                } else if is_recovered_pending_file(&path) {
                    self.note_recovered_pending_copy(&path, signature);
                }

                if let Some(file_id) = read_file_id_xattr(&path) {
                    self.file_id_to_mount_path.insert(file_id, path);
                }
            }
        }

        Ok(())
    }

    async fn retry_pending_writebacks_before_scan<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        encrypted_root: &Path,
        mount_root: &Path,
    ) -> Result<(), MountSyncError> {
        if self.pending_writebacks.is_empty() {
            return Ok(());
        }

        let mut pending = self
            .pending_writebacks
            .iter()
            .map(|(mount_path, entry)| {
                (
                    mount_path.clone(),
                    entry.encrypted_path.clone(),
                    entry.last_observed_at,
                )
            })
            .collect::<Vec<_>>();
        pending.sort_by(|left, right| right.2.cmp(&left.2));

        for (mount_path, encrypted_path, _) in pending {
            let Some(existing) = self.pending_writebacks.get(&mount_path).cloned() else {
                continue;
            };
            if self.is_path_excluded(&mount_path) {
                info!(
                    "Clearing excluded pending writeback for {}",
                    mount_path.display()
                );
                self.pending_stable.remove(&mount_path);
                self.clear_pending_writeback(&mount_path);
                continue;
            }
            if !should_fast_drain_pending_writeback(&existing) {
                continue;
            }
            if !mount_path.exists() {
                if encrypted_path.exists() {
                    info!(
                        "Clearing stale pending writeback for {} because the decrypted source is gone and the encrypted file exists",
                        mount_path.display()
                    );
                    self.clear_pending_writeback(&mount_path);
                }
                continue;
            }

            let metadata = match fs::metadata(&mount_path) {
                Ok(metadata) => metadata,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(MountSyncError::Io(err)),
            };
            if !metadata.is_file()
                || is_conflict_file(&mount_path)
                || is_recovered_pending_file(&mount_path)
            {
                continue;
            }

            let signature = FileSignature::from_metadata(&metadata);
            let stable_entry = self.pending_stable.get(&mount_path).copied();
            let stable_ready = match stable_entry {
                Some(entry) if entry.signature == signature => {
                    if self.should_stream_file(metadata.len()) && self.stream_stability_age_secs > 0
                    {
                        entry.first_seen.elapsed()
                            >= Duration::from_secs(self.stream_stability_age_secs)
                    } else {
                        true
                    }
                }
                _ => false,
            };

            if !stable_ready {
                self.pending_stable
                    .entry(mount_path.clone())
                    .and_modify(|entry| {
                        if entry.signature != signature {
                            *entry = StableEntry {
                                signature,
                                first_seen: Instant::now(),
                            };
                        }
                    })
                    .or_insert(StableEntry {
                        signature,
                        first_seen: Instant::now(),
                    });
                continue;
            }

            self.pending_stable.remove(&mount_path);
            if self.mount_readonly_active {
                let err = low_space_readonly_error(&mount_path);
                self.record_pending_writeback(&mount_path, &encrypted_path, Some(&err));
                self.pending_stable.insert(
                    mount_path.clone(),
                    StableEntry {
                        signature,
                        first_seen: Instant::now(),
                    },
                );
                continue;
            }

            match self
                .encrypt_decrypted_file(
                    crypto,
                    mount_root,
                    encrypted_root,
                    &mount_path,
                    &encrypted_path,
                )
                .await
            {
                Ok((encrypted_signature, file_id)) => {
                    self.encrypted_signatures
                        .insert(encrypted_path.clone(), encrypted_signature);
                    self.decrypted_signatures
                        .insert(mount_path.clone(), signature);
                    self.refresh_decrypted_metadata_hash(&mount_path);
                    self.clear_pending_writeback(&mount_path);
                    self.file_id_to_mount_path.insert(file_id, mount_path);
                }
                Err(MountSyncError::UnstableFile(reason)) => {
                    self.record_pending_writeback(
                        &mount_path,
                        &encrypted_path,
                        Some(&MountSyncError::UnstableFile(reason.clone())),
                    );
                    self.pending_stable.insert(
                        mount_path.clone(),
                        StableEntry {
                            signature,
                            first_seen: Instant::now(),
                        },
                    );
                }
                Err(err) if is_low_space_error(&err) => {
                    self.record_pending_writeback(&mount_path, &encrypted_path, Some(&err));
                    self.pending_stable.insert(
                        mount_path.clone(),
                        StableEntry {
                            signature,
                            first_seen: Instant::now(),
                        },
                    );
                }
                Err(err) => {
                    self.record_pending_writeback(&mount_path, &encrypted_path, Some(&err));
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    pub async fn sync<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        encrypted_root: &Path,
        mount_root: &Path,
    ) -> Result<(), MountSyncError> {
        if !mount_root.exists() {
            self.decrypted_signatures.clear();
            self.decrypted_directory_signatures.clear();
            self.decrypted_hashes.clear();
            self.decrypted_metadata_hashes.clear();
            self.decrypted_directory_metadata_hashes.clear();
            self.encrypted_signatures.clear();
            self.encrypted_directory_signatures.clear();
            self.file_id_to_mount_path.clear();
            self.pending_orphans.clear();
            self.pending_writebacks.clear();
            self.pending_refreshes.clear();
            self.pending_open_unlinked.clear();
            self.unsupported_transactional_paths.clear();
            self.unsupported_hard_link_paths.clear();
            self.mount_collision_keys.clear();
            self.pending_temp.clear();
            self.pending_sparse.clear();
            self.conflict_baselines.clear();
            self.recovered_pending_paths.clear();
            self.last_open_unlinked_warning = None;
            self.mount_readonly_active = false;
            self.mount_readonly_restore_modes.clear();
            self.hard_link_block_restore_modes.clear();
            self.pending_orphans_dirty = true;
            self.pending_writebacks_dirty = true;
            self.pending_refreshes_dirty = true;
            self.pending_open_unlinked_dirty = true;
            self.conflict_registry_dirty = true;
            self.recovery_registry_dirty = true;
            self.flush_pending_deletions();
            self.flush_pending_orphans();
            self.flush_pending_writebacks();
            self.flush_pending_refreshes();
            self.flush_pending_open_unlinked();
            self.flush_pending_metadata();
            self.flush_conflict_registry(mount_root);
            self.flush_recovery_registry(mount_root);
            return Ok(());
        }

        // Health check: verify mount is accessible and healthy
        self.scan_health = self.check_mount_health(mount_root)?;
        self.refresh_space_warnings(encrypted_root, mount_root);
        self.enforce_low_space_mount_mode(mount_root)?;
        self.rebuild_mount_collision_index(mount_root);
        self.retry_pending_metadata(crypto).await;
        self.refresh_pending_open_unlinked(crypto, encrypted_root, mount_root)
            .await?;
        self.retry_pending_writebacks_before_scan(crypto, encrypted_root, mount_root)
            .await?;

        let mut expected: HashSet<PathBuf> = HashSet::new();
        let mut expected_directories: HashSet<PathBuf> = HashSet::new();
        let mut protected_missing_paths: HashSet<PathBuf> = HashSet::new();
        let mut stack = vec![encrypted_root.to_path_buf()];

        while let Some(current) = stack.pop() {
            let entries = fs::read_dir(&current)?;

            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let metadata = entry.metadata()?;

                if metadata.is_dir() {
                    if path.file_name().and_then(|n| n.to_str()) == Some(ENCRYPTED_TMP_DIR_NAME) {
                        cleanup_encrypted_tmp_dir(&path);
                        continue;
                    }
                    stack.push(path);
                    continue;
                }

                if path.extension().and_then(|e| e.to_str()) != Some("encrypted") {
                    continue;
                }

                let signature = FileSignature::from_metadata(&metadata);
                if is_directory_metadata_file(&path) {
                    match self
                        .decrypt_directory_metadata(
                            crypto,
                            encrypted_root,
                            mount_root,
                            &path,
                            signature,
                        )
                        .await?
                    {
                        DecryptOutcome::Ready(directory_path) => {
                            expected.insert(directory_path.clone());
                            expected_directories.insert(directory_path);
                        }
                        DecryptOutcome::DeferredLowSpace(directory_path) => {
                            expected.insert(directory_path.clone());
                            expected_directories.insert(directory_path.clone());
                            protected_missing_paths.insert(directory_path);
                        }
                    }
                    continue;
                }
                match self
                    .decrypt_file(crypto, encrypted_root, mount_root, &path, signature)
                    .await?
                {
                    DecryptOutcome::Ready(decrypted_path) => {
                        expected.insert(decrypted_path);
                    }
                    DecryptOutcome::DeferredLowSpace(decrypted_path) => {
                        expected.insert(decrypted_path.clone());
                        protected_missing_paths.insert(decrypted_path);
                    }
                }
            }
        }

        let pending_refresh_count = self.pending_refreshes.len();
        self.pending_refreshes
            .retain(|path, _| expected.contains(path));
        if self.pending_refreshes.len() != pending_refresh_count {
            self.pending_refreshes_dirty = true;
        }

        self.track_missing_encrypted_directories(
            encrypted_root,
            mount_root,
            &expected_directories,
            &protected_missing_paths,
        )?;
        self.track_missing_encrypted_files(encrypted_root, mount_root, &expected)?;
        self.sync_decrypted_changes(
            crypto,
            encrypted_root,
            mount_root,
            &mut expected,
            &protected_missing_paths,
        )
        .await?;

        // Process pending deletions if mount is healthy
        if self.mount_readonly_active {
            debug!(
                "Skipping deletion/orphan processing for {} while low-space read-only mode is active",
                mount_root.display()
            );
        } else if self.suppress_deletion_processing {
            debug!(
                "Skipping deletion/orphan processing for {} during startup rehydrate mode",
                mount_root.display()
            );
        } else if matches!(self.scan_health, ScanHealth::Healthy) {
            self.process_pending_deletions(encrypted_root, mount_root)
                .await?;
            self.process_pending_orphans(mount_root)?;
        } else {
            // Reset consecutive counts if unhealthy (recount requirement)
            self.reset_pending_deletion_counts();
            self.reset_pending_orphan_counts();
        }

        self.refresh_space_warnings(encrypted_root, mount_root);
        self.enforce_low_space_mount_mode(mount_root)?;

        self.flush_pending_deletions();
        self.flush_pending_orphans();
        self.flush_pending_writebacks();
        self.flush_pending_refreshes();
        self.flush_pending_open_unlinked();
        self.flush_pending_metadata();
        self.flush_conflict_registry(mount_root);
        self.flush_recovery_registry(mount_root);

        Ok(())
    }

    /// Check if mount directory is healthy (accessible, no IO errors)
    fn check_mount_health(&self, mount_root: &Path) -> Result<ScanHealth, MountSyncError> {
        // Check root accessibility
        match fs::metadata(mount_root) {
            Ok(_) => {}
            Err(e) => {
                return Ok(ScanHealth::Unhealthy {
                    reason: format!("Mount root not accessible: {}", e),
                });
            }
        }

        // Perform a lightweight directory walk to check for IO errors
        let mut stack = vec![mount_root.to_path_buf()];
        let mut checked_count = 0;
        const MAX_HEALTH_CHECK_ENTRIES: usize = 100; // Limit health check depth

        while let Some(current) = stack.pop() {
            if checked_count >= MAX_HEALTH_CHECK_ENTRIES {
                break; // Health check passed, mount is accessible
            }

            match fs::read_dir(&current) {
                Ok(entries) => {
                    for entry in entries {
                        checked_count += 1;
                        if checked_count >= MAX_HEALTH_CHECK_ENTRIES {
                            break;
                        }

                        match entry {
                            Ok(e) => {
                                if let Ok(meta) = e.metadata() {
                                    if meta.is_dir() {
                                        stack.push(e.path());
                                    }
                                }
                            }
                            Err(e) => {
                                return Ok(ScanHealth::Unhealthy {
                                    reason: format!("IO error during health check: {}", e),
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    return Ok(ScanHealth::Unhealthy {
                        reason: format!("Cannot read directory {}: {}", current.display(), e),
                    });
                }
            }
        }

        Ok(ScanHealth::Healthy)
    }

    /// Reset consecutive missing scan counts when health becomes unhealthy (recount requirement)
    fn reset_pending_deletion_counts(&mut self) {
        if self.pending_deletions.is_empty() {
            return;
        }

        for pending in self.pending_deletions.values_mut() {
            pending.consecutive_missing_scans = 0;
        }
        self.pending_deletions_dirty = true;
    }

    fn reset_pending_orphan_counts(&mut self) {
        if self.pending_orphans.is_empty() {
            return;
        }

        for pending in self.pending_orphans.values_mut() {
            pending.consecutive_missing_scans = 0;
        }
        self.pending_orphans_dirty = true;
    }

    pub(crate) fn is_local_mount_path_dirty_with_signature(
        &mut self,
        path: &Path,
        current_sig: FileSignature,
    ) -> bool {
        let stored = match self.decrypted_signatures.get(path).copied() {
            Some(stored) => stored,
            None => return true,
        };

        if stored == current_sig {
            return false;
        }

        if stored.ctime_only_change(&current_sig) {
            let mut matched = false;
            let mut updated_hash: Option<[u8; 32]> = None;
            let current_metadata_hash = capture_platform_metadata_hash(path);
            let metadata_matches = match (
                self.decrypted_metadata_hashes.get(path),
                current_metadata_hash.as_ref(),
            ) {
                (None, None) => true,
                (Some(previous), Some(current)) => previous == current,
                _ => false,
            };

            if let Some(prev_hash) = self.decrypted_hashes.get(path) {
                if let Ok(current_hash) = hash_file(path) {
                    matched = &current_hash == prev_hash;
                    updated_hash = Some(current_hash);
                }
            } else if let Ok(current_hash) = hash_file(path) {
                matched = true;
                updated_hash = Some(current_hash);
            }

            if let Some(hash) = updated_hash {
                self.decrypted_hashes.insert(path.to_path_buf(), hash);
            }
            if let Some(hash) = current_metadata_hash {
                self.decrypted_metadata_hashes
                    .insert(path.to_path_buf(), hash);
            } else {
                self.decrypted_metadata_hashes.remove(path);
            }

            return !(matched && metadata_matches);
        }

        true
    }

    /// Process pending deletions: run rapid verification scans and move to retention if criteria met
    async fn process_pending_deletions(
        &mut self,
        encrypted_root: &Path,
        mount_root: &Path,
    ) -> Result<(), MountSyncError> {
        // First, clean up old files from retention folder
        self.cleanup_retention_folder()?;

        if self.pending_deletions.is_empty() {
            return Ok(());
        }

        // Run rapid verification scans for files that need more verification
        let mut to_verify: Vec<PathBuf> = self
            .pending_deletions
            .iter()
            .filter(|(_, pending)| {
                pending.consecutive_missing_scans
                    < self.deletion_config.min_consecutive_missing_scans
            })
            .map(|(encrypted_path, _)| encrypted_path.clone())
            .collect();

        if !to_verify.is_empty() {
            self.run_rapid_verification_scans(mount_root, &mut to_verify)
                .await?;
        }

        // Process deletions that have met criteria
        let mut to_delete: Vec<PathBuf> = Vec::new();
        let mut to_remove: Vec<PathBuf> = Vec::new();
        let mut changed = false;

        for (encrypted_path, pending) in &self.pending_deletions {
            if !encrypted_path.starts_with(encrypted_root)
                || !pending.mount_path.starts_with(mount_root)
            {
                debug!(
                    "Skipping pending deletion outside current mount scope: encrypted={} mount={}",
                    encrypted_path.display(),
                    pending.mount_path.display()
                );
                continue;
            }
            if self.pending_open_unlinked.contains_key(&pending.mount_path) {
                warn!(
                    "Deferring deletion for {} because deleted-open path {} is still active",
                    encrypted_path.display(),
                    pending.mount_path.display()
                );
                continue;
            }
            if self.pending_metadata.contains_key(encrypted_path) {
                warn!(
                    "Deferring deletion for {} until coverage metadata is stored",
                    encrypted_path.display()
                );
                continue;
            }
            // Check if mount file reappeared (user restored the file)
            if pending.mount_path.exists() {
                debug!(
                    "Mount file {} reappeared, canceling pending deletion of {}",
                    pending.mount_path.display(),
                    encrypted_path.display()
                );
                to_remove.push(encrypted_path.clone());
                continue;
            }

            // Check if deletion criteria met: required scans + healthy scan occurred
            if pending.consecutive_missing_scans
                >= self.deletion_config.min_consecutive_missing_scans
                && pending.had_healthy_scan
            {
                to_delete.push(encrypted_path.clone());
                to_remove.push(encrypted_path.clone());
            }
        }

        // Remove recovered files from pending
        for encrypted_path in &to_remove {
            if !to_delete.contains(encrypted_path) {
                self.pending_deletions.remove(encrypted_path);
                changed = true;
            }
        }

        // Move encrypted files to retention folder (or delete if no retention configured)
        for encrypted_path in &to_delete {
            let scan_count = self
                .pending_deletions
                .get(encrypted_path)
                .map(|p| p.consecutive_missing_scans)
                .unwrap_or(0);

            if encrypted_path.exists() {
                if let Some(ref retention_folder) = self.deletion_config.retention_folder {
                    // Move to retention folder
                    match self.move_to_retention(encrypted_path, retention_folder) {
                        Ok(()) => {
                            info!(
                                "Moved encrypted file {} to retention folder after {} consecutive missing scans",
                                encrypted_path.display(),
                                scan_count
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to move {} to retention folder {}: {}. File will be deleted immediately.",
                                encrypted_path.display(),
                                retention_folder.display(),
                                e
                            );
                            // Fallback to immediate deletion if retention move fails
                            if let Err(delete_err) = fs::remove_file(encrypted_path) {
                                if delete_err.kind() != io::ErrorKind::NotFound {
                                    warn!(
                                        "Failed to remove encrypted file {}: {}",
                                        encrypted_path.display(),
                                        delete_err
                                    );
                                }
                            }
                        }
                    }
                } else {
                    // No retention folder - delete immediately (legacy behavior)
                    warn!(
                        "Retention folder not configured - deleting encrypted file {} immediately after {} consecutive missing scans",
                        encrypted_path.display(),
                        scan_count
                    );
                    if let Err(e) = fs::remove_file(encrypted_path) {
                        if e.kind() != io::ErrorKind::NotFound {
                            warn!(
                                "Failed to remove encrypted file {}: {}",
                                encrypted_path.display(),
                                e
                            );
                        }
                    } else {
                        info!(
                            "Deleted encrypted file {} after {} consecutive missing scans (no retention folder)",
                            encrypted_path.display(),
                            scan_count
                        );
                    }
                }
            }

            // Find mount path for cleanup
            let mount_paths_to_clean: Vec<PathBuf> = self
                .path_mapping
                .iter()
                .filter(|(enc, _)| *enc == encrypted_path)
                .map(|(_, dec)| dec.clone())
                .collect();

            // Clean up tracking
            for mount_path in &mount_paths_to_clean {
                self.clear_decrypted_tracking(mount_path);
                self.path_mapping.retain(|_enc, dec| dec != mount_path);
                self.file_id_to_mount_path
                    .retain(|_file_id, mp| mp != mount_path);
            }
            self.encrypted_signatures.remove(encrypted_path);
            self.pending_deletions.remove(encrypted_path);
            changed = true;
        }

        if changed {
            self.pending_deletions_dirty = true;
        }

        Ok(())
    }

    fn process_pending_orphans(&mut self, mount_root: &Path) -> Result<(), MountSyncError> {
        if self.pending_orphans.is_empty() {
            return Ok(());
        }

        let mut to_remove: Vec<PathBuf> = Vec::new();
        let mut to_retain: Vec<PathBuf> = Vec::new();
        let pending_entries: Vec<(PathBuf, PendingOrphan)> = self
            .pending_orphans
            .iter()
            .map(|(mount_path, pending)| (mount_path.clone(), pending.clone()))
            .collect();

        for (mount_path, pending) in pending_entries {
            if !mount_path.starts_with(mount_root) {
                debug!(
                    "Skipping pending orphan outside current mount scope: {}",
                    mount_path.display()
                );
                continue;
            }
            if pending.encrypted_path.exists() {
                debug!(
                    "Encrypted file {} reappeared, canceling pending orphan state for {}",
                    pending.encrypted_path.display(),
                    mount_path.display()
                );
                to_remove.push(mount_path);
                continue;
            }

            if !mount_path.exists() {
                debug!(
                    "Mount file {} disappeared while pending orphan verification; cleaning up tracking",
                    mount_path.display()
                );
                to_remove.push(mount_path);
                continue;
            }

            let current_sig = match fs::metadata(&mount_path) {
                Ok(meta) => FileSignature::from_metadata(&meta),
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    to_remove.push(mount_path);
                    continue;
                }
                Err(err) => {
                    warn!(
                        "Failed to stat pending orphan {}: {}",
                        mount_path.display(),
                        err
                    );
                    continue;
                }
            };

            if self.is_local_mount_path_dirty_with_signature(&mount_path, current_sig) {
                debug!(
                    "Canceling pending orphan state for {} because local plaintext changed",
                    mount_path.display()
                );
                to_remove.push(mount_path);
                continue;
            }

            if pending.consecutive_missing_scans
                >= self.deletion_config.min_consecutive_missing_scans
                && pending.had_healthy_scan
            {
                to_retain.push(mount_path);
            }
        }

        for mount_path in &to_retain {
            let Some(pending) = self.pending_orphans.get(mount_path).cloned() else {
                continue;
            };

            if let Some(ref retention_folder) = self.deletion_config.retention_folder {
                match self.move_mount_file_to_retention(mount_path, retention_folder) {
                    Ok(retention_path) => {
                        info!(
                            "Moved orphaned plaintext {} to retention at {} after {} consecutive missing scans",
                            mount_path.display(),
                            retention_path.display(),
                            pending.consecutive_missing_scans
                        );
                    }
                    Err(err) => {
                        warn!(
                            "Failed to move orphaned plaintext {} to retention: {}. Removing file.",
                            mount_path.display(),
                            err
                        );
                        if let Err(remove_err) = fs::remove_file(mount_path) {
                            if remove_err.kind() != io::ErrorKind::NotFound {
                                warn!(
                                    "Failed to remove orphaned plaintext {}: {}",
                                    mount_path.display(),
                                    remove_err
                                );
                                continue;
                            }
                        }
                    }
                }
            } else if let Err(remove_err) = fs::remove_file(mount_path) {
                if remove_err.kind() != io::ErrorKind::NotFound {
                    warn!(
                        "Failed to remove orphaned plaintext {}: {}",
                        mount_path.display(),
                        remove_err
                    );
                    continue;
                }
            }

            self.clear_decrypted_tracking(mount_path);
            self.file_id_to_mount_path
                .retain(|_file_id, path| path != mount_path);
            self.path_mapping
                .retain(|enc, dec| dec != mount_path && enc != &pending.encrypted_path);
            self.encrypted_signatures.remove(&pending.encrypted_path);
            to_remove.push(mount_path.clone());
        }

        if !to_remove.is_empty() {
            let mut removed_any = false;
            for mount_path in to_remove {
                removed_any |= self.pending_orphans.remove(&mount_path).is_some();
            }
            if removed_any {
                self.pending_orphans_dirty = true;
            }
        }

        Ok(())
    }

    /// Move a file to the retention folder with timestamp prefix
    fn move_to_retention(
        &self,
        encrypted_path: &Path,
        retention_folder: &Path,
    ) -> Result<(), MountSyncError> {
        // Create retention folder if needed
        fs::create_dir_all(retention_folder)?;

        // Generate unique name with timestamp
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let file_name = encrypted_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let retention_name = format!("{}_{}", timestamp, file_name);
        let retention_path = retention_folder.join(&retention_name);
        let retention_meta_path = retention_folder.join(format!("{}.meta.json", retention_name));

        // Move file to retention folder
        match fs::rename(encrypted_path, &retention_path) {
            Ok(_) => {
                debug!(
                    "Moved {} to retention: {}",
                    encrypted_path.display(),
                    retention_path.display()
                );
                let metadata = RetentionMetadata {
                    deleted_at: Utc::now(),
                };
                if let Ok(data) = serde_json::to_vec_pretty(&metadata) {
                    if let Err(err) = Self::write_atomic_bytes(&retention_meta_path, &data) {
                        warn!(
                            "Failed to write retention metadata {}: {}",
                            retention_meta_path.display(),
                            err
                        );
                    }
                }
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
                // Cross-device move - copy then delete
                fs::copy(encrypted_path, &retention_path)?;
                fs::remove_file(encrypted_path)?;
                debug!(
                    "Copied {} to retention (cross-device): {}",
                    encrypted_path.display(),
                    retention_path.display()
                );
                let metadata = RetentionMetadata {
                    deleted_at: Utc::now(),
                };
                if let Ok(data) = serde_json::to_vec_pretty(&metadata) {
                    if let Err(err) = Self::write_atomic_bytes(&retention_meta_path, &data) {
                        warn!(
                            "Failed to write retention metadata {}: {}",
                            retention_meta_path.display(),
                            err
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(MountSyncError::Io(e)),
        }
    }

    fn move_mount_file_to_retention(
        &self,
        mount_path: &Path,
        retention_folder: &Path,
    ) -> Result<PathBuf, MountSyncError> {
        let plaintext_retention_folder = retention_folder.join("plaintext-orphans");
        fs::create_dir_all(&plaintext_retention_folder)?;

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let file_name = mount_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let retention_name = format!("{}_{}", timestamp, file_name);
        let retention_path = plaintext_retention_folder.join(&retention_name);
        let retention_meta_path =
            plaintext_retention_folder.join(format!("{}.meta.json", retention_name));

        match fs::rename(mount_path, &retention_path) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::CrossesDevices => {
                fs::copy(mount_path, &retention_path)?;
                fs::remove_file(mount_path)?;
            }
            Err(err) => return Err(MountSyncError::Io(err)),
        }

        let metadata = RetentionMetadata {
            deleted_at: Utc::now(),
        };
        if let Ok(data) = serde_json::to_vec_pretty(&metadata) {
            if let Err(err) = Self::write_atomic_bytes(&retention_meta_path, &data) {
                warn!(
                    "Failed to write plaintext retention metadata {}: {}",
                    retention_meta_path.display(),
                    err
                );
            }
        }

        Ok(retention_path)
    }

    /// Clean up old files from retention folder based on retention_days
    /// Uses the timestamp in the filename (when file was moved to retention) rather than file modification time
    fn cleanup_retention_folder(&self) -> Result<(), MountSyncError> {
        let retention_folder = match &self.deletion_config.retention_folder {
            Some(folder) => folder,
            None => return Ok(()),
        };

        if !retention_folder.exists() {
            return Ok(());
        }

        let retention_duration =
            Duration::from_secs(self.deletion_config.retention_days as u64 * 24 * 60 * 60);
        let now = Utc::now();

        let entries = match fs::read_dir(retention_folder) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(MountSyncError::Io(e)),
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // Parse timestamp from filename: format is YYYYMMDD_HHMMSS_filename
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name,
                None => continue,
            };
            if file_name.ends_with(".meta.json") {
                continue;
            }

            let retention_meta_path = retention_folder.join(format!("{}.meta.json", file_name));

            // Extract timestamp from filename (first 15 characters: YYYYMMDD_HHMMSS)
            let retention_timestamp = if retention_meta_path.exists() {
                match fs::read(&retention_meta_path)
                    .ok()
                    .and_then(|data| serde_json::from_slice::<RetentionMetadata>(&data).ok())
                {
                    Some(metadata) => metadata.deleted_at,
                    None => now,
                }
            } else if file_name.len() >= 16 && file_name.chars().nth(8) == Some('_') {
                // Try to parse the timestamp prefix (naive datetime, then convert to UTC)
                match NaiveDateTime::parse_from_str(&file_name[0..15], "%Y%m%d_%H%M%S") {
                    Ok(naive_dt) => DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc),
                    Err(_) => {
                        // If parsing fails, fall back to file modification time (for legacy files)
                        debug!(
                            "Could not parse timestamp from retention filename {}, using file modification time",
                            file_name
                        );
                        let metadata = match entry.metadata() {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        let modified = match metadata.modified() {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        // Convert SystemTime to DateTime<Utc>
                        match modified.duration_since(UNIX_EPOCH) {
                            Ok(duration) => {
                                DateTime::<Utc>::from_timestamp(duration.as_secs() as i64, 0)
                                    .unwrap_or_else(|| now)
                            }
                            Err(_) => continue,
                        }
                    }
                }
            } else {
                // Filename doesn't match expected format, use file modification time
                debug!(
                    "Retention filename {} doesn't match expected format, using file modification time",
                    file_name
                );
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let modified = match metadata.modified() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                // Convert SystemTime to DateTime<Utc>
                match modified.duration_since(UNIX_EPOCH) {
                    Ok(duration) => DateTime::<Utc>::from_timestamp(duration.as_secs() as i64, 0)
                        .unwrap_or_else(|| now),
                    Err(_) => continue,
                }
            };

            // Calculate age since file was moved to retention
            let age = now.signed_duration_since(retention_timestamp);
            let age_secs = age.num_seconds().max(0) as u64;

            if age_secs > retention_duration.as_secs() {
                if let Err(e) = fs::remove_file(&path) {
                    warn!(
                        "Failed to remove old retention file {}: {}",
                        path.display(),
                        e
                    );
                } else {
                    if let Err(err) = fs::remove_file(&retention_meta_path) {
                        if err.kind() != io::ErrorKind::NotFound {
                            warn!(
                                "Failed to remove retention metadata {}: {}",
                                retention_meta_path.display(),
                                err
                            );
                        }
                    }
                    info!(
                        "Permanently deleted retention file {} (age in retention: {} days, retention_days: {})",
                        path.display(),
                        age_secs / 86400,
                        self.deletion_config.retention_days
                    );
                }
            }
        }

        Ok(())
    }

    /// Run rapid verification scans: 7 quick checks within ~2.71828 seconds
    /// Checks if the mount file (decrypted file) reappears - if so, user restored it
    async fn run_rapid_verification_scans(
        &mut self,
        mount_root: &Path,
        files_to_verify: &mut Vec<PathBuf>,
    ) -> Result<(), MountSyncError> {
        if files_to_verify.is_empty() {
            return Ok(());
        }

        let start_time = Instant::now();
        let mut scan_count = 0u32;
        let mut dirty = false;

        debug!(
            "Starting rapid verification scans for {} files",
            files_to_verify.len()
        );

        // Run scans until we've done required scans or exceeded time limit
        while scan_count < self.deletion_config.min_consecutive_missing_scans
            && start_time.elapsed().as_millis()
                < self.deletion_config.rapid_scan_total_duration_ms as u128
        {
            // Check health before each scan
            let health = self.check_mount_health(mount_root)?;
            let is_healthy = matches!(health, ScanHealth::Healthy);

            // Update pending deletions based on current scan
            // Check if the MOUNT file (decrypted view) reappeared - user restored it
            let mut recovered_files = Vec::new();
            for encrypted_path in files_to_verify.clone() {
                if let Some(pending) = self.pending_deletions.get_mut(&encrypted_path) {
                    // Check if mount file (decrypted file) reappeared
                    if pending.mount_path.exists() {
                        // Mount file reappeared - user restored or recreated the file
                        debug!(
                            "Mount file {} reappeared during verification, canceling deletion of {}",
                            pending.mount_path.display(),
                            encrypted_path.display()
                        );
                        recovered_files.push(encrypted_path.clone());
                        pending.consecutive_missing_scans = 0; // Reset on recovery
                        dirty = true;
                    } else {
                        // Mount file still missing - increment count
                        pending.consecutive_missing_scans += 1;
                        if is_healthy {
                            pending.had_healthy_scan = true;
                        }
                        dirty = true;
                    }
                }
            }
            // Remove recovered files from verification list
            files_to_verify.retain(|path| !recovered_files.contains(path));

            scan_count += 1;

            // Sleep between scans (except for the last one)
            if scan_count < self.deletion_config.min_consecutive_missing_scans
                && start_time.elapsed().as_millis()
                    < self.deletion_config.rapid_scan_total_duration_ms as u128
            {
                // Use tokio sleep for async
                tokio::time::sleep(Duration::from_millis(
                    self.deletion_config.rapid_scan_interval_ms(),
                ))
                .await;
            }
        }

        debug!(
            "Completed {} rapid verification scans in {:?}",
            scan_count,
            start_time.elapsed()
        );

        if dirty {
            self.pending_deletions_dirty = true;
        }

        Ok(())
    }

    fn defer_low_space_refresh(
        &mut self,
        encrypted_path: &Path,
        target: &Path,
        signature: FileSignature,
        err: &MountSyncError,
    ) -> Result<DecryptOutcome, MountSyncError> {
        warn!(
            "Low-space condition deferred plaintext refresh for {} -> {}: {}",
            encrypted_path.display(),
            target.display(),
            err
        );
        self.record_pending_refresh(target, encrypted_path, err);
        self.encrypted_signatures
            .insert(encrypted_path.to_path_buf(), signature);
        self.path_mapping
            .insert(encrypted_path.to_path_buf(), target.to_path_buf());
        Ok(DecryptOutcome::DeferredLowSpace(target.to_path_buf()))
    }

    async fn decrypt_file<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        encrypted_root: &Path,
        mount_root: &Path,
        encrypted_path: &Path,
        signature: FileSignature,
    ) -> Result<DecryptOutcome, MountSyncError> {
        // Parse early to get file_id for tracking-based restoration detection
        let parsed = parse_encrypted_file_with_root(encrypted_root, encrypted_path)?;
        let file_id = &parsed.metadata.file_id;
        let tracked_mount_path = self.file_id_to_mount_path.get(file_id).cloned();
        if let Some(pending) = self.pending_deletions.get(encrypted_path) {
            debug!(
                "Encrypted file {} is still pending deletion; skipping plaintext restore to {}",
                encrypted_path.display(),
                pending.mount_path.display()
            );
            self.path_mapping
                .insert(encrypted_path.to_path_buf(), pending.mount_path.clone());
            self.encrypted_signatures
                .insert(encrypted_path.to_path_buf(), signature);
            return Ok(DecryptOutcome::Ready(pending.mount_path.clone()));
        }
        let mut target =
            decrypted_target_path(encrypted_root, encrypted_path, mount_root, &parsed)?;
        let raw_name = target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("decrypted")
            .to_string();
        let mut original_name: Option<String> = None;
        if let Some(ref tracked) = tracked_mount_path {
            target = tracked.clone();
        } else {
            let (sanitized_name, changed) = sanitize_mount_file_name(&raw_name, file_id);
            if changed {
                target.set_file_name(&sanitized_name);
                original_name = Some(raw_name.clone());
            }
        }

        if self.unsupported_hard_link_paths.contains_key(&target) {
            debug!(
                "Skipping decrypt refresh for {} because hard-link handling is blocked for {}",
                encrypted_path.display(),
                target.display()
            );
            self.path_mapping
                .insert(encrypted_path.to_path_buf(), target.clone());
            return Ok(DecryptOutcome::Ready(target));
        }

        if target.exists() {
            match fs::metadata(&target) {
                Ok(metadata) => {
                    if let Some(reason) = hard_link_block_reason(&target, &metadata) {
                        self.record_unsupported_hard_link_path(&target, &reason)?;
                        debug!(
                            "Skipping decrypt refresh for {} because target {} is hard-linked",
                            encrypted_path.display(),
                            target.display()
                        );
                        self.path_mapping
                            .insert(encrypted_path.to_path_buf(), target.clone());
                        return Ok(DecryptOutcome::Ready(target));
                    }
                    self.clear_unsupported_hard_link_path(&target)?;
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(MountSyncError::Io(err)),
            }
        }

        if self.pending_open_unlinked.contains_key(&target) && !target.exists() {
            debug!(
                "Skipping decrypt refresh for {} because a deleted-open handle is still active",
                target.display()
            );
            self.path_mapping
                .insert(encrypted_path.to_path_buf(), target.clone());
            self.encrypted_signatures
                .insert(encrypted_path.to_path_buf(), signature);
            return Ok(DecryptOutcome::Ready(target));
        }

        // Check if this file_id has been successfully decrypted before
        if let Some(tracked_mount_path) = tracked_mount_path.as_ref() {
            // File_id is tracked - check if mount file actually exists
            if tracked_mount_path.exists() {
                // Normal case: file exists, check if signature changed
                let needs_refresh = self
                    .encrypted_signatures
                    .get(encrypted_path)
                    .map(|stored| !stored.content_signature_eq(&signature))
                    .unwrap_or(true);

                if !needs_refresh {
                    // Fast path: file hasn't changed, use cached path mapping if available
                    if let Some(cached_target) = self.path_mapping.get(encrypted_path).cloned() {
                        if cached_target.exists() {
                            // Verify decrypted signature is tracked
                            if !self.decrypted_signatures.contains_key(&cached_target) {
                                if let Ok(meta) = fs::metadata(&cached_target) {
                                    let sig = FileSignature::from_metadata(&meta);
                                    self.decrypted_signatures.insert(cached_target.clone(), sig);
                                    self.refresh_decrypted_metadata_hash(&cached_target);
                                }
                            }
                            return Ok(DecryptOutcome::Ready(cached_target));
                        }
                    }

                    // Update path mapping cache
                    self.path_mapping
                        .insert(encrypted_path.to_path_buf(), target.clone());

                    if !self.decrypted_signatures.contains_key(&target) {
                        if let Ok(meta) = fs::metadata(&target) {
                            let sig = FileSignature::from_metadata(&meta);
                            self.decrypted_signatures.insert(target.clone(), sig);
                            self.refresh_decrypted_metadata_hash(&target);
                        }
                    }
                    return Ok(DecryptOutcome::Ready(target));
                }
                // Signature changed, fall through to re-decrypt
            } else {
                // file_id is tracked but mount file is missing
                // Check if encrypted file was deleted and restored (not in encrypted_signatures)
                // or if signature changed
                let was_deleted_and_restored =
                    !self.encrypted_signatures.contains_key(encrypted_path);
                let encrypted_signature_changed = self
                    .encrypted_signatures
                    .get(encrypted_path)
                    .map(|stored| !stored.content_signature_eq(&signature))
                    .unwrap_or(true);

                if was_deleted_and_restored || encrypted_signature_changed {
                    // Encrypted file was restored/modified - re-decrypt it
                    debug!(
                        "File {} (file_id: {}) is tracked but encrypted file {} - re-decrypting to {}",
                        encrypted_path.display(),
                        file_id,
                        if was_deleted_and_restored { "was deleted and restored" } else { "changed" },
                        tracked_mount_path.display()
                    );
                    // Fall through to decrypt below
                } else {
                    // Encrypted file unchanged, mount file missing = user deleted from mount view
                    // Don't re-decrypt - let the deletion logic in sync_decrypted_changes handle it
                    debug!(
                        "File {} (file_id: {}) is tracked but mount file {} is missing - user deleted it, skipping re-decrypt",
                        encrypted_path.display(),
                        file_id,
                        tracked_mount_path.display()
                    );
                    // Still return the target path for bookkeeping, but don't decrypt
                    self.path_mapping
                        .insert(encrypted_path.to_path_buf(), target.clone());
                    self.encrypted_signatures
                        .insert(encrypted_path.to_path_buf(), signature);
                    return Ok(DecryptOutcome::Ready(target));
                }
            }
        }
        // file_id is NOT tracked - this is either a new file or a restored file
        // Proceed with decryption
        debug!(
            "File {} (file_id: {}) is not tracked - will decrypt to {}",
            encrypted_path.display(),
            file_id,
            target.display()
        );

        // Skip files that are missing key wrap material; these are unreadable and should not
        // fail the entire mount. We still return the intended target path so bookkeeping
        // remains consistent without writing plaintext.
        if parsed.metadata.wrapped_file_key.is_none() || parsed.metadata.key_wrap_nonce.is_none() {
            warn!(
                "Skipping encrypted file {}: missing wrapped key or nonce",
                encrypted_path.display()
            );
            self.encrypted_signatures
                .insert(encrypted_path.to_path_buf(), signature);
            self.path_mapping
                .insert(encrypted_path.to_path_buf(), target.clone());
            return Ok(DecryptOutcome::Ready(target));
        }

        if tracked_mount_path.is_none() {
            let resolved = self.resolve_mount_collision_target(mount_root, &target, file_id);
            if resolved != target && original_name.is_none() {
                original_name = Some(raw_name.clone());
            }
            target = resolved;
        }

        let mut initial_sig: Option<FileSignature> = None;
        let local_dirty = if target.exists() {
            match fs::metadata(&target) {
                Ok(meta) => {
                    let current_sig = FileSignature::from_metadata(&meta);
                    initial_sig = Some(current_sig);
                    let stored = self.decrypted_signatures.get(&target).copied();
                    let mut dirty = match stored {
                        Some(prev) => prev != current_sig,
                        None => true,
                    };

                    if dirty {
                        if let Some(prev) = stored {
                            if prev.ctime_only_change(&current_sig) {
                                let mut matched = false;
                                let mut updated_hash: Option<[u8; 32]> = None;
                                let current_metadata_hash = capture_platform_metadata_hash(&target);
                                let metadata_matches = match (
                                    self.decrypted_metadata_hashes.get(&target),
                                    current_metadata_hash.as_ref(),
                                ) {
                                    (None, None) => true,
                                    (Some(previous), Some(current)) => previous == current,
                                    _ => false,
                                };
                                if let Some(prev_hash) = self.decrypted_hashes.get(&target) {
                                    if let Ok(current_hash) = hash_file(&target) {
                                        matched = &current_hash == prev_hash;
                                        updated_hash = Some(current_hash);
                                    }
                                } else if let Ok(current_hash) = hash_file(&target) {
                                    matched = true;
                                    updated_hash = Some(current_hash);
                                }

                                if matched && metadata_matches {
                                    dirty = false;
                                }
                                if let Some(hash) = updated_hash {
                                    self.decrypted_hashes.insert(target.clone(), hash);
                                }
                                if let Some(hash) = current_metadata_hash {
                                    self.decrypted_metadata_hashes.insert(target.clone(), hash);
                                } else {
                                    self.decrypted_metadata_hashes.remove(&target);
                                }
                            }
                        }
                    }
                    dirty
                }
                Err(err) => {
                    debug!(
                        "Failed to read metadata for {} while checking dirty state: {}",
                        target.display(),
                        err
                    );
                    false
                }
            }
        } else {
            false
        };

        // Update path mapping cache
        self.path_mapping
            .insert(encrypted_path.to_path_buf(), target.clone());

        let mut write_conflict = local_dirty;
        if !write_conflict {
            let pre_write_dirty = match fs::metadata(&target) {
                Ok(meta) => {
                    let current_sig = FileSignature::from_metadata(&meta);
                    match initial_sig {
                        Some(prev) if prev.ctime_only_change(&current_sig) => {
                            let mut matched = false;
                            let mut updated_hash: Option<[u8; 32]> = None;
                            let current_metadata_hash = capture_platform_metadata_hash(&target);
                            let metadata_matches = match (
                                self.decrypted_metadata_hashes.get(&target),
                                current_metadata_hash.as_ref(),
                            ) {
                                (None, None) => true,
                                (Some(previous), Some(current)) => previous == current,
                                _ => false,
                            };
                            if let Some(prev_hash) = self.decrypted_hashes.get(&target) {
                                if let Ok(current_hash) = hash_file(&target) {
                                    matched = &current_hash == prev_hash;
                                    updated_hash = Some(current_hash);
                                }
                            } else if let Ok(current_hash) = hash_file(&target) {
                                matched = true;
                                updated_hash = Some(current_hash);
                            }

                            if let Some(hash) = updated_hash {
                                self.decrypted_hashes.insert(target.clone(), hash);
                            }
                            if let Some(hash) = current_metadata_hash {
                                self.decrypted_metadata_hashes.insert(target.clone(), hash);
                            } else {
                                self.decrypted_metadata_hashes.remove(&target);
                            }

                            !(matched && metadata_matches)
                        }
                        Some(prev) => prev != current_sig,
                        None => true,
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => false,
                Err(err) => {
                    debug!(
                        "Failed to re-check metadata for {} before decrypt write: {}",
                        target.display(),
                        err
                    );
                    false
                }
            };

            if pre_write_dirty {
                warn!(
                    "Local edits detected for {} during decrypt. Writing encrypted update to conflict file.",
                    target.display()
                );
                write_conflict = true;
            }
        }

        let write_target = if write_conflict {
            let conflict_path = conflict_path_for(&target);
            warn!(
                "Writing encrypted update for {} to conflict file {}.",
                target.display(),
                conflict_path.display()
            );
            conflict_path
        } else {
            target.clone()
        };

        if self.mount_readonly_active {
            let err = low_space_readonly_error(&target);
            return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
        }

        let plaintext_budget = parsed
            .metadata
            .content_size
            .saturating_add(LOW_SPACE_ATOMIC_WRITE_OVERHEAD_BYTES);
        if let Err(err) = self.ensure_space_budget(
            &write_target,
            plaintext_budget,
            LOW_SPACE_WARNING_RESERVE_BYTES,
            "plaintext refresh",
        ) {
            return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
        }
        if let Some(journal_path) = self.journal_budget_path() {
            if let Err(err) = self.ensure_space_budget(
                journal_path,
                LOW_SPACE_JOURNAL_RESERVE_BYTES,
                LOW_SPACE_JOURNAL_RESERVE_BYTES,
                "pending refresh journal",
            ) {
                return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
            }
        }

        if let Some(parent) = write_target.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                let mount_err = MountSyncError::Io(err);
                if is_low_space_error(&mount_err) {
                    return self.defer_low_space_refresh(
                        encrypted_path,
                        &target,
                        signature,
                        &mount_err,
                    );
                }
                return Err(mount_err);
            }
        }
        let mut decrypted_hash: Option<[u8; 32]> = None;
        if parsed.metadata.content_chunk_size.is_some() {
            match crypto
                .decrypt_file_streaming(encrypted_path, &write_target, &parsed.metadata)
                .await
            {
                Ok(()) => {}
                Err(err) if is_low_space_error(&err) => {
                    return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
                }
                Err(err) => return Err(err),
            }
        } else {
            let decrypted = match crypto.decrypt_file(encrypted_path, &parsed.metadata).await {
                Ok(decrypted) => decrypted,
                Err(err) if is_low_space_error(&err) => {
                    return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
                }
                Err(err) => return Err(err),
            };
            if !write_conflict {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&Sha256::digest(&decrypted));
                decrypted_hash = Some(hash);
            }
            if let Err(err) = Self::write_atomic_bytes(&write_target, &decrypted) {
                if is_low_space_error(&err) {
                    return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
                }
                return Err(err);
            }
        }

        if let Some(platform_metadata) = parsed.metadata.platform_metadata.as_ref() {
            if let Err(err) = apply_platform_metadata(&write_target, platform_metadata) {
                debug!(
                    "Failed to restore platform metadata for {}: {}",
                    write_target.display(),
                    err
                );
            }
        }

        if !write_conflict {
            if let Err(err) = write_file_id_xattr(&write_target, file_id) {
                debug!(
                    "Failed to persist file_id xattr for {}: {}",
                    write_target.display(),
                    err
                );
            }
            if let Some(ref original) = original_name {
                if let Err(err) = write_original_name_xattr(&write_target, original) {
                    debug!(
                        "Failed to persist original_name xattr for {}: {}",
                        write_target.display(),
                        err
                    );
                }
            }
        }

        if !write_conflict {
            // Preserve timestamp using the encrypted file's mtime to avoid always showing mount time.
            if let Ok(enc_meta) = encrypted_path.metadata() {
                if let Ok(modified) = enc_meta.modified() {
                    let ft = FileTime::from_system_time(modified);
                    let _ = set_file_times(&write_target, ft, ft);
                }
            }
        }

        if let Ok(meta) = fs::metadata(&write_target) {
            let sig = FileSignature::from_metadata(&meta);
            self.decrypted_signatures.insert(write_target.clone(), sig);
            if write_conflict {
                self.refresh_decrypted_metadata_hash(&write_target);
                self.update_conflict_file_tracking(&write_target, sig);
            }
        }

        if !write_conflict {
            if let Some(hash) = decrypted_hash {
                self.decrypted_hashes.insert(write_target.clone(), hash);
            } else {
                self.decrypted_hashes.remove(&write_target);
            }
            self.remember_decrypted_metadata_hash(
                &write_target,
                parsed.metadata.platform_metadata.as_ref(),
            );
        } else {
            self.decrypted_hashes.remove(&write_target);
        }

        // Track this file_id as successfully decrypted
        debug!(
            "Successfully decrypted {} (file_id: {}) to {}",
            encrypted_path.display(),
            file_id,
            target.display()
        );
        self.file_id_to_mount_path
            .insert(file_id.clone(), target.clone());

        self.encrypted_signatures
            .insert(encrypted_path.to_path_buf(), signature);
        self.clear_pending_refresh(&target);
        Ok(DecryptOutcome::Ready(target))
    }

    async fn decrypt_directory_metadata<C: MountCrypto + ?Sized>(
        &mut self,
        _crypto: &C,
        encrypted_root: &Path,
        mount_root: &Path,
        encrypted_path: &Path,
        signature: FileSignature,
    ) -> Result<DecryptOutcome, MountSyncError> {
        let parsed = parse_encrypted_file_with_root(encrypted_root, encrypted_path)?;
        let target = decrypted_directory_target_path(encrypted_root, encrypted_path, mount_root)?;

        let needs_refresh = self
            .encrypted_directory_signatures
            .get(encrypted_path)
            .map(|stored| !stored.content_signature_eq(&signature))
            .unwrap_or(true);
        if !needs_refresh && target.exists() {
            if !self.decrypted_directory_signatures.contains_key(&target) {
                if let Ok(meta) = fs::metadata(&target) {
                    self.decrypted_directory_signatures
                        .insert(target.clone(), FileSignature::from_metadata(&meta));
                    self.refresh_decrypted_directory_metadata_hash(&target);
                }
            }
            return Ok(DecryptOutcome::Ready(target));
        }

        if !needs_refresh
            && !target.exists()
            && self.decrypted_directory_signatures.contains_key(&target)
            && !self.pending_refreshes.contains_key(&target)
        {
            debug!(
                "Directory metadata {} is unchanged but mounted directory {} is missing - treating as mounted-side delete",
                encrypted_path.display(),
                target.display()
            );
            self.encrypted_directory_signatures
                .insert(encrypted_path.to_path_buf(), signature);
            return Ok(DecryptOutcome::Ready(target));
        }

        if self.mount_readonly_active {
            let err = low_space_readonly_error(&target);
            return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
        }

        if let Err(err) = self.ensure_space_budget(
            &target,
            LOW_SPACE_DIRECTORY_CREATE_BYTES,
            LOW_SPACE_WARNING_RESERVE_BYTES,
            "directory metadata refresh",
        ) {
            return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
        }
        if let Some(journal_path) = self.journal_budget_path() {
            if let Err(err) = self.ensure_space_budget(
                journal_path,
                LOW_SPACE_JOURNAL_RESERVE_BYTES,
                LOW_SPACE_JOURNAL_RESERVE_BYTES,
                "pending refresh journal",
            ) {
                return self.defer_low_space_refresh(encrypted_path, &target, signature, &err);
            }
        }

        if let Err(err) = fs::create_dir_all(&target) {
            let mount_err = MountSyncError::Io(err);
            if is_low_space_error(&mount_err) {
                return self.defer_low_space_refresh(
                    encrypted_path,
                    &target,
                    signature,
                    &mount_err,
                );
            }
            return Err(mount_err);
        }

        if let Some(platform_metadata) = parsed.metadata.platform_metadata.as_ref() {
            if let Err(err) = apply_platform_metadata(&target, platform_metadata) {
                debug!(
                    "Failed to restore directory metadata for {}: {}",
                    target.display(),
                    err
                );
            }
        }

        if let Ok(meta) = fs::metadata(&target) {
            self.decrypted_directory_signatures
                .insert(target.clone(), FileSignature::from_metadata(&meta));
        }
        self.remember_decrypted_directory_metadata_hash(
            &target,
            parsed.metadata.platform_metadata.as_ref(),
        );
        self.encrypted_directory_signatures
            .insert(encrypted_path.to_path_buf(), signature);
        self.clear_pending_refresh(&target);
        Ok(DecryptOutcome::Ready(target))
    }

    async fn sync_decrypted_changes<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        encrypted_root: &Path,
        mount_root: &Path,
        expected: &mut HashSet<PathBuf>,
        protected_missing_paths: &HashSet<PathBuf>,
    ) -> Result<(), MountSyncError> {
        let mut current: HashSet<PathBuf> = HashSet::new();
        let mut current_directories: HashSet<PathBuf> = HashSet::new();
        let mut current_conflicts: HashSet<PathBuf> = HashSet::new();
        let mut current_recovered: HashSet<PathBuf> = HashSet::new();
        let mut stack = vec![mount_root.to_path_buf()];

        while let Some(current_dir) = stack.pop() {
            let entries = match fs::read_dir(&current_dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(MountSyncError::Io(e)),
            };

            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;

                if file_type.is_symlink() {
                    warn!(
                        "Skipping symlink in mount root {} to avoid following external targets",
                        path.display()
                    );
                    continue;
                }

                if file_type.is_dir() {
                    if self.is_path_excluded(&path) {
                        continue;
                    }

                    if path != mount_root {
                        current_directories.insert(path.clone());
                        expected.insert(path.clone());
                        self.sync_decrypted_directory(crypto, encrypted_root, mount_root, &path)
                            .await?;
                    }
                    stack.push(path.clone());
                    continue;
                }

                if !file_type.is_file() {
                    warn!("Skipping non-file entry in mount root: {}", path.display());
                    continue;
                }

                if self.is_path_excluded(&path) {
                    continue;
                }

                let metadata = entry.metadata()?;
                current.insert(path.clone());
                expected.insert(path.clone());

                if self.pending_open_unlinked.remove(&path).is_some() {
                    self.pending_open_unlinked_dirty = true;
                }

                let signature = FileSignature::from_metadata(&metadata);

                if is_conflict_file(&path) {
                    debug!(
                        "Skipping conflict file {} from encryption sync",
                        path.display()
                    );
                    current_conflicts.insert(path.clone());
                    self.update_conflict_file_tracking(&path, signature);
                    self.decrypted_signatures.insert(path.clone(), signature);
                    self.refresh_decrypted_metadata_hash(&path);
                    continue;
                }

                if is_recovered_pending_file(&path) {
                    debug!(
                        "Skipping recovered pending copy {} from encryption sync",
                        path.display()
                    );
                    current_recovered.insert(path.clone());
                    self.note_recovered_pending_copy(&path, signature);
                    continue;
                }

                let stored = self.decrypted_signatures.get(&path).copied();
                let encrypted_path = encrypted_path_for(encrypted_root, mount_root, &path)?;
                let encrypted_exists = encrypted_path.exists();
                let file_name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");

                if !encrypted_exists && self.pending_orphans.contains_key(&path) {
                    if self.is_local_mount_path_dirty_with_signature(&path, signature) {
                        debug!(
                            "Local edits detected for pending orphan {}. Re-encrypting plaintext.",
                            path.display()
                        );
                        if self.pending_orphans.remove(&path).is_some() {
                            self.pending_orphans_dirty = true;
                        }
                    } else {
                        debug!(
                            "Keeping {} as a pending orphan until encrypted-side disappearance is verified",
                            path.display()
                        );
                        self.decrypted_signatures.insert(path.clone(), signature);
                        continue;
                    }
                } else if encrypted_exists && self.pending_orphans.remove(&path).is_some() {
                    self.pending_orphans_dirty = true;
                }

                if is_temp_like_name(file_name) && !encrypted_exists {
                    let first_seen = self
                        .pending_temp
                        .entry(path.clone())
                        .or_insert_with(Instant::now);
                    if first_seen.elapsed() < Duration::from_secs(TEMP_FILE_GRACE_SECS) {
                        debug!(
                            "Deferring temp-like file {} until it persists beyond grace window",
                            path.display()
                        );
                        self.decrypted_signatures.insert(path.clone(), signature);
                        continue;
                    }
                    self.pending_temp.remove(&path);
                } else {
                    self.pending_temp.remove(&path);
                }

                if should_skip_sparse_update(
                    &metadata,
                    encrypted_exists,
                    self.sparse_skip_size_bytes,
                ) {
                    if self.pending_sparse.insert(path.clone()) {
                        warn!(
                            "Skipping sparse file update for {} to avoid densification (size: {} bytes)",
                            path.display(),
                            metadata.len()
                        );
                    }
                    self.decrypted_signatures.insert(path.clone(), signature);
                    self.refresh_decrypted_metadata_hash(&path);
                    continue;
                } else {
                    self.pending_sparse.remove(&path);
                }

                if let Some(reason) = hard_link_block_reason(&path, &metadata) {
                    self.record_unsupported_hard_link_path(&path, &reason)?;
                    if self.pending_deletions.remove(&encrypted_path).is_some() {
                        self.pending_deletions_dirty = true;
                    }
                    self.decrypted_signatures.insert(path.clone(), signature);
                    self.refresh_decrypted_metadata_hash(&path);
                    continue;
                } else {
                    self.clear_unsupported_hard_link_path(&path)?;
                }

                if let Some(reason) = transactional_format_reason(mount_root, &path) {
                    self.record_unsupported_transactional_path(&path, &reason);
                    self.decrypted_signatures.insert(path.clone(), signature);
                    self.refresh_decrypted_metadata_hash(&path);
                    self.pending_stable.remove(&path);
                    self.clear_pending_writeback(&path);
                    continue;
                }

                let mut xattr_file_id = read_file_id_xattr(&path);
                if xattr_file_id.is_none() && encrypted_exists {
                    match parse_encrypted_file_with_root(encrypted_root, &encrypted_path) {
                        Ok(parsed) => {
                            if let Err(err) = write_file_id_xattr(&path, &parsed.metadata.file_id) {
                                debug!(
                                    "Failed to backfill file_id xattr for {}: {}",
                                    path.display(),
                                    err
                                );
                            } else {
                                xattr_file_id = Some(parsed.metadata.file_id);
                            }
                        }
                        Err(err) => {
                            debug!(
                                "Failed to parse encrypted file {} for file_id backfill: {}",
                                encrypted_path.display(),
                                err
                            );
                        }
                    }
                }

                if let Some(ref file_id) = xattr_file_id {
                    if let Some(existing_path) = self.file_id_to_mount_path.get(file_id) {
                        if existing_path.as_path() != path.as_path() && existing_path.exists() {
                            warn!(
                                "Duplicate file_id {} detected for {} (already mapped to {}). Assigning new file_id.",
                                file_id,
                                path.display(),
                                existing_path.display()
                            );
                            let _ = clear_file_id_xattr(&path);
                            xattr_file_id = None;
                        }
                    }
                }
                if let Some(ref file_id) = xattr_file_id {
                    self.file_id_to_mount_path
                        .insert(file_id.clone(), path.clone());
                }

                let mut skip_encrypt_for_ctime_only = false;
                if encrypted_exists {
                    if let Some(prev) = stored {
                        if prev.ctime_only_change(&signature) {
                            let mut updated_hash: Option<[u8; 32]> = None;
                            let current_metadata_hash = capture_platform_metadata_hash(&path);
                            let metadata_matches = match (
                                self.decrypted_metadata_hashes.get(&path),
                                current_metadata_hash.as_ref(),
                            ) {
                                (None, None) => true,
                                (Some(previous), Some(current)) => previous == current,
                                _ => false,
                            };
                            let hash_baseline_limit = if self.stream_threshold_bytes == 0 {
                                STREAM_THRESHOLD_BYTES
                            } else {
                                self.stream_threshold_bytes
                            };
                            if let Some(prev_hash) = self.decrypted_hashes.get(&path) {
                                match hash_file(&path) {
                                    Ok(current_hash) => {
                                        if &current_hash == prev_hash {
                                            skip_encrypt_for_ctime_only = true;
                                        }
                                        updated_hash = Some(current_hash);
                                    }
                                    Err(err) => {
                                        warn!(
                                            "Failed to hash {} for ctime-only change check: {}",
                                            path.display(),
                                            err
                                        );
                                    }
                                }
                            } else if metadata.len() <= hash_baseline_limit {
                                match hash_file(&path) {
                                    Ok(current_hash) => {
                                        skip_encrypt_for_ctime_only = true;
                                        updated_hash = Some(current_hash);
                                    }
                                    Err(err) => {
                                        warn!(
                                            "Failed to hash {} for ctime-only change baseline: {}",
                                            path.display(),
                                            err
                                        );
                                    }
                                }
                            } else {
                                debug!(
                                    "Skipping ctime-only re-encrypt for {} without baseline hash (size: {} bytes)",
                                    path.display(),
                                    metadata.len()
                                );
                                skip_encrypt_for_ctime_only = true;
                            }

                            if let Some(hash) = updated_hash {
                                self.decrypted_hashes.insert(path.clone(), hash);
                            }
                            if let Some(hash) = current_metadata_hash {
                                self.decrypted_metadata_hashes.insert(path.clone(), hash);
                            } else {
                                self.decrypted_metadata_hashes.remove(&path);
                            }

                            if !metadata_matches {
                                skip_encrypt_for_ctime_only = false;
                            }
                        }
                    }
                }

                let needs_encrypt = !skip_encrypt_for_ctime_only
                    && (!encrypted_exists || stored.map(|sig| sig != signature).unwrap_or(true));

                if needs_encrypt {
                    self.record_pending_writeback(&path, &encrypted_path, None);
                    let stable_entry = self.pending_stable.get(&path).copied();
                    let stable_ready = match stable_entry {
                        Some(entry) if entry.signature == signature => {
                            if self.should_stream_file(metadata.len())
                                && self.stream_stability_age_secs > 0
                            {
                                entry.first_seen.elapsed()
                                    >= Duration::from_secs(self.stream_stability_age_secs)
                            } else {
                                true
                            }
                        }
                        _ => false,
                    };

                    if !stable_ready {
                        self.pending_stable.insert(
                            path.clone(),
                            StableEntry {
                                signature,
                                first_seen: Instant::now(),
                            },
                        );
                        debug!(
                            "Deferring encryption for {} until stable across scans",
                            path.display()
                        );
                        self.refresh_decrypted_metadata_hash(&path);
                        continue;
                    }
                    self.pending_stable.remove(&path);
                    if self.mount_readonly_active {
                        let err = low_space_readonly_error(&path);
                        self.record_pending_writeback(&path, &encrypted_path, Some(&err));
                        self.pending_stable.insert(
                            path.clone(),
                            StableEntry {
                                signature,
                                first_seen: Instant::now(),
                            },
                        );
                        continue;
                    }
                    match self
                        .encrypt_decrypted_file(
                            crypto,
                            mount_root,
                            encrypted_root,
                            &path,
                            &encrypted_path,
                        )
                        .await
                    {
                        Ok((encrypted_signature, file_id)) => {
                            self.encrypted_signatures
                                .insert(encrypted_path.clone(), encrypted_signature);
                            self.clear_pending_writeback(&path);
                            // Track the file_id for this newly encrypted file
                            self.file_id_to_mount_path.insert(file_id, path.clone());
                        }
                        Err(MountSyncError::UnstableFile(reason)) => {
                            self.record_pending_writeback(
                                &path,
                                &encrypted_path,
                                Some(&MountSyncError::UnstableFile(reason.clone())),
                            );
                            warn!("Deferring encryption for {}: {}", path.display(), reason);
                            self.pending_stable.insert(
                                path.clone(),
                                StableEntry {
                                    signature,
                                    first_seen: Instant::now(),
                                },
                            );
                            continue;
                        }
                        Err(err) if is_low_space_error(&err) => {
                            self.record_pending_writeback(&path, &encrypted_path, Some(&err));
                            warn!(
                                "Low-space condition deferred encrypted writeback for {}: {}",
                                path.display(),
                                err
                            );
                            self.pending_stable.insert(
                                path.clone(),
                                StableEntry {
                                    signature,
                                    first_seen: Instant::now(),
                                },
                            );
                            continue;
                        }
                        Err(MountSyncError::PathExcluded(reason)) => {
                            debug!("Skipping excluded file {}: {}", path.display(), reason);
                            self.clear_pending_writeback(&path);
                            continue;
                        }
                        Err(err) => {
                            warn!(
                                "Encryption failed for {}; deferring as pending writeback: {}",
                                path.display(),
                                err
                            );
                            self.record_pending_writeback(&path, &encrypted_path, Some(&err));
                            self.pending_stable.insert(
                                path.clone(),
                                StableEntry {
                                    signature,
                                    first_seen: Instant::now(),
                                },
                            );
                            continue;
                        }
                    }
                } else if skip_encrypt_for_ctime_only {
                    self.pending_stable.remove(&path);
                    self.clear_pending_writeback(&path);
                }

                self.decrypted_signatures.insert(path.clone(), signature);
                self.refresh_decrypted_metadata_hash(&path);
                self.pending_stable.remove(&path);

                if self.encrypted_signatures.get(&encrypted_path).is_none() && encrypted_exists {
                    if let Ok(meta) = encrypted_path.metadata() {
                        let sig = FileSignature::from_metadata(&meta);
                        self.encrypted_signatures
                            .insert(encrypted_path.clone(), sig);
                    }
                }
            }
        }

        self.prune_conflict_tracking(&current_conflicts);
        self.prune_recovered_pending_tracking(&current_recovered);

        self.refresh_pending_open_unlinked(crypto, encrypted_root, mount_root)
            .await?;

        if self.mount_readonly_active {
            debug!(
                "Skipping delete propagation from mountpoint {} while low-space read-only mode is active",
                mount_root.display()
            );
        } else if self.suppress_deletion_inference {
            debug!(
                "Skipping delete propagation from mountpoint {} during startup rehydrate mode",
                mount_root.display()
            );
        } else {
            // Handle deletions: if a file was previously tracked (successfully decrypted)
            // but is now missing from the mount directory, it was intentionally deleted.
            // Delete the corresponding encrypted file.
            //
            // We only act on files that are in decrypted_signatures (were previously decrypted),
            // which prevents accidental deletions during initial sync when files are still
            // being decrypted and added to the tracking set.
            let tracked: Vec<PathBuf> = self.decrypted_signatures.keys().cloned().collect();
            for tracked_path in tracked {
                if current.contains(&tracked_path) {
                    continue;
                }

                if protected_missing_paths.contains(&tracked_path) {
                    debug!(
                        "Skipping delete propagation for {} because plaintext refresh was deferred",
                        tracked_path.display()
                    );
                    continue;
                }

                if self.pending_open_unlinked.contains_key(&tracked_path) {
                    debug!(
                        "Skipping delete propagation for {} because a deleted-open handle is still active",
                        tracked_path.display()
                    );
                    let encrypted_path =
                        encrypted_path_for(encrypted_root, mount_root, &tracked_path)?;
                    if self.pending_deletions.remove(&encrypted_path).is_some() {
                        self.pending_deletions_dirty = true;
                    }
                    continue;
                }

                if self.unsupported_hard_link_paths.contains_key(&tracked_path) {
                    let encrypted_path =
                        encrypted_path_for(encrypted_root, mount_root, &tracked_path)?;
                    if encrypted_path.exists() {
                        if let Ok(parsed) =
                            parse_encrypted_file_with_root(encrypted_root, &encrypted_path)
                        {
                            if let Some(new_mount_path) =
                                self.file_id_to_mount_path.get(&parsed.metadata.file_id)
                            {
                                if new_mount_path.as_path() != tracked_path.as_path()
                                    && new_mount_path.exists()
                                {
                                    let new_encrypted_path = encrypted_path_for(
                                        encrypted_root,
                                        mount_root,
                                        new_mount_path,
                                    )?;
                                    if new_encrypted_path.exists() {
                                        if let Ok(new_parsed) = parse_encrypted_file_with_root(
                                            encrypted_root,
                                            &new_encrypted_path,
                                        ) {
                                            if new_parsed.metadata.file_id
                                                == parsed.metadata.file_id
                                            {
                                                debug!(
                                                    "Resolved blocked hard-link path {} -> {}; removing old encrypted file {}",
                                                    tracked_path.display(),
                                                    new_mount_path.display(),
                                                    encrypted_path.display()
                                                );
                                                if let Err(err) = fs::remove_file(&encrypted_path) {
                                                    if err.kind() != io::ErrorKind::NotFound {
                                                        warn!(
                                                            "Failed to remove old encrypted file {} after hard-link resolution: {}",
                                                            encrypted_path.display(),
                                                            err
                                                        );
                                                    }
                                                }
                                                self.clear_unsupported_hard_link_path(
                                                    &tracked_path,
                                                )?;
                                                self.clear_decrypted_tracking(&tracked_path);
                                                self.encrypted_signatures.remove(&encrypted_path);
                                                self.path_mapping
                                                    .retain(|_enc, dec| dec != &tracked_path);
                                                self.file_id_to_mount_path.retain(
                                                    |_file_id, mount_path| {
                                                        mount_path != &tracked_path
                                                    },
                                                );
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        debug!(
                            "Skipping delete propagation for {} because sync mount is blocking hard-link semantics for this path",
                            tracked_path.display()
                        );
                    } else {
                        debug!(
                            "Clearing missing blocked hard-link path {} because no encrypted version remains",
                            tracked_path.display()
                        );
                        self.clear_unsupported_hard_link_path(&tracked_path)?;
                        self.clear_decrypted_tracking(&tracked_path);
                        self.encrypted_signatures.remove(&encrypted_path);
                        self.path_mapping.retain(|_enc, dec| dec != &tracked_path);
                        self.file_id_to_mount_path
                            .retain(|_file_id, mount_path| mount_path != &tracked_path);
                    }
                    if self.pending_deletions.remove(&encrypted_path).is_some() {
                        self.pending_deletions_dirty = true;
                    }
                    continue;
                }

                // File was tracked (previously decrypted) but is now missing from mount
                // Mark as pending deletion instead of immediately deleting (two-phase deletion)
                let encrypted_path = encrypted_path_for(encrypted_root, mount_root, &tracked_path)?;

                if encrypted_path.exists() {
                    if let Ok(parsed) =
                        parse_encrypted_file_with_root(encrypted_root, &encrypted_path)
                    {
                        if let Some(new_mount_path) =
                            self.file_id_to_mount_path.get(&parsed.metadata.file_id)
                        {
                            if new_mount_path.as_path() != tracked_path.as_path()
                                && new_mount_path.exists()
                            {
                                let new_encrypted_path =
                                    encrypted_path_for(encrypted_root, mount_root, new_mount_path)?;
                                if new_encrypted_path.exists() {
                                    if let Ok(new_parsed) = parse_encrypted_file_with_root(
                                        encrypted_root,
                                        &new_encrypted_path,
                                    ) {
                                        if new_parsed.metadata.file_id == parsed.metadata.file_id {
                                            debug!(
                                                "Detected rename/move {} -> {}; removing old encrypted file {}",
                                                tracked_path.display(),
                                                new_mount_path.display(),
                                                encrypted_path.display()
                                            );
                                            if let Err(err) = fs::remove_file(&encrypted_path) {
                                                if err.kind() != io::ErrorKind::NotFound {
                                                    warn!(
                                                        "Failed to remove old encrypted file {} after rename: {}",
                                                        encrypted_path.display(),
                                                        err
                                                    );
                                                }
                                            }
                                            self.clear_decrypted_tracking(&tracked_path);
                                            self.encrypted_signatures.remove(&encrypted_path);
                                            self.path_mapping
                                                .retain(|_enc, dec| dec != &tracked_path);
                                            continue;
                                        }
                                    }
                                } else {
                                    debug!(
                                        "Deferring deletion for {} until new encrypted path exists",
                                        tracked_path.display()
                                    );
                                    continue;
                                }
                            }
                        }
                    }

                    // Check if already pending deletion (using encrypted_path as key)
                    if let Some(pending) = self.pending_deletions.get_mut(&encrypted_path) {
                        // Already pending - increment will happen in rapid verification scans
                        debug!(
                            "File {} already pending deletion ({} scans)",
                            encrypted_path.display(),
                            pending.consecutive_missing_scans
                        );
                    } else {
                        // New pending deletion - key by encrypted_path, store mount_path for verification
                        debug!(
                            "Marking encrypted file {} for pending deletion (mount file: {})",
                            encrypted_path.display(),
                            tracked_path.display()
                        );
                        self.pending_deletions.insert(
                            encrypted_path.clone(),
                            PendingDeletion {
                                mount_path: tracked_path.clone(),
                                first_missing_time: Instant::now(),
                                consecutive_missing_scans: 1, // First detection
                                had_healthy_scan: matches!(self.scan_health, ScanHealth::Healthy),
                            },
                        );
                        self.pending_deletions_dirty = true;
                    }
                } else {
                    // Encrypted file doesn't exist - clean up tracking immediately
                    self.clear_decrypted_tracking(&tracked_path);
                    self.encrypted_signatures.remove(&encrypted_path);
                    self.path_mapping.retain(|_enc, dec| dec != &tracked_path);
                    self.file_id_to_mount_path
                        .retain(|_file_id, mount_path| mount_path != &tracked_path);
                    // Also remove from pending if it was there (using encrypted_path as key)
                    if self.pending_deletions.remove(&encrypted_path).is_some() {
                        self.pending_deletions_dirty = true;
                    }
                }
            }

            let tracked_directories: Vec<PathBuf> = self
                .decrypted_directory_signatures
                .keys()
                .cloned()
                .collect();
            let mut orphaned_encrypted_dirs: Vec<PathBuf> = Vec::new();
            for tracked_path in tracked_directories {
                if tracked_path == mount_root || current_directories.contains(&tracked_path) {
                    continue;
                }
                if protected_missing_paths.contains(&tracked_path) {
                    continue;
                }

                let encrypted_path = encrypted_directory_metadata_path_for(
                    encrypted_root,
                    mount_root,
                    &tracked_path,
                )?;
                match fs::remove_file(&encrypted_path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(MountSyncError::Io(err)),
                }
                if let Some(parent) = encrypted_path.parent() {
                    if parent != encrypted_root {
                        orphaned_encrypted_dirs.push(parent.to_path_buf());
                    }
                }
                self.clear_decrypted_directory_tracking(&tracked_path);
                self.encrypted_directory_signatures.remove(&encrypted_path);
                self.clear_pending_writeback(&tracked_path);
                self.clear_pending_refresh(&tracked_path);
            }
            // Remove the now-empty encrypted-side directories deepest-first.
            // encrypt_directory_metadata creates these via create_dir_all; without
            // this cleanup they linger in the enrolled folder after a mounted-side delete.
            orphaned_encrypted_dirs
                .sort_by(|a, b| b.components().count().cmp(&a.components().count()));
            for encrypted_parent in orphaned_encrypted_dirs {
                let tmp_dir = encrypted_parent.join(ENCRYPTED_TMP_DIR_NAME);
                if tmp_dir.exists() {
                    let _ = fs::remove_dir_all(&tmp_dir);
                }
                match fs::remove_dir(&encrypted_parent) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                    Err(err) => {
                        warn!(
                            "Failed to remove orphaned encrypted directory {}: {}",
                            encrypted_parent.display(),
                            err
                        );
                    }
                }
            }
        }

        self.pending_stable.retain(|path, _| current.contains(path));
        self.pending_temp.retain(|path, _| current.contains(path));
        self.pending_sparse.retain(|path| current.contains(path));
        self.unsupported_transactional_paths
            .retain(|path, _| current.contains(path));
        self.hard_link_block_restore_modes
            .retain(|path, _| current.contains(path));
        self.decrypted_directory_signatures
            .retain(|path, _| current_directories.contains(path));
        self.decrypted_directory_metadata_hashes
            .retain(|path, _| current_directories.contains(path));
        let pending_writeback_count = self.pending_writebacks.len();
        self.pending_writebacks
            .retain(|path, _| current.contains(path) || current_directories.contains(path));
        if self.pending_writebacks.len() != pending_writeback_count {
            self.pending_writebacks_dirty = true;
        }

        Ok(())
    }

    async fn sync_decrypted_directory<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        encrypted_root: &Path,
        mount_root: &Path,
        directory_path: &Path,
    ) -> Result<(), MountSyncError> {
        if directory_path == mount_root {
            return Ok(());
        }

        let metadata = fs::metadata(directory_path)?;
        let signature = FileSignature::from_metadata(&metadata);
        let encrypted_path =
            encrypted_directory_metadata_path_for(encrypted_root, mount_root, directory_path)?;
        let encrypted_exists = encrypted_path.exists();

        // If the sidecar was previously tracked but is now externally deleted (e.g. by the
        // File Provider tracker on a mounted-side delete), propagate the deletion back to the
        // enrolled/mounted directory instead of re-creating the sidecar.
        if !encrypted_exists
            && self
                .encrypted_directory_signatures
                .contains_key(&encrypted_path)
        {
            debug!(
                "Encrypted sidecar {} was externally deleted while enrolled directory {} still exists — propagating delete",
                encrypted_path.display(),
                directory_path.display()
            );
            self.encrypted_directory_signatures.remove(&encrypted_path);
            self.clear_decrypted_directory_tracking(directory_path);
            self.clear_pending_writeback(directory_path);
            self.clear_pending_refresh(directory_path);
            match fs::remove_dir_all(directory_path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    warn!(
                        "Failed to remove enrolled directory {} after external sidecar deletion: {}",
                        directory_path.display(),
                        err
                    );
                }
            }
            return Ok(());
        }

        if !self.should_sync_directory_metadata(encrypted_root, mount_root, directory_path) {
            self.decrypted_directory_signatures
                .insert(directory_path.to_path_buf(), signature);
            self.refresh_decrypted_directory_metadata_hash(directory_path);
            self.clear_pending_writeback(directory_path);
            return Ok(());
        }

        let current_hash = capture_platform_metadata_hash(directory_path);
        let metadata_changed = match (
            self.decrypted_directory_metadata_hashes.get(directory_path),
            current_hash.as_ref(),
        ) {
            (None, None) => false,
            (Some(previous), Some(current)) => previous != current,
            _ => true,
        };
        let needs_encrypt = !encrypted_exists
            || metadata_changed
            || !self
                .decrypted_directory_signatures
                .contains_key(directory_path);

        if needs_encrypt {
            self.record_pending_writeback(directory_path, &encrypted_path, None);
            if self.mount_readonly_active {
                let err = low_space_readonly_error(directory_path);
                self.record_pending_writeback(directory_path, &encrypted_path, Some(&err));
            } else {
                match self
                    .encrypt_directory_metadata(crypto, mount_root, directory_path, &encrypted_path)
                    .await
                {
                    Ok(encrypted_signature) => {
                        self.encrypted_directory_signatures
                            .insert(encrypted_path.clone(), encrypted_signature);
                        self.clear_pending_writeback(directory_path);
                    }
                    Err(err) if is_low_space_error(&err) => {
                        self.record_pending_writeback(directory_path, &encrypted_path, Some(&err));
                        warn!(
                            "Low-space condition deferred directory metadata writeback for {}: {}",
                            directory_path.display(),
                            err
                        );
                    }
                    Err(err) => {
                        self.record_pending_writeback(directory_path, &encrypted_path, Some(&err));
                        return Err(err);
                    }
                }
            }
        } else {
            self.clear_pending_writeback(directory_path);
        }

        self.decrypted_directory_signatures
            .insert(directory_path.to_path_buf(), signature);
        self.refresh_decrypted_directory_metadata_hash(directory_path);
        if self
            .encrypted_directory_signatures
            .get(&encrypted_path)
            .is_none()
            && encrypted_exists
        {
            if let Ok(meta) = encrypted_path.metadata() {
                let sig = FileSignature::from_metadata(&meta);
                self.encrypted_directory_signatures
                    .insert(encrypted_path.clone(), sig);
            }
        }

        Ok(())
    }

    async fn encrypt_directory_metadata<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        mount_root: &Path,
        directory_path: &Path,
        encrypted_path: &Path,
    ) -> Result<FileSignature, MountSyncError> {
        if self.mount_readonly_active {
            return Err(low_space_readonly_error(directory_path));
        }

        let relative = directory_path.strip_prefix(mount_root).map_err(|_| {
            MountSyncError::Format(format!(
                "Directory {} is outside mount root",
                directory_path.display()
            ))
        })?;
        let aad_label = normalize_relative_path(relative);
        let original_name = directory_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|value| value.to_string());
        let platform_metadata = capture_platform_metadata(directory_path);

        let ciphertext_budget =
            LOW_SPACE_DIRECTORY_CREATE_BYTES.saturating_add(LOW_SPACE_ATOMIC_WRITE_OVERHEAD_BYTES);
        self.ensure_space_budget(
            encrypted_path,
            ciphertext_budget,
            LOW_SPACE_WARNING_RESERVE_BYTES,
            "directory metadata writeback",
        )?;
        if let Some(journal_path) = self.journal_budget_path() {
            self.ensure_space_budget(
                journal_path,
                LOW_SPACE_JOURNAL_RESERVE_BYTES,
                LOW_SPACE_JOURNAL_RESERVE_BYTES,
                "pending writeback journal",
            )?;
        }

        let existing_file_id = if encrypted_path.exists() {
            parse_encrypted_file(encrypted_path)
                .ok()
                .map(|parsed| parsed.metadata.file_id)
        } else {
            None
        };
        let result = if let Some(ref file_id) = existing_file_id {
            crypto
                .encrypt_file_with_id(&aad_label, b"", file_id)
                .await?
        } else {
            crypto.encrypt_file(&aad_label, b"").await?
        };

        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let header = SerializedEncryptedHeader {
            file_id: &result.file_id,
            file_path: &result.file_path,
            group_id: result.group_id,
            epoch_id: result.epoch_id,
            header_version: result.header_version.unwrap_or(1),
            wrapped_file_key: result
                .wrapped_file_key
                .as_ref()
                .ok_or_else(|| MountSyncError::Format("Missing wrapped_file_key".into()))?,
            key_wrap_nonce: result
                .key_wrap_nonce
                .as_ref()
                .ok_or_else(|| MountSyncError::Format("Missing key_wrap_nonce".into()))?,
            key_wrap_aad_hash: result
                .key_wrap_aad_hash
                .as_ref()
                .ok_or_else(|| MountSyncError::Format("Missing key_wrap_aad_hash".into()))?,
            content_nonce: result
                .content_nonce
                .as_ref()
                .ok_or_else(|| MountSyncError::Format("Missing content_nonce".into()))?,
            content_chunk_size: result.content_chunk_size,
            original_size: 0,
            encrypted_size: result.encrypted_size,
            encrypted_at: result.created_at,
            original_name: original_name.as_deref(),
            platform_metadata: platform_metadata.as_ref(),
            sparse_metadata: None,
        };

        Self::write_encrypted_file_atomic(encrypted_path, &header, &result.encrypted_content)?;

        let mut integrity_hash = [0u8; 32];
        integrity_hash.copy_from_slice(&Sha256::digest([]));
        let metadata_record = Self::build_metadata_record(
            result.file_path.clone(),
            result.file_id.clone(),
            result.group_id,
            result.epoch_id,
            result.header_version,
            result.wrapped_file_key.clone(),
            result.key_wrap_nonce.clone(),
            result.key_wrap_aad_hash.clone(),
            result.content_nonce.clone(),
            result.content_chunk_size,
            0,
            integrity_hash,
            result.encrypted_size,
        );
        match crypto
            .coverage_store_metadata(metadata_record.clone())
            .await
        {
            Ok(()) => {
                self.clear_pending_metadata(encrypted_path);
            }
            Err(err) => {
                warn!(
                    "Coverage metadata write failed for {}: {}",
                    encrypted_path.display(),
                    err
                );
                self.record_pending_metadata(encrypted_path, metadata_record);
            }
        }

        self.remember_decrypted_directory_metadata_hash(directory_path, platform_metadata.as_ref());

        Ok(encrypted_path
            .metadata()
            .map(|meta| FileSignature::from_metadata(&meta))
            .unwrap_or(ZERO_SIGNATURE))
    }

    async fn encrypt_decrypted_file<C: MountCrypto + ?Sized>(
        &mut self,
        crypto: &C,
        mount_root: &Path,
        encrypted_root: &Path,
        decrypted_path: &Path,
        encrypted_path: &Path,
    ) -> Result<(FileSignature, String), MountSyncError> {
        if self.mount_readonly_active {
            return Err(low_space_readonly_error(decrypted_path));
        }

        let relative = decrypted_path.strip_prefix(mount_root).map_err(|_| {
            MountSyncError::Format(format!(
                "Decrypted file {} is outside mount root",
                decrypted_path.display()
            ))
        })?;

        let pre_meta = fs::metadata(decrypted_path)?;
        let pre_signature = FileSignature::from_metadata(&pre_meta);

        // Use normalized relative path so file IDs remain stable across devices
        let aad_label = normalize_relative_path(relative);

        let mut desired_file_id = read_file_id_xattr(decrypted_path);
        if let Some(ref file_id) = desired_file_id {
            if let Some(existing_path) = self.file_id_to_mount_path.get(file_id) {
                if existing_path.as_path() != decrypted_path && existing_path.exists() {
                    warn!(
                        "Duplicate file_id {} detected for {} (already mapped to {}). Assigning new file_id.",
                        file_id,
                        decrypted_path.display(),
                        existing_path.display()
                    );
                    let _ = clear_file_id_xattr(decrypted_path);
                    desired_file_id = None;
                }
            }
        }

        let existing_file_id = if encrypted_path.exists() {
            match parse_encrypted_file_with_root(encrypted_root, encrypted_path) {
                Ok(parsed) => Some(parsed.metadata.file_id),
                Err(err) => {
                    warn!(
                        "Failed to parse existing encrypted file {} for stable file_id: {}",
                        encrypted_path.display(),
                        err
                    );
                    None
                }
            }
        } else {
            None
        };

        if desired_file_id.is_none() {
            if let Some(ref file_id) = existing_file_id {
                if let Err(err) = write_file_id_xattr(decrypted_path, file_id) {
                    debug!(
                        "Failed to persist file_id xattr for {}: {}",
                        decrypted_path.display(),
                        err
                    );
                }
            }
            desired_file_id = existing_file_id.clone();
        }

        let original_name = read_original_name_xattr(decrypted_path).or_else(|| {
            decrypted_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
        });
        let platform_metadata = capture_platform_metadata(decrypted_path);
        let logical_content_size = pre_meta.len();
        let sparse_metadata = sparse_file_metadata(decrypted_path, &pre_meta)?;

        let ciphertext_budget = if let Some(sparse_metadata) = sparse_metadata.as_ref() {
            let chunk_size = self
                .stream_chunk_size()
                .unwrap_or(STREAM_CHUNK_SIZE_BYTES as usize);
            let packed_size = sparse_metadata.packed_size();
            let ciphertext_size = chunked_encrypted_size(packed_size, chunk_size)
                .map_err(|err| MountSyncError::Format(err.to_string()))?;
            packed_size
                .saturating_add(ciphertext_size.saturating_mul(2))
                .saturating_add(LOW_SPACE_ATOMIC_WRITE_OVERHEAD_BYTES)
        } else {
            logical_content_size.saturating_add(LOW_SPACE_ATOMIC_WRITE_OVERHEAD_BYTES)
        };
        self.ensure_space_budget(
            encrypted_path,
            ciphertext_budget,
            LOW_SPACE_WARNING_RESERVE_BYTES,
            "encrypted writeback",
        )?;
        if let Some(journal_path) = self.journal_budget_path() {
            self.ensure_space_budget(
                journal_path,
                LOW_SPACE_JOURNAL_RESERVE_BYTES,
                LOW_SPACE_JOURNAL_RESERVE_BYTES,
                "pending writeback journal",
            )?;
        }

        if let Some(sparse_metadata) = sparse_metadata.as_ref() {
            let parent = encrypted_path.parent().ok_or_else(|| {
                MountSyncError::Format(format!(
                    "Encrypted file path {} has no parent directory",
                    encrypted_path.display()
                ))
            })?;
            let tmp_dir = parent.join(ENCRYPTED_TMP_DIR_NAME);
            fs::create_dir_all(&tmp_dir)?;
            let file_name = encrypted_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "encrypted".to_string());
            let temp_id = Uuid::new_v4();
            let packed_path = tmp_dir.join(format!("sparse-packed-{}.{}", temp_id, file_name));
            let staged_encrypted_path =
                tmp_dir.join(format!("sparse-cipher-{}.{}", temp_id, file_name));
            let chunk_size = self
                .stream_chunk_size()
                .unwrap_or(STREAM_CHUNK_SIZE_BYTES as usize);

            if let Err(err) =
                copy_sparse_extents_to_dense_file(decrypted_path, &packed_path, sparse_metadata)
            {
                let _ = fs::remove_file(&packed_path);
                return Err(err);
            }

            let streaming_result = if let Some(ref file_id) = desired_file_id {
                match crypto
                    .encrypt_file_streaming_with_id(
                        &aad_label,
                        &packed_path,
                        &staged_encrypted_path,
                        original_name.as_deref(),
                        platform_metadata.as_ref(),
                        file_id,
                        chunk_size,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        let _ = fs::remove_file(&packed_path);
                        let _ = fs::remove_file(&staged_encrypted_path);
                        return Err(err);
                    }
                }
            } else {
                match crypto
                    .encrypt_file_streaming(
                        &aad_label,
                        &packed_path,
                        &staged_encrypted_path,
                        original_name.as_deref(),
                        platform_metadata.as_ref(),
                        chunk_size,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        let _ = fs::remove_file(&packed_path);
                        let _ = fs::remove_file(&staged_encrypted_path);
                        return Err(err);
                    }
                }
            };
            let _ = fs::remove_file(&packed_path);

            let post_meta = fs::metadata(decrypted_path)?;
            let post_signature = FileSignature::from_metadata(&post_meta);
            if pre_signature != post_signature {
                let _ = fs::remove_file(&staged_encrypted_path);
                return Err(MountSyncError::UnstableFile(format!(
                    "File {} changed during sparse encryption; deferring encryption",
                    decrypted_path.display()
                )));
            }

            let header = SerializedEncryptedHeader {
                file_id: &streaming_result.metadata.file_id,
                file_path: &streaming_result.metadata.file_path,
                group_id: streaming_result.metadata.group_id,
                epoch_id: streaming_result.metadata.epoch_id,
                header_version: streaming_result.metadata.header_version.unwrap_or(1),
                wrapped_file_key: streaming_result
                    .metadata
                    .wrapped_file_key
                    .as_ref()
                    .ok_or_else(|| MountSyncError::Format("Missing wrapped_file_key".into()))?,
                key_wrap_nonce: streaming_result
                    .metadata
                    .key_wrap_nonce
                    .as_ref()
                    .ok_or_else(|| MountSyncError::Format("Missing key_wrap_nonce".into()))?,
                key_wrap_aad_hash: streaming_result
                    .metadata
                    .key_wrap_aad_hash
                    .as_ref()
                    .ok_or_else(|| MountSyncError::Format("Missing key_wrap_aad_hash".into()))?,
                content_nonce: streaming_result
                    .metadata
                    .content_nonce
                    .as_ref()
                    .ok_or_else(|| MountSyncError::Format("Missing content_nonce".into()))?,
                content_chunk_size: streaming_result.metadata.content_chunk_size,
                original_size: logical_content_size,
                encrypted_size: streaming_result.metadata.encrypted_size,
                encrypted_at: streaming_result.metadata.created_at,
                original_name: original_name.as_deref(),
                platform_metadata: platform_metadata.as_ref(),
                sparse_metadata: Some(sparse_metadata),
            };
            if let Err(err) = rewrite_encrypted_file_atomic_from_ciphertext(
                &staged_encrypted_path,
                encrypted_path,
                &header,
            ) {
                let _ = fs::remove_file(&staged_encrypted_path);
                return Err(err);
            }
            let _ = fs::remove_file(&staged_encrypted_path);

            if let Err(err) =
                write_file_id_xattr(decrypted_path, &streaming_result.metadata.file_id)
            {
                debug!(
                    "Failed to persist file_id xattr for {}: {}",
                    decrypted_path.display(),
                    err
                );
            }

            let integrity_hash = hash_file(decrypted_path)?;
            let metadata_record = Self::build_metadata_record(
                streaming_result.metadata.file_path.clone(),
                streaming_result.metadata.file_id.clone(),
                streaming_result.metadata.group_id,
                streaming_result.metadata.epoch_id,
                streaming_result.metadata.header_version,
                streaming_result.metadata.wrapped_file_key.clone(),
                streaming_result.metadata.key_wrap_nonce.clone(),
                streaming_result.metadata.key_wrap_aad_hash.clone(),
                streaming_result.metadata.content_nonce.clone(),
                streaming_result.metadata.content_chunk_size,
                logical_content_size,
                integrity_hash,
                streaming_result.metadata.encrypted_size,
            );

            match crypto
                .coverage_store_metadata(metadata_record.clone())
                .await
            {
                Ok(()) => {
                    self.clear_pending_metadata(encrypted_path);
                }
                Err(err) => {
                    warn!(
                        "Coverage metadata write failed for {}: {}",
                        encrypted_path.display(),
                        err
                    );
                    self.record_pending_metadata(encrypted_path, metadata_record);
                }
            }

            let signature = encrypted_path
                .metadata()
                .map(|meta| FileSignature::from_metadata(&meta))
                .unwrap_or(ZERO_SIGNATURE);

            self.decrypted_hashes
                .insert(decrypted_path.to_path_buf(), integrity_hash);
            self.remember_decrypted_metadata_hash(decrypted_path, platform_metadata.as_ref());

            return Ok((signature, streaming_result.metadata.file_id));
        }

        if self.should_stream_file(pre_meta.len()) {
            if let Some(chunk_size) = self.stream_chunk_size() {
                let streaming_result = if let Some(ref file_id) = desired_file_id {
                    crypto
                        .encrypt_file_streaming_with_id(
                            &aad_label,
                            decrypted_path,
                            encrypted_path,
                            original_name.as_deref(),
                            platform_metadata.as_ref(),
                            file_id,
                            chunk_size,
                        )
                        .await?
                } else {
                    crypto
                        .encrypt_file_streaming(
                            &aad_label,
                            decrypted_path,
                            encrypted_path,
                            original_name.as_deref(),
                            platform_metadata.as_ref(),
                            chunk_size,
                        )
                        .await?
                };

                let post_meta = fs::metadata(decrypted_path)?;
                let post_signature = FileSignature::from_metadata(&post_meta);
                if pre_signature != post_signature {
                    let _ = fs::remove_file(encrypted_path);
                    return Err(MountSyncError::UnstableFile(format!(
                        "File {} changed during streaming encryption; deferring encryption",
                        decrypted_path.display()
                    )));
                }

                if let Err(err) =
                    write_file_id_xattr(decrypted_path, &streaming_result.metadata.file_id)
                {
                    debug!(
                        "Failed to persist file_id xattr for {}: {}",
                        decrypted_path.display(),
                        err
                    );
                }

                let metadata_record = Self::build_metadata_record(
                    streaming_result.metadata.file_path.clone(),
                    streaming_result.metadata.file_id.clone(),
                    streaming_result.metadata.group_id,
                    streaming_result.metadata.epoch_id,
                    streaming_result.metadata.header_version,
                    streaming_result.metadata.wrapped_file_key.clone(),
                    streaming_result.metadata.key_wrap_nonce.clone(),
                    streaming_result.metadata.key_wrap_aad_hash.clone(),
                    streaming_result.metadata.content_nonce.clone(),
                    streaming_result.metadata.content_chunk_size,
                    streaming_result.metadata.content_size,
                    streaming_result.integrity_hash,
                    streaming_result.metadata.encrypted_size,
                );

                match crypto
                    .coverage_store_metadata(metadata_record.clone())
                    .await
                {
                    Ok(()) => {
                        self.clear_pending_metadata(encrypted_path);
                    }
                    Err(err) => {
                        warn!(
                            "Coverage metadata write failed for {}: {}",
                            encrypted_path.display(),
                            err
                        );
                        self.record_pending_metadata(encrypted_path, metadata_record);
                    }
                }

                let signature = encrypted_path
                    .metadata()
                    .map(|meta| FileSignature::from_metadata(&meta))
                    .unwrap_or(ZERO_SIGNATURE);

                self.decrypted_hashes.insert(
                    decrypted_path.to_path_buf(),
                    streaming_result.integrity_hash,
                );
                self.remember_decrypted_metadata_hash(decrypted_path, platform_metadata.as_ref());

                return Ok((signature, streaming_result.metadata.file_id));
            }
        }

        let file_bytes = fs::read(decrypted_path)?;
        let post_meta = fs::metadata(decrypted_path)?;
        let post_signature = FileSignature::from_metadata(&post_meta);
        if pre_signature != post_signature {
            return Err(MountSyncError::UnstableFile(format!(
                "File {} changed during read (likely mid-write); deferring encryption",
                decrypted_path.display()
            )));
        }

        let result = if let Some(ref file_id) = desired_file_id {
            crypto
                .encrypt_file_with_id(&aad_label, &file_bytes, file_id)
                .await?
        } else {
            crypto.encrypt_file(&aad_label, &file_bytes).await?
        };

        if let Err(err) = write_file_id_xattr(decrypted_path, &result.file_id) {
            debug!(
                "Failed to persist file_id xattr for {}: {}",
                decrypted_path.display(),
                err
            );
        }

        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let header = SerializedEncryptedHeader {
            file_id: &result.file_id,
            file_path: &result.file_path,
            group_id: result.group_id,
            epoch_id: result.epoch_id,
            header_version: result.header_version.unwrap_or(1),
            wrapped_file_key: result
                .wrapped_file_key
                .as_ref()
                .ok_or_else(|| MountSyncError::Format("Missing wrapped_file_key".into()))?,
            key_wrap_nonce: result
                .key_wrap_nonce
                .as_ref()
                .ok_or_else(|| MountSyncError::Format("Missing key_wrap_nonce".into()))?,
            key_wrap_aad_hash: result
                .key_wrap_aad_hash
                .as_ref()
                .ok_or_else(|| MountSyncError::Format("Missing key_wrap_aad_hash".into()))?,
            content_nonce: result
                .content_nonce
                .as_ref()
                .ok_or_else(|| MountSyncError::Format("Missing content_nonce".into()))?,
            content_chunk_size: result.content_chunk_size,
            original_size: result.content_size,
            encrypted_size: result.encrypted_size,
            encrypted_at: result.created_at,
            original_name: original_name.as_deref(),
            platform_metadata: platform_metadata.as_ref(),
            sparse_metadata: None,
        };

        Self::write_encrypted_file_atomic(encrypted_path, &header, &result.encrypted_content)?;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&Sha256::digest(&file_bytes));
        let metadata_record = Self::build_metadata_record(
            result.file_path.clone(),
            result.file_id.clone(),
            result.group_id,
            result.epoch_id,
            result.header_version,
            result.wrapped_file_key.clone(),
            result.key_wrap_nonce.clone(),
            result.key_wrap_aad_hash.clone(),
            result.content_nonce.clone(),
            result.content_chunk_size,
            file_bytes.len() as u64,
            hash,
            result.encrypted_size,
        );
        match crypto
            .coverage_store_metadata(metadata_record.clone())
            .await
        {
            Ok(()) => {
                self.clear_pending_metadata(encrypted_path);
            }
            Err(err) => {
                warn!(
                    "Coverage metadata write failed for {}: {}",
                    encrypted_path.display(),
                    err
                );
                self.record_pending_metadata(encrypted_path, metadata_record);
            }
        }

        let signature = encrypted_path
            .metadata()
            .map(|meta| FileSignature::from_metadata(&meta))
            .unwrap_or(ZERO_SIGNATURE);

        self.decrypted_hashes
            .insert(decrypted_path.to_path_buf(), hash);
        self.remember_decrypted_metadata_hash(decrypted_path, platform_metadata.as_ref());

        let _ = encrypted_root;
        Ok((signature, result.file_id))
    }

    fn record_pending_writeback(
        &mut self,
        mount_path: &Path,
        encrypted_path: &Path,
        err: Option<&MountSyncError>,
    ) {
        let now = Utc::now();
        let new_last_error = err.map(|value| value.to_string());
        let new_low_space = err.map(is_low_space_error).unwrap_or(false);
        let mut changed = false;

        match self.pending_writebacks.get_mut(mount_path) {
            Some(existing) => {
                if existing.encrypted_path != encrypted_path {
                    existing.encrypted_path = encrypted_path.to_path_buf();
                    changed = true;
                }
                if existing.last_error != new_last_error {
                    existing.last_error = new_last_error.clone();
                    changed = true;
                }
                if existing.low_space != new_low_space {
                    existing.low_space = new_low_space;
                    changed = true;
                }
                if existing.last_observed_at != now {
                    existing.last_observed_at = now;
                    changed = true;
                }
            }
            None => {
                self.pending_writebacks.insert(
                    mount_path.to_path_buf(),
                    PendingWriteback {
                        encrypted_path: encrypted_path.to_path_buf(),
                        last_error: new_last_error,
                        low_space: new_low_space,
                        first_observed_at: now,
                        last_observed_at: now,
                    },
                );
                changed = true;
            }
        }

        if changed {
            self.pending_writebacks_dirty = true;
            self.flush_pending_writebacks();
        }
    }

    fn clear_pending_writeback(&mut self, mount_path: &Path) {
        if self.pending_writebacks.remove(mount_path).is_some() {
            self.pending_writebacks_dirty = true;
            self.flush_pending_writebacks();
        }
    }

    fn record_pending_refresh(
        &mut self,
        mount_path: &Path,
        encrypted_path: &Path,
        err: &MountSyncError,
    ) {
        let new_last_error = Some(err.to_string());
        let mut changed = false;

        match self.pending_refreshes.get_mut(mount_path) {
            Some(existing) => {
                if existing.encrypted_path != encrypted_path {
                    existing.encrypted_path = encrypted_path.to_path_buf();
                    changed = true;
                }
                if existing.last_error != new_last_error {
                    existing.last_error = new_last_error.clone();
                    changed = true;
                }
            }
            None => {
                self.pending_refreshes.insert(
                    mount_path.to_path_buf(),
                    PendingRefresh {
                        encrypted_path: encrypted_path.to_path_buf(),
                        last_error: new_last_error,
                    },
                );
                changed = true;
            }
        }

        if changed {
            self.pending_refreshes_dirty = true;
            self.flush_pending_refreshes();
        }
    }

    fn clear_pending_refresh(&mut self, mount_path: &Path) {
        if self.pending_refreshes.remove(mount_path).is_some() {
            self.pending_refreshes_dirty = true;
            self.flush_pending_refreshes();
        }
    }

    fn record_pending_metadata(&mut self, encrypted_path: &Path, metadata: FileMetadataData) {
        self.pending_metadata
            .insert(encrypted_path.to_path_buf(), metadata);
        self.pending_metadata_dirty = true;
        self.flush_pending_metadata();
    }

    fn clear_pending_metadata(&mut self, encrypted_path: &Path) {
        if self.pending_metadata.remove(encrypted_path).is_some() {
            self.pending_metadata_dirty = true;
            self.flush_pending_metadata();
        }
    }

    fn rebuild_mount_collision_index(&mut self, mount_root: &Path) {
        self.mount_collision_keys.clear();
        let mut seen: HashSet<PathBuf> = HashSet::new();
        for path in self
            .decrypted_signatures
            .keys()
            .chain(self.file_id_to_mount_path.values())
        {
            if !seen.insert(path.clone()) {
                continue;
            }
            if !path.exists() {
                continue;
            }
            if let Some(key) = mount_collision_key(mount_root, path) {
                self.mount_collision_keys
                    .entry(key)
                    .or_insert_with(|| path.clone());
            }
        }
    }

    fn resolve_mount_collision_target(
        &mut self,
        mount_root: &Path,
        target: &Path,
        file_id: &str,
    ) -> PathBuf {
        let key = match mount_collision_key(mount_root, target) {
            Some(key) => key,
            None => return target.to_path_buf(),
        };

        if target.exists() {
            if let Some(existing_id) = read_file_id_xattr(target) {
                if existing_id == file_id {
                    self.mount_collision_keys
                        .entry(key)
                        .or_insert_with(|| target.to_path_buf());
                    return target.to_path_buf();
                }
            }

            let resolved = collision_safe_path(target, file_id);
            let resolved_key =
                mount_collision_key(mount_root, &resolved).unwrap_or_else(|| key.clone());
            self.mount_collision_keys
                .insert(resolved_key, resolved.clone());
            warn!(
                "Mount path collision for {} (file_id: {}), writing to {}",
                target.display(),
                file_id,
                resolved.display()
            );
            return resolved;
        }

        if let Some(existing_path) = self.mount_collision_keys.get(&key) {
            if existing_path.as_path() != target {
                let resolved = collision_safe_path(target, file_id);
                let resolved_key =
                    mount_collision_key(mount_root, &resolved).unwrap_or_else(|| key.clone());
                self.mount_collision_keys
                    .insert(resolved_key, resolved.clone());
                warn!(
                    "Mount path collision for {} (file_id: {}), writing to {}",
                    target.display(),
                    file_id,
                    resolved.display()
                );
                return resolved;
            }
        }

        self.mount_collision_keys.insert(key, target.to_path_buf());
        target.to_path_buf()
    }

    async fn retry_pending_metadata<C: MountCrypto + ?Sized>(&mut self, crypto: &C) {
        if self.pending_metadata.is_empty() {
            return;
        }

        let pending: Vec<(PathBuf, FileMetadataData)> = self
            .pending_metadata
            .iter()
            .map(|(path, metadata)| (path.clone(), metadata.clone()))
            .collect();

        let mut resolved: Vec<PathBuf> = Vec::new();
        for (path, metadata) in pending {
            match crypto.coverage_store_metadata(metadata).await {
                Ok(()) => resolved.push(path),
                Err(err) => {
                    warn!(
                        "Coverage metadata retry failed for {}: {}",
                        path.display(),
                        err
                    );
                }
            }
        }

        for path in resolved {
            self.clear_pending_metadata(&path);
        }
    }

    fn load_pending_deletions(&mut self) -> Result<(), MountSyncError> {
        let path = match self.pending_deletion_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(MountSyncError::Io(err)),
        };

        let records: Vec<PendingDeletionRecord> = serde_json::from_slice(&data).map_err(|e| {
            MountSyncError::Format(format!("Failed to parse pending deletions: {}", e))
        })?;

        self.pending_deletions.clear();
        for record in records {
            self.pending_deletions.insert(
                record.encrypted_path.clone(),
                PendingDeletion {
                    mount_path: record.mount_path,
                    first_missing_time: Instant::now(),
                    consecutive_missing_scans: record.consecutive_missing_scans,
                    had_healthy_scan: record.had_healthy_scan,
                },
            );
        }

        Ok(())
    }

    fn flush_pending_deletions(&mut self) {
        if !self.pending_deletions_dirty {
            return;
        }

        match self.persist_pending_deletions() {
            Ok(()) => {
                self.pending_deletions_dirty = false;
            }
            Err(err) => {
                warn!("Failed to persist pending deletions: {}", err);
            }
        }
    }

    fn persist_pending_deletions(&self) -> Result<(), MountSyncError> {
        let path = match self.pending_deletion_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let records: Vec<PendingDeletionRecord> = self
            .pending_deletions
            .iter()
            .map(|(encrypted_path, pending)| PendingDeletionRecord {
                encrypted_path: encrypted_path.clone(),
                mount_path: pending.mount_path.clone(),
                consecutive_missing_scans: pending.consecutive_missing_scans,
                had_healthy_scan: pending.had_healthy_scan,
            })
            .collect();

        let data = serde_json::to_vec_pretty(&records).map_err(|e| {
            MountSyncError::Format(format!("Failed to serialize pending deletions: {}", e))
        })?;

        Self::write_atomic_bytes(path, &data)?;

        Ok(())
    }

    fn load_pending_orphans(&mut self) -> Result<(), MountSyncError> {
        let path = match self.pending_orphan_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(MountSyncError::Io(err)),
        };

        let records: Vec<PendingOrphanRecord> = serde_json::from_slice(&data).map_err(|e| {
            MountSyncError::Format(format!("Failed to parse pending orphans: {}", e))
        })?;

        self.pending_orphans.clear();
        for record in records {
            self.pending_orphans.insert(
                record.mount_path,
                PendingOrphan {
                    encrypted_path: record.encrypted_path,
                    consecutive_missing_scans: record.consecutive_missing_scans,
                    had_healthy_scan: record.had_healthy_scan,
                },
            );
        }

        Ok(())
    }

    fn load_pending_writebacks(&mut self) -> Result<(), MountSyncError> {
        let path = match self.pending_writeback_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(MountSyncError::Io(err)),
        };

        let records: Vec<PendingWritebackRecord> = serde_json::from_slice(&data).map_err(|e| {
            MountSyncError::Format(format!("Failed to parse pending writebacks: {}", e))
        })?;

        self.pending_writebacks.clear();
        for record in records {
            self.pending_writebacks.insert(
                record.mount_path,
                PendingWriteback {
                    encrypted_path: record.encrypted_path,
                    last_error: record.last_error,
                    low_space: record.low_space,
                    first_observed_at: record.first_observed_at,
                    last_observed_at: record.last_observed_at.max(record.first_observed_at),
                },
            );
        }

        Ok(())
    }

    fn load_pending_refreshes(&mut self) -> Result<(), MountSyncError> {
        let path = match self.pending_refresh_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(MountSyncError::Io(err)),
        };

        let records: Vec<PendingRefreshRecord> = serde_json::from_slice(&data).map_err(|e| {
            MountSyncError::Format(format!("Failed to parse pending refreshes: {}", e))
        })?;

        self.pending_refreshes.clear();
        for record in records {
            self.pending_refreshes.insert(
                record.mount_path,
                PendingRefresh {
                    encrypted_path: record.encrypted_path,
                    last_error: record.last_error,
                },
            );
        }

        Ok(())
    }

    fn load_pending_open_unlinked(&mut self) -> Result<(), MountSyncError> {
        let path = match self.pending_open_unlinked_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(MountSyncError::Io(err)),
        };

        let records: Vec<PendingOpenUnlinkedRecord> =
            serde_json::from_slice(&data).map_err(|e| {
                MountSyncError::Format(format!(
                    "Failed to parse pending deleted-open journal: {}",
                    e
                ))
            })?;

        self.pending_open_unlinked.clear();
        for record in records {
            self.pending_open_unlinked.insert(
                record.mount_path,
                PendingOpenUnlinked {
                    encrypted_path: record.encrypted_path,
                    encrypted_version_exists: record.encrypted_version_exists,
                    had_unsynced_local_writeback: record.had_unsynced_local_writeback,
                    first_seen_at: record.first_seen_at,
                    last_seen_at: record.last_seen_at,
                    owners: record.owners,
                },
            );
        }

        Ok(())
    }

    fn load_pending_metadata(&mut self) -> Result<(), MountSyncError> {
        let path = match self.pending_metadata_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(MountSyncError::Io(err)),
        };

        let records: Vec<PendingMetadataRecord> = serde_json::from_slice(&data).map_err(|e| {
            MountSyncError::Format(format!("Failed to parse pending metadata: {}", e))
        })?;

        self.pending_metadata.clear();
        for record in records {
            self.pending_metadata
                .insert(record.encrypted_path, record.metadata);
        }

        Ok(())
    }

    fn load_sync_baseline(&mut self) -> Result<(), MountSyncError> {
        let path = match self.sync_baseline_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(MountSyncError::Io(err)),
        };

        let record: SyncBaselineRecord = serde_json::from_slice(&data)
            .map_err(|e| MountSyncError::Format(format!("Failed to parse sync baseline: {}", e)))?;

        self.encrypted_signatures.clear();
        self.decrypted_signatures.clear();
        self.path_mapping.clear();
        self.file_id_to_mount_path.clear();
        self.decrypted_hashes.clear();
        self.decrypted_metadata_hashes.clear();

        for entry in record.encrypted_signatures {
            self.encrypted_signatures
                .insert(entry.encrypted_path, entry.signature);
        }
        for entry in record.decrypted_signatures {
            self.decrypted_signatures
                .insert(entry.mount_path, entry.signature);
        }
        for entry in record.path_mappings {
            self.path_mapping
                .insert(entry.encrypted_path, entry.mount_path);
        }
        for entry in record.file_id_mappings {
            self.file_id_to_mount_path
                .insert(entry.file_id, entry.mount_path);
        }
        for entry in record.decrypted_hashes {
            self.decrypted_hashes.insert(entry.mount_path, entry.hash);
        }
        for entry in record.decrypted_metadata_hashes {
            self.decrypted_metadata_hashes
                .insert(entry.mount_path, entry.hash);
        }

        Ok(())
    }

    fn flush_pending_orphans(&mut self) {
        if !self.pending_orphans_dirty {
            return;
        }

        match self.persist_pending_orphans() {
            Ok(()) => {
                self.pending_orphans_dirty = false;
            }
            Err(err) => {
                warn!("Failed to persist pending orphans: {}", err);
            }
        }
    }

    fn flush_pending_writebacks(&mut self) {
        if !self.pending_writebacks_dirty {
            return;
        }

        match self.persist_pending_writebacks() {
            Ok(()) => {
                self.pending_writebacks_dirty = false;
            }
            Err(err) => {
                warn!("Failed to persist pending writebacks: {}", err);
            }
        }
    }

    fn flush_pending_refreshes(&mut self) {
        if !self.pending_refreshes_dirty {
            return;
        }

        match self.persist_pending_refreshes() {
            Ok(()) => {
                self.pending_refreshes_dirty = false;
            }
            Err(err) => {
                warn!("Failed to persist pending refreshes: {}", err);
            }
        }
    }

    fn flush_pending_open_unlinked(&mut self) {
        if !self.pending_open_unlinked_dirty {
            return;
        }

        match self.persist_pending_open_unlinked() {
            Ok(()) => {
                self.pending_open_unlinked_dirty = false;
            }
            Err(err) => {
                warn!("Failed to persist pending deleted-open journal: {}", err);
            }
        }
    }

    fn flush_pending_metadata(&mut self) {
        if !self.pending_metadata_dirty {
            return;
        }

        match self.persist_pending_metadata() {
            Ok(()) => {
                self.pending_metadata_dirty = false;
            }
            Err(err) => {
                warn!("Failed to persist pending metadata: {}", err);
            }
        }
    }

    fn persist_pending_orphans(&self) -> Result<(), MountSyncError> {
        let path = match self.pending_orphan_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let records: Vec<PendingOrphanRecord> = self
            .pending_orphans
            .iter()
            .map(|(mount_path, pending)| PendingOrphanRecord {
                mount_path: mount_path.clone(),
                encrypted_path: pending.encrypted_path.clone(),
                consecutive_missing_scans: pending.consecutive_missing_scans,
                had_healthy_scan: pending.had_healthy_scan,
            })
            .collect();

        let data = serde_json::to_vec_pretty(&records).map_err(|e| {
            MountSyncError::Format(format!("Failed to serialize pending orphans: {}", e))
        })?;

        Self::write_atomic_bytes(path, &data)?;

        Ok(())
    }

    fn persist_pending_writebacks(&self) -> Result<(), MountSyncError> {
        let path = match self.pending_writeback_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let records: Vec<PendingWritebackRecord> = self
            .pending_writebacks
            .iter()
            .map(|(mount_path, pending)| PendingWritebackRecord {
                mount_path: mount_path.clone(),
                encrypted_path: pending.encrypted_path.clone(),
                last_error: pending.last_error.clone(),
                low_space: pending.low_space,
                first_observed_at: pending.first_observed_at,
                last_observed_at: pending.last_observed_at,
            })
            .collect();

        let data = serde_json::to_vec_pretty(&records).map_err(|e| {
            MountSyncError::Format(format!("Failed to serialize pending writebacks: {}", e))
        })?;

        Self::write_atomic_bytes(path, &data)?;

        Ok(())
    }

    fn persist_pending_refreshes(&self) -> Result<(), MountSyncError> {
        let path = match self.pending_refresh_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let records: Vec<PendingRefreshRecord> = self
            .pending_refreshes
            .iter()
            .map(|(mount_path, pending)| PendingRefreshRecord {
                mount_path: mount_path.clone(),
                encrypted_path: pending.encrypted_path.clone(),
                last_error: pending.last_error.clone(),
            })
            .collect();

        let data = serde_json::to_vec_pretty(&records).map_err(|e| {
            MountSyncError::Format(format!("Failed to serialize pending refreshes: {}", e))
        })?;

        Self::write_atomic_bytes(path, &data)?;

        Ok(())
    }

    fn persist_pending_open_unlinked(&self) -> Result<(), MountSyncError> {
        let path = match self.pending_open_unlinked_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let records: Vec<PendingOpenUnlinkedRecord> = self
            .pending_open_unlinked
            .iter()
            .map(|(mount_path, pending)| PendingOpenUnlinkedRecord {
                mount_path: mount_path.clone(),
                encrypted_path: pending.encrypted_path.clone(),
                encrypted_version_exists: pending.encrypted_version_exists,
                had_unsynced_local_writeback: pending.had_unsynced_local_writeback,
                first_seen_at: pending.first_seen_at,
                last_seen_at: pending.last_seen_at,
                owners: pending.owners.clone(),
            })
            .collect();

        let data = serde_json::to_vec_pretty(&records).map_err(|e| {
            MountSyncError::Format(format!(
                "Failed to serialize pending deleted-open journal: {}",
                e
            ))
        })?;

        Self::write_atomic_bytes(path, &data)?;

        Ok(())
    }

    fn persist_pending_metadata(&self) -> Result<(), MountSyncError> {
        let path = match self.pending_metadata_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let records: Vec<PendingMetadataRecord> = self
            .pending_metadata
            .iter()
            .map(|(encrypted_path, metadata)| PendingMetadataRecord {
                encrypted_path: encrypted_path.clone(),
                metadata: metadata.clone(),
            })
            .collect();

        let data = serde_json::to_vec_pretty(&records).map_err(|e| {
            MountSyncError::Format(format!("Failed to serialize pending metadata: {}", e))
        })?;

        Self::write_atomic_bytes(path, &data)?;

        Ok(())
    }

    pub fn persist_sync_baseline(&self) -> Result<(), MountSyncError> {
        let path = match self.sync_baseline_path.as_ref() {
            Some(path) => path,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let record = SyncBaselineRecord {
            encrypted_signatures: self
                .encrypted_signatures
                .iter()
                .map(
                    |(encrypted_path, signature)| SyncBaselineEncryptedSignatureRecord {
                        encrypted_path: encrypted_path.clone(),
                        signature: *signature,
                    },
                )
                .collect(),
            decrypted_signatures: self
                .decrypted_signatures
                .iter()
                .map(
                    |(mount_path, signature)| SyncBaselineDecryptedSignatureRecord {
                        mount_path: mount_path.clone(),
                        signature: *signature,
                    },
                )
                .collect(),
            path_mappings: self
                .path_mapping
                .iter()
                .map(
                    |(encrypted_path, mount_path)| SyncBaselinePathMappingRecord {
                        encrypted_path: encrypted_path.clone(),
                        mount_path: mount_path.clone(),
                    },
                )
                .collect(),
            file_id_mappings: self
                .file_id_to_mount_path
                .iter()
                .map(|(file_id, mount_path)| SyncBaselineFileIdMappingRecord {
                    file_id: file_id.clone(),
                    mount_path: mount_path.clone(),
                })
                .collect(),
            decrypted_hashes: self
                .decrypted_hashes
                .iter()
                .map(|(mount_path, hash)| SyncBaselineHashRecord {
                    mount_path: mount_path.clone(),
                    hash: *hash,
                })
                .collect(),
            decrypted_metadata_hashes: self
                .decrypted_metadata_hashes
                .iter()
                .map(|(mount_path, hash)| SyncBaselineHashRecord {
                    mount_path: mount_path.clone(),
                    hash: *hash,
                })
                .collect(),
        };

        let data = serde_json::to_vec_pretty(&record).map_err(|e| {
            MountSyncError::Format(format!("Failed to serialize sync baseline: {}", e))
        })?;
        Self::write_atomic_bytes(path, &data)?;
        Ok(())
    }

    fn write_encrypted_file_atomic(
        path: &Path,
        header: &SerializedEncryptedHeader<'_>,
        encrypted_content: &[u8],
    ) -> Result<(), MountSyncError> {
        let parent = path.parent().ok_or_else(|| {
            MountSyncError::Format(format!(
                "Encrypted file path {} has no parent directory",
                path.display()
            ))
        })?;
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "encrypted".to_string());
        let tmp_dir = parent.join(ENCRYPTED_TMP_DIR_NAME);
        fs::create_dir_all(&tmp_dir)?;
        let tmp_name = format!("tmp-{}.{}", Uuid::new_v4(), file_name);
        let tmp_path = tmp_dir.join(tmp_name);

        write_encrypted_file(&tmp_path, header, encrypted_content)
            .map_err(|e| MountSyncError::Format(e.to_string()))?;

        if let Ok(file) = fs::File::open(&tmp_path) {
            let _ = file.sync_all();
        }

        #[cfg(target_os = "windows")]
        {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }

        if let Err(err) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(MountSyncError::Io(err));
        }

        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    pub fn flush_conflict_and_recovery_registries(&mut self, mount_root: &Path) {
        self.flush_conflict_registry(mount_root);
        self.flush_recovery_registry(mount_root);
    }

    fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), MountSyncError> {
        let parent = path.parent().ok_or_else(|| {
            MountSyncError::Format(format!("Path {} has no parent directory", path.display()))
        })?;
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "pending_deletions".to_string());
        let tmp_name = format!("{}.tmp-{}", file_name, Uuid::new_v4());
        let tmp_path = parent.join(tmp_name);

        {
            let mut file = fs::File::create(&tmp_path)?;
            file.write_all(bytes)?;
            let _ = file.sync_all();
        }

        #[cfg(target_os = "windows")]
        {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }

        if let Err(err) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(MountSyncError::Io(err));
        }

        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    fn track_missing_encrypted_directories(
        &mut self,
        encrypted_root: &Path,
        mount_root: &Path,
        expected_directories: &HashSet<PathBuf>,
        protected_missing_paths: &HashSet<PathBuf>,
    ) -> Result<(), MountSyncError> {
        let tracked: Vec<PathBuf> = self
            .decrypted_directory_signatures
            .keys()
            .cloned()
            .collect();
        for tracked_path in tracked {
            if tracked_path == mount_root {
                continue;
            }

            if expected_directories.contains(&tracked_path)
                || protected_missing_paths.contains(&tracked_path)
            {
                continue;
            }

            let encrypted_path =
                encrypted_directory_metadata_path_for(encrypted_root, mount_root, &tracked_path)?;
            if !self
                .encrypted_directory_signatures
                .contains_key(&encrypted_path)
            {
                continue;
            }

            if !tracked_path.exists() {
                self.clear_decrypted_directory_tracking(&tracked_path);
                self.encrypted_directory_signatures.remove(&encrypted_path);
                continue;
            }

            if self.is_local_mount_directory_dirty(&tracked_path) {
                continue;
            }

            if !directory_is_empty(&tracked_path)? {
                continue;
            }

            match fs::remove_dir(&tracked_path) {
                Ok(()) => {
                    self.clear_decrypted_directory_tracking(&tracked_path);
                    self.encrypted_directory_signatures.remove(&encrypted_path);
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    self.clear_decrypted_directory_tracking(&tracked_path);
                    self.encrypted_directory_signatures.remove(&encrypted_path);
                }
                Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                Err(err) => return Err(MountSyncError::Io(err)),
            }
        }

        Ok(())
    }

    fn track_missing_encrypted_files(
        &mut self,
        encrypted_root: &Path,
        mount_root: &Path,
        expected: &HashSet<PathBuf>,
    ) -> Result<(), MountSyncError> {
        let tracked: Vec<PathBuf> = self.decrypted_signatures.keys().cloned().collect();
        for tracked_path in tracked {
            if is_conflict_file(&tracked_path) {
                continue;
            }

            if self.is_path_excluded(&tracked_path) {
                continue;
            }

            if expected.contains(&tracked_path) {
                if self.pending_orphans.remove(&tracked_path).is_some() {
                    self.pending_orphans_dirty = true;
                }
                continue;
            }

            if self.unsupported_hard_link_paths.contains_key(&tracked_path) {
                continue;
            }

            let encrypted_path = encrypted_path_for(encrypted_root, mount_root, &tracked_path)?;
            let known_encrypted = self.encrypted_signatures.contains_key(&encrypted_path)
                || self
                    .path_mapping
                    .get(&encrypted_path)
                    .map(|mapped| mapped.as_path() == tracked_path.as_path())
                    .unwrap_or(false);

            if !known_encrypted {
                if self.pending_orphans.remove(&tracked_path).is_some() {
                    self.pending_orphans_dirty = true;
                }
                continue;
            }

            let current_sig = match fs::metadata(&tracked_path) {
                Ok(meta) => FileSignature::from_metadata(&meta),
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    self.clear_decrypted_tracking(&tracked_path);
                    self.encrypted_signatures.remove(&encrypted_path);
                    self.file_id_to_mount_path
                        .retain(|_file_id, mount_path| mount_path != &tracked_path);
                    self.path_mapping.retain(|_enc, dec| dec != &tracked_path);
                    if self.pending_orphans.remove(&tracked_path).is_some() {
                        self.pending_orphans_dirty = true;
                    }
                    continue;
                }
                Err(err) => {
                    warn!(
                        "Failed to stat {} while verifying encrypted-side disappearance: {}",
                        tracked_path.display(),
                        err
                    );
                    continue;
                }
            };

            if self.is_local_mount_path_dirty_with_signature(&tracked_path, current_sig) {
                debug!(
                    "Preserving {} because local plaintext changed after encrypted-side disappearance",
                    tracked_path.display()
                );
                if self.pending_orphans.remove(&tracked_path).is_some() {
                    self.pending_orphans_dirty = true;
                }
                continue;
            }

            let initial_count = if matches!(self.scan_health, ScanHealth::Healthy) {
                1
            } else {
                0
            };

            match self.pending_orphans.get_mut(&tracked_path) {
                Some(pending) => {
                    pending.encrypted_path = encrypted_path.clone();
                    if matches!(self.scan_health, ScanHealth::Healthy) {
                        pending.consecutive_missing_scans += 1;
                        pending.had_healthy_scan = true;
                    }
                    self.pending_orphans_dirty = true;
                }
                None => {
                    debug!(
                        "Marking {} as pending orphan after encrypted-side disappearance",
                        tracked_path.display()
                    );
                    self.pending_orphans.insert(
                        tracked_path.clone(),
                        PendingOrphan {
                            encrypted_path,
                            consecutive_missing_scans: initial_count,
                            had_healthy_scan: matches!(self.scan_health, ScanHealth::Healthy),
                        },
                    );
                    self.pending_orphans_dirty = true;
                }
            }
        }

        if !mount_root.exists() {
            fs::create_dir_all(mount_root)?;
        }

        Ok(())
    }
}

fn exclusion_path_candidates(path: &Path) -> Vec<String> {
    let mut candidates = Vec::new();
    let normalized = path.to_string_lossy().replace('\\', "/");

    if !normalized.is_empty() {
        candidates.push(normalized.clone());
    }

    let trimmed = normalized.trim_start_matches("./").trim_start_matches('/');
    if !trimmed.is_empty() && trimmed != normalized {
        candidates.push(trimmed.to_string());
    }

    let components: Vec<&str> = trimmed
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();

    for index in 0..components.len() {
        let suffix = components[index..].join("/");
        if !suffix.is_empty() {
            candidates.push(suffix);
        }
    }

    candidates
}

pub fn encrypted_path_for(
    encrypted_root: &Path,
    mount_root: &Path,
    decrypted_path: &Path,
) -> Result<PathBuf, MountSyncError> {
    let relative = decrypted_path.strip_prefix(mount_root).map_err(|_| {
        MountSyncError::Format(format!(
            "Decrypted file {} is outside mount root",
            decrypted_path.display()
        ))
    })?;

    let mut encrypted_relative = relative.to_path_buf();
    let encrypted_name = encrypted_relative
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    encrypted_relative.set_file_name(format!("{}.encrypted", encrypted_name));

    Ok(encrypted_root.join(encrypted_relative))
}

pub fn decrypted_target_path(
    encrypted_root: &Path,
    encrypted_path: &Path,
    mount_root: &Path,
    parsed: &ParsedEncryptedFile,
) -> Result<PathBuf, MountSyncError> {
    let relative = encrypted_path.strip_prefix(encrypted_root).map_err(|_| {
        MountSyncError::Format("Encrypted file is outside the selected root".into())
    })?;
    let mut target = mount_root.join(relative);
    target.set_file_name(decrypted_file_name(encrypted_path, parsed));
    Ok(target)
}

fn decrypted_file_name(encrypted_path: &Path, parsed: &ParsedEncryptedFile) -> String {
    if let Some(original) = &parsed.original_name {
        return original.clone();
    }
    if let Some(name) = encrypted_path.file_name().and_then(|s| s.to_str()) {
        strip_encrypted_suffix(name)
    } else {
        "decrypted".to_string()
    }
}

fn strip_encrypted_suffix(name: &str) -> String {
    name.trim_end_matches(".encrypted").to_string()
}

#[derive(Debug)]
pub struct ParsedEncryptedFile {
    pub metadata: EncryptedFileMetadata,
    pub original_name: Option<String>,
}

/// Parse only the JSON header of an encrypted file — skips reading the ciphertext payload.
/// Returns `(file_id, epoch_id, encrypted_size)` for use during inventory scans where
/// reading the full payload (O(file size) per file) would be unacceptably slow.
pub fn parse_encrypted_header_only(path: &Path) -> Result<(String, u64, u64), MountSyncError> {
    use std::io::{BufRead, BufReader, Seek};

    let file_len = fs::metadata(path)?.len();
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut header_bytes = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            return Err(MountSyncError::Format(
                "Invalid encrypted file format: separator not found".into(),
            ));
        }
        if line == b"---ENCRYPTED_DATA---\n" || line == b"---ENCRYPTED_DATA---" {
            break;
        }
        header_bytes.extend_from_slice(&line);
    }
    let ciphertext_offset = reader
        .stream_position()
        .map_err(|e| MountSyncError::Format(format!("Failed to locate ciphertext: {}", e)))?;

    let json: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| MountSyncError::Format(format!("Failed to parse metadata: {}", e)))?;

    let file_id = json["file_id"]
        .as_str()
        .ok_or_else(|| MountSyncError::Format("Missing file_id in metadata".into()))?
        .to_string();
    let epoch_id = json["epoch_id"]
        .as_u64()
        .ok_or_else(|| MountSyncError::Format("Missing epoch_id in metadata".into()))?;
    let encrypted_size = file_len.saturating_sub(ciphertext_offset);

    Ok((file_id, epoch_id, encrypted_size))
}

pub fn parse_encrypted_file(path: &Path) -> Result<ParsedEncryptedFile, MountSyncError> {
    // Best-effort fallback: assume the immediate parent is the root to preserve previous behaviour.
    let fallback_root = path.parent().unwrap_or_else(|| Path::new(""));
    parse_encrypted_file_with_root(fallback_root, path)
}

pub fn parse_encrypted_file_with_root(
    _encrypted_root: &Path,
    path: &Path,
) -> Result<ParsedEncryptedFile, MountSyncError> {
    use std::io::{BufRead, BufReader, Read, Seek};

    let file_len = fs::metadata(path)?.len();
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut header_bytes = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            return Err(MountSyncError::Format(
                "Invalid encrypted file format: separator not found".into(),
            ));
        }
        if line == b"---ENCRYPTED_DATA---\n" || line == b"---ENCRYPTED_DATA---" {
            break;
        }
        header_bytes.extend_from_slice(&line);
    }

    let ciphertext_offset = reader
        .stream_position()
        .map_err(|e| MountSyncError::Format(format!("Failed to locate ciphertext: {}", e)))?;

    let json: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| MountSyncError::Format(format!("Failed to parse metadata: {}", e)))?;

    let file_id = json["file_id"]
        .as_str()
        .ok_or_else(|| MountSyncError::Format("Missing file_id in metadata".into()))?;
    let epoch_id = json["epoch_id"]
        .as_u64()
        .ok_or_else(|| MountSyncError::Format("Missing epoch_id in metadata".into()))?;
    let content_size = json["file_size"]
        .as_u64()
        .or_else(|| json["original_size"].as_u64())
        .unwrap_or(0);
    let content_chunk_size = json.get("chunk_size").and_then(|v| v.as_u64());
    let original_name = json
        .get("original_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let group_id = json
        .get("group_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    let header_version = json
        .get("header_version")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let key_wrap_aad_hash = json
        .get("key_wrap_aad_hash")
        .and_then(|v| v.as_str())
        .and_then(|s| B64.decode(s).ok());

    let stored_file_path = json
        .get("file_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| MountSyncError::Format("Missing file_path in metadata".into()))?;
    let aad_path = normalize_file_identifier(&stored_file_path);

    let header_version_value = header_version.unwrap_or(1);

    let header_version = Some(header_version_value);
    let wrapped_file_key = json
        .get("wrapped_file_key")
        .and_then(|v| v.as_str())
        .and_then(|s| B64.decode(s).ok());
    let key_wrap_nonce = json
        .get("key_wrap_nonce")
        .and_then(|v| v.as_str())
        .and_then(|s| B64.decode(s).ok());
    let content_nonce = json
        .get("content_nonce")
        .and_then(|v| v.as_str())
        .and_then(|s| B64.decode(s).ok());

    let created_at = json
        .get("encrypted_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);
    let platform_metadata = json
        .get("platform_metadata")
        .and_then(|value| serde_json::from_value::<PlatformFileMetadata>(value.clone()).ok())
        .filter(|metadata| !metadata.is_empty());
    let sparse_metadata = json
        .get("sparse_metadata")
        .and_then(|value| serde_json::from_value::<SparseFileMetadata>(value.clone()).ok())
        .filter(SparseFileMetadata::is_effectively_sparse);

    let mut ciphertext = Vec::new();
    if header_version_value < CHUNKED_HEADER_VERSION && content_chunk_size.is_none() {
        reader
            .read_to_end(&mut ciphertext)
            .map_err(MountSyncError::Io)?;
    }
    let encrypted_size = if ciphertext.is_empty() {
        file_len.saturating_sub(ciphertext_offset)
    } else {
        ciphertext.len() as u64
    };

    let metadata = EncryptedFileMetadata {
        file_id: file_id.to_string(),
        file_path: aad_path,
        group_id,
        epoch_id,
        header_version,
        wrapped_file_key,
        key_wrap_nonce,
        key_wrap_aad_hash,
        content_nonce,
        content_chunk_size,
        content_size,
        encrypted_size,
        created_at,
        platform_metadata,
        sparse_metadata,
        encrypted_content: ciphertext,
    };

    Ok(ParsedEncryptedFile {
        metadata,
        original_name,
    })
}

// Re-export mount runner types and functions
#[cfg(not(target_os = "linux"))]
pub use mount_runner::fuse_prereqs;
#[cfg(target_os = "linux")]
pub use mount_runner::{build_mount_options, fuse_prereqs, run_fuse_mount};
pub use mount_runner::{
    determine_mount_strategy, run_sync_mount, run_sync_mount_with_config, unmount_mountpoint,
    MountClient, MountStrategy,
};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct MockCrypto;
    struct LowSpaceEncryptCrypto;
    struct MixedDecryptCrypto;
    struct RoundTripMetadataCrypto {
        plaintext: Vec<u8>,
    }

    fn mock_metadata(relative_path: &str, plaintext: &[u8]) -> EncryptedFileMetadata {
        let mut integrity_hash = [0u8; 32];
        integrity_hash.copy_from_slice(&Sha256::digest(plaintext));
        EncryptedFileMetadata {
            file_id: "mock-file-id".to_string(),
            file_path: relative_path.to_string(),
            group_id: None,
            epoch_id: 1,
            header_version: Some(1),
            wrapped_file_key: Some(vec![1; 32]),
            key_wrap_nonce: Some(vec![2; 24]),
            key_wrap_aad_hash: Some(vec![3; 32]),
            content_nonce: Some(vec![4; 24]),
            content_chunk_size: None,
            content_size: plaintext.len() as u64,
            encrypted_size: plaintext.len() as u64,
            created_at: Utc::now(),
            platform_metadata: None,
            sparse_metadata: None,
            encrypted_content: integrity_hash.to_vec(),
        }
    }

    fn mock_file_metadata_record(file_path: &str) -> FileMetadataData {
        FileMetadataData {
            file_path: file_path.to_string(),
            file_id: Some("mock-file-id".to_string()),
            group_id: None,
            epoch_id: 1,
            header_version: Some(1),
            wrapped_file_key: Some(vec![1; 32]),
            key_wrap_nonce: Some(vec![2; 24]),
            key_wrap_aad_hash: Some(vec![3; 32]),
            content_nonce: Some(vec![4; 24]),
            content_chunk_size: None,
            algorithm: "chacha20poly1305".to_string(),
            file_size: 9,
            modified_at: Utc::now(),
            integrity_hash: [7; 32],
            permissions: AccessControlData {
                readers: Vec::new(),
                writers: Vec::new(),
                is_public: false,
            },
            version: 1,
            chunks: Vec::new(),
            encrypted_size: 42,
            encrypted_at: Utc::now(),
        }
    }

    #[test]
    fn exclusion_matching_handles_absolute_obsidian_paths() {
        let mut tracker = SyncTracker::new();
        tracker.set_excluded_patterns(vec![
            ".obsidian".to_string(),
            ".obsidian/**".to_string(),
            "**/.obsidian".to_string(),
            "**/.obsidian/**".to_string(),
        ]);

        let absolute_dir = PathBuf::from(
            "/Users/test/Library/CloudStorage/Dropbox/Hybridcipher_development/.obsidian",
        );
        let absolute_file = absolute_dir.join("workspace.json");

        assert!(tracker.is_path_excluded(&absolute_dir));
        assert!(tracker.is_path_excluded(&absolute_file));
    }

    #[test]
    fn exclusion_matching_handles_absolute_target_paths() {
        let mut tracker = SyncTracker::new();
        tracker.set_excluded_patterns(vec!["target/**".to_string(), "**/target/**".to_string()]);

        let absolute_file =
            PathBuf::from("/Users/test/project/target/debug/deps/hybridcipher_client");
        assert!(tracker.is_path_excluded(&absolute_file));
    }

    #[async_trait]
    impl MountCrypto for MockCrypto {
        async fn decrypt_file(
            &self,
            _encrypted_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> Result<Vec<u8>, MountSyncError> {
            Err(MountSyncError::Crypto(
                "decrypt not used in test".to_string(),
            ))
        }

        async fn decrypt_file_streaming(
            &self,
            _encrypted_path: &Path,
            _output_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> Result<(), MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming decrypt not used in test".to_string(),
            ))
        }

        async fn encrypt_file(
            &self,
            relative_path: &str,
            plaintext: &[u8],
        ) -> Result<EncryptedFileMetadata, MountSyncError> {
            Ok(mock_metadata(relative_path, plaintext))
        }

        async fn encrypt_file_with_id(
            &self,
            relative_path: &str,
            plaintext: &[u8],
            file_id: &str,
        ) -> Result<EncryptedFileMetadata, MountSyncError> {
            let mut metadata = mock_metadata(relative_path, plaintext);
            metadata.file_id = file_id.to_string();
            Ok(metadata)
        }

        async fn encrypt_file_streaming(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _chunk_size: usize,
        ) -> Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming encrypt not used in test".to_string(),
            ))
        }

        async fn encrypt_file_streaming_with_id(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _file_id: &str,
            _chunk_size: usize,
        ) -> Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming encrypt not used in test".to_string(),
            ))
        }

        async fn coverage_store_metadata(
            &self,
            _metadata: FileMetadataData,
        ) -> Result<(), MountSyncError> {
            Ok(())
        }
    }

    #[async_trait]
    impl MountCrypto for RoundTripMetadataCrypto {
        async fn decrypt_file(
            &self,
            _encrypted_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> Result<Vec<u8>, MountSyncError> {
            Ok(self.plaintext.clone())
        }

        async fn decrypt_file_streaming(
            &self,
            _encrypted_path: &Path,
            _output_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> Result<(), MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming decrypt not used in test".to_string(),
            ))
        }

        async fn encrypt_file(
            &self,
            relative_path: &str,
            plaintext: &[u8],
        ) -> Result<EncryptedFileMetadata, MountSyncError> {
            Ok(mock_metadata(relative_path, plaintext))
        }

        async fn encrypt_file_with_id(
            &self,
            relative_path: &str,
            plaintext: &[u8],
            file_id: &str,
        ) -> Result<EncryptedFileMetadata, MountSyncError> {
            let mut metadata = mock_metadata(relative_path, plaintext);
            metadata.file_id = file_id.to_string();
            Ok(metadata)
        }

        async fn encrypt_file_streaming(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _chunk_size: usize,
        ) -> Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming encrypt not used in test".to_string(),
            ))
        }

        async fn encrypt_file_streaming_with_id(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _file_id: &str,
            _chunk_size: usize,
        ) -> Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming encrypt not used in test".to_string(),
            ))
        }

        async fn coverage_store_metadata(
            &self,
            _metadata: FileMetadataData,
        ) -> Result<(), MountSyncError> {
            Ok(())
        }
    }

    fn seed_tracked_file(
        tracker: &mut SyncTracker,
        encrypted_root: &Path,
        mount_root: &Path,
        mount_path: &Path,
    ) -> PathBuf {
        let encrypted_path = encrypted_path_for(encrypted_root, mount_root, mount_path).unwrap();
        let decrypted_signature = FileSignature::from_metadata(&fs::metadata(mount_path).unwrap());
        tracker.seed_file(
            encrypted_path.clone(),
            mount_path.to_path_buf(),
            ZERO_SIGNATURE,
            decrypted_signature,
        );
        encrypted_path
    }

    fn write_test_encrypted_file(
        path: &Path,
        file_id: &str,
        relative_path: &str,
    ) -> Result<(), MountSyncError> {
        let wrapped_file_key = vec![1; 32];
        let key_wrap_nonce = vec![2; 24];
        let key_wrap_aad_hash = vec![3; 32];
        let content_nonce = vec![4; 24];
        let header = SerializedEncryptedHeader {
            file_id,
            file_path: relative_path,
            group_id: None,
            epoch_id: 1,
            header_version: 1,
            wrapped_file_key: &wrapped_file_key,
            key_wrap_nonce: &key_wrap_nonce,
            key_wrap_aad_hash: &key_wrap_aad_hash,
            content_nonce: &content_nonce,
            content_chunk_size: None,
            original_size: 4,
            encrypted_size: 4,
            encrypted_at: Utc::now(),
            original_name: None,
            platform_metadata: None,
            sparse_metadata: None,
        };
        write_encrypted_file(path, &header, b"test")
            .map_err(|err| MountSyncError::Format(err.to_string()))
    }

    fn write_test_directory_metadata_object(
        path: &Path,
        file_id: &str,
        relative_path: &str,
        platform_metadata: &PlatformFileMetadata,
    ) -> Result<(), MountSyncError> {
        let wrapped_file_key = vec![1; 32];
        let key_wrap_nonce = vec![2; 24];
        let key_wrap_aad_hash = vec![3; 32];
        let content_nonce = vec![4; 24];
        let header = SerializedEncryptedHeader {
            file_id,
            file_path: relative_path,
            group_id: None,
            epoch_id: 1,
            header_version: 1,
            wrapped_file_key: &wrapped_file_key,
            key_wrap_nonce: &key_wrap_nonce,
            key_wrap_aad_hash: &key_wrap_aad_hash,
            content_nonce: &content_nonce,
            content_chunk_size: None,
            original_size: 0,
            encrypted_size: 0,
            encrypted_at: Utc::now(),
            original_name: Path::new(relative_path)
                .file_name()
                .and_then(|name| name.to_str()),
            platform_metadata: Some(platform_metadata),
            sparse_metadata: None,
        };
        write_encrypted_file(path, &header, b"")
            .map_err(|err| MountSyncError::Format(err.to_string()))
    }

    #[tokio::test]
    async fn dirty_plaintext_is_reencrypted_instead_of_marked_orphan() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        fs::write(&mount_path, b"original").unwrap();

        let mut tracker = SyncTracker::new();
        let encrypted_path =
            seed_tracked_file(&mut tracker, &encrypted_root, &mount_root, &mount_path);

        fs::write(&mount_path, b"local edits").unwrap();

        tracker
            .track_missing_encrypted_files(&encrypted_root, &mount_root, &HashSet::new())
            .unwrap();
        assert!(tracker.pending_orphans.is_empty());

        let mut expected = HashSet::new();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        assert!(encrypted_path.exists());
        assert_eq!(fs::read(&mount_path).unwrap(), b"local edits");
        assert!(tracker.pending_orphans.is_empty());
    }

    #[test]
    fn pending_orphan_journal_round_trips() {
        let temp = TempDir::new().unwrap();
        let mount_path = temp.path().join("document.txt");
        let encrypted_path = temp.path().join("document.txt.encrypted");
        fs::write(&mount_path, b"content").unwrap();

        let journal_path = temp.path().join("pending_orphans.json");

        let mut tracker = SyncTracker::new();
        tracker.pending_orphans.insert(
            mount_path.clone(),
            PendingOrphan {
                encrypted_path: encrypted_path.clone(),
                consecutive_missing_scans: 3,
                had_healthy_scan: true,
            },
        );
        tracker.pending_orphan_path = Some(journal_path.clone());
        tracker.pending_orphans_dirty = true;
        tracker.flush_pending_orphans();

        let mut reloaded = SyncTracker::new();
        reloaded.set_pending_orphan_path(journal_path);

        let pending = reloaded.pending_orphans.get(&mount_path).unwrap();
        assert_eq!(pending.encrypted_path, encrypted_path);
        assert_eq!(pending.consecutive_missing_scans, 3);
        assert!(pending.had_healthy_scan);
    }

    #[test]
    fn pending_writeback_journal_round_trips_and_blocks_cleanup() {
        let temp = TempDir::new().unwrap();
        let mount_path = temp.path().join("document.txt");
        let encrypted_path = temp.path().join("document.txt.encrypted");
        let journal_path = temp.path().join("pending_writebacks.json");

        let mut tracker = SyncTracker::new();
        tracker.pending_writebacks.insert(
            mount_path.clone(),
            PendingWriteback {
                encrypted_path: encrypted_path.clone(),
                last_error: Some("I/O error: No space left on device".to_string()),
                low_space: true,
                first_observed_at: Utc::now(),
                last_observed_at: Utc::now(),
            },
        );
        tracker.pending_writeback_path = Some(journal_path.clone());
        tracker.pending_writebacks_dirty = true;
        tracker.flush_pending_writebacks();

        let mut reloaded = SyncTracker::new();
        reloaded.set_pending_writeback_path(journal_path);

        let pending = reloaded.pending_writebacks.get(&mount_path).unwrap();
        assert_eq!(pending.encrypted_path, encrypted_path);
        assert_eq!(
            pending.last_error.as_deref(),
            Some("I/O error: No space left on device")
        );
        assert!(pending.low_space);
        assert!(!reloaded.can_cleanup_mountpoint());
    }

    #[test]
    fn pending_refresh_journal_round_trips() {
        let temp = TempDir::new().unwrap();
        let mount_path = temp.path().join("document.txt");
        let encrypted_path = temp.path().join("document.txt.encrypted");
        let journal_path = temp.path().join("pending_refreshes.json");

        let mut tracker = SyncTracker::new();
        tracker.pending_refreshes.insert(
            mount_path.clone(),
            PendingRefresh {
                encrypted_path: encrypted_path.clone(),
                last_error: Some("No space left on device".to_string()),
            },
        );
        tracker.pending_refresh_path = Some(journal_path.clone());
        tracker.pending_refreshes_dirty = true;
        tracker.flush_pending_refreshes();

        let mut reloaded = SyncTracker::new();
        reloaded.set_pending_refresh_path(journal_path);

        let pending = reloaded.pending_refreshes.get(&mount_path).unwrap();
        assert_eq!(pending.encrypted_path, encrypted_path);
        assert_eq!(
            pending.last_error.as_deref(),
            Some("No space left on device")
        );
    }

    #[test]
    fn pending_metadata_journal_round_trips() {
        let temp = TempDir::new().unwrap();
        let encrypted_path = temp.path().join("document.txt.encrypted");
        let journal_path = temp.path().join("pending_metadata.json");

        let mut tracker = SyncTracker::new();
        tracker.pending_metadata.insert(
            encrypted_path.clone(),
            mock_file_metadata_record("document.txt"),
        );
        tracker.pending_metadata_path = Some(journal_path.clone());
        tracker.pending_metadata_dirty = true;
        tracker.flush_pending_metadata();

        let mut reloaded = SyncTracker::new();
        reloaded.set_pending_metadata_path(journal_path);

        let pending = reloaded.pending_metadata.get(&encrypted_path).unwrap();
        assert_eq!(pending.file_path, "document.txt");
        assert_eq!(pending.file_id.as_deref(), Some("mock-file-id"));
        assert_eq!(pending.encrypted_size, 42);
    }

    #[test]
    fn embedded_platform_metadata_round_trips_in_header() {
        let temp = TempDir::new().unwrap();
        let encrypted_path = temp.path().join("document.txt.encrypted");
        let wrapped_file_key = vec![1; 32];
        let key_wrap_nonce = vec![2; 24];
        let key_wrap_aad_hash = vec![3; 32];
        let content_nonce = vec![4; 24];
        let platform_metadata = PlatformFileMetadata {
            unix_mode: Some(0o640),
            macos: Some(MacOsFileMetadata {
                xattrs: vec![
                    PlatformXattr::from_bytes("com.apple.quarantine", b"quarantine"),
                    PlatformXattr::from_bytes("com.apple.ResourceFork", b"resource-fork"),
                ],
                acl_text: Some("everyone allow readattr".to_string()),
            }),
        };

        let header = SerializedEncryptedHeader {
            file_id: "header-metadata-file-id",
            file_path: "document.txt",
            group_id: None,
            epoch_id: 1,
            header_version: 1,
            wrapped_file_key: &wrapped_file_key,
            key_wrap_nonce: &key_wrap_nonce,
            key_wrap_aad_hash: &key_wrap_aad_hash,
            content_nonce: &content_nonce,
            content_chunk_size: None,
            original_size: 4,
            encrypted_size: 4,
            encrypted_at: Utc::now(),
            original_name: Some("document.txt"),
            platform_metadata: Some(&platform_metadata),
            sparse_metadata: None,
        };

        write_encrypted_file(&encrypted_path, &header, b"test").unwrap();

        let parsed = parse_encrypted_file(&encrypted_path).unwrap();
        assert_eq!(parsed.metadata.platform_metadata, Some(platform_metadata));
    }

    #[test]
    fn sparse_metadata_round_trips_in_header() {
        let temp = TempDir::new().unwrap();
        let encrypted_path = temp.path().join("sparse.bin.encrypted");
        let wrapped_file_key = vec![1; 32];
        let key_wrap_nonce = vec![2; 24];
        let key_wrap_aad_hash = vec![3; 32];
        let content_nonce = vec![4; 24];
        let sparse_metadata = SparseFileMetadata {
            logical_size: 16 * 1024,
            extents: vec![
                SparseExtent {
                    offset: 4 * 1024,
                    length: 4 * 1024,
                },
                SparseExtent {
                    offset: 12 * 1024,
                    length: 2 * 1024,
                },
            ],
        };
        let ciphertext = vec![0xAB; sparse_metadata.packed_size() as usize];

        let header = SerializedEncryptedHeader {
            file_id: "sparse-header-file-id",
            file_path: "sparse.bin",
            group_id: None,
            epoch_id: 1,
            header_version: 2,
            wrapped_file_key: &wrapped_file_key,
            key_wrap_nonce: &key_wrap_nonce,
            key_wrap_aad_hash: &key_wrap_aad_hash,
            content_nonce: &content_nonce,
            content_chunk_size: Some(4096),
            original_size: sparse_metadata.logical_size,
            encrypted_size: ciphertext.len() as u64,
            encrypted_at: Utc::now(),
            original_name: Some("sparse.bin"),
            platform_metadata: None,
            sparse_metadata: Some(&sparse_metadata),
        };

        write_encrypted_file(&encrypted_path, &header, &ciphertext).unwrap();

        let parsed = parse_encrypted_file(&encrypted_path).unwrap();
        assert_eq!(parsed.metadata.sparse_metadata, Some(sparse_metadata));
    }

    #[cfg(unix)]
    #[test]
    fn sparse_packed_extents_reconstruct_logical_file() {
        let temp = TempDir::new().unwrap();
        let sparse_path = temp.path().join("sparse.bin");
        let packed_path = temp.path().join("packed.bin");
        let sparse_metadata = SparseFileMetadata {
            logical_size: 128 * 1024,
            extents: vec![
                SparseExtent {
                    offset: 4 * 1024,
                    length: 8 * 1024,
                },
                SparseExtent {
                    offset: 64 * 1024,
                    length: 4 * 1024,
                },
            ],
        };

        let mut file = fs::File::create(&sparse_path).unwrap();
        file.set_len(sparse_metadata.logical_size).unwrap();
        let first_extent = vec![0x41; sparse_metadata.extents[0].length as usize];
        let second_extent = vec![0x5A; sparse_metadata.extents[1].length as usize];
        file.seek(io::SeekFrom::Start(sparse_metadata.extents[0].offset))
            .unwrap();
        file.write_all(&first_extent).unwrap();
        file.seek(io::SeekFrom::Start(sparse_metadata.extents[1].offset))
            .unwrap();
        file.write_all(&second_extent).unwrap();
        file.sync_all().unwrap();

        let logical = fs::read(&sparse_path).unwrap();
        copy_sparse_extents_to_dense_file(&sparse_path, &packed_path, &sparse_metadata).unwrap();
        let packed = fs::read(&packed_path).unwrap();
        assert_eq!(packed.len() as u64, sparse_metadata.packed_size());

        let mut reconstructed = vec![0u8; sparse_metadata.logical_size as usize];
        let mut packed_offset = 0usize;
        for extent in &sparse_metadata.extents {
            let extent_len = extent.length as usize;
            let next_packed = packed_offset + extent_len;
            reconstructed[extent.offset as usize..extent.offset as usize + extent_len]
                .copy_from_slice(&packed[packed_offset..next_packed]);
            packed_offset = next_packed;
        }

        assert_eq!(reconstructed, logical);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_metadata_only_change_round_trips_through_encrypt_and_decrypt() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let plaintext = b"same-content".to_vec();
        let mount_path = mount_root.join("document.txt");
        fs::write(&mount_path, &plaintext).unwrap();
        fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o640)).unwrap();
        xattr::set(&mount_path, "com.apple.quarantine", b"qv1").unwrap();
        xattr::set(
            &mount_path,
            "com.apple.metadata:_kMDItemUserTags",
            b"tag-v1",
        )
        .unwrap();
        xattr::set(&mount_path, "com.apple.ResourceFork", b"fork-v1").unwrap();

        let crypto = RoundTripMetadataCrypto {
            plaintext: plaintext.clone(),
        };
        let mut tracker = SyncTracker::new();
        let mut expected = HashSet::new();

        tracker
            .sync_decrypted_changes(
                &crypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();
        expected.clear();
        tracker
            .sync_decrypted_changes(
                &crypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let encrypted_path = encrypted_root.join("document.txt.encrypted");
        let parsed_before = parse_encrypted_file(&encrypted_path).unwrap();
        let initial_metadata = capture_platform_metadata(&mount_path).unwrap();
        assert_eq!(
            parsed_before.metadata.platform_metadata,
            Some(initial_metadata.clone())
        );

        xattr::set(&mount_path, "com.apple.quarantine", b"qv2").unwrap();
        xattr::set(
            &mount_path,
            "com.apple.metadata:_kMDItemUserTags",
            b"tag-v2",
        )
        .unwrap();
        xattr::set(&mount_path, "com.apple.ResourceFork", b"fork-v2").unwrap();

        expected.clear();
        tracker
            .sync_decrypted_changes(
                &crypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();
        expected.clear();
        tracker
            .sync_decrypted_changes(
                &crypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let updated_metadata = capture_platform_metadata(&mount_path).unwrap();
        assert_ne!(updated_metadata, initial_metadata);

        let parsed_after = parse_encrypted_file(&encrypted_path).unwrap();
        assert_eq!(
            parsed_after.metadata.platform_metadata,
            Some(updated_metadata.clone())
        );

        fs::remove_file(&mount_path).unwrap();

        let mut restore_tracker = SyncTracker::new();
        restore_tracker
            .sync(&crypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let restored_path = mount_root.join("document.txt");
        assert_eq!(fs::read(&restored_path).unwrap(), plaintext);
        assert_eq!(
            capture_platform_metadata(&restored_path),
            Some(updated_metadata)
        );
    }

    #[test]
    fn runtime_status_reports_pending_commit_and_low_space_state() {
        let mut tracker = SyncTracker::new();
        tracker.pending_writebacks.insert(
            PathBuf::from("/mount/document.txt"),
            PendingWriteback {
                encrypted_path: PathBuf::from("/encrypted/document.txt.encrypted"),
                last_error: Some("No space left on device".to_string()),
                low_space: true,
                first_observed_at: Utc::now(),
                last_observed_at: Utc::now(),
            },
        );
        tracker.pending_refreshes.insert(
            PathBuf::from("/mount/other.txt"),
            PendingRefresh {
                encrypted_path: PathBuf::from("/encrypted/other.txt.encrypted"),
                last_error: Some("No space left on device".to_string()),
            },
        );
        tracker.space_warnings = SpaceWarningState {
            mount_low: true,
            encrypted_low: false,
            journal_low: true,
        };

        let status = tracker.runtime_status();
        assert_eq!(status.pending_writeback_count, 1);
        assert_eq!(status.pending_refresh_count, 1);
        assert_eq!(status.pending_low_space_path_count, 2);
        assert_eq!(status.low_space_mode, LowSpaceMode::FullyDegraded);
        assert!(!status.safe_to_unmount);
        assert!(status
            .unsafe_reasons
            .iter()
            .any(|reason| matches!(reason, MountSafetyReason::PendingWriteback { .. })));
        assert!(status
            .unsafe_reasons
            .iter()
            .any(|reason| matches!(reason, MountSafetyReason::LowSpaceDegraded { .. })));
        assert!(status
            .preflight_warnings
            .iter()
            .any(|warning| warning.contains("pending encrypted commit(s) still need to finish")));
        assert!(status.preflight_warnings.iter().any(|warning| warning
            .contains("pending plaintext refresh(es) are still rebuilding the local mount state")));
        assert!(status
            .preflight_warnings
            .iter()
            .any(|warning| warning.contains("mount volume below reserve")));
        assert!(status
            .preflight_warnings
            .iter()
            .any(|warning| warning.contains("journal volume below reserve")));
    }

    #[test]
    fn pending_writeback_journal_loads_without_timestamp_fields() {
        let temp = TempDir::new().unwrap();
        let journal_path = temp.path().join("pending_writebacks.json");
        let old_format = serde_json::json!([
            {
                "mount_path": "/mount/document.txt",
                "encrypted_path": "/encrypted/document.txt.encrypted",
                "last_error": null,
                "low_space": false
            }
        ]);
        fs::write(
            &journal_path,
            serde_json::to_vec_pretty(&old_format).unwrap(),
        )
        .unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_pending_writeback_path(journal_path);

        let pending = tracker
            .pending_writebacks
            .get(Path::new("/mount/document.txt"))
            .unwrap();
        assert!(pending.first_observed_at <= pending.last_observed_at);
    }

    #[tokio::test]
    async fn fast_drain_retry_commits_small_pending_writeback() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        fs::write(&mount_path, b"local edits").unwrap();
        let encrypted_path = encrypted_root.join("document.txt.encrypted");
        let signature = FileSignature::from_metadata(&fs::metadata(&mount_path).unwrap());

        let mut tracker = SyncTracker::new();
        tracker.record_pending_writeback(&mount_path, &encrypted_path, None);
        tracker.pending_stable.insert(
            mount_path.clone(),
            StableEntry {
                signature,
                first_seen: Instant::now() - Duration::from_millis(400),
            },
        );

        tracker
            .retry_pending_writebacks_before_scan(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(!tracker.pending_writebacks.contains_key(&mount_path));
        assert!(encrypted_path.exists());
    }

    #[tokio::test]
    async fn fast_drain_retry_clears_excluded_pending_directory_writeback() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let journal_root = temp.path().join("journal");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&journal_root).unwrap();

        let mount_path = mount_root.join(".obsidian");
        fs::create_dir_all(&mount_path).unwrap();
        let encrypted_path = encrypted_root
            .join(".obsidian")
            .join(DIRECTORY_METADATA_FILE_NAME);

        let mut tracker = SyncTracker::new();
        tracker.set_excluded_patterns(vec![
            ".obsidian".to_string(),
            ".obsidian/**".to_string(),
            "**/.obsidian".to_string(),
            "**/.obsidian/**".to_string(),
        ]);
        tracker.set_pending_writeback_path(journal_root.join("pending_writebacks.json"));
        tracker.record_pending_writeback(
            &mount_path,
            &encrypted_path,
            Some(&MountSyncError::PathExcluded(".obsidian".to_string())),
        );

        tracker
            .retry_pending_writebacks_before_scan(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(!tracker.pending_writebacks.contains_key(&mount_path));
        assert!(!encrypted_path.exists());
        assert!(mount_path.exists());
    }

    #[tokio::test]
    async fn sync_skips_excluded_directory_metadata_sidecar() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let ignored_dir = mount_root.join(".obsidian");
        fs::create_dir_all(&ignored_dir).unwrap();
        fs::write(mount_root.join("note.md"), b"hello").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_excluded_patterns(vec![
            ".obsidian".to_string(),
            ".obsidian/**".to_string(),
            "**/.obsidian".to_string(),
            "**/.obsidian/**".to_string(),
        ]);
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(!encrypted_root
            .join(".obsidian")
            .join(DIRECTORY_METADATA_FILE_NAME)
            .exists());
        assert!(encrypted_root.join("note.md.encrypted").exists());
    }

    #[tokio::test]
    async fn recovered_pending_copy_is_tracked_readonly_and_skipped_from_sync() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let quarantine_root = temp.path().join("quarantine");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(quarantine_root.join("folder")).unwrap();

        let mount_path = mount_root.join("folder").join("document.txt");
        fs::create_dir_all(mount_path.parent().unwrap()).unwrap();
        fs::write(&mount_path, b"current live").unwrap();
        fs::write(
            quarantine_root.join("folder").join("document.txt"),
            b"pending copy",
        )
        .unwrap();

        let mut tracker = SyncTracker::new();
        let created = tracker
            .materialize_recovered_pending_copies(
                &quarantine_root,
                &mount_root,
                &[mount_path.clone()],
            )
            .unwrap();
        assert_eq!(created.len(), 1);

        let recovery_path = created[0].clone();
        assert!(is_recovered_pending_file(&recovery_path));
        assert_eq!(fs::read(&recovery_path).unwrap(), b"pending copy");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&recovery_path).unwrap().permissions().mode() & 0o222,
            0
        );

        let status = tracker.runtime_status();
        assert_eq!(status.recovered_pending_copy_count, 1);
        assert!(!status.safe_to_unmount);
        assert!(status
            .unsafe_reasons
            .iter()
            .any(|reason| matches!(reason, MountSafetyReason::RecoveryCopiesPresent { .. })));

        let mut expected = HashSet::new();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();
        let recovery_encrypted =
            encrypted_path_for(&encrypted_root, &mount_root, &recovery_path).unwrap();
        assert!(!recovery_encrypted.exists());
    }

    #[tokio::test]
    async fn recovery_registry_persists_recreated_recovery_copy_records() {
        let temp = TempDir::new().unwrap();
        let mount_root = temp.path().join("mount");
        let quarantine_root = temp.path().join("quarantine");
        let registry_path = temp.path().join("recovery.json");
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(quarantine_root.join("folder")).unwrap();

        let live_path = mount_root.join("folder").join("document.txt");
        fs::create_dir_all(live_path.parent().unwrap()).unwrap();
        fs::write(&live_path, b"live").unwrap();
        fs::write(
            quarantine_root.join("folder").join("document.txt"),
            b"pending copy",
        )
        .unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_recovery_registry_path(registry_path.clone());
        tracker
            .materialize_recovered_pending_copies(
                &quarantine_root,
                &mount_root,
                &[live_path.clone()],
            )
            .unwrap();
        tracker.flush_recovery_registry(&mount_root);

        let records = load_mount_recovery_registry(&registry_path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].live_relative_path,
            PathBuf::from("folder/document.txt")
        );
        assert!(records[0]
            .recovery_relative_path
            .to_string_lossy()
            .contains(".recovered-pending-"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn existing_recovery_copy_is_rematerialized_after_restart() {
        let temp = TempDir::new().unwrap();
        let mount_root = temp.path().join("mount");
        let quarantine_root = temp.path().join("quarantine");
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(quarantine_root.join("folder")).unwrap();

        let recovery_path = quarantine_root
            .join("folder")
            .join("document.txt.recovered-pending-20260313_120000");
        fs::write(&recovery_path, b"recovered pending").unwrap();

        let mut tracker = SyncTracker::new();
        let created = tracker
            .materialize_existing_recovered_pending_copies(&quarantine_root, &mount_root)
            .unwrap();
        assert_eq!(created.len(), 1);
        assert!(created[0].starts_with(&mount_root));
        assert!(is_recovered_pending_file(&created[0]));
        assert_eq!(fs::read(&created[0]).unwrap(), b"recovered pending");
        assert_eq!(
            fs::metadata(&created[0]).unwrap().permissions().mode() & 0o222,
            0
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replace_recovery_copy_resolution_promotes_copy_and_clears_local_only_state() {
        let temp = TempDir::new().unwrap();
        let mount_root = temp.path().join("mount");
        let config_root = temp.path().join("config");
        fs::create_dir_all(mount_root.join("folder")).unwrap();
        fs::create_dir_all(&config_root).unwrap();

        let live_path = mount_root.join("folder").join("document.txt");
        let recovery_path = mount_root
            .join("folder")
            .join("document.txt.recovered-pending-20260313_120005");
        fs::write(&live_path, b"old live").unwrap();
        fs::write(&recovery_path, b"recovered live").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_retention_folder(&config_root);
        tracker.note_recovered_pending_copy(
            &recovery_path,
            FileSignature::from_metadata(&fs::metadata(&recovery_path).unwrap()),
        );

        let result = tracker
            .resolve_recovery_copy_action(
                &mount_root,
                &RecoveryCopyResolutionRequest {
                    request_id: Uuid::new_v4(),
                    recovery_relative_path: PathBuf::from(
                        "folder/document.txt.recovered-pending-20260313_120005",
                    ),
                    action: RecoveryCopyResolutionAction::ReplaceMountedFile,
                    destination_path: None,
                    requested_at: Utc::now(),
                },
            )
            .unwrap();

        assert!(result.requires_writeback);
        assert_eq!(fs::read(&live_path).unwrap(), b"recovered live");
        assert!(!recovery_path.exists());
        assert!(read_local_only_reason(&live_path).is_none());
        assert_ne!(
            fs::metadata(&live_path).unwrap().permissions().mode() & 0o200,
            0
        );
        assert!(tracker.runtime_status().recovered_pending_copy_count == 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn conflict_file_is_marked_readonly_and_blocks_cleanup() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let conflict_path = mount_root.join("document.txt.conflict-20260313_120000");
        fs::write(&conflict_path, b"local conflict").unwrap();

        let mut tracker = SyncTracker::new();
        let mut expected = HashSet::new();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let status = tracker.runtime_status();
        assert_eq!(
            fs::metadata(&conflict_path).unwrap().permissions().mode() & 0o222,
            0
        );
        assert_eq!(status.pending_conflict_count, 1);
        assert_eq!(status.edited_conflict_count, 0);
        assert_eq!(
            status.conflict_paths,
            vec![conflict_path.display().to_string()]
        );
        assert!(!status.safe_to_unmount);
        assert!(status
            .preflight_warnings
            .iter()
            .any(|warning| warning.contains("unresolved conflict file(s) remain local-only")));
        assert!(!tracker.can_cleanup_mountpoint());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn edited_conflict_file_is_detected_after_local_change() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let conflict_path = mount_root.join("document.txt.conflict-20260313_120001");
        fs::write(&conflict_path, b"original conflict").unwrap();

        let mut tracker = SyncTracker::new();
        let mut expected = HashSet::new();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let mut permissions = fs::metadata(&conflict_path).unwrap().permissions();
        permissions.set_mode(permissions.mode() | 0o200);
        fs::set_permissions(&conflict_path, permissions).unwrap();
        fs::write(&conflict_path, b"edited conflict").unwrap();

        expected.clear();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let status = tracker.runtime_status();
        assert_eq!(status.pending_conflict_count, 1);
        assert_eq!(status.edited_conflict_count, 1);
        assert_eq!(
            status.edited_conflict_paths,
            vec![conflict_path.display().to_string()]
        );
        assert!(status
            .preflight_warnings
            .iter()
            .any(|warning| warning.contains("were edited locally and are still not protected")));
    }

    #[tokio::test]
    async fn conflict_registry_persists_decrypt_collision_records() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let registry_path = temp.path().join("conflicts.json");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let conflict_path = mount_root.join("document.txt.conflict-20260313_120002");
        fs::write(&conflict_path, b"conflict payload").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_registry_path(registry_path.clone());
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let records = load_mount_conflict_registry(&registry_path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, ConflictKind::DecryptCollision);
        assert_eq!(records[0].live_relative_path, PathBuf::from("document.txt"));
        assert_eq!(
            records[0].conflict_relative_path,
            PathBuf::from("document.txt.conflict-20260313_120002")
        );
    }

    #[tokio::test]
    async fn conflict_registry_marks_deleted_open_recovery_kind() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let registry_path = temp.path().join("conflicts.json");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let encrypted_path = encrypted_root.join("document.txt.encrypted");
        let mount_path = mount_root.join("document.txt");
        write_test_encrypted_file(&encrypted_path, "recover-id", "document.txt").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_registry_path(registry_path.clone());
        let crypto = RoundTripMetadataCrypto {
            plaintext: b"recovered".to_vec(),
        };
        let conflict_path = tracker
            .recover_deleted_open_conflict(&crypto, &encrypted_path, &mount_path)
            .await
            .unwrap();
        tracker.flush_conflict_registry(&mount_root);

        let records = load_mount_conflict_registry(&registry_path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, ConflictKind::DeletedOpenRecovery);
        assert_eq!(
            records[0].conflict_relative_path,
            conflict_path
                .strip_prefix(&mount_root)
                .unwrap()
                .to_path_buf()
        );
    }

    #[tokio::test]
    async fn keep_mounted_resolution_archives_conflict_and_clears_tracker_state() {
        let temp = TempDir::new().unwrap();
        let mount_root = temp.path().join("mount");
        let config_root = temp.path().join("config");
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&config_root).unwrap();

        let live_path = mount_root.join("document.txt");
        let conflict_path = mount_root.join("document.txt.conflict-20260313_120010");
        fs::write(&live_path, b"live").unwrap();
        fs::write(&conflict_path, b"conflict").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_retention_folder(&config_root);
        tracker.update_conflict_file_tracking(
            &conflict_path,
            FileSignature::from_metadata(&fs::metadata(&conflict_path).unwrap()),
        );

        let result = tracker
            .resolve_conflict_action(
                &mount_root,
                &ConflictResolutionRequest {
                    request_id: Uuid::new_v4(),
                    conflict_id: tracker.conflict_records(&mount_root)[0].id,
                    action: ConflictResolutionAction::KeepMountedFile,
                    merged_text: None,
                    destination_path: None,
                    requested_at: Utc::now(),
                },
            )
            .unwrap();

        assert!(result.archive_paths.len() == 1);
        assert!(!conflict_path.exists());
        assert_eq!(fs::read(&live_path).unwrap(), b"live");
        assert!(tracker.conflict_records(&mount_root).is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn use_conflict_resolution_promotes_copy_and_restores_writable_file() {
        let temp = TempDir::new().unwrap();
        let mount_root = temp.path().join("mount");
        let config_root = temp.path().join("config");
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&config_root).unwrap();

        let live_path = mount_root.join("document.txt");
        let conflict_path = mount_root.join("document.txt.conflict-20260313_120011");
        fs::write(&live_path, b"live").unwrap();
        fs::write(&conflict_path, b"conflict").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_retention_folder(&config_root);
        tracker.update_conflict_file_tracking(
            &conflict_path,
            FileSignature::from_metadata(&fs::metadata(&conflict_path).unwrap()),
        );

        let conflict_id = tracker.conflict_records(&mount_root)[0].id;
        let result = tracker
            .resolve_conflict_action(
                &mount_root,
                &ConflictResolutionRequest {
                    request_id: Uuid::new_v4(),
                    conflict_id,
                    action: ConflictResolutionAction::UseConflictCopy,
                    merged_text: None,
                    destination_path: None,
                    requested_at: Utc::now(),
                },
            )
            .unwrap();

        assert!(result.requires_writeback);
        assert_eq!(fs::read(&live_path).unwrap(), b"conflict");
        assert!(!conflict_path.exists());
        assert!(read_local_only_reason(&live_path).is_none());
        assert_ne!(
            fs::metadata(&live_path).unwrap().permissions().mode() & 0o200,
            0
        );
    }

    #[tokio::test]
    async fn merge_text_resolution_archives_inputs_and_writes_merged_output() {
        let temp = TempDir::new().unwrap();
        let mount_root = temp.path().join("mount");
        let config_root = temp.path().join("config");
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&config_root).unwrap();

        let live_path = mount_root.join("document.txt");
        let conflict_path = mount_root.join("document.txt.conflict-20260313_120012");
        fs::write(&live_path, b"live version").unwrap();
        fs::write(&conflict_path, b"conflict version").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_retention_folder(&config_root);
        tracker.update_conflict_file_tracking(
            &conflict_path,
            FileSignature::from_metadata(&fs::metadata(&conflict_path).unwrap()),
        );

        let result = tracker
            .resolve_conflict_action(
                &mount_root,
                &ConflictResolutionRequest {
                    request_id: Uuid::new_v4(),
                    conflict_id: tracker.conflict_records(&mount_root)[0].id,
                    action: ConflictResolutionAction::MergeText,
                    merged_text: Some("merged result".to_string()),
                    destination_path: None,
                    requested_at: Utc::now(),
                },
            )
            .unwrap();

        assert_eq!(result.archive_paths.len(), 2);
        assert!(result.requires_writeback);
        assert_eq!(fs::read_to_string(&live_path).unwrap(), "merged result");
        assert!(!conflict_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn save_conflict_as_new_resolution_creates_normal_synced_file() {
        let temp = TempDir::new().unwrap();
        let mount_root = temp.path().join("mount");
        let config_root = temp.path().join("config");
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&config_root).unwrap();

        let live_path = mount_root.join("document.txt");
        let conflict_path = mount_root.join("document.txt.conflict-20260313_120013");
        let destination_path = PathBuf::from("resolved").join("document-final.txt");
        fs::write(&live_path, b"live").unwrap();
        fs::write(&conflict_path, b"conflict payload").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_retention_folder(&config_root);
        tracker.update_conflict_file_tracking(
            &conflict_path,
            FileSignature::from_metadata(&fs::metadata(&conflict_path).unwrap()),
        );

        let result = tracker
            .resolve_conflict_action(
                &mount_root,
                &ConflictResolutionRequest {
                    request_id: Uuid::new_v4(),
                    conflict_id: tracker.conflict_records(&mount_root)[0].id,
                    action: ConflictResolutionAction::SaveConflictAsNew,
                    merged_text: None,
                    destination_path: Some(destination_path.clone()),
                    requested_at: Utc::now(),
                },
            )
            .unwrap();

        let absolute_destination = mount_root.join(&destination_path);
        assert!(result.requires_writeback);
        assert_eq!(
            fs::read(&absolute_destination).unwrap(),
            b"conflict payload"
        );
        assert!(read_local_only_reason(&absolute_destination).is_none());
        assert_ne!(
            fs::metadata(&absolute_destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o200,
            0
        );
        assert!(!conflict_path.exists());
    }

    #[tokio::test]
    async fn manual_conflict_cleanup_prunes_registry_and_unblocks_cleanup() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let registry_path = temp.path().join("conflicts.json");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let conflict_path = mount_root.join("document.txt.conflict-20260313_120014");
        fs::write(&conflict_path, b"conflict").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_registry_path(registry_path.clone());
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        assert_eq!(tracker.runtime_status().pending_conflict_count, 1);

        fs::remove_file(&conflict_path).unwrap();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert_eq!(tracker.runtime_status().pending_conflict_count, 0);
        assert!(tracker.can_cleanup_mountpoint());
        let records = load_mount_conflict_registry(&registry_path).unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn low_space_writeback_is_journaled_and_cleanup_is_blocked() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let journal_root = temp.path().join("journal");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&journal_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        fs::write(&mount_path, b"local edits").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_pending_writeback_path(journal_root.join("pending_writebacks.json"));

        let mut expected = HashSet::new();
        tracker
            .sync_decrypted_changes(
                &LowSpaceEncryptCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();
        expected.clear();
        tracker
            .sync_decrypted_changes(
                &LowSpaceEncryptCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let pending = tracker.pending_writebacks.get(&mount_path).unwrap();
        assert!(pending.low_space);
        assert!(pending
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("No space left on device"));
        assert!(mount_path.exists());
        assert!(!tracker.can_cleanup_mountpoint());
    }

    #[tokio::test]
    async fn low_space_decrypt_is_isolated_per_file() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        write_test_encrypted_file(
            &encrypted_root.join("good.txt.encrypted"),
            "good-id",
            "good.txt",
        )
        .unwrap();
        write_test_encrypted_file(
            &encrypted_root.join("blocked.txt.encrypted"),
            "blocked-id",
            "blocked.txt",
        )
        .unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MixedDecryptCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert_eq!(fs::read(mount_root.join("good.txt")).unwrap(), b"decrypted");
        assert!(!mount_root.join("blocked.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn low_space_readonly_mode_defers_new_local_changes_and_restores_permissions() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let journal_root = temp.path().join("journal");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&journal_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        fs::write(&mount_path, b"local edits").unwrap();
        let original_mode = fs::metadata(&mount_path).unwrap().permissions().mode();

        let mut tracker = SyncTracker::new();
        tracker.set_pending_writeback_path(journal_root.join("pending_writebacks.json"));
        tracker.pending_refreshes.insert(
            mount_root.join("stale.txt"),
            PendingRefresh {
                encrypted_path: encrypted_root.join("stale.txt.encrypted"),
                last_error: Some("No space left on device".to_string()),
            },
        );
        tracker.enforce_low_space_mount_mode(&mount_root).unwrap();

        let mut expected = HashSet::new();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();
        expected.clear();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let pending = tracker.pending_writebacks.get(&mount_path).unwrap();
        assert!(pending.low_space);
        assert!(tracker.mount_readonly_active);
        assert_eq!(
            fs::metadata(&mount_path).unwrap().permissions().mode() & 0o222,
            0
        );
        assert!(!encrypted_root.join("document.txt.encrypted").exists());

        tracker.clear_pending_refreshes();
        tracker.clear_pending_writebacks();
        tracker.enforce_low_space_mount_mode(&mount_root).unwrap();

        assert!(!tracker.mount_readonly_active);
        assert_eq!(
            fs::metadata(&mount_path).unwrap().permissions().mode() & 0o777,
            original_mode & 0o777
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn empty_directory_metadata_round_trips_via_sidecar() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let folder_path = mount_root.join("folder");
        fs::create_dir_all(&folder_path).unwrap();
        fs::set_permissions(&folder_path, fs::Permissions::from_mode(0o750)).unwrap();
        #[cfg(target_os = "macos")]
        xattr::set(
            &folder_path,
            "com.apple.metadata:_kMDItemUserTags",
            b"folder-tag",
        )
        .unwrap();

        let expected_metadata = capture_platform_metadata(&folder_path).unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let sidecar_path = encrypted_root
            .join("folder")
            .join(DIRECTORY_METADATA_FILE_NAME);
        assert!(sidecar_path.exists());
        let parsed = parse_encrypted_file(&sidecar_path).unwrap();
        assert_eq!(
            parsed.metadata.platform_metadata,
            Some(expected_metadata.clone())
        );

        fs::remove_dir_all(&folder_path).unwrap();

        let mut restored = SyncTracker::new();
        restored
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(folder_path.is_dir());
        assert_eq!(
            capture_platform_metadata(&folder_path),
            Some(expected_metadata)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tracked_directory_delete_removes_sidecar_instead_of_restoring_folder() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let folder_path = mount_root.join("untitled folder");
        fs::create_dir_all(&folder_path).unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let sidecar_path = encrypted_root
            .join("untitled folder")
            .join(DIRECTORY_METADATA_FILE_NAME);
        assert!(sidecar_path.exists());
        assert!(tracker
            .decrypted_directory_signatures
            .contains_key(&folder_path));
        assert!(tracker
            .encrypted_directory_signatures
            .contains_key(&sidecar_path));

        fs::remove_dir_all(&folder_path).unwrap();

        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(
            !folder_path.exists(),
            "unchanged encrypted directory metadata must not recreate a mounted-side delete"
        );
        assert!(
            !sidecar_path.exists(),
            "mounted-side directory delete should remove the encrypted sidecar"
        );
        assert!(!tracker
            .decrypted_directory_signatures
            .contains_key(&folder_path));
        assert!(!tracker
            .encrypted_directory_signatures
            .contains_key(&sidecar_path));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tracked_directory_rename_replaces_old_sidecar_without_restoring_old_name() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let old_folder_path = mount_root.join("untitled folder");
        let new_folder_path = mount_root.join("Project Alpha");
        fs::create_dir_all(&old_folder_path).unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let old_sidecar_path = encrypted_root
            .join("untitled folder")
            .join(DIRECTORY_METADATA_FILE_NAME);
        let new_sidecar_path = encrypted_root
            .join("Project Alpha")
            .join(DIRECTORY_METADATA_FILE_NAME);
        assert!(old_sidecar_path.exists());

        fs::rename(&old_folder_path, &new_folder_path).unwrap();

        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(
            !old_folder_path.exists(),
            "directory rename must not restore Finder's temporary source name"
        );
        assert!(new_folder_path.is_dir());
        assert!(
            !old_sidecar_path.exists(),
            "directory rename should remove the old encrypted sidecar"
        );
        assert!(
            new_sidecar_path.exists(),
            "directory rename should publish the new encrypted sidecar"
        );
        assert!(!tracker
            .decrypted_directory_signatures
            .contains_key(&old_folder_path));
        assert!(tracker
            .decrypted_directory_signatures
            .contains_key(&new_folder_path));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn externally_deleted_sidecar_removes_enrolled_directory() {
        // Simulates the File Provider tracker deleting a sidecar (mounted-side delete)
        // while the mount runner has the same enrolled dir still present. The mount
        // runner must propagate the delete to the enrolled dir, not re-create the sidecar.
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let folder_path = mount_root.join("folder_a");
        fs::create_dir_all(&folder_path).unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let sidecar_path = encrypted_root
            .join("folder_a")
            .join(DIRECTORY_METADATA_FILE_NAME);
        assert!(sidecar_path.exists());
        assert!(tracker
            .encrypted_directory_signatures
            .contains_key(&sidecar_path));

        // Simulate File Provider tracker externally deleting the sidecar.
        fs::remove_file(&sidecar_path).unwrap();

        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(
            !folder_path.exists(),
            "enrolled directory must be removed when its sidecar is externally deleted"
        );
        assert!(
            !sidecar_path.exists(),
            "sidecar must remain absent after propagation"
        );
        assert!(!tracker
            .decrypted_directory_signatures
            .contains_key(&folder_path));
        assert!(!tracker
            .encrypted_directory_signatures
            .contains_key(&sidecar_path));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn externally_renamed_sidecar_removes_old_enrolled_directory_and_keeps_new() {
        // Simulates the File Provider rename "untitled folder" → "Project Alpha":
        // old sidecar deleted, new sidecar created externally. The mount runner must
        // remove the enrolled "untitled folder" and keep/create "Project Alpha".
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let old_folder_path = mount_root.join("untitled folder");
        fs::create_dir_all(&old_folder_path).unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let old_sidecar_path = encrypted_root
            .join("untitled folder")
            .join(DIRECTORY_METADATA_FILE_NAME);
        assert!(old_sidecar_path.exists());

        // Simulate FP tracker: delete old sidecar, create new sidecar for renamed dir.
        fs::remove_file(&old_sidecar_path).unwrap();
        // The encrypted dir for the new name must exist for the sidecar to live in.
        let new_encrypted_dir = encrypted_root.join("Project Alpha");
        fs::create_dir_all(&new_encrypted_dir).unwrap();
        let _new_sidecar_path = new_encrypted_dir.join(DIRECTORY_METADATA_FILE_NAME);
        // Write a minimal placeholder so the sidecar file exists (MockCrypto will
        // re-encrypt it, but we need it present for decrypt_directory_metadata).
        // Use a real sync-created sidecar by first creating the enrolled dir, syncing,
        // then removing the enrolled dir to simulate the rename.
        // Simpler: just let the sync create it from scratch by pre-creating the enrolled dir.
        let new_folder_path = mount_root.join("Project Alpha");
        fs::create_dir_all(&new_folder_path).unwrap();

        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(
            !old_folder_path.exists(),
            "old enrolled directory must be removed after its sidecar was externally deleted"
        );
        assert!(
            new_folder_path.is_dir(),
            "new enrolled directory must remain present"
        );
        assert!(!tracker
            .decrypted_directory_signatures
            .contains_key(&old_folder_path));
        assert!(tracker
            .decrypted_directory_signatures
            .contains_key(&new_folder_path));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn encrypted_package_directory_metadata_restores_package_root() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let package_sidecar = encrypted_root
            .join("Document.pages")
            .join(DIRECTORY_METADATA_FILE_NAME);
        fs::create_dir_all(package_sidecar.parent().unwrap()).unwrap();

        let platform_metadata = PlatformFileMetadata {
            unix_mode: Some(0o750),
            #[cfg(target_os = "macos")]
            macos: Some(MacOsFileMetadata {
                xattrs: vec![PlatformXattr::from_bytes(
                    "com.apple.metadata:_kMDItemUserTags",
                    b"package-tag",
                )],
                acl_text: None,
            }),
            #[cfg(not(target_os = "macos"))]
            macos: None,
        };
        write_test_directory_metadata_object(
            &package_sidecar,
            "package-dir-id",
            "Document.pages",
            &platform_metadata,
        )
        .unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let package_root = mount_root.join("Document.pages");
        assert!(package_root.is_dir());
        let restored = capture_platform_metadata(&package_root).unwrap();
        assert_eq!(restored.unix_mode.map(|mode| mode & 0o777), Some(0o750));
        #[cfg(target_os = "macos")]
        {
            let tag = restored
                .macos
                .as_ref()
                .and_then(|metadata| {
                    metadata
                        .xattrs
                        .iter()
                        .find(|xattr| xattr.name == "com.apple.metadata:_kMDItemUserTags")
                })
                .and_then(|xattr| B64.decode(&xattr.value_base64).ok());
            assert_eq!(tag.as_deref(), Some(&b"package-tag"[..]));
        }
    }

    #[tokio::test]
    async fn transactional_sqlite_file_is_blocked_from_sync_and_cleanup() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let mount_path = mount_root.join("library.sqlite");
        fs::write(&mount_path, b"sqlite payload").unwrap();

        let mut tracker = SyncTracker::new();
        let mut expected = HashSet::new();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let encrypted_path = encrypted_path_for(&encrypted_root, &mount_root, &mount_path).unwrap();
        assert!(!encrypted_path.exists());
        assert!(tracker
            .unsupported_transactional_paths
            .contains_key(&mount_path));
        assert!(!tracker.can_cleanup_mountpoint());

        let status = tracker.runtime_status();
        assert!(status
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("transactional path(s) blocked"));
    }

    #[tokio::test]
    async fn transactional_package_contents_are_blocked_from_sync() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let package_root = mount_root.join("Document.pages");
        fs::create_dir_all(&package_root).unwrap();
        let mount_path = package_root.join("Index.xml");
        fs::write(&mount_path, b"package payload").unwrap();

        let mut tracker = SyncTracker::new();
        let mut expected = HashSet::new();
        tracker
            .sync_decrypted_changes(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                &mut expected,
                &HashSet::new(),
            )
            .await
            .unwrap();

        let encrypted_path = encrypted_path_for(&encrypted_root, &mount_root, &mount_path).unwrap();
        assert!(!encrypted_path.exists());
        assert!(tracker
            .unsupported_transactional_paths
            .contains_key(&mount_path));
        assert!(!tracker.can_cleanup_mountpoint());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_linked_file_is_blocked_from_sync_and_cleanup() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        let alias_path = mount_root.join("document-copy.txt");
        fs::write(&mount_path, b"original").unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let encrypted_path = encrypted_root.join("document.txt.encrypted");
        let parsed_before = parse_encrypted_file(&encrypted_path).unwrap();
        assert_eq!(
            parsed_before.metadata.encrypted_content,
            Sha256::digest(b"original").to_vec()
        );

        fs::hard_link(&mount_path, &alias_path).unwrap();
        fs::write(&alias_path, b"changed via hard link").unwrap();

        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(tracker
            .unsupported_hard_link_paths
            .contains_key(&mount_path));
        assert!(tracker
            .unsupported_hard_link_paths
            .contains_key(&alias_path));
        assert_eq!(
            fs::metadata(&mount_path).unwrap().permissions().mode() & 0o222,
            0
        );
        assert_eq!(
            fs::metadata(&alias_path).unwrap().permissions().mode() & 0o222,
            0
        );
        assert!(!encrypted_root.join("document-copy.txt.encrypted").exists());
        assert_eq!(
            parse_encrypted_file(&encrypted_path)
                .unwrap()
                .metadata
                .encrypted_content,
            Sha256::digest(b"original").to_vec()
        );
        assert!(!tracker.can_cleanup_mountpoint());

        let status = tracker.runtime_status();
        let hard_link_reason = status
            .unsafe_reasons
            .iter()
            .find_map(|reason| match reason {
                MountSafetyReason::HardLinkBlocked {
                    count,
                    sample_paths,
                } => Some((*count, sample_paths.clone())),
                _ => None,
            })
            .expect("expected hard-link unsafe reason");
        assert_eq!(hard_link_reason.0, 2);
        assert!(hard_link_reason
            .1
            .iter()
            .any(|path| path.ends_with("document.txt") || path.ends_with("document-copy.txt")));
        assert!(status
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("hard-linked file(s) blocked"));
        assert!(status
            .preflight_warnings
            .iter()
            .any(|warning| warning.contains("hard-linked file(s) are blocked")));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_link_block_restores_writable_mode_when_link_removed() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        let alias_path = mount_root.join("document-copy.txt");
        fs::write(&mount_path, b"original").unwrap();
        let original_mode = fs::metadata(&mount_path).unwrap().permissions().mode() & 0o777;

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        fs::hard_link(&mount_path, &alias_path).unwrap();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        assert_eq!(
            fs::metadata(&mount_path).unwrap().permissions().mode() & 0o222,
            0
        );

        fs::remove_file(&alias_path).unwrap();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(!tracker
            .unsupported_hard_link_paths
            .contains_key(&mount_path));
        assert_eq!(
            fs::metadata(&mount_path).unwrap().permissions().mode() & 0o777,
            original_mode
        );
        assert!(!tracker
            .runtime_status()
            .unsafe_reasons
            .iter()
            .any(|reason| matches!(reason, MountSafetyReason::HardLinkBlocked { .. })));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_link_delete_is_suppressed_until_resolution() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        let alias_path = mount_root.join("document-copy.txt");
        fs::write(&mount_path, b"original").unwrap();

        let mut tracker = SyncTracker::new();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        let original_encrypted_path = encrypted_root.join("document.txt.encrypted");
        let original_file_id = parse_encrypted_file(&original_encrypted_path)
            .unwrap()
            .metadata
            .file_id;

        fs::hard_link(&mount_path, &alias_path).unwrap();
        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        assert!(tracker
            .unsupported_hard_link_paths
            .contains_key(&mount_path));
        assert!(tracker
            .unsupported_hard_link_paths
            .contains_key(&alias_path));

        fs::remove_file(&mount_path).unwrap();

        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        let renamed_encrypted_path = encrypted_root.join("document-copy.txt.encrypted");
        assert!(original_encrypted_path.exists());
        assert!(!renamed_encrypted_path.exists());

        tracker
            .sync(&MockCrypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
        assert!(!original_encrypted_path.exists());
        assert!(renamed_encrypted_path.exists());
        assert_eq!(
            parse_encrypted_file(&renamed_encrypted_path)
                .unwrap()
                .metadata
                .file_id,
            original_file_id
        );
    }

    #[tokio::test]
    async fn pending_deletion_journal_survives_restart_without_redecrypting_file() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let config_root = temp.path().join("config");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&config_root).unwrap();

        let encrypted_path = encrypted_root.join("document.txt.encrypted");
        let mount_path = mount_root.join("document.txt");
        let journal_path = config_root.join("pending_deletions.json");
        write_test_encrypted_file(&encrypted_path, "pending-delete-id", "document.txt").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_deletion_config(DeletionConfig {
            min_consecutive_missing_scans: 10,
            rapid_scan_total_duration_ms: 1,
            retention_days: 7,
            retention_folder: None,
        });
        tracker.pending_deletions.insert(
            encrypted_path.clone(),
            PendingDeletion {
                mount_path: mount_path.clone(),
                first_missing_time: Instant::now(),
                consecutive_missing_scans: 1,
                had_healthy_scan: true,
            },
        );
        tracker.pending_deletion_path = Some(journal_path.clone());
        tracker.pending_deletions_dirty = true;
        tracker.flush_pending_deletions();

        let mut reloaded = SyncTracker::new();
        reloaded.set_deletion_config(DeletionConfig {
            min_consecutive_missing_scans: 10,
            rapid_scan_total_duration_ms: 1,
            retention_days: 7,
            retention_folder: None,
        });
        reloaded.set_pending_deletion_path(journal_path);

        let crypto = RoundTripMetadataCrypto {
            plaintext: b"decrypted".to_vec(),
        };
        reloaded
            .sync(&crypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(!mount_path.exists());
        assert!(reloaded.pending_deletions.contains_key(&encrypted_path));
    }

    #[tokio::test]
    async fn startup_rehydrate_mode_restores_plaintext_without_delete_inference() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let encrypted_path = encrypted_root.join("document.txt.encrypted");
        let mount_path = mount_root.join("document.txt");
        write_test_encrypted_file(&encrypted_path, "rehydrate-id", "document.txt").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.seed_file(
            encrypted_path.clone(),
            mount_path.clone(),
            ZERO_SIGNATURE,
            ZERO_SIGNATURE,
        );
        tracker.pending_deletions.insert(
            encrypted_path.clone(),
            PendingDeletion {
                mount_path: mount_path.clone(),
                first_missing_time: Instant::now(),
                consecutive_missing_scans: 1,
                had_healthy_scan: true,
            },
        );

        tracker.enter_startup_rehydrate_mode();
        assert!(tracker.pending_deletions.is_empty());

        let crypto = RoundTripMetadataCrypto {
            plaintext: b"decrypted".to_vec(),
        };
        tracker
            .sync(&crypto, &encrypted_root, &mount_root)
            .await
            .unwrap();

        assert!(mount_path.exists());
        assert_eq!(fs::read(&mount_path).unwrap(), b"decrypted");
        assert!(tracker.pending_deletions.is_empty());

        tracker.exit_startup_rehydrate_mode();
        assert!(!tracker.suppress_deletion_inference);
        assert!(!tracker.suppress_deletion_processing);
    }

    #[test]
    fn pending_open_unlinked_journal_round_trips() {
        let temp = TempDir::new().unwrap();
        let journal_path = temp.path().join("pending_open_unlinked.json");
        let mount_path = PathBuf::from("/mount/document.txt");
        let encrypted_path = PathBuf::from("/encrypted/document.txt.encrypted");
        let first_seen_at = Utc::now();
        let last_seen_at = first_seen_at + chrono::TimeDelta::seconds(5);

        let mut tracker = SyncTracker::new();
        tracker.pending_open_unlinked.insert(
            mount_path.clone(),
            PendingOpenUnlinked {
                encrypted_path: Some(encrypted_path.clone()),
                encrypted_version_exists: true,
                had_unsynced_local_writeback: true,
                first_seen_at,
                last_seen_at,
                owners: vec![OpenUnlinkedOwner {
                    pid: 42,
                    name: "TextEdit".to_string(),
                }],
            },
        );
        tracker.pending_open_unlinked_path = Some(journal_path.clone());
        tracker.pending_open_unlinked_dirty = true;
        tracker.flush_pending_open_unlinked();

        let mut reloaded = SyncTracker::new();
        reloaded.set_pending_open_unlinked_path(journal_path);

        let pending = reloaded.pending_open_unlinked.get(&mount_path).unwrap();
        assert_eq!(pending.encrypted_path.as_ref(), Some(&encrypted_path));
        assert!(pending.encrypted_version_exists);
        assert!(pending.had_unsynced_local_writeback);
        assert_eq!(pending.first_seen_at, first_seen_at);
        assert_eq!(pending.last_seen_at, last_seen_at);
        assert_eq!(pending.owners[0].name, "TextEdit");
        assert!(!reloaded.can_cleanup_mountpoint());
    }

    #[tokio::test]
    async fn deleted_open_observation_converts_pending_writeback_and_blocks_cleanup() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        let encrypted_path = encrypted_root.join("document.txt.encrypted");
        write_test_encrypted_file(&encrypted_path, "deleted-open-id", "document.txt").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.pending_writebacks.insert(
            mount_path.clone(),
            PendingWriteback {
                encrypted_path: encrypted_path.clone(),
                last_error: Some("pending writeback".to_string()),
                low_space: false,
                first_observed_at: Utc::now(),
                last_observed_at: Utc::now(),
            },
        );
        tracker.pending_deletions.insert(
            encrypted_path.clone(),
            PendingDeletion {
                mount_path: mount_path.clone(),
                first_missing_time: Instant::now(),
                consecutive_missing_scans: 1,
                had_healthy_scan: true,
            },
        );

        let mut observed = HashMap::new();
        observed.insert(
            mount_path.clone(),
            vec![OpenUnlinkedOwner {
                pid: 99,
                name: "Preview".to_string(),
            }],
        );

        tracker
            .reconcile_pending_open_unlinked(&MockCrypto, &encrypted_root, &mount_root, observed)
            .await
            .unwrap();

        assert!(tracker.pending_writebacks.is_empty());
        assert!(tracker.pending_deletions.is_empty());
        let pending = tracker.pending_open_unlinked.get(&mount_path).unwrap();
        assert!(pending.encrypted_version_exists);
        assert!(pending.had_unsynced_local_writeback);
        assert_eq!(pending.owners[0].name, "Preview");
        assert!(!tracker.can_cleanup_mountpoint());

        let status = tracker.runtime_status();
        assert_eq!(status.pending_open_unlinked_count, 1);
        assert_eq!(
            status.open_unlinked_paths,
            vec![mount_path.display().to_string()]
        );
        assert!(!status.safe_to_unmount);
    }

    #[tokio::test]
    async fn deleted_open_recovery_writes_conflict_file_after_handle_closes() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let encrypted_path = encrypted_root.join("document.txt.encrypted");
        let mount_path = mount_root.join("document.txt");
        write_test_encrypted_file(&encrypted_path, "recover-id", "document.txt").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.pending_open_unlinked.insert(
            mount_path.clone(),
            PendingOpenUnlinked {
                encrypted_path: Some(encrypted_path.clone()),
                encrypted_version_exists: true,
                had_unsynced_local_writeback: true,
                first_seen_at: Utc::now(),
                last_seen_at: Utc::now(),
                owners: vec![OpenUnlinkedOwner {
                    pid: 7,
                    name: "TextEdit".to_string(),
                }],
            },
        );

        let crypto = RoundTripMetadataCrypto {
            plaintext: b"decrypted".to_vec(),
        };
        tracker
            .reconcile_pending_open_unlinked(&crypto, &encrypted_root, &mount_root, HashMap::new())
            .await
            .unwrap();

        assert!(tracker.pending_open_unlinked.is_empty());
        assert!(encrypted_path.exists());

        let recovered_entries = fs::read_dir(&mount_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert_eq!(recovered_entries.len(), 1);
        let recovered_path = &recovered_entries[0];
        assert!(is_conflict_file(recovered_path));
        assert_eq!(fs::read(recovered_path).unwrap(), b"decrypted");
        assert!(tracker
            .last_open_unlinked_warning
            .as_deref()
            .unwrap_or_default()
            .contains("Later unlinked local writes"));
    }

    #[tokio::test]
    async fn deleted_open_local_only_file_clears_without_fake_recovery() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();

        let mount_path = mount_root.join("draft.txt");
        let mut tracker = SyncTracker::new();
        tracker.pending_open_unlinked.insert(
            mount_path.clone(),
            PendingOpenUnlinked {
                encrypted_path: Some(encrypted_root.join("draft.txt.encrypted")),
                encrypted_version_exists: false,
                had_unsynced_local_writeback: true,
                first_seen_at: Utc::now(),
                last_seen_at: Utc::now(),
                owners: vec![OpenUnlinkedOwner {
                    pid: 11,
                    name: "Notes".to_string(),
                }],
            },
        );

        tracker
            .reconcile_pending_open_unlinked(
                &MockCrypto,
                &encrypted_root,
                &mount_root,
                HashMap::new(),
            )
            .await
            .unwrap();

        assert!(tracker.pending_open_unlinked.is_empty());
        assert!(fs::read_dir(&mount_root).unwrap().next().is_none());
        assert!(tracker
            .last_open_unlinked_warning
            .as_deref()
            .unwrap_or_default()
            .contains("could not recover"));
    }

    #[test]
    fn unchanged_orphaned_plaintext_moves_to_retention_after_threshold() {
        let temp = TempDir::new().unwrap();
        let encrypted_root = temp.path().join("encrypted");
        let mount_root = temp.path().join("mount");
        let config_root = temp.path().join("config");
        fs::create_dir_all(&encrypted_root).unwrap();
        fs::create_dir_all(&mount_root).unwrap();
        fs::create_dir_all(&config_root).unwrap();

        let mount_path = mount_root.join("document.txt");
        fs::write(&mount_path, b"stable content").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_retention_folder(&config_root);
        tracker.set_deletion_config(DeletionConfig {
            min_consecutive_missing_scans: 2,
            rapid_scan_total_duration_ms: 100,
            retention_days: 7,
            retention_folder: None,
        });
        seed_tracked_file(&mut tracker, &encrypted_root, &mount_root, &mount_path);

        tracker
            .track_missing_encrypted_files(&encrypted_root, &mount_root, &HashSet::new())
            .unwrap();
        assert!(mount_path.exists());
        assert_eq!(tracker.pending_orphans.len(), 1);

        tracker
            .track_missing_encrypted_files(&encrypted_root, &mount_root, &HashSet::new())
            .unwrap();
        tracker.process_pending_orphans(&mount_root).unwrap();

        assert!(!mount_path.exists());
        assert!(tracker.pending_orphans.is_empty());

        let retained_root = config_root.join("retention").join("plaintext-orphans");
        let retained_entries: Vec<_> = fs::read_dir(&retained_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) != Some("json"))
            .collect();
        assert_eq!(retained_entries.len(), 1);
        assert_eq!(
            fs::read(retained_entries[0].path()).unwrap(),
            b"stable content"
        );
    }

    #[test]
    fn retention_cleanup_clamps_future_timestamps() {
        let temp = TempDir::new().unwrap();
        let config_root = temp.path().join("config");
        fs::create_dir_all(&config_root).unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_retention_folder(&config_root);
        tracker.set_deletion_config(DeletionConfig {
            min_consecutive_missing_scans: 2,
            rapid_scan_total_duration_ms: 100,
            retention_days: 1,
            retention_folder: None,
        });

        let retention_root = config_root.join("retention");
        fs::create_dir_all(&retention_root).unwrap();
        let retained_path = retention_root.join("20260311_120000_document.txt.encrypted");
        let metadata_path = retention_root.join("20260311_120000_document.txt.encrypted.meta.json");
        fs::write(&retained_path, b"ciphertext").unwrap();
        fs::write(
            &metadata_path,
            serde_json::to_vec_pretty(&RetentionMetadata {
                deleted_at: Utc::now() + chrono::Duration::days(1),
            })
            .unwrap(),
        )
        .unwrap();

        tracker.cleanup_retention_folder().unwrap();

        assert!(retained_path.exists());
        assert!(metadata_path.exists());
    }

    #[test]
    fn temp_like_name_detection_covers_windows_pdf_editor_patterns() {
        for name in [
            "~wang_2020_nature_intergrated_photonic.pdf",
            "wang_2020_nature_intergrated_photonic.pdf.bak",
            "#wang_2020_nature_intergrated_photonic.pdf#",
            ".~lock.wang_2020_nature_intergrated_photonic.pdf#",
            "wang_2020_nature_intergrated_photonic.pdf~",
        ] {
            assert!(
                is_temp_like_name(name),
                "expected temp-like name to be detected: {name}"
            );
        }
    }

    #[test]
    fn temp_like_name_detection_keeps_normal_pdf_names() {
        for name in [
            "wang_2020_nature_intergrated_photonic.pdf",
            "team-notes.bakery.pdf",
            "tilde-analysis.pdf",
        ] {
            assert!(
                !is_temp_like_name(name),
                "expected normal name to remain syncable: {name}"
            );
        }
    }

    #[async_trait]
    impl MountCrypto for LowSpaceEncryptCrypto {
        async fn decrypt_file(
            &self,
            _encrypted_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> Result<Vec<u8>, MountSyncError> {
            Err(MountSyncError::Crypto(
                "decrypt not used in test".to_string(),
            ))
        }

        async fn decrypt_file_streaming(
            &self,
            _encrypted_path: &Path,
            _output_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> Result<(), MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming decrypt not used in test".to_string(),
            ))
        }

        async fn encrypt_file(
            &self,
            _relative_path: &str,
            _plaintext: &[u8],
        ) -> Result<EncryptedFileMetadata, MountSyncError> {
            Err(MountSyncError::Io(io::Error::from_raw_os_error(28)))
        }

        async fn encrypt_file_with_id(
            &self,
            _relative_path: &str,
            _plaintext: &[u8],
            _file_id: &str,
        ) -> Result<EncryptedFileMetadata, MountSyncError> {
            Err(MountSyncError::Io(io::Error::from_raw_os_error(28)))
        }

        async fn encrypt_file_streaming(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _chunk_size: usize,
        ) -> Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Io(io::Error::from_raw_os_error(28)))
        }

        async fn encrypt_file_streaming_with_id(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _file_id: &str,
            _chunk_size: usize,
        ) -> Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Io(io::Error::from_raw_os_error(28)))
        }

        async fn coverage_store_metadata(
            &self,
            _metadata: FileMetadataData,
        ) -> Result<(), MountSyncError> {
            Ok(())
        }
    }

    #[async_trait]
    impl MountCrypto for MixedDecryptCrypto {
        async fn decrypt_file(
            &self,
            encrypted_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> Result<Vec<u8>, MountSyncError> {
            if encrypted_path.file_name().and_then(|name| name.to_str())
                == Some("blocked.txt.encrypted")
            {
                return Err(MountSyncError::Io(io::Error::from_raw_os_error(28)));
            }
            Ok(b"decrypted".to_vec())
        }

        async fn decrypt_file_streaming(
            &self,
            _encrypted_path: &Path,
            _output_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> Result<(), MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming decrypt not used in test".to_string(),
            ))
        }

        async fn encrypt_file(
            &self,
            relative_path: &str,
            plaintext: &[u8],
        ) -> Result<EncryptedFileMetadata, MountSyncError> {
            Ok(mock_metadata(relative_path, plaintext))
        }

        async fn encrypt_file_with_id(
            &self,
            relative_path: &str,
            plaintext: &[u8],
            file_id: &str,
        ) -> Result<EncryptedFileMetadata, MountSyncError> {
            let mut metadata = mock_metadata(relative_path, plaintext);
            metadata.file_id = file_id.to_string();
            Ok(metadata)
        }

        async fn encrypt_file_streaming(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _chunk_size: usize,
        ) -> Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming encrypt not used in test".to_string(),
            ))
        }

        async fn encrypt_file_streaming_with_id(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _file_id: &str,
            _chunk_size: usize,
        ) -> Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Crypto(
                "streaming encrypt not used in test".to_string(),
            ))
        }

        async fn coverage_store_metadata(
            &self,
            _metadata: FileMetadataData,
        ) -> Result<(), MountSyncError> {
            Ok(())
        }
    }
}
