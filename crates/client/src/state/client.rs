use crate::coverage::{
    CoverageRoot, CoverageRootKind, CoverageRootState, FileCoverageState, FileIndexEntry,
    FileOrphanKind,
};
use crate::epoch_key_source::EpochKeySource;
use crate::errors::{ErrorCode, ErrorContext};
use crate::file::encrypt::{
    build_wrap_aad, chunked_encrypted_size, derive_chunk_nonce, encrypt_content,
    encrypt_content_chunked, generate_file_id, hash_wrap_aad, serialize_encrypted_header,
    wrap_file_key, write_encrypted_file_atomic_for_coverage, PlatformFileMetadata,
    SerializedEncryptedHeader, SparseFileMetadata, AEAD_TAG_SIZE, CHUNKED_HEADER_VERSION,
};
use crate::invitation::InvitationKeyPair;
use crate::network::Network;
use crate::pinning::{
    KeyPinningManager, PinningConfig, PinningPolicy, PinningPrompt, PinningVerificationResult,
};
#[cfg(test)]
use crate::rekey::api::ActivationDecision;
use crate::rekey::api::{PolicyEvaluationSnapshot, RootCoverageKpiPayload};
use crate::rekey::{
    ApiMigrationProgress, ApiRekeyError, CutoverRequest, CutoverResponsePayload,
    EncryptedWelcomeMessage, EpochChangeReason, RekeyDescriptorList, RekeyDescriptorSummary,
    RekeyFallbackRequestPayload, RekeyFallbackResponsePayload, RekeyHeartbeatRequestPayload,
    RekeyInitiateRequest, RekeyProgressState, RekeyProgressUpdateRequest, RekeyResponsePayload,
    RekeyStatus, RekeyStatusPayload,
};
use crate::security::{ClientConfiguration, DeploymentMode, SecurityValidator};
use crate::storage::{
    AccessControlData, CoverageLogData, CoverageLogDeltaData, FileMetadataData, Storage,
    StorageError,
};
use crate::welcome_manager::{ServerWelcomeMessage, ServerWelcomeSignable, WelcomeManager};
use crate::ClientConfig;
use base64::{engine::general_purpose, Engine as _};
use chrono::{serde::ts_seconds, serde::ts_seconds_option, DateTime, Duration, Utc};
use filetime::{set_file_mtime, set_file_times, FileTime};
use glob::Pattern;
use hex;
#[cfg(feature = "mount-fs")]
use hybridcipher_coverage::{CoverageCounts, CoverageRootSnapshot};
use hybridcipher_coverage::{CoverageLog, CoverageTransparencyMetadata, FileEpochEntry};
use hybridcipher_crypto::account_protection::{
    decrypt_with_ad, ProtectedData, PROTECTED_DATA_MAGIC,
};
use hybridcipher_crypto::epoch_id::EpochIdMapper;
use hybridcipher_crypto::{
    aead::AeadContext,
    hybridkem::HybridPublicKey,
    kdf::{hkdf_expand, HkdfContext},
    open, AeadKey, AeadNonce,
};
use hybridcipher_crypto::{
    rekey::cutover_commit_message,
    signatures::{Ed25519KeyPair, VERIFYING_KEY_LEN},
};
use hybridcipher_merkle::InclusionProof;
use hybridcipher_messages::join_card::JoinCard as MessagesJoinCard;
use notify::event::{CreateKind, Event, EventKind};
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use rand::{rngs::OsRng, thread_rng, Rng, RngCore};
use reqwest::{header::HeaderMap, StatusCode};
use serde::{de::Error as DeError, Deserialize, Serialize};
use serde_json::{self, Value};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio::{
    fs,
    sync::{mpsc, Mutex, RwLock},
    task,
    time::{interval, sleep, MissedTickBehavior},
};
use uuid::Uuid;
use walkdir::WalkDir;

#[cfg(test)]
const HEARTBEAT_BASE_INTERVAL_SECS: u64 = 10;
#[cfg(test)]
const HEARTBEAT_MIN_INTERVAL_SECS: u64 = 5;
const HEARTBEAT_JITTER_SECS: u64 = 5;
const HEARTBEAT_MAX_INTERVAL_SECS: u64 = 30;
const HEARTBEAT_BUCKET_CAPACITY: f64 = 4.0;
const STATE_RELOAD_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(1);
const TRACKED_STATS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const COVERAGE_RESCAN_TTL: std::time::Duration = std::time::Duration::from_secs(30);
const RETENTION_WARNING_COOLDOWN_SECS: i64 = 300;
const COVERAGE_WATCHER_INTERVAL_SECS: u64 = 300;
const COVERAGE_WATCHER_MIN_RESCAN_SECS: u64 = 15;
const COVERAGE_WATCHER_ROOT_REFRESH_SECS: u64 = 5;
const COVERAGE_LOG_SNAPSHOT_INTERVAL: u64 = 128;
const COVERAGE_MARKER_PREFIX: &str = ".hybridcipher-root-";
const COVERAGE_MARKER_SUFFIX: &str = ".json";
const DIRECTORY_METADATA_FILE_NAME: &str = ".hybridcipher_dir.encrypted";
const ENCRYPTED_FILE_SEPARATOR: &[u8] = b"\n---ENCRYPTED_DATA---\n";

const DEFAULT_SERVER_URL: &str = "https://api.hybridcipher.com";
const ACCOUNT_KEY_CACHE_FILE: &str = ".account_key_cache";
const DEVICE_KEY_FILE: &str = "device_key.protected";
const SESSION_FILE_AAD: &[u8] = b"hybridcipher/session";
const DEVICE_KEY_FILE_AAD: &[u8] = b"hybridcipher/device_key_material";
const GROUP_MEMBERSHIP_INDEX_KEY: &str = "group_membership_index";
const COVERAGE_ROOT_REGISTRY_KEY: &str = "coverage_root_registry";

mod coverage;
mod coverage_filesystem;
mod files;
mod groups;
mod persistence;
mod rekey;
mod security;
mod session;
#[cfg(test)]
mod tests;
mod welcome;

use self::coverage_filesystem::{
    canonicalize_existing_path, coverage_log_from_data, coverage_log_to_data, find_marker_for_path,
    make_placeholder_file_epoch_entry, marker_path_from_marker, paths_overlap, rekey_debug_enabled,
    remove_marker_for_root, write_marker_for_root, FileExclusionList,
};

/// Server response structures for Welcome messages
#[derive(Debug, Deserialize)]
struct WelcomeMessagesResponse {
    pub group_id: uuid::Uuid,
    pub epoch_uuid: uuid::Uuid,
    pub epoch_id: u64,
    pub legacy_mapping: bool,
    pub messages: Vec<WelcomeMessagePayload>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct WelcomeMessagePayload {
    pub message_id: uuid::Uuid,
    pub epoch_id: uuid::Uuid,
    pub group_id: uuid::Uuid,
    pub recipient_user_id: uuid::Uuid,
    pub recipient_device_id: String,
    #[serde(alias = "encrypted_message")]
    pub encrypted_epoch_key: Vec<u8>,
    #[serde(default)]
    pub signature: Vec<u8>,
    #[serde(default)]
    pub signing_public_key: Vec<u8>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response payload from the HybridCipher server when listing groups
#[derive(Debug, Deserialize)]
struct GroupListApiResponse {
    pub groups: Vec<ServerGroupInfo>,
    #[allow(dead_code)]
    pub total_count: Option<u32>,
}

/// Minimal group information parsed from the server response
#[derive(Debug, Clone, Deserialize)]
struct ServerGroupInfo {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub current_epoch: Option<String>,
    #[serde(default)]
    pub user_role: ServerGroupRole,
}

/// Server-side group roles
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ServerGroupRole {
    Admin,
    Member,
    Viewer,
}

impl Default for ServerGroupRole {
    fn default() -> Self {
        ServerGroupRole::Member
    }
}

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct GeneratedWelcomeMessage {
    pub recipient_user_id: uuid::Uuid,
    pub device_id: String,
    pub encrypted_epoch_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct SelfIssuedWelcomePayload {
    pub group_id: uuid::Uuid,
    pub recipient_user_id: uuid::Uuid,
    pub device_id: String,
    pub encrypted_epoch_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct SubmitSelfWelcomeRequest {
    pub encrypted_epoch_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<(uuid::Uuid, GeneratedWelcomeMessage)> for SelfIssuedWelcomePayload {
    fn from(value: (uuid::Uuid, GeneratedWelcomeMessage)) -> Self {
        let (group_id, message) = value;
        Self {
            group_id,
            recipient_user_id: message.recipient_user_id,
            device_id: message.device_id,
            encrypted_epoch_key: message.encrypted_epoch_key,
            signature: message.signature,
            signing_public_key: message.signing_public_key,
            created_at: message.created_at,
            expires_at: message.expires_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct GenesisInitRequestBody {
    pub client_epoch_id: u64,
    pub welcome_messages: Vec<GeneratedWelcomeMessage>,
}

#[derive(Debug, Deserialize)]
struct ServerInfoResponse {
    public_keys: ServerInfoPublicKeys,
}

#[derive(Debug, Deserialize)]
struct ServerInfoPublicKeys {
    #[serde(default)]
    welcome_signing: Option<ServerInfoSigningKey>,
}

#[derive(Debug, Deserialize)]
struct ServerInfoSigningKey {
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct GenesisInitResponseBody {
    pub epoch_id: String,
    pub epoch_number: u64,
    #[serde(default)]
    pub welcome_message_count: usize,
}

/// Metadata for an encrypted file with all necessary information for decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFileMetadata {
    /// Unique file identifier
    pub file_id: String,

    /// Original file path
    pub file_path: String,

    /// Header format/version to support dual-format reads
    #[serde(default)]
    pub header_version: Option<u32>,

    /// Group the file belongs to (added for multi-group support)
    #[serde(default)]
    pub group_id: Option<Uuid>,

    /// Epoch ID used for encryption
    pub epoch_id: u64,

    /// Wrapped per-file DEK (new format). Empty/None means legacy derive-only format.
    #[serde(default)]
    pub wrapped_file_key: Option<Vec<u8>>,

    /// Nonce used to wrap the DEK
    #[serde(default)]
    pub key_wrap_nonce: Option<Vec<u8>>,

    /// Hash of the AAD used for key wrapping (to validate header integrity)
    #[serde(default)]
    pub key_wrap_aad_hash: Option<Vec<u8>>,

    /// Content nonce for the encrypted body (present in new format; legacy keeps nonce in ciphertext prefix)
    #[serde(default)]
    pub content_nonce: Option<Vec<u8>>,

    /// Chunk size for chunked content encryption (header_version >= 2)
    #[serde(default)]
    pub content_chunk_size: Option<u64>,

    /// Original content size in bytes
    pub content_size: u64,

    /// Encrypted content size in bytes
    pub encrypted_size: u64,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Filesystem metadata that must survive encrypt/decrypt round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_metadata: Option<PlatformFileMetadata>,

    /// Sparse file layout metadata. When present, `content_size` remains the logical size and the
    /// encrypted body stores only packed data extents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse_metadata: Option<SparseFileMetadata>,

    /// Encrypted content (nonce + ciphertext)
    pub encrypted_content: Vec<u8>,
}

/// Result of adding a new member to the group
#[derive(Debug)]
pub struct AddMemberResult {
    pub group_update: crate::group::SignedGroupUpdate,
    pub welcome_message: crate::welcome_manager::WelcomeMessage,
    pub new_epoch_id: u64,
}

/// Result of removing a member from the group
#[derive(Debug)]
pub struct RemoveMemberResult {
    pub group_update: crate::group::SignedGroupUpdate,
    pub rekey_required: bool,
    pub rekey_plan: Option<RekeyPlan>,
}

/// Plan for rekeying operations after member changes
#[derive(Debug)]
pub struct RekeyPlan {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub files_to_migrate: Vec<String>,
    pub estimated_duration: std::time::Duration,
    pub reason: String,
}

/// Local tracking state for automatic rekey heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekeyHeartbeatState {
    #[serde(default)]
    sequence: u64,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    last_observed_at: Option<DateTime<Utc>>,
    #[serde(default = "default_bucket_tokens")]
    bucket_tokens: f64,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    bucket_last_refill: Option<DateTime<Utc>>,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    last_emitted_at: Option<DateTime<Utc>>,
    #[serde(default)]
    last_descriptor_commitment: Option<String>,
    #[serde(default)]
    last_coverage_bytes: u64,
    #[serde(default)]
    last_coverage_items: u64,
    #[serde(default)]
    last_protected_bytes: u64,
    #[serde(default)]
    last_protected_items: u64,
    #[serde(default)]
    confirmed_reported: bool,
    #[serde(default)]
    last_tracked_files: u64,
    #[serde(default)]
    stuck_tracked_files_count: u32,
    #[serde(default)]
    pending_emit: bool,
}

fn default_bucket_tokens() -> f64 {
    HEARTBEAT_BUCKET_CAPACITY
}

impl Default for RekeyHeartbeatState {
    fn default() -> Self {
        Self {
            sequence: 0,
            last_observed_at: None,
            bucket_tokens: HEARTBEAT_BUCKET_CAPACITY,
            bucket_last_refill: None,
            last_emitted_at: None,
            last_descriptor_commitment: None,
            last_coverage_bytes: 0,
            last_coverage_items: 0,
            last_protected_bytes: 0,
            last_protected_items: 0,
            confirmed_reported: false,
            last_tracked_files: 0,
            stuck_tracked_files_count: 0,
            pending_emit: false,
        }
    }
}

#[derive(Debug, Default)]
struct HeartbeatWorkerState {
    running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRewrap {
    path: String,
    from_epoch: u64,
    to_epoch: u64,
    group_id: Uuid,
    attempts: u32,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    last_attempt: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoveragePendingFile {
    pub path: String,
    pub current_epoch: u64,
    pub target_epoch: u64,
    pub file_size: u64,
    pub last_modified: DateTime<Utc>,
    pub attempts: u32,
    pub last_attempt: Option<DateTime<Utc>>,
}

/// Summary returned after scanning enrolled coverage roots.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CoverageScanSummary {
    /// Number of roots successfully scanned
    pub roots_scanned: usize,
    /// Number of files that are now tracked across all scanned roots
    pub files_indexed: usize,
    /// Number of previously tracked files that went missing during the scan
    pub orphaned_files: usize,
    /// Number of files discovered on disk without coverage metadata
    pub unmanaged_files: usize,
    /// Enrolled roots that could not be scanned because the path is missing or unreadable.
    #[serde(default)]
    pub missing_roots: Vec<PathBuf>,
}

/// Summary returned after syncing local coverage state to the server.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CoverageSyncSummary {
    /// Number of roots evaluated for sync.
    pub roots_synced: usize,
    /// Number of file index entries considered for sync.
    pub entries_considered: usize,
    /// Number of upsert deltas prepared.
    pub upserts_prepared: usize,
    /// Number of removal deltas prepared.
    pub removals_prepared: usize,
    /// Number of entries skipped due to missing identifiers.
    pub skipped_entries: usize,
    /// Number of deltas successfully uploaded.
    pub uploaded_deltas: usize,
    /// Number of upload batches completed.
    pub uploaded_batches: usize,
    /// Number of entries uploaded via baseline sync (0 if baseline was not used).
    #[serde(default)]
    pub baseline_entries: usize,
}

/// Progress callback for coverage scans: (root, processed, total).
pub type CoverageScanProgress =
    std::sync::Arc<dyn Fn(&CoverageRoot, usize, usize) + Send + Sync + 'static>;

/// Progress callback for coverage sync: (processed, total).
pub type CoverageSyncProgress = std::sync::Arc<dyn Fn(usize, usize) + Send + Sync + 'static>;

/// Progress callback for coverage sync uploads: (uploaded, total).
pub type CoverageUploadProgress = std::sync::Arc<dyn Fn(usize, usize) + Send + Sync + 'static>;

/// Detailed file-level view after a coverage scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageFileRecord {
    pub root: CoverageRoot,
    pub entry: FileIndexEntry,
}

/// Summary of guard/remediation actions performed across orphaned entries.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CoverageGuardSummary {
    /// Number of orphaned entries enqueued for migration/rewrap.
    pub migrated: usize,
    /// Number of missing-file orphan entries pruned.
    pub pruned: usize,
    /// Number of ciphertext-without-metadata orphan entries adopted successfully.
    pub adopted: usize,
    /// Paths that failed to adopt (typically due to missing metadata).
    #[serde(default)]
    pub adopt_failures: Vec<String>,
    /// Number of outcast orphan entries purged.
    #[serde(default)]
    pub purged_outcast: usize,
}

/// Progress summary for coverage migration runs.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct CoverageMigrationProgress {
    pub total_files: usize,
    pub migrated_files: usize,
    pub failed_files: usize,
}

/// Result returned when adopting a file into coverage tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAdoptResult {
    pub root: CoverageRoot,
    pub entry: FileIndexEntry,
}

/// Preview of orphaned files that still need adoption under a root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageOrphanSample {
    pub relative_path: String,
    pub size: u64,
    pub last_seen: DateTime<Utc>,
    pub state: FileCoverageState,
    pub orphan_kind: Option<FileOrphanKind>,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageDeltaUploadEntry {
    sequence: u64,
    file_id: String,
    epoch_id: u64,
    updated_at: DateTime<Utc>,
    #[serde(default)]
    action: crate::storage::CoverageDeltaAction,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageDeltaUploadRequest {
    device_id: String,
    deltas: Vec<CoverageDeltaUploadEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct CoverageDeltaUploadResponse {
    acknowledged_sequence: u64,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageBaselineEntry {
    file_id: String,
    epoch_id: u64,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageBaselineRequest {
    device_id: String,
    last_sequence: u64,
    entries: Vec<CoverageBaselineEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct CoverageBaselineResponse {
    #[serde(rename = "acknowledged_sequence")]
    _acknowledged_sequence: u64,
    #[serde(rename = "total_entries")]
    _total_entries: u64,
}

#[derive(Debug, Default)]
struct IdleCrawlerState {
    running: bool,
    abort: bool,
}

#[derive(Debug, Default)]
struct CoverageWatcherState {
    running: bool,
}

#[derive(Debug, Default)]
struct CoverageEnrollmentState {
    in_progress_roots: HashSet<Uuid>,
}

#[derive(Debug, Default)]
struct CoverageReplicationState {
    running: bool,
}

/// Maximum number of consecutive terminal coverage upload failures before disabling replication.
const COVERAGE_TERMINAL_FAILURE_LIMIT: u32 = 3;

#[derive(Debug)]
struct CoverageUploadThrottle {
    min_interval: std::time::Duration,
    backoff_base: std::time::Duration,
    backoff_max: std::time::Duration,
    state: Mutex<CoverageUploadThrottleState>,
}

#[derive(Debug)]
struct CoverageUploadThrottleState {
    next_allowed: Instant,
    backoff: std::time::Duration,
}

#[derive(Debug)]
struct RekeyRequestThrottle {
    backoff_base: std::time::Duration,
    backoff_max: std::time::Duration,
    state: Mutex<RekeyRequestThrottleState>,
}

#[derive(Debug)]
struct RekeyRequestThrottleState {
    next_allowed: Instant,
    backoff: std::time::Duration,
}

#[derive(Debug, Default)]
struct StateReloadCache {
    last_checked_at: Option<Instant>,
    cached_generation: Option<u64>,
}

#[derive(Debug, Default)]
struct TrackedStatsCache {
    last_updated_at: Option<Instant>,
    root_ids_hash: Option<u64>,
    tracked_files: u64,
    tracked_bytes: u64,
    invalidated: bool,
}

#[derive(Debug, Default)]
struct CoverageRescanCache {
    last_rescan_at: Option<Instant>,
}

impl CoverageUploadThrottle {
    fn new(config: &ClientConfig) -> Self {
        let min_interval = std::time::Duration::from_millis(config.coverage_upload_min_interval_ms);
        let backoff_base = std::time::Duration::from_millis(config.coverage_upload_backoff_base_ms);
        let mut backoff_max =
            std::time::Duration::from_millis(config.coverage_upload_backoff_max_ms);
        if backoff_max < backoff_base {
            backoff_max = backoff_base;
        }
        Self {
            min_interval,
            backoff_base,
            backoff_max,
            state: Mutex::new(CoverageUploadThrottleState {
                next_allowed: Instant::now(),
                backoff: std::time::Duration::from_secs(0),
            }),
        }
    }

    async fn wait_for_slot(&self) {
        loop {
            let delay = {
                let mut state = self.state.lock().await;
                let now = Instant::now();
                if now >= state.next_allowed {
                    state.next_allowed = now + self.min_interval;
                    return;
                }
                state.next_allowed.saturating_duration_since(now)
            };

            if delay.is_zero() {
                return;
            }
            sleep(delay).await;
        }
    }

    async fn register_success(&self) {
        let mut state = self.state.lock().await;
        state.backoff = std::time::Duration::from_secs(0);
    }

    async fn register_failure(&self, retry_after: Option<std::time::Duration>) {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        let mut next_backoff = if state.backoff.is_zero() {
            self.backoff_base
        } else {
            state.backoff.saturating_mul(2)
        };

        if let Some(retry_after) = retry_after {
            next_backoff = next_backoff.max(retry_after);
        }

        if self.backoff_max != std::time::Duration::from_secs(0) && next_backoff > self.backoff_max
        {
            next_backoff = self.backoff_max;
        }

        if next_backoff.is_zero() {
            return;
        }

        state.backoff = next_backoff;
        let candidate = now + next_backoff;
        if candidate > state.next_allowed {
            state.next_allowed = candidate;
        }
    }
}

impl RekeyRequestThrottle {
    const BACKOFF_BASE_SECS: u64 = 2;
    const BACKOFF_MAX_SECS: u64 = 60;

    fn new() -> Self {
        Self {
            backoff_base: std::time::Duration::from_secs(Self::BACKOFF_BASE_SECS),
            backoff_max: std::time::Duration::from_secs(Self::BACKOFF_MAX_SECS),
            state: Mutex::new(RekeyRequestThrottleState {
                next_allowed: Instant::now(),
                backoff: std::time::Duration::from_secs(0),
            }),
        }
    }

    async fn wait_for_slot(&self) {
        loop {
            let delay = {
                let state = self.state.lock().await;
                let now = Instant::now();
                if now >= state.next_allowed {
                    return;
                }
                state.next_allowed.saturating_duration_since(now)
            };

            if delay.is_zero() {
                return;
            }
            sleep(delay).await;
        }
    }

    async fn register_success(&self) {
        let mut state = self.state.lock().await;
        state.backoff = std::time::Duration::from_secs(0);
        state.next_allowed = Instant::now();
    }

    async fn register_failure(&self, retry_after: Option<std::time::Duration>) {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        let mut next_backoff = if state.backoff.is_zero() {
            self.backoff_base
        } else {
            state.backoff.saturating_mul(2)
        };

        if let Some(retry_after) = retry_after {
            next_backoff = next_backoff.max(retry_after);
        }

        if self.backoff_max != std::time::Duration::from_secs(0) && next_backoff > self.backoff_max
        {
            next_backoff = self.backoff_max;
        }

        if next_backoff.is_zero() {
            return;
        }

        state.backoff = next_backoff;
        let candidate = now + next_backoff;
        if candidate > state.next_allowed {
            state.next_allowed = candidate;
        }
    }
}

fn should_backoff(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn retry_after_delay(headers: &HeaderMap) -> Option<std::time::Duration> {
    let header = headers.get(reqwest::header::RETRY_AFTER)?;
    let header = header.to_str().ok()?;
    let seconds: u64 = header.parse().ok()?;
    Some(std::time::Duration::from_secs(seconds))
}

#[derive(Debug)]
enum CoverageUploadFailure {
    Retryable {
        retry_after: Option<std::time::Duration>,
    },
    Terminal {
        reason: String,
        retry_after: Option<std::time::Duration>,
    },
}

fn classify_coverage_upload_failure(
    status: StatusCode,
    body: &str,
    retry_after: Option<std::time::Duration>,
) -> CoverageUploadFailure {
    if status.is_server_error()
        || matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS
                | StatusCode::REQUEST_TIMEOUT
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        )
    {
        return CoverageUploadFailure::Retryable { retry_after };
    }

    let reason = match status {
        StatusCode::NOT_FOUND => {
            if body.to_ascii_lowercase().contains("group not found") {
                "coverage group not found on server".to_string()
            } else {
                "coverage upload returned 404 for coverage log".to_string()
            }
        }
        StatusCode::FORBIDDEN => {
            "coverage upload forbidden (membership or ACL revoked)".to_string()
        }
        StatusCode::GONE => "coverage group has been removed (410)".to_string(),
        StatusCode::BAD_REQUEST => "coverage upload payload rejected by server (400)".to_string(),
        _ if status.is_client_error() => {
            format!("coverage upload rejected ({}): {}", status, body)
        }
        _ => return CoverageUploadFailure::Retryable { retry_after },
    };

    CoverageUploadFailure::Terminal {
        reason,
        retry_after,
    }
}

#[derive(Debug, Default)]
struct CoverageCompactionState {
    running: bool,
    bulk_depth: usize,
    pending_groups: HashSet<Uuid>,
    trackers: HashMap<Uuid, CoverageCompactionTracker>,
}

#[derive(Debug, Default, Clone)]
struct CoverageCompactionTracker {
    last_compact_sequence: u64,
    last_compact_at: Option<Instant>,
    last_update_at: Option<Instant>,
    backoff_until: Option<Instant>,
}

#[derive(Debug)]
struct FileIndexCache {
    entries_by_root: HashMap<Uuid, Vec<FileIndexEntry>>,
    lru: VecDeque<Uuid>,
    max_roots: usize,
}

impl FileIndexCache {
    fn new(max_roots: usize) -> Self {
        Self {
            entries_by_root: HashMap::new(),
            lru: VecDeque::new(),
            max_roots,
        }
    }

    fn is_enabled(&self) -> bool {
        self.max_roots > 0
    }

    fn get(&mut self, root_id: Uuid) -> Option<Vec<FileIndexEntry>> {
        if !self.is_enabled() {
            return None;
        }
        if !self.entries_by_root.contains_key(&root_id) {
            return None;
        }
        self.promote(root_id);
        self.entries_by_root.get(&root_id).cloned()
    }

    fn insert(&mut self, root_id: Uuid, entries: Vec<FileIndexEntry>) {
        if !self.is_enabled() {
            return;
        }
        self.entries_by_root.insert(root_id, entries);
        self.promote(root_id);
        while self.entries_by_root.len() > self.max_roots {
            if let Some(evict) = self.lru.pop_front() {
                self.entries_by_root.remove(&evict);
            }
        }
    }

    fn update_entry(&mut self, entry: &FileIndexEntry) {
        if !self.is_enabled() {
            return;
        }
        let Some(entries) = self.entries_by_root.get_mut(&entry.root_id) else {
            return;
        };
        if let Some(existing) = entries
            .iter_mut()
            .find(|existing| existing.file_uuid == entry.file_uuid)
        {
            *existing = entry.clone();
        } else {
            entries.push(entry.clone());
        }
        self.promote(entry.root_id);
    }

    fn remove_entry(&mut self, root_id: Uuid, file_uuid: Uuid) {
        if !self.is_enabled() {
            return;
        }
        let Some(entries) = self.entries_by_root.get_mut(&root_id) else {
            return;
        };
        entries.retain(|entry| entry.file_uuid != file_uuid);
        self.promote(root_id);
    }

    fn promote(&mut self, root_id: Uuid) {
        self.lru.retain(|id| *id != root_id);
        self.lru.push_back(root_id);
    }

    fn size(&self) -> usize {
        self.entries_by_root.len()
    }
}

#[derive(Debug)]
struct StateSaveCoordinator {
    debounce: std::time::Duration,
    last_save_millis: AtomicU64,
    pending: AtomicBool,
    scheduled: AtomicBool,
}

impl StateSaveCoordinator {
    fn new(debounce: std::time::Duration) -> Self {
        Self {
            debounce,
            last_save_millis: AtomicU64::new(0),
            pending: AtomicBool::new(false),
            scheduled: AtomicBool::new(false),
        }
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64
    }

    fn has_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    fn mark_pending(&self) {
        self.pending.store(true, Ordering::Release);
    }

    fn take_pending(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }

    fn mark_saved(&self) {
        self.pending.store(false, Ordering::Release);
        self.last_save_millis
            .store(Self::now_millis(), Ordering::Release);
    }

    fn try_schedule(&self) -> bool {
        !self.scheduled.swap(true, Ordering::AcqRel)
    }

    fn clear_scheduled(&self) {
        self.scheduled.store(false, Ordering::Release);
    }

    fn next_delay(&self) -> std::time::Duration {
        let debounce_ms = self.debounce.as_millis().min(u64::MAX as u128) as u64;
        if debounce_ms == 0 {
            return std::time::Duration::from_millis(0);
        }

        let last = self.last_save_millis.load(Ordering::Acquire);
        if last == 0 {
            return self.debounce;
        }

        let now = Self::now_millis();
        let elapsed = now.saturating_sub(last);
        if elapsed >= debounce_ms {
            std::time::Duration::from_millis(0)
        } else {
            std::time::Duration::from_millis(debounce_ms - elapsed)
        }
    }
}

#[derive(Debug)]
struct CoverageCompactionPlan {
    compact_up_to: u64,
}

#[derive(Debug)]
enum CoverageWatcherEvent {
    RootChanged(Uuid),
    FileCreated {
        root_id: Uuid,
        root_path: PathBuf,
        created_path: PathBuf,
    },
    WatcherError {
        root_id: Uuid,
        message: String,
    },
}

struct CoverageRootWatcher {
    _root_id: Uuid,
    _path: PathBuf,
    _watcher: RecommendedWatcher,
}

impl CoverageRootWatcher {
    fn new(
        root: CoverageRoot,
        sender: mpsc::UnboundedSender<CoverageWatcherEvent>,
        logger: Arc<crate::logging::StructuredLogger>,
    ) -> notify::Result<Self> {
        let root_id = root.root_id;
        let path = root.path.clone();
        let display_path = path.display().to_string();

        let config = NotifyConfig::default().with_poll_interval(std::time::Duration::from_secs(5));
        let mut watcher = RecommendedWatcher::new(
            {
                let logger = logger.clone();
                let sender = sender;
                let root_path = path.clone();
                move |res: notify::Result<Event>| match res {
                    Ok(event) => {
                        if coverage_event_is_file_create(&event.kind) {
                            for file_path in event.paths.iter().cloned() {
                                let _ = sender.send(CoverageWatcherEvent::FileCreated {
                                    root_id,
                                    root_path: root_path.clone(),
                                    created_path: file_path,
                                });
                            }
                        }

                        if coverage_event_requires_scan(&event.kind) {
                            let _ = sender.send(CoverageWatcherEvent::RootChanged(root_id));
                        }
                    }
                    Err(err) => {
                        let message =
                            format!("Filesystem watcher error for {}: {}", display_path, err);
                        logger.log(
                            crate::logging::LogLevel::Warn,
                            &message,
                            Some("coverage_watcher_error"),
                        );
                        let _ =
                            sender.send(CoverageWatcherEvent::WatcherError { root_id, message });
                    }
                }
            },
            config,
        )?;

        let recursive_mode = if root.kind == CoverageRootKind::Folder {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        watcher.watch(&path, recursive_mode)?;

        Ok(Self {
            _root_id: root_id,
            _path: path,
            _watcher: watcher,
        })
    }
}

fn coverage_event_requires_scan(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Create(_)
            | EventKind::Modify(_)
            | EventKind::Remove(_)
            | EventKind::Any
            | EventKind::Other
    )
}

fn coverage_event_is_file_create(kind: &EventKind) -> bool {
    match kind {
        EventKind::Create(CreateKind::File | CreateKind::Any | CreateKind::Other) => true,
        _ => false,
    }
}

/// Aggregated per-root statistics returned for UX surfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRootStats {
    pub root: CoverageRoot,
    pub tracked_files: usize,
    pub tracked_bytes: u64,
    pub orphaned_files: usize,
    pub orphaned_bytes: u64,
    #[serde(default)]
    pub orphan_wrong_epoch: usize,
    #[serde(default)]
    pub orphan_missing_file: usize,
    #[serde(default)]
    pub orphan_missing_metadata: usize,
    #[serde(default)]
    pub orphan_outcast: usize,
    pub unmanaged_files: usize,
    pub unmanaged_bytes: u64,
    pub coverage_ratio: f64,
    #[serde(default)]
    pub recent_orphans: Vec<CoverageOrphanSample>,
    #[serde(default)]
    pub recent_unmanaged: Vec<CoverageOrphanSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CoverageLedgerMeta {
    #[serde(default)]
    sequence: u64,
    #[serde(default)]
    snapshot_sequence: u64,
    #[serde(default)]
    ack_sequence: u64,
    #[serde(default)]
    delta_ack_sequence: u64,
    #[serde(default)]
    consecutive_failures: u32,
    #[serde(default)]
    permanently_disabled: bool,
    #[serde(default)]
    disabled_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct CoverageLedgerState {
    log: CoverageLog,
    loaded: bool,
    sequence: u64,
    snapshot_sequence: u64,
    ack_sequence: u64,
    delta_ack_sequence: u64,
    consecutive_failures: u32,
    permanently_disabled: bool,
    disabled_reason: Option<String>,
    /// Skip one seed-from-index cycle after an explicit reset (e.g., fallback) to avoid
    /// reintroducing stale coverage before a fresh scan runs.
    skip_seed_once: bool,
}

impl Default for CoverageLedgerState {
    fn default() -> Self {
        Self {
            log: CoverageLog::new(),
            loaded: false,
            sequence: 0,
            snapshot_sequence: 0,
            ack_sequence: 0,
            delta_ack_sequence: 0,
            consecutive_failures: 0,
            permanently_disabled: false,
            disabled_reason: None,
            skip_seed_once: false,
        }
    }
}

impl CoverageLedgerState {
    fn to_meta(&self) -> CoverageLedgerMeta {
        CoverageLedgerMeta {
            sequence: self.sequence,
            snapshot_sequence: self.snapshot_sequence,
            ack_sequence: self.ack_sequence,
            delta_ack_sequence: self.delta_ack_sequence,
            consecutive_failures: self.consecutive_failures,
            permanently_disabled: self.permanently_disabled,
            disabled_reason: self.disabled_reason.clone(),
        }
    }

    fn apply_meta(&mut self, meta: &CoverageLedgerMeta) {
        self.ack_sequence = meta.ack_sequence;
        self.delta_ack_sequence = meta.delta_ack_sequence;
        self.consecutive_failures = meta.consecutive_failures;
        self.permanently_disabled = meta.permanently_disabled;
        self.disabled_reason = meta.disabled_reason.clone();
    }
}

/// Snapshot of a coverage root registry entry for listing across groups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRegistryEntry {
    pub path: String,
    pub group_id: Uuid,
    pub root_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoverageMarkerFile {
    root_id: Uuid,
    group_id: Uuid,
    kind: CoverageRootKind,
    root_name: String,
    #[serde(default)]
    path_hint: Option<String>,
}

/// Details about a scanned marker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedMarkerInfo {
    pub marker_path: PathBuf,
    pub root_id: Uuid,
    pub root_path: PathBuf,
    pub kind: CoverageRootKind,
}

/// Summary of marker-based recovery.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageMarkerRecoveryResult {
    pub scanned: usize,
    pub eligible: usize,
    pub already_enrolled: usize,
    pub group_mismatch: usize,
    pub enrolled: Vec<PathBuf>,
    pub missing_paths: Vec<PathBuf>,
    // Detailed information
    pub scanned_markers: Vec<ScannedMarkerInfo>,
    pub eligible_markers: Vec<ScannedMarkerInfo>,
    pub already_enrolled_markers: Vec<ScannedMarkerInfo>,
    pub group_mismatch_markers: Vec<ScannedMarkerInfo>,
}

/// Summary of an active server-side rekey operation tracked by the client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveRekeyOperation {
    pub rekey_id: Uuid,
    pub group_id: Uuid,
    pub new_epoch_id: Option<Uuid>,
    pub new_epoch_label: String,
    pub status: RekeyStatus,
    pub started_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub estimated_completion: Option<DateTime<Utc>>,
    pub can_cutover: bool,
    pub progress: RekeyProgress,
    pub policy: Option<PolicyEvaluationSnapshot>,
    pub errors: Vec<RekeyErrorEntry>,
    #[serde(default)]
    pub descriptor_commitment: Option<String>,
    /// If true, skip the local override once to avoid showing stale progress from a previous rekey.
    #[serde(default)]
    pub suppress_local_override: bool,
}

/// Aggregated migration progress reported by the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyProgress {
    pub total_files: u64,
    pub migrated_files: u64,
    pub total_members: u32,
    pub confirmed_members: u32,
    #[serde(default)]
    pub reporting_members: u32,
    pub estimated_time_remaining_minutes: Option<u32>,
}

/// Error emitted by the server while processing member/device migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyErrorEntry {
    pub error_type: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub member_id: Option<Uuid>,
}

/// Options controlling how the client initiates a rekey operation
#[derive(Debug, Clone)]
pub struct RekeyInitiationOptions {
    pub reason: EpochChangeReason,
    pub emergency: bool,
    pub welcome_messages: Vec<EncryptedWelcomeMessage>,
    pub client_epoch_id: Option<u64>,
    pub config: Option<Value>,
    pub member_updates: Option<Value>,
}

impl Default for RekeyInitiationOptions {
    fn default() -> Self {
        Self {
            reason: EpochChangeReason::KeyRotation,
            emergency: false,
            welcome_messages: Vec::new(),
            client_epoch_id: None,
            config: None,
            member_updates: None,
        }
    }
}

/// Summary returned after a successful cutover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CutoverSummary {
    pub cutover_id: Uuid,
    pub group_id: Uuid,
    pub new_epoch_id: Uuid,
    pub old_epoch_id: Uuid,
    pub completed_at: DateTime<Utc>,
    pub cleanup_status: String,
}

/// Summary returned after cancelling an active rekey operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyFallbackSummary {
    pub rekey_id: Uuid,
    pub group_id: Uuid,
    pub cancelled_at: DateTime<Utc>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub new_epoch_id: Option<Uuid>,
    #[serde(default)]
    pub new_epoch_number: Option<u64>,
    #[serde(default)]
    pub previous_epoch_id: Option<Uuid>,
    #[serde(default)]
    pub previous_epoch_number: Option<u64>,
}

#[cfg(feature = "mount-fs")]
#[derive(Debug, Clone)]
pub struct CoverageSnapshotInfo {
    pub merkle_root_hex: String,
    pub verifying_key_base64: String,
    pub signing_key_id: Option<String>,
    pub signature_base64: Option<String>,
}

#[cfg(feature = "mount-fs")]
#[derive(Debug, Clone)]
pub struct CoverageEpochSummary {
    pub epoch_id: u64,
    pub total_files: u64,
    pub rewrapped_files: u64,
    pub coverage_ratio: f64,
    pub is_active: bool,
    pub is_migration_target: bool,
}

#[cfg(feature = "mount-fs")]
#[derive(Debug, Clone)]
pub struct CoverageOverview {
    pub generated_at: DateTime<Utc>,
    pub current_epoch: u64,
    pub migration_target_epoch: Option<u64>,
    pub total_tracked_files: u64,
    pub epochs: Vec<CoverageEpochSummary>,
    pub latest_snapshot: Option<CoverageSnapshotInfo>,
}

#[derive(Debug, Deserialize)]
struct CoverageSnapshotDownloadEntry {
    file_id: String,
    epoch_number: u64,
}

fn deserialize_coverage_generated_at<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TimestampValue {
        Seconds(i64),
        Unsigned(u64),
        String(String),
    }

    let value = TimestampValue::deserialize(deserializer)?;
    match value {
        TimestampValue::Seconds(seconds) => DateTime::from_timestamp(seconds, 0)
            .ok_or_else(|| DeError::custom("coverage_generated_at seconds out of range")),
        TimestampValue::Unsigned(seconds) => {
            let seconds = i64::try_from(seconds)
                .map_err(|_| DeError::custom("coverage_generated_at seconds out of range"))?;
            DateTime::from_timestamp(seconds, 0)
                .ok_or_else(|| DeError::custom("coverage_generated_at seconds out of range"))
        }
        TimestampValue::String(value) => DateTime::parse_from_rfc3339(&value)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(DeError::custom),
    }
}

#[derive(Debug, Deserialize)]
struct CoverageSnapshotDownloadResponse {
    snapshot_id: Uuid,
    group_id: Uuid,
    epoch_id: Uuid,
    merkle_root_hex: String,
    signature_base64: String,
    verifying_key_base64: String,
    signing_key_id: Option<String>,
    total_files: u64,
    #[serde(deserialize_with = "deserialize_coverage_generated_at")]
    coverage_generated_at: DateTime<Utc>,
    #[serde(default)]
    transparency_metadata: Option<CoverageTransparencyMetadata>,
    #[serde(default)]
    entries_total: Option<u64>,
    #[serde(rename = "entries_offset", default)]
    _entries_offset: Option<u64>,
    #[serde(rename = "entries_limit", default)]
    _entries_limit: Option<u64>,
    #[serde(rename = "entries_truncated", default)]
    _entries_truncated: Option<bool>,
    entries: Vec<CoverageSnapshotDownloadEntry>,
}

#[derive(Debug, Deserialize)]
struct CoverageProofResponse {
    snapshot_id: Uuid,
    group_id: Uuid,
    epoch_id: Uuid,
    merkle_root_hex: String,
    signature_base64: String,
    verifying_key_base64: String,
    signing_key_id: Option<String>,
    total_files: u64,
    #[serde(deserialize_with = "deserialize_coverage_generated_at")]
    coverage_generated_at: DateTime<Utc>,
    file_id: String,
    file_epoch: u64,
    proof: hybridcipher_merkle::InclusionProof,
}

/// Public representation of a server-side coverage snapshot download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSnapshotArtifact {
    pub snapshot_id: Uuid,
    pub group_id: Uuid,
    pub epoch_id: Uuid,
    pub merkle_root: [u8; 32],
    pub signature: Vec<u8>,
    pub verifying_key: [u8; VERIFYING_KEY_LEN],
    pub signing_key_id: Option<String>,
    pub total_files: u64,
    pub generated_at: DateTime<Utc>,
    pub transparency_metadata: Option<CoverageTransparencyMetadata>,
    pub entries: Vec<CoverageSnapshotEntry>,
}

/// Coverage proof for a specific file in the latest snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageProofArtifact {
    pub snapshot_id: Uuid,
    pub group_id: Uuid,
    pub epoch_id: Uuid,
    pub merkle_root: [u8; 32],
    pub signature: Vec<u8>,
    pub verifying_key: [u8; VERIFYING_KEY_LEN],
    pub signing_key_id: Option<String>,
    pub total_files: u64,
    pub generated_at: DateTime<Utc>,
    pub file_id: String,
    pub file_epoch: u64,
    pub proof: hybridcipher_merkle::InclusionProof,
}

/// File-level entry contained inside a downloaded coverage snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSnapshotEntry {
    pub file_id: String,
    pub epoch_number: u64,
}

#[cfg(feature = "mount-fs")]
#[derive(Debug, Clone)]
pub struct RekeyHeartbeatSummary {
    pub rekey_id: Uuid,
    pub sequence: u64,
    pub last_emitted_at: Option<DateTime<Utc>>,
    pub last_observed_at: Option<DateTime<Utc>>,
    pub descriptor_commitment: Option<String>,
    pub last_coverage_bytes: u64,
    pub last_coverage_items: u64,
    pub last_protected_bytes: u64,
    pub last_protected_items: u64,
    pub confirmed_reported: bool,
}

#[cfg(feature = "mount-fs")]
#[derive(Debug, Clone)]
pub struct PendingRewrapSummary {
    pub path: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub group_id: Uuid,
    pub attempts: u32,
    pub last_attempt: Option<DateTime<Utc>>,
}

#[cfg(feature = "mount-fs")]
#[derive(Debug, Clone)]
pub struct RekeyOverlayState {
    pub generated_at: DateTime<Utc>,
    pub active_operation: Option<ActiveRekeyOperation>,
    pub migration: Option<MigrationState>,
    pub heartbeats: Vec<RekeyHeartbeatSummary>,
    pub pending_rewraps: Vec<PendingRewrapSummary>,
}

/// Local-only view of the rewrap queue to surface progress without server calls.
#[derive(Debug, Clone)]
pub struct LocalRewrapSnapshot {
    pub total_files: u64,
    pub migrated_files: u64,
    pub pending_rewraps: u64,
}

impl ActiveRekeyOperation {
    fn from_initiation(payload: RekeyResponsePayload) -> Self {
        let (new_epoch_id, new_epoch_label) = parse_epoch_identifier(&payload.new_epoch_id);

        Self {
            rekey_id: payload.rekey_id,
            group_id: payload.group_id,
            new_epoch_id,
            new_epoch_label,
            status: payload.status,
            started_at: payload.initiated_at,
            last_updated: payload.initiated_at,
            estimated_completion: Some(payload.estimated_completion),
            can_cutover: matches!(
                payload.status,
                RekeyStatus::AwaitingCutover | RekeyStatus::Completing | RekeyStatus::Completed
            ),
            progress: payload.migration_progress.into(),
            policy: None,
            errors: Vec::new(),
            descriptor_commitment: payload.descriptor_commitment.clone(),
            suppress_local_override: false,
        }
    }

    fn from_status(payload: &RekeyStatusPayload) -> Self {
        let (parsed_epoch_id, label) = payload
            .new_epoch_id
            .as_deref()
            .map(parse_epoch_identifier)
            .unwrap_or((None, "unknown".to_string()));

        let mut operation = Self {
            rekey_id: payload.rekey_id,
            group_id: payload.group_id,
            new_epoch_id: parsed_epoch_id,
            new_epoch_label: label,
            status: payload.status,
            started_at: payload.started_at,
            last_updated: payload.last_updated,
            estimated_completion: None,
            can_cutover: payload.can_cutover,
            progress: payload.progress.clone().into(),
            policy: payload.policy.clone(),
            errors: payload.errors.iter().cloned().map(Into::into).collect(),
            descriptor_commitment: payload.descriptor_commitment.clone(),
            suppress_local_override: false,
        };
        operation.ensure_completion_percentage();
        operation
    }

    fn update_from_status(&mut self, payload: &RekeyStatusPayload) {
        self.status = payload.status;
        self.last_updated = payload.last_updated;
        self.can_cutover = payload.can_cutover;
        self.progress = payload.progress.clone().into();
        self.policy = payload.policy.clone();
        self.errors = payload.errors.iter().cloned().map(Into::into).collect();
        self.descriptor_commitment = payload.descriptor_commitment.clone();
        // Once an operation is in-flight, default to allowing local overrides unless explicitly set.
        self.suppress_local_override = false;

        if let Some(epoch_str) = payload.new_epoch_id.as_deref() {
            let (new_id, label) = parse_epoch_identifier(epoch_str);
            if new_id.is_some() {
                self.new_epoch_id = new_id;
            }
            self.new_epoch_label = label;
        }
        self.ensure_completion_percentage();
    }

    fn ensure_completion_percentage(&mut self) {
        if self.progress.total_files == 0 && matches!(self.status, RekeyStatus::Completed) {
            self.progress.migrated_files = 0;
            self.progress.total_files = 0;
        }
    }

    #[cfg(test)]
    fn migration_ratio(&self) -> Option<f64> {
        if self.progress.total_files == 0 {
            None
        } else {
            Some(self.progress.migrated_files as f64 / self.progress.total_files as f64)
        }
    }

    #[cfg(test)]
    fn recommended_heartbeat_interval_secs(&self) -> u64 {
        let mut interval = match self.migration_ratio() {
            Some(ratio) if ratio < 0.10 => HEARTBEAT_MIN_INTERVAL_SECS,
            Some(ratio) if ratio < 0.35 => HEARTBEAT_BASE_INTERVAL_SECS,
            Some(ratio) if ratio < 0.70 => {
                (HEARTBEAT_BASE_INTERVAL_SECS + HEARTBEAT_MAX_INTERVAL_SECS) / 2
            }
            Some(_) => HEARTBEAT_MAX_INTERVAL_SECS,
            None => HEARTBEAT_MAX_INTERVAL_SECS,
        };

        if let Some(policy) = &self.policy {
            if let Some(coverage) = policy
                .coverage_percent_bytes
                .or(policy.coverage_percent_items)
            {
                interval = interval.max(Self::interval_from_coverage(coverage));
            }

            let device_shortfall = policy.required_devices_met < policy.quorum_devices;
            if device_shortfall {
                interval = HEARTBEAT_MIN_INTERVAL_SECS;
            }

            match policy.decision {
                ActivationDecision::BlockedSafety => {
                    interval = HEARTBEAT_MIN_INTERVAL_SECS;
                }
                ActivationDecision::GraceReady | ActivationDecision::Ready => {
                    if !device_shortfall {
                        interval = interval
                            .max((HEARTBEAT_BASE_INTERVAL_SECS + HEARTBEAT_MAX_INTERVAL_SECS) / 2);
                    }
                }
                ActivationDecision::Pending => {}
            }
        }

        if let Some(eta_minutes) = self.progress.estimated_time_remaining_minutes {
            if eta_minutes > 30 {
                interval =
                    interval.max((HEARTBEAT_BASE_INTERVAL_SECS + HEARTBEAT_MAX_INTERVAL_SECS) / 2);
            } else if eta_minutes < 5 {
                interval = HEARTBEAT_MIN_INTERVAL_SECS;
            }
        }

        interval.clamp(HEARTBEAT_MIN_INTERVAL_SECS, HEARTBEAT_MAX_INTERVAL_SECS)
    }

    #[cfg(test)]
    fn interval_from_coverage(coverage_percent: f64) -> u64 {
        let coverage = coverage_percent.clamp(0.0, 100.0);
        if coverage >= 95.0 {
            HEARTBEAT_MAX_INTERVAL_SECS
        } else if coverage >= 85.0 {
            HEARTBEAT_MAX_INTERVAL_SECS - 5
        } else if coverage >= 70.0 {
            (HEARTBEAT_BASE_INTERVAL_SECS + HEARTBEAT_MAX_INTERVAL_SECS) / 2
        } else if coverage >= 50.0 {
            HEARTBEAT_BASE_INTERVAL_SECS
        } else {
            HEARTBEAT_MIN_INTERVAL_SECS
        }
    }
}

impl From<ApiMigrationProgress> for RekeyProgress {
    fn from(value: ApiMigrationProgress) -> Self {
        Self {
            total_files: value.total_files,
            migrated_files: value.migrated_files,
            total_members: value.total_members,
            confirmed_members: value.confirmed_members,
            reporting_members: value.reporting_members,
            estimated_time_remaining_minutes: value.estimated_time_remaining_minutes,
        }
    }
}

impl From<ApiRekeyError> for RekeyErrorEntry {
    fn from(value: ApiRekeyError) -> Self {
        Self {
            error_type: value.error_type,
            message: value.message,
            timestamp: value.timestamp,
            member_id: value.member_id,
        }
    }
}

fn parse_epoch_identifier(raw: &str) -> (Option<Uuid>, String) {
    match Uuid::parse_str(raw) {
        Ok(id) => (Some(id), raw.to_string()),
        Err(_) => (None, raw.to_string()),
    }
}

#[cfg(test)]
mod rekey_tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::sync::Arc;

    use crate::{network::MockNetwork, storage::MockStorage};

    #[test]
    fn parse_epoch_identifier_accepts_uuid() {
        let uuid = Uuid::new_v4();
        let (parsed, label) = parse_epoch_identifier(&uuid.to_string());
        assert_eq!(parsed, Some(uuid));
        assert_eq!(label, uuid.to_string());
    }

    #[test]
    fn parse_epoch_identifier_handles_non_uuid() {
        let (parsed, label) = parse_epoch_identifier("epoch-42");
        assert!(parsed.is_none());
        assert_eq!(label, "epoch-42");
    }

    #[test]
    fn active_rekey_from_initiation_maps_payload() {
        let rekey_id = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let new_epoch = Uuid::new_v4();
        let initiated_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let eta = Utc.timestamp_opt(1_700_000_600, 0).unwrap();

        let payload = RekeyResponsePayload {
            rekey_id,
            group_id,
            new_epoch_id: new_epoch.to_string(),
            status: RekeyStatus::Initiated,
            initiated_at,
            estimated_completion: eta,
            migration_progress: ApiMigrationProgress {
                total_files: 10,
                migrated_files: 3,
                total_members: 5,
                confirmed_members: 2,
                reporting_members: 0,
                estimated_time_remaining_minutes: Some(15),
            },
            descriptor_commitment: None,
        };

        let operation = ActiveRekeyOperation::from_initiation(payload);

        assert_eq!(operation.rekey_id, rekey_id);
        assert_eq!(operation.group_id, group_id);
        assert_eq!(operation.new_epoch_id, Some(new_epoch));
        assert_eq!(operation.status, RekeyStatus::Initiated);
        assert_eq!(operation.progress.total_files, 10);
        assert_eq!(operation.progress.migrated_files, 3);
        assert_eq!(operation.progress.total_members, 5);
        assert_eq!(operation.progress.confirmed_members, 2);
        assert_eq!(operation.started_at, initiated_at);
        assert_eq!(operation.last_updated, initiated_at);
        assert_eq!(operation.estimated_completion, Some(eta));
    }

    #[test]
    fn recommended_interval_follows_migration_ratio() {
        let now = Utc::now();
        let mut operation = ActiveRekeyOperation {
            rekey_id: Uuid::new_v4(),
            group_id: Uuid::new_v4(),
            new_epoch_id: None,
            new_epoch_label: "epoch".into(),
            status: RekeyStatus::InProgress,
            started_at: now,
            last_updated: now,
            estimated_completion: None,
            can_cutover: false,
            progress: RekeyProgress {
                total_files: 100,
                migrated_files: 5,
                total_members: 0,
                confirmed_members: 0,
                reporting_members: 0,
                estimated_time_remaining_minutes: None,
            },
            policy: None,
            errors: vec![],
            descriptor_commitment: None,
            suppress_local_override: false,
        };

        assert_eq!(
            operation.recommended_heartbeat_interval_secs(),
            HEARTBEAT_MIN_INTERVAL_SECS
        );

        operation.progress.migrated_files = 30;
        assert_eq!(
            operation.recommended_heartbeat_interval_secs(),
            HEARTBEAT_BASE_INTERVAL_SECS
        );

        operation.progress.migrated_files = 60;
        assert_eq!(
            operation.recommended_heartbeat_interval_secs(),
            (HEARTBEAT_BASE_INTERVAL_SECS + HEARTBEAT_MAX_INTERVAL_SECS) / 2
        );

        operation.progress.migrated_files = 95;
        assert_eq!(
            operation.recommended_heartbeat_interval_secs(),
            HEARTBEAT_MAX_INTERVAL_SECS
        );
    }

    #[test]
    fn recommended_interval_respects_policy_hints() {
        let now = Utc::now();
        let mut operation = ActiveRekeyOperation {
            rekey_id: Uuid::new_v4(),
            group_id: Uuid::new_v4(),
            new_epoch_id: None,
            new_epoch_label: "epoch".into(),
            status: RekeyStatus::InProgress,
            started_at: now,
            last_updated: now,
            estimated_completion: None,
            can_cutover: false,
            progress: RekeyProgress {
                total_files: 100,
                migrated_files: 20,
                total_members: 0,
                confirmed_members: 0,
                reporting_members: 0,
                estimated_time_remaining_minutes: None,
            },
            policy: Some(PolicyEvaluationSnapshot {
                decision: ActivationDecision::BlockedSafety,
                activation_time: now,
                grace_deadline: now,
                retention_deadline: now,
                coverage_percent_bytes: None,
                coverage_percent_items: None,
                lowest_root_coverage: None,
                quorum_devices: 5,
                required_devices_met: 2,
                stale_devices: 0,
            }),
            errors: vec![],
            descriptor_commitment: None,
            suppress_local_override: false,
        };

        assert_eq!(
            operation.recommended_heartbeat_interval_secs(),
            HEARTBEAT_MIN_INTERVAL_SECS
        );

        operation.policy = Some(PolicyEvaluationSnapshot {
            decision: ActivationDecision::Pending,
            activation_time: now,
            grace_deadline: now,
            retention_deadline: now,
            coverage_percent_bytes: Some(90.0),
            coverage_percent_items: None,
            lowest_root_coverage: None,
            quorum_devices: 1,
            required_devices_met: 1,
            stale_devices: 0,
        });
        assert_eq!(
            operation.recommended_heartbeat_interval_secs(),
            HEARTBEAT_MAX_INTERVAL_SECS - 5
        );

        operation.policy = Some(PolicyEvaluationSnapshot {
            decision: ActivationDecision::GraceReady,
            activation_time: now,
            grace_deadline: now,
            retention_deadline: now,
            coverage_percent_bytes: Some(60.0),
            coverage_percent_items: None,
            lowest_root_coverage: None,
            quorum_devices: 3,
            required_devices_met: 1,
            stale_devices: 0,
        });
        assert_eq!(
            operation.recommended_heartbeat_interval_secs(),
            HEARTBEAT_MIN_INTERVAL_SECS
        );
    }

    #[tokio::test]
    async fn retention_lock_status_sets_warning_and_returns_error() {
        use reqwest::header::HeaderValue;

        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let client = Client::new(Ed25519KeyPair::generate(), storage, network);

        let mut headers = HeaderMap::new();
        headers.insert("Rekey-Required", HeaderValue::from_static("true"));

        let result = client
            .handle_retention_status(StatusCode::LOCKED, &headers, "unit_test_locked")
            .await;
        assert!(matches!(result, Some(ClientError::NetworkError { .. })));

        let state = client.state.read().await;
        assert!(state.last_retention_warning.is_some());
    }

    #[tokio::test]
    async fn retention_purge_status_sets_warning_and_returns_error() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let client = Client::new(Ed25519KeyPair::generate(), storage, network);

        let headers = HeaderMap::new();
        let result = client
            .handle_retention_status(StatusCode::GONE, &headers, "unit_test_purge")
            .await;
        assert!(matches!(result, Some(ClientError::NetworkError { .. })));

        let state = client.state.read().await;
        assert!(state.last_retention_purge_warning.is_some());
    }

    #[tokio::test]
    async fn update_coverage_log_records_entries() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let client = Client::new(Ed25519KeyPair::generate(), storage, network);

        {
            let mut state = client.state.write().await;
            let group_id = Uuid::new_v4();
            state.active_group_id = Some(group_id);
            state
                .coverage_ledgers
                .insert(group_id, CoverageLedgerState::default());
            let epoch_state = EpochState {
                group_id: Some(group_id),
                epoch_id: 7,
                encryption_key: [0u8; 32],
                key_source: EpochKeySource::Placeholder,
                members: Vec::new(),
                created_at: Utc::now(),
                is_active: true,
                file_count: 0,
                marked_for_removal: false,
                removal_eligible_at: None,
            };
            state
                .epochs
                .entry(7)
                .or_insert_with(Vec::new)
                .push(epoch_state);
        }

        client
            .update_coverage_for_file("file-123", 7)
            .await
            .expect("coverage update should succeed");

        let state = client.state.read().await;
        let counts = state
            .coverage_ledgers
            .values()
            .next()
            .map(|l| l.log.counts_for_epoch(7))
            .unwrap_or_default();
        assert_eq!(counts.total_items, 1);
        assert_eq!(counts.rewrapped_items, 1);
    }
}

/// Core client for HybridCipher secure file sharing
///
/// The Client maintains cryptographic state, coordinates epoch transitions,
/// and manages coverage tracking with persistence and recovery capabilities.
///
/// ## Thread Safety
/// All client operations are thread-safe using Arc<RwLock<>> for state management.
/// Lock ordering: state -> storage -> network to prevent deadlocks.
///
/// ## Concurrency Guarantees
/// - Multiple readers can access state simultaneously
/// - Writers get exclusive access during state transitions
/// - Epoch operations are atomic to prevent race conditions
/// - Migration state is consistent across concurrent file operations
pub struct Client<S: Storage, N: Network> {
    /// Device identity key pair for signing operations
    device_identity: Ed25519KeyPair,

    /// Persistent storage backend
    storage: Arc<S>,

    /// Network communication layer
    network: Arc<N>,

    /// Thread-safe client state
    state: Arc<RwLock<ClientState>>,

    /// Key pinning manager for out-of-band verification
    pinning_manager: Arc<KeyPinningManager<S>>,

    /// Structured logger for observability
    logger: Arc<crate::logging::StructuredLogger>,

    /// Metrics collector for operational monitoring
    metrics: Arc<crate::metrics::MetricsCollector>,

    /// Configured exclusion patterns for encryption and coverage flows.
    file_exclusions: Arc<FileExclusionList>,

    /// Security validator for configuration enforcement
    security_validator: Arc<SecurityValidator>,

    /// Background heartbeat worker coordination
    heartbeat_worker: Arc<Mutex<HeartbeatWorkerState>>,

    /// Rekey request backoff coordination
    rekey_request_throttle: Arc<RekeyRequestThrottle>,

    /// Idle crawler coordination state
    idle_crawler: Arc<Mutex<IdleCrawlerState>>,

    /// Background coverage watcher coordination
    coverage_watcher: Arc<Mutex<CoverageWatcherState>>,
    /// Roots currently being hydrated after enrollment.
    coverage_enrollment: Arc<Mutex<CoverageEnrollmentState>>,
    /// Background coverage replication coordinator
    coverage_replication: Arc<Mutex<CoverageReplicationState>>,
    /// Background coverage compaction coordinator
    coverage_compaction: Arc<Mutex<CoverageCompactionState>>,

    /// Mutex to serialize state loading operations (prevents concurrent state file access)
    state_loading: Arc<tokio::sync::Mutex<()>>,

    /// In-memory cache for per-root file index entries
    file_index_cache: Arc<RwLock<FileIndexCache>>,

    /// Cache for state generation reload checks
    state_reload_cache: Arc<tokio::sync::Mutex<StateReloadCache>>,

    /// Cache for tracked file stats aggregation
    tracked_stats_cache: Arc<tokio::sync::Mutex<TrackedStatsCache>>,

    /// Cache for coverage rescan throttling
    coverage_rescan_cache: Arc<tokio::sync::Mutex<CoverageRescanCache>>,

    /// Coordinator for deferred state saves during bulk operations
    state_save: Arc<StateSaveCoordinator>,

    /// Client configuration
    config: ClientConfig,
}

impl<S: Storage, N: Network> Clone for Client<S, N> {
    fn clone(&self) -> Self {
        Self {
            device_identity: self.device_identity.clone(),
            storage: self.storage.clone(),
            network: self.network.clone(),
            state: self.state.clone(),
            pinning_manager: self.pinning_manager.clone(),
            logger: self.logger.clone(),
            metrics: self.metrics.clone(),
            file_exclusions: self.file_exclusions.clone(),
            security_validator: self.security_validator.clone(),
            heartbeat_worker: self.heartbeat_worker.clone(),
            rekey_request_throttle: self.rekey_request_throttle.clone(),
            idle_crawler: self.idle_crawler.clone(),
            coverage_watcher: self.coverage_watcher.clone(),
            coverage_enrollment: self.coverage_enrollment.clone(),
            coverage_replication: self.coverage_replication.clone(),
            coverage_compaction: self.coverage_compaction.clone(),
            state_loading: self.state_loading.clone(),
            file_index_cache: self.file_index_cache.clone(),
            state_reload_cache: self.state_reload_cache.clone(),
            tracked_stats_cache: self.tracked_stats_cache.clone(),
            coverage_rescan_cache: self.coverage_rescan_cache.clone(),
            state_save: self.state_save.clone(),
            config: self.config.clone(),
        }
    }
}

impl<S: Storage, N: Network> std::fmt::Debug for Client<S, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("device_identity", &"<Ed25519KeyPair>")
            .field("storage", &"<Storage>")
            .field("network", &"<Network>")
            .field("state", &"<Arc<RwLock<ClientState>>>")
            .field("pinning_manager", &"<Arc<KeyPinningManager>>")
            .field("security_validator", &"<Arc<SecurityValidator>>")
            .field("heartbeat_worker", &"<Arc<Mutex<HeartbeatWorkerState>>>")
            .field("rekey_request_throttle", &"<Arc<RekeyRequestThrottle>>")
            .field("idle_crawler", &"<Arc<Mutex<IdleCrawlerState>>>")
            .field("coverage_watcher", &"<Arc<Mutex<CoverageWatcherState>>>")
            .field(
                "coverage_enrollment",
                &"<Arc<Mutex<CoverageEnrollmentState>>>",
            )
            .field(
                "coverage_compaction",
                &"<Arc<Mutex<CoverageCompactionState>>>",
            )
            .field("state_loading", &"<Arc<tokio::sync::Mutex<()>>>")
            .field("file_index_cache", &"<Arc<RwLock<FileIndexCache>>>")
            .field("state_save", &"<Arc<StateSaveCoordinator>>")
            .finish()
    }
}

pub struct CoverageBulkGuard<S: Storage, N: Network> {
    client: Client<S, N>,
}

impl<S: Storage, N: Network> Drop for CoverageBulkGuard<S, N> {
    fn drop(&mut self) {
        let client = self.client.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                client.end_coverage_bulk_operation().await;
            });
        }
    }
}

/// Current client state with epoch and migration tracking
///
/// ## State Machine
/// The client state follows a strict state machine for epoch transitions:
///
/// ```text
/// Normal -> Preparing -> Committing -> Normal
///    |         |           |
///    v         v           v
/// Rollback <- Failed <- Rollback
/// ```
///
/// ## Migration Phases
/// During two-phase rekey operations:
/// 1. Preparation: New epoch keys are generated and distributed
/// 2. Commitment: Files are migrated to the new epoch atomically
/// 3. Cleanup: Old epoch state is securely destroyed
#[derive(Debug, Clone)]
pub struct ClientState {
    /// Current active epoch states by epoch ID
    epochs: HashMap<u64, Vec<EpochState>>,

    /// Currently active epoch ID
    current_epoch: u64,

    /// Currently selected group for local operations
    active_group_id: Option<Uuid>,

    /// Migration state for two-phase rekey operations
    migration: Option<MigrationState>,

    /// Active server-side rekey operation metadata
    active_rekey: Option<ActiveRekeyOperation>,

    /// Locally tracked heartbeat sequencing per rekey operation
    rekey_heartbeats: HashMap<Uuid, RekeyHeartbeatState>,

    /// Pending rewrap tasks awaiting background processing
    pending_rewraps: VecDeque<PendingRewrap>,

    /// Enrolled coverage roots and folder scopes
    coverage_roots: HashMap<Uuid, CoverageRoot>,

    /// Coverage ledgers per group
    coverage_ledgers: HashMap<Uuid, CoverageLedgerState>,

    /// Serialized metadata for coverage ledgers (used before lazy log load)
    coverage_ledgers_meta: HashMap<Uuid, CoverageLedgerMeta>,

    /// Monotonic generation counter used for cross-process invalidation.
    state_generation: u64,

    /// Last successful state synchronization timestamp
    last_sync: DateTime<Utc>,

    /// Client configuration version for compatibility checking
    version: u32,

    /// Current group memberships for cross-device access
    group_memberships: HashMap<Uuid, GroupMembership>,

    /// Authentication credentials for server communication
    auth_credentials: Option<AuthCredentials>,

    /// Invitation keypair for receiving Welcome messages
    invitation_keypair: Option<InvitationKeyPair>,

    /// Last time we warned the user about retention-locked content
    last_retention_warning: Option<DateTime<Utc>>,

    /// Last time we warned the user about purged retention content
    last_retention_purge_warning: Option<DateTime<Utc>>,

    /// Cached welcome signing keys keyed by server URL
    welcome_signing_keys: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CoverageRootRegistry {
    entries: HashMap<String, CoverageRootRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoverageRootRegistryEntry {
    group_id: Uuid,
    #[serde(default)]
    root_id: Option<Uuid>,
}

/// Serializable version of ClientState (excluding non-serializable fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableClientState {
    epochs: HashMap<u64, Vec<EpochState>>,
    current_epoch: u64,
    active_group_id: Option<Uuid>,
    migration: Option<MigrationState>,
    active_rekey: Option<ActiveRekeyOperation>,
    #[serde(default)]
    rekey_heartbeats: HashMap<Uuid, RekeyHeartbeatState>,
    #[serde(default)]
    pending_rewraps: VecDeque<PendingRewrap>,
    #[serde(default)]
    coverage_roots: HashMap<Uuid, CoverageRoot>,
    #[serde(default)]
    coverage_ledgers_meta: HashMap<Uuid, CoverageLedgerMeta>,
    #[serde(default)]
    state_generation: u64,
    last_sync: DateTime<Utc>,
    version: u32,
    group_memberships: HashMap<Uuid, GroupMembership>,
    auth_credentials: Option<AuthCredentials>,
    invitation_keypair: Option<InvitationKeyPair>,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    last_retention_warning: Option<DateTime<Utc>>,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    last_retention_purge_warning: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ClientStateGenerationSnapshot {
    #[serde(default)]
    state_generation: u64,
}

/// State for a specific epoch with cryptographic keys and metadata
///
/// Each epoch maintains its own cryptographic state to enable
/// forward secrecy and support concurrent operations during migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochState {
    /// Owning group identifier
    #[serde(default)]
    pub group_id: Option<Uuid>,

    /// Epoch identifier
    pub epoch_id: u64,

    /// Epoch-specific encryption key derived from group state
    pub encryption_key: [u8; 32],

    /// Provenance for the epoch key material.
    #[serde(default)]
    pub key_source: EpochKeySource,

    /// Group members participating in this epoch
    pub members: Vec<GroupMember>,

    /// Epoch creation timestamp
    pub created_at: DateTime<Utc>,

    /// Whether this epoch is active for new file operations
    pub is_active: bool,

    /// Files currently encrypted under this epoch
    pub file_count: u64,

    /// Whether this epoch is marked for deferred removal (e.g., after fallback)
    #[serde(default)]
    pub marked_for_removal: bool,

    /// Timestamp when this epoch becomes eligible for removal (24h after 100% coverage)
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    pub removal_eligible_at: Option<DateTime<Utc>>,
}

/// Group member information for access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Member's unique identifier
    pub member_id: [u8; 32],

    /// Member's public signing key
    pub public_key: [u8; 32],

    /// Member capabilities and permissions
    pub capabilities: MemberCapabilities,

    /// When this member joined the group
    pub joined_at: DateTime<Utc>,
}

/// Member permissions and capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberCapabilities {
    /// Can read files
    pub can_read: bool,

    /// Can write/modify files
    pub can_write: bool,

    /// Can invite new members
    pub can_invite: bool,

    /// Can initiate epoch transitions
    pub can_rekey: bool,

    /// Can remove other members
    pub can_remove: bool,
}

/// Group membership information for multi-device access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    /// Group unique identifier
    pub group_id: Uuid,

    /// Human-readable group name
    pub group_name: String,

    /// Group description
    pub group_description: Option<String>,

    /// Current user's role in this group
    pub user_role: GroupRole,

    /// When this device joined the group
    pub joined_at: DateTime<Utc>,

    /// Current epoch ID for this group
    pub current_epoch_id: Option<u64>,

    /// Last successful sync with group server
    pub last_sync: DateTime<Utc>,

    /// Group members (for admins)
    pub members: Vec<GroupMember>,
}

/// Exported epoch secret entry for recovery capsules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEpochSecret {
    pub epoch_number: u64,
    pub epoch_uuid: Uuid,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub file_count: u64,
    pub encryption_key_b64: String,
}

/// Plaintext payload bundled into a sealed recovery capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCapsulePlain {
    pub group_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub epochs: Vec<RecoveryEpochSecret>,
}

/// User role within a group
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GroupRole {
    /// Group administrator with full permissions
    Admin,
    /// Regular group member with standard permissions
    Member,
}

impl From<ServerGroupRole> for GroupRole {
    fn from(role: ServerGroupRole) -> Self {
        match role {
            ServerGroupRole::Admin => GroupRole::Admin,
            ServerGroupRole::Member | ServerGroupRole::Viewer => GroupRole::Member,
        }
    }
}

/// Status outcome when syncing Welcome messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WelcomeSyncStatus {
    /// Epoch keys installed or refreshed successfully
    Updated,
    /// No Welcome messages were available for this device in the current epoch
    NoMessages,
    /// The server reports that the group has no active epoch yet
    NoActiveEpoch,
    /// The operation was skipped (for example, group not found)
    Skipped,
    /// An error occurred while processing the group
    Error,
}

/// Summary of a Welcome message synchronization attempt for a single group
#[derive(Debug, Clone)]
pub struct WelcomeSyncResult {
    pub group_id: Uuid,
    pub group_name: String,
    pub processed_epoch: Option<u64>,
    pub messages_processed: usize,
    pub status: WelcomeSyncStatus,
    pub detail: Option<String>,
}

/// Authentication credentials for server communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCredentials {
    /// JWT access token for API authentication
    pub access_token: String,

    /// JWT refresh token for token renewal
    pub refresh_token: Option<String>,

    /// User ID associated with these credentials
    pub user_id: Uuid,

    /// Device ID for this specific device
    pub device_id: String,

    /// Token expiration time
    pub expires_at: DateTime<Utc>,

    /// When these credentials were last refreshed
    pub last_refreshed: DateTime<Utc>,
}

/// Result returned after invoking the device removal endpoint.
#[derive(Debug, Clone)]
pub struct DeviceRemovalSummary {
    pub removed_device_id: String,
    pub revoked_sessions: usize,
    pub updated_groups: Vec<Uuid>,
    pub remaining_devices: usize,
    pub removed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct DeviceRemovalResponse {
    removed_device_id: String,
    revoked_sessions: usize,
    updated_groups: Vec<Uuid>,
    remaining_devices: usize,
    removed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    token: String,
    user_id: Option<Uuid>,
    device_id: Option<String>,
    server_url: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    device_status: Option<String>,
    device_verified: bool,
}

/// Migration state for tracking two-phase rekey progress
///
/// ## File-Level Granularity
/// Migration tracks progress at the file level to enable:
/// - Incremental progress with crash recovery
/// - Concurrent file operations during migration
/// - Fine-grained rollback on partial failures
///
/// ## Consistency Guarantees
/// - All files are migrated atomically within a transaction
/// - No file exists in an inconsistent state between epochs
/// - Migration can be safely resumed after crash/restart
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationState {
    /// Source epoch being migrated from
    pub from_epoch: u64,

    /// Target epoch being migrated to
    pub to_epoch: u64,

    /// Current migration phase
    pub phase: MigrationPhase,

    /// Files that have been successfully migrated
    pub migrated_files: Vec<String>,
    #[serde(skip, default)]
    pub(crate) migrated_files_set: HashSet<String>,

    /// Files that failed migration and need retry
    pub failed_files: Vec<String>,

    /// Total number of files to migrate
    pub total_files: u64,

    /// Migration start timestamp
    pub started_at: DateTime<Utc>,

    /// Estimated completion time based on current progress
    pub estimated_completion: Option<DateTime<Utc>>,
}

impl MigrationState {
    fn rebuild_migrated_cache(&mut self) {
        self.migrated_files_set = self.migrated_files.iter().cloned().collect();
    }

    fn clear_migrated_files(&mut self) {
        self.migrated_files.clear();
        self.migrated_files_set.clear();
    }

    fn record_migrated_file(&mut self, path: String) {
        if self.migrated_files_set.insert(path.clone()) {
            self.migrated_files.push(path);
        }
    }
}

/// Two-phase migration process stages
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MigrationPhase {
    /// Preparing new epoch keys and coordinating with group
    Preparing,

    /// Actively migrating files to new epoch
    Migrating,

    /// Committing migration and updating coverage log
    Committing,

    /// Cleaning up old epoch state
    Cleanup,

    /// Migration failed and needs rollback
    Failed,

    /// Rolling back to previous state
    Rollback,
}

impl<S: Storage, N: Network> Client<S, N> {
    /// Return the currently selected group ID if available.
    pub async fn active_group_id_opt(&self) -> Option<Uuid> {
        self.state.read().await.active_group_id
    }
    fn upsert_epoch_state(state: &mut ClientState, group_id: Uuid, mut epoch_state: EpochState) {
        epoch_state.group_id = Some(group_id);
        let entry = state
            .epochs
            .entry(epoch_state.epoch_id)
            .or_insert_with(Vec::new);
        if let Some(existing) = entry.iter_mut().find(|e| e.group_id == Some(group_id)) {
            *existing = epoch_state;
        } else {
            entry.push(epoch_state);
        }
    }

    fn get_epoch_state<'a>(
        state: &'a ClientState,
        group_id: Uuid,
        epoch_id: u64,
    ) -> Option<&'a EpochState> {
        state
            .epochs
            .get(&epoch_id)
            .and_then(|entries| entries.iter().find(|e| e.group_id == Some(group_id)))
    }

    fn remove_epoch_state(state: &mut ClientState, group_id: Uuid, epoch_id: u64) {
        if let Some(entries) = state.epochs.get_mut(&epoch_id) {
            entries.retain(|e| e.group_id != Some(group_id));
            if entries.is_empty() {
                state.epochs.remove(&epoch_id);
            }
        }
    }

    fn active_group_epoch_ids(state: &ClientState) -> (Option<Uuid>, HashSet<u64>) {
        let mut epochs = HashSet::new();
        let group_id = state.active_group_id;

        if let Some(active_group) = group_id {
            if state.current_epoch > 0 {
                epochs.insert(state.current_epoch);
            }

            for (epoch_id, entries) in &state.epochs {
                if entries
                    .iter()
                    .any(|entry| entry.group_id == Some(active_group))
                {
                    epochs.insert(*epoch_id);
                }
            }
        }

        (group_id, epochs)
    }

    async fn purge_group_epoch_state(&self, group_id: Uuid) {
        let epoch_ids: Vec<u64> = {
            let state = self.state.read().await;
            state
                .epochs
                .iter()
                .filter_map(|(epoch_id, entries)| {
                    if entries.iter().any(|entry| entry.group_id == Some(group_id)) {
                        Some(*epoch_id)
                    } else {
                        None
                    }
                })
                .collect()
        };

        if epoch_ids.is_empty() {
            return;
        }

        let mut state = self.state.write().await;
        for epoch_id in epoch_ids {
            Self::remove_epoch_state(&mut state, group_id, epoch_id);
        }
    }

    #[cfg(not(feature = "mount-fs"))]
    fn filesystem_feature_disabled(operation: &str) -> ClientError {
        ClientError::InvalidState(format!(
            "{operation} is unavailable in this build. Enable the `mount-fs` feature to use filesystem operations."
        ))
    }

    fn local_device_id(&self) -> String {
        let public_bytes = self.device_identity.public_key_bytes();
        format!("device_{}", hex::encode(&public_bytes[..8]))
    }

    fn uuid_to_member_id(user_id: &Uuid) -> [u8; 32] {
        let mut member_id = [0u8; 32];
        let raw = user_id.as_bytes();
        member_id[..raw.len()].copy_from_slice(raw);
        member_id
    }

    fn extract_public_key(bytes: &[u8]) -> Result<[u8; 32], ClientError> {
        if bytes.len() != 32 {
            return Err(ClientError::InvalidState(format!(
                "Invalid identity key length (expected 32 bytes, got {})",
                bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(key)
    }

    fn normalize_capabilities(is_admin: bool) -> MemberCapabilities {
        let mut capabilities = MemberCapabilities::default();
        if is_admin {
            capabilities.can_invite = true;
            capabilities.can_rekey = true;
            capabilities.can_remove = true;
        }
        capabilities
    }

    fn hydrate_group_members(
        raw_members: &[crate::welcome_manager::GroupMember],
    ) -> Result<Vec<GroupMember>, ClientError> {
        raw_members
            .iter()
            .map(|member| {
                Ok(GroupMember {
                    member_id: Self::uuid_to_member_id(&member.user_id),
                    public_key: Self::extract_public_key(&member.identity_public)?,
                    capabilities: Self::normalize_capabilities(member.is_admin),
                    joined_at: member.joined_at,
                })
            })
            .collect()
    }

    fn member_uuid(member: &GroupMember) -> Option<Uuid> {
        Uuid::from_slice(&member.member_id[..16]).ok()
    }
    /// Create a new client with the given identity, storage, and network
    ///
    /// # Arguments
    /// * `device_identity` - Ed25519 key pair for device authentication
    /// * `storage` - Persistent storage backend
    /// * `network` - Network communication layer
    ///
    /// # Returns
    /// New client instance with initialized state
    pub fn new(device_identity: Ed25519KeyPair, storage: Arc<S>, network: Arc<N>) -> Self {
        Self::with_deployment_mode(
            device_identity,
            storage,
            network,
            DeploymentMode::Production,
            ClientConfig::default(),
        )
    }

    /// Return the configured network handle.
    pub fn network(&self) -> Arc<N> {
        Arc::clone(&self.network)
    }

    /// Create a new client with an explicit client configuration.
    pub fn with_client_config(
        device_identity: Ed25519KeyPair,
        storage: Arc<S>,
        network: Arc<N>,
        client_config: ClientConfig,
    ) -> Self {
        Self::with_deployment_mode(
            device_identity,
            storage,
            network,
            DeploymentMode::Production,
            client_config,
        )
    }

    /// Create a new HybridCipher client with production configuration
    ///
    /// # Arguments
    /// * `device_identity` - Ed25519 key pair for device authentication
    /// * `storage` - Storage backend implementation
    /// * `network` - Network communication layer
    /// * `config` - Production configuration manager
    ///
    /// # Returns
    /// New client instance with production configuration
    pub fn with_config(
        device_identity: Ed25519KeyPair,
        storage: Arc<S>,
        network: Arc<N>,
        config: crate::config::ConfigManager,
    ) -> Self {
        let deployment_mode = if config.is_production() {
            DeploymentMode::Production
        } else {
            DeploymentMode::Development
        };

        // Create client with deployment mode
        let client = Self::with_deployment_mode(
            device_identity,
            storage,
            network,
            deployment_mode,
            ClientConfig::default(),
        );

        // Production configuration is applied at the application level
        // Configuration validation was done during ConfigManager creation

        client
    }

    /// Create a new HybridCipher client with specified deployment mode
    ///
    /// # Arguments
    /// * `device_identity` - Ed25519 key pair for device authentication
    /// * `storage` - Storage backend implementation
    /// * `network` - Network communication layer
    /// * `deployment_mode` - Security policy deployment mode
    ///
    /// # Returns
    /// New client instance with initialized state and security validation
    pub fn with_deployment_mode(
        device_identity: Ed25519KeyPair,
        storage: Arc<S>,
        network: Arc<N>,
        deployment_mode: DeploymentMode,
        client_config: ClientConfig,
    ) -> Self {
        // NOTE: Genesis epoch will be initialized when needed via Welcome messages
        // Instead of using fixed seeds, epoch keys will be distributed via Welcome messages
        // This ensures proper cross-device compatibility through server-mediated key distribution
        // Start with empty epochs map - will be populated when group is initialized

        let epochs = HashMap::new();

        let initial_state = ClientState {
            epochs,
            current_epoch: 0,
            active_group_id: None,
            migration: None,
            active_rekey: None,
            rekey_heartbeats: HashMap::new(),
            pending_rewraps: VecDeque::new(),
            coverage_roots: HashMap::new(),
            coverage_ledgers: HashMap::new(),
            coverage_ledgers_meta: HashMap::new(),
            state_generation: 0,
            last_sync: Utc::now(),
            version: 1,
            group_memberships: HashMap::new(),
            auth_credentials: None,
            invitation_keypair: None,
            last_retention_warning: None,
            last_retention_purge_warning: None,
            welcome_signing_keys: HashMap::new(),
        };

        // Initialize security validator based on deployment mode
        let security_validator = Arc::new(match deployment_mode {
            DeploymentMode::Production => SecurityValidator::production(),
            DeploymentMode::Development => SecurityValidator::development(),
            _ => SecurityValidator::production(), // Default to production security
        });

        // Initialize logging and metrics
        let logging_config = crate::logging::LoggingConfig {
            level: crate::logging::LogLevel::Info,
            enable_metrics: true,
            enable_security_logging: true,
            rotation: crate::logging::LogRotationConfig {
                max_file_size: 100 * 1024 * 1024, // 100MB
                max_files: 5,
                compress: true,
            },
            format: crate::logging::LogFormat::Json,
            privacy: crate::logging::PrivacyConfig {
                log_user_ids: true,
                log_file_paths: false,
                redact_sensitive: true,
                max_string_length: 512,
            },
        };

        let logger = Arc::new(crate::logging::StructuredLogger::new(
            logging_config,
            "hybridcipher-client".to_string(),
        ));

        let metrics = Arc::new(crate::metrics::MetricsCollector::new());
        let file_exclusions = Arc::new(FileExclusionList::from_patterns(
            &client_config.excluded_file_patterns,
        ));

        // Initialize key pinning manager
        let pinning_manager = Arc::new(KeyPinningManager::new(
            storage.clone(),
            PinningConfig::default(),
        ));

        // Configure coverage transparency publisher
        crate::coverage::set_transparency_config(client_config.transparency_config.clone());

        // Log client initialization with security mode
        logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Client initialized with {:?} security mode",
                deployment_mode
            ),
            None,
        );

        let client = Self {
            device_identity,
            storage,
            network,
            state: Arc::new(RwLock::new(initial_state)),
            pinning_manager,
            logger,
            metrics,
            file_exclusions,
            security_validator,
            heartbeat_worker: Arc::new(Mutex::new(HeartbeatWorkerState::default())),
            rekey_request_throttle: Arc::new(RekeyRequestThrottle::new()),
            idle_crawler: Arc::new(Mutex::new(IdleCrawlerState::default())),
            coverage_watcher: Arc::new(Mutex::new(CoverageWatcherState::default())),
            coverage_enrollment: Arc::new(Mutex::new(CoverageEnrollmentState::default())),
            coverage_replication: Arc::new(Mutex::new(CoverageReplicationState::default())),
            coverage_compaction: Arc::new(Mutex::new(CoverageCompactionState::default())),
            state_loading: Arc::new(tokio::sync::Mutex::new(())),
            file_index_cache: Arc::new(RwLock::new(FileIndexCache::new(
                client_config.file_index_cache_max_roots,
            ))),
            state_reload_cache: Arc::new(tokio::sync::Mutex::new(StateReloadCache::default())),
            tracked_stats_cache: Arc::new(tokio::sync::Mutex::new(TrackedStatsCache::default())),
            coverage_rescan_cache: Arc::new(
                tokio::sync::Mutex::new(CoverageRescanCache::default()),
            ),
            state_save: Arc::new(StateSaveCoordinator::new(std::time::Duration::from_millis(
                client_config.state_save_debounce_ms,
            ))),
            config: client_config,
        };

        // Load saved state if available (this is async, so we'll do it on first operation)
        // For now, we'll mark that state loading is needed

        client
    }

    fn resolve_server_base_url(session_url: Option<String>) -> String {
        if let Some(raw_url) = session_url {
            let trimmed = raw_url.trim();
            if !trimmed.is_empty() {
                return trimmed.trim_end_matches('/').to_string();
            }
        }

        if let Some(active_url) = Self::load_active_user_server_url() {
            let trimmed = active_url.trim();
            if !trimmed.is_empty() {
                return trimmed.trim_end_matches('/').to_string();
            }
        }

        DEFAULT_SERVER_URL.to_string()
    }

    async fn active_server_base_url(&self) -> String {
        let session_url = self
            .get_session_info()
            .await
            .ok()
            .and_then(|info| info.server_url.clone());
        Self::resolve_server_base_url(session_url)
    }

    async fn handle_retention_status(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        operation: &str,
    ) -> Option<ClientError> {
        match status {
            StatusCode::LOCKED => {
                let rekey_required = headers
                    .get("Rekey-Required")
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                let now = Utc::now();
                let should_log = {
                    let mut state = self.state.write().await;
                    let should = state
                        .last_retention_warning
                        .map(|ts| (now - ts).num_seconds() >= RETENTION_WARNING_COOLDOWN_SECS)
                        .unwrap_or(true);
                    if should {
                        state.last_retention_warning = Some(now);
                    }
                    should
                };

                if should_log {
                    let mut message = String::from(
                        "Server is withholding content during the retention window (HTTP 423 Locked).",
                    );
                    if rekey_required {
                        message.push_str(
                            " Rekey-Required header present – leave this device online so background rewrapping can complete.",
                        );
                    } else {
                        message
                            .push_str(" Leave the client running so the migration can continue.");
                    }
                    self.logger
                        .log(crate::logging::LogLevel::Warn, &message, Some(operation));
                }

                return Some(ClientError::network_error(
                    ErrorCode::NetworkProtocol,
                    format!(
                        "Server returned HTTP 423 Locked while performing {}",
                        operation
                    ),
                    operation.to_string(),
                    0,
                    if rekey_required {
                        "retention_locked_rekey".to_string()
                    } else {
                        "retention_locked".to_string()
                    },
                ));
            }
            StatusCode::GONE => {
                let now = Utc::now();
                let should_log = {
                    let mut state = self.state.write().await;
                    let should = state
                        .last_retention_purge_warning
                        .map(|ts| (now - ts).num_seconds() >= RETENTION_WARNING_COOLDOWN_SECS)
                        .unwrap_or(true);
                    if should {
                        state.last_retention_purge_warning = Some(now);
                    }
                    should
                };

                if should_log {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        "Server reports requested content has been purged after retention (HTTP 410 Gone). This device may have been offline beyond the retention window—contact an administrator if you need the data restored.",
                        Some(operation),
                    );
                }

                return Some(ClientError::network_error(
                    ErrorCode::NetworkProtocol,
                    format!(
                        "Server returned HTTP 410 Gone while performing {}",
                        operation
                    ),
                    operation.to_string(),
                    0,
                    "retention_purged".to_string(),
                ));
            }
            _ => None,
        }
    }

    fn load_active_user_server_url() -> Option<String> {
        let path = Self::resolve_home_dir()?
            .join(".hybridcipher")
            .join("global")
            .join("active_user.json");

        let content = std::fs::read_to_string(path).ok()?;
        let json_value: serde_json::Value = serde_json::from_str(&content).ok()?;
        json_value
            .get("server_url")
            .and_then(|value| value.as_str())
            .map(|s| s.trim().to_string())
    }

    fn is_crypto_decryption_error(error: &ClientError) -> bool {
        match error {
            ClientError::CryptographicError { context, .. } => matches!(
                context.code,
                ErrorCode::CryptoDecryption
                    | ErrorCode::CryptoInvalidKey
                    | ErrorCode::CryptoInvalidNonce
                    | ErrorCode::CryptoHkdf
                    | ErrorCode::CryptoVerification
                    | ErrorCode::CryptoSignature
            ),
            _ => false,
        }
    }

    async fn migration_active(&self) -> bool {
        let state = self.state.read().await;
        state.migration.is_some()
    }
}

// Re-export ClientError for backward compatibility
pub use crate::errors::ClientError;

impl Default for MemberCapabilities {
    fn default() -> Self {
        Self {
            can_read: true,
            can_write: true,
            can_invite: false,
            can_rekey: false,
            can_remove: false,
        }
    }
}

impl<S: Storage, N: Network> Client<S, N> {}
