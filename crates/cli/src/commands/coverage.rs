use crate::{
    commands::{
        file_ops::{
            enforce_directory_ciphertext_policy, scan_directory_ciphertext_groups,
            DirectoryCiphertextGroup, DirectoryCiphertextPolicyError, LocalClient, TraversalMode,
        },
        mount,
        recovery::{upload_coverage_registry_entries, upload_coverage_registry_snapshot},
        CoverageCommands,
    },
    error::CliError,
    session::{ActiveUserSummary, SessionManager},
    ui,
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use dirs;
use hex;
use hybridcipher_client::state::client::{
    CoverageFileRecord, CoverageScanProgress, CoverageScanSummary, CoverageSyncProgress,
    CoverageUploadProgress,
};
use hybridcipher_client::{
    coverage::{
        set_transparency_config, try_build_transparency_handles, CoverageRoot, CoverageRootKind,
        CoverageRootState, CoverageTransparencyMetadata, CoverageTransparencyVerifier,
        FileCoverageState, FileOrphanKind,
    },
    ipc::coverage::{
        CoverageDecryptProgress, CoverageEnrollOutcome, CoverageEnrollPhase,
        CoverageEnrollProgress, CoverageHydrationSummary, CoverageIpcClient, CoverageIpcError,
        CoverageScanProgressEvent, CoverageUnenrollOutcome,
    },
    network::MockNetwork,
    state::client::{
        CoverageAdoptResult, CoverageGuardSummary, CoverageMarkerRecoveryResult,
        CoverageMigrationProgress, CoveragePendingFile, CoverageProofArtifact,
        CoverageRegistryEntry, CoverageRootStats, CoverageSnapshotArtifact, CoverageSnapshotEntry,
        CoverageSyncSummary, MigrationState,
    },
};
use hybridcipher_crypto::signatures::{self, Signature as CoverageSignature, VerifyingKey};
use hybridcipher_merkle::MerkleTree;
use hybridcipher_messages::transparency::{TransparencyConfig, TransparencyOperation};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt, fs as stdfs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

/// Coverage audit results structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAuditResults {
    /// Total number of files in the system
    pub total_files: u64,
    /// Number of files with valid coverage
    pub covered_files: u64,
    /// Coverage percentage
    pub coverage_percentage: f64,
    /// Coverage log integrity status
    pub log_integrity_valid: bool,
    /// Merkle root verification status
    pub merkle_root_valid: bool,
    /// Number of pending files in migration
    pub pending_files: u64,
    /// Epoch statistics
    pub epoch_stats: HashMap<u64, EpochCoverageStats>,
    /// Audit timestamp
    pub audit_timestamp: DateTime<Utc>,
    /// Detection of any Byzantine faults
    pub byzantine_faults_detected: Vec<String>,
    /// Latest signed Merkle root (hex)
    pub merkle_root_hex: String,
    /// Per-root coverage KPIs
    pub per_root_stats: Vec<CoverageRootStats>,
    /// Number of proofs verified during audit
    pub proofs_checked: u64,
    /// Total number of proofs available
    pub proofs_total: u64,
    /// Transparency verification status
    pub transparency_status: TransparencyVerificationStatus,
    /// Transparency log URL (if discoverable)
    pub transparency_log_url: Option<String>,
    /// Transparency metadata for the snapshot (if available)
    pub transparency_metadata: Option<CoverageTransparencyMetadata>,
    /// Transparency verification error (if any)
    pub transparency_error: Option<String>,
}

fn coverage_ipc_socket_path(session_manager: &SessionManager) -> Option<PathBuf> {
    if coverage_ipc_opted_out(session_manager) {
        return None;
    }
    let dir = session_manager.user_config_dir()?;
    let socket_path = dir.join("coverage_ipc.sock");
    if socket_path.exists() {
        Some(socket_path)
    } else {
        None
    }
}

fn coverage_ipc_opted_out(session_manager: &SessionManager) -> bool {
    let env_name = session_manager.coverage_ipc_opt_out_env();
    let env_name = env_name.trim();
    if env_name.is_empty() {
        return false;
    }
    match std::env::var(env_name) {
        Ok(value) => {
            let trimmed = value.trim().to_lowercase();
            !(trimmed.is_empty() || trimmed == "0" || trimmed == "false" || trimmed == "off")
        }
        Err(_) => false,
    }
}

fn normalize_ipc_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }

    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path,
    }
}

fn normalize_ipc_path_opt(path: Option<PathBuf>) -> Option<PathBuf> {
    path.map(normalize_ipc_path)
}

fn normalize_ipc_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().map(normalize_ipc_path).collect()
}

async fn try_coverage_ipc_root_stats(
    session_manager: &SessionManager,
) -> Result<Option<Vec<CoverageRootStats>>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.coverage_root_stats().await {
        Ok(stats) => Ok(Some(stats)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to load stats: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_rescan_with_progress<F>(
    session_manager: &SessionManager,
    root: Option<PathBuf>,
    on_progress: &mut F,
) -> Result<Option<CoverageScanSummary>, CliError>
where
    F: FnMut(CoverageScanProgressEvent),
{
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    let normalized_root = normalize_ipc_path_opt(root.clone());
    match client
        .coverage_rescan_with_progress(normalized_root.clone(), |progress| {
            on_progress(progress);
        })
        .await
    {
        Ok(summary) => Ok(Some(summary)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => {
            let fallback = matches!(
                &err,
                CoverageIpcError::Remote(message)
                    if message == "empty response from coverage IPC server"
            );
            if !fallback {
                return Err(CliError::coverage(format!(
                    "Coverage IPC failed to run scan: {}",
                    err
                )));
            }
            match client.coverage_rescan(normalized_root).await {
                Ok(summary) => Ok(Some(summary)),
                Err(err) if err.is_connection_error() => Ok(None),
                Err(err) => Err(CliError::coverage(format!(
                    "Coverage IPC failed to run scan: {}",
                    err
                ))),
            }
        }
    }
}

async fn try_coverage_ipc_file_records(
    session_manager: &SessionManager,
    root: Option<PathBuf>,
) -> Result<Option<Vec<CoverageFileRecord>>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_file_records(normalize_ipc_path_opt(root))
        .await
    {
        Ok(records) => Ok(Some(records)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to load scan records: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_roots(
    session_manager: &SessionManager,
) -> Result<Option<Vec<CoverageRoot>>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.coverage_roots().await {
        Ok(roots) => Ok(Some(roots)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to load roots: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_enroll_and_hydrate(
    session_manager: &SessionManager,
    path: PathBuf,
) -> Result<Option<CoverageEnrollOutcome>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_enroll_and_hydrate(normalize_ipc_path(path))
        .await
    {
        Ok(outcome) => Ok(Some(outcome)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to enroll and hydrate root: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_enroll_and_hydrate_with_progress<F>(
    session_manager: &SessionManager,
    path: PathBuf,
    on_progress: &mut F,
) -> Result<Option<CoverageEnrollOutcome>, CliError>
where
    F: FnMut(CoverageEnrollProgress),
{
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_enroll_and_hydrate_with_progress(normalize_ipc_path(path.clone()), |progress| {
            on_progress(progress);
        })
        .await
    {
        Ok(outcome) => Ok(Some(outcome)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => {
            let fallback = matches!(
                &err,
                CoverageIpcError::Remote(message)
                    if message == "empty response from coverage IPC server"
            );
            if !fallback {
                return Err(CliError::coverage(format!(
                    "Coverage IPC failed to enroll and hydrate root: {}",
                    err
                )));
            }
            try_coverage_ipc_enroll_and_hydrate(session_manager, path).await
        }
    }
}

async fn try_coverage_ipc_unenroll_and_decrypt(
    session_manager: &SessionManager,
    path: PathBuf,
) -> Result<Option<CoverageUnenrollOutcome>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_unenroll_and_decrypt(normalize_ipc_path(path))
        .await
    {
        Ok(outcome) => Ok(Some(outcome)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to unenroll and decrypt root: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_unenroll_and_decrypt_with_progress<F>(
    session_manager: &SessionManager,
    path: PathBuf,
    on_progress: &mut F,
) -> Result<Option<CoverageUnenrollOutcome>, CliError>
where
    F: FnMut(CoverageDecryptProgress),
{
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_unenroll_and_decrypt_with_progress(normalize_ipc_path(path.clone()), |progress| {
            on_progress(progress);
        })
        .await
    {
        Ok(outcome) => Ok(Some(outcome)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => {
            let fallback = matches!(
                &err,
                CoverageIpcError::Remote(message)
                    if message == "empty response from coverage IPC server"
            );
            if !fallback {
                return Err(CliError::coverage(format!(
                    "Coverage IPC failed to unenroll and decrypt root: {}",
                    err
                )));
            }
            try_coverage_ipc_unenroll_and_decrypt(session_manager, path).await
        }
    }
}

async fn try_coverage_ipc_registry_entries(
    session_manager: &SessionManager,
) -> Result<Option<Vec<CoverageRegistryEntry>>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.coverage_root_registry_entries().await {
        Ok(entries) => Ok(Some(entries)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to load registry entries: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_adopt_path(
    session_manager: &SessionManager,
    path: PathBuf,
) -> Result<Option<CoverageAdoptResult>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.coverage_adopt_path(normalize_ipc_path(path)).await {
        Ok(result) => Ok(Some(result)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to adopt file: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_adopt_missing_metadata(
    session_manager: &SessionManager,
    root: Option<PathBuf>,
    all: bool,
) -> Result<Option<CoverageGuardSummary>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_adopt_missing_metadata(normalize_ipc_path_opt(root), all)
        .await
    {
        Ok(summary) => Ok(Some(summary)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to adopt missing metadata: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_migrate_orphans_with_progress<F>(
    session_manager: &SessionManager,
    file: Option<PathBuf>,
    root: Option<PathBuf>,
    all: bool,
    on_progress: &mut F,
) -> Result<Option<CoverageMigrationProgress>, CliError>
where
    F: FnMut(CoverageMigrationProgress),
{
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    let normalized_file = normalize_ipc_path_opt(file.clone());
    let normalized_root = normalize_ipc_path_opt(root.clone());
    match client
        .coverage_migrate_orphans_with_progress(
            normalized_file.clone(),
            normalized_root.clone(),
            all,
            |progress| {
                on_progress(progress);
            },
        )
        .await
    {
        Ok(progress) => Ok(Some(progress)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => {
            let fallback = matches!(
                &err,
                CoverageIpcError::Remote(message)
                    if message == "empty response from coverage IPC server"
            );
            if !fallback {
                return Err(CliError::coverage(format!(
                    "Coverage IPC failed to migrate orphans: {}",
                    err
                )));
            }
            match client
                .coverage_migrate_orphans(normalized_file, normalized_root, all)
                .await
            {
                Ok(progress) => {
                    on_progress(progress);
                    Ok(Some(progress))
                }
                Err(err) if err.is_connection_error() => Ok(None),
                Err(err) => Err(CliError::coverage(format!(
                    "Coverage IPC failed to migrate orphans: {}",
                    err
                ))),
            }
        }
    }
}

async fn try_coverage_ipc_prune_orphan_file(
    session_manager: &SessionManager,
    path: PathBuf,
) -> Result<Option<bool>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_prune_orphan_file(normalize_ipc_path(path))
        .await
    {
        Ok(removed) => Ok(Some(removed)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to prune orphan file: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_prune_orphans(
    session_manager: &SessionManager,
    root: Option<PathBuf>,
    all: bool,
) -> Result<Option<usize>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_prune_orphans(normalize_ipc_path_opt(root), all)
        .await
    {
        Ok(count) => Ok(Some(count)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to prune orphans: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_purge_outcasts(
    session_manager: &SessionManager,
    file: Option<PathBuf>,
    root: Option<PathBuf>,
    all: bool,
) -> Result<Option<usize>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_purge_outcasts(
            normalize_ipc_path_opt(file),
            normalize_ipc_path_opt(root),
            all,
        )
        .await
    {
        Ok(count) => Ok(Some(count)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to purge outcasts: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_guard(
    session_manager: &SessionManager,
    root: Option<PathBuf>,
    all: bool,
) -> Result<Option<CoverageGuardSummary>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_guard(normalize_ipc_path_opt(root), all)
        .await
    {
        Ok(summary) => Ok(Some(summary)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to run guard: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_sync(
    session_manager: &SessionManager,
    root: Option<PathBuf>,
) -> Result<Option<CoverageSyncSummary>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.coverage_sync(normalize_ipc_path_opt(root)).await {
        Ok(summary) => Ok(Some(summary)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to sync coverage: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_pending_files(
    session_manager: &SessionManager,
) -> Result<Option<Vec<CoveragePendingFile>>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.pending_coverage_files().await {
        Ok(files) => Ok(Some(files)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to load pending files: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_recover_markers(
    session_manager: &SessionManager,
    search: Vec<PathBuf>,
    max_depth: usize,
    show_progress: bool,
) -> Result<Option<CoverageMarkerRecoveryResult>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client
        .coverage_recover_from_markers(normalize_ipc_paths(search), max_depth, show_progress)
        .await
    {
        Ok(result) => Ok(Some(result)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to recover markers: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_current_epoch(
    session_manager: &SessionManager,
) -> Result<Option<Option<u64>>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.current_epoch_id().await {
        Ok(epoch) => Ok(Some(epoch)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to load current epoch: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_migration_snapshot(
    session_manager: &SessionManager,
) -> Result<Option<Option<MigrationState>>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.migration_snapshot().await {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to load migration snapshot: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_snapshot_artifact(
    session_manager: &SessionManager,
) -> Result<Option<CoverageSnapshotArtifact>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.download_coverage_snapshot_artifact().await {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to download snapshot: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_file_proof(
    session_manager: &SessionManager,
    file_id: &str,
) -> Result<Option<CoverageProofArtifact>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.download_coverage_file_proof(file_id).await {
        Ok(proof) => Ok(Some(proof)),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to download file proof: {}",
            err
        ))),
    }
}

async fn try_coverage_ipc_transparency_config(
    session_manager: &SessionManager,
) -> Result<Option<TransparencyConfig>, CliError> {
    let Some(socket_path) = coverage_ipc_socket_path(session_manager) else {
        return Ok(None);
    };
    let client = CoverageIpcClient::new(socket_path);
    match client.coverage_transparency_config().await {
        Ok(config) => Ok(config),
        Err(err) if err.is_connection_error() => Ok(None),
        Err(err) => Err(CliError::coverage(format!(
            "Coverage IPC failed to load transparency config: {}",
            err
        ))),
    }
}

/// Transparency verification status values for audit output
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyVerificationStatus {
    Verified,
    Failed,
    Unavailable,
    Skipped,
}

/// Coverage statistics per epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCoverageStats {
    /// Epoch identifier
    pub epoch_id: u64,
    /// Number of files in this epoch
    pub file_count: u64,
    /// Coverage percentage for this epoch
    pub coverage_percentage: f64,
    /// Merkle root for this epoch
    pub merkle_root: String,
    /// Verification status
    pub verified: bool,
}

/// Pending file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingFileInfo {
    /// File path
    pub file_path: String,
    /// Current epoch
    pub current_epoch: u64,
    /// Target epoch for migration
    pub target_epoch: u64,
    /// Migration progress (0.0 to 1.0)
    pub migration_progress: f64,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
    /// File size in bytes
    pub file_size: u64,
    /// Number of rewrap attempts recorded
    pub attempts: u32,
    /// Timestamp of the last rewrap attempt, if any
    pub last_attempt: Option<DateTime<Utc>>,
}

/// Coverage verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageVerificationResult {
    /// File identifier
    pub file_id: String,
    /// Verification status
    pub verified: bool,
    /// Merkle proof chain
    pub proof_chain: Vec<String>,
    /// Coverage log entry
    pub coverage_entry: Option<CoverageLogEntry>,
    /// Verification errors
    pub errors: Vec<String>,
    /// Verification timestamp
    pub verification_timestamp: DateTime<Utc>,
}

/// Coverage log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageLogEntry {
    /// File identifier
    pub file_id: String,
    /// Epoch identifier
    pub epoch_id: u64,
    /// Coverage proof hash
    pub proof_hash: String,
    /// Entry timestamp
    pub timestamp: DateTime<Utc>,
    /// Entry signature
    pub signature: String,
}

/// Handle coverage subcommands
pub async fn handle_coverage_command(
    command: CoverageCommands,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    // Require authentication for all coverage operations
    session_manager.require_auth()?;

    match command {
        CoverageCommands::Enroll { path, all_group } => {
            if all_group {
                return handle_coverage_enroll_list_all(session_manager).await;
            }
            handle_coverage_enroll(path, session_manager).await
        }
        CoverageCommands::Unenroll { path } => {
            handle_coverage_unenroll(path, session_manager).await
        }
        CoverageCommands::Status { root } => handle_coverage_status(root, session_manager).await,
        CoverageCommands::Adopt { path, all, root } => {
            handle_coverage_adopt(path, all, root, session_manager).await
        }
        CoverageCommands::Scan { root } => handle_coverage_scan(root, session_manager).await,
        CoverageCommands::Sync { root } => handle_coverage_sync(root, session_manager).await,
        CoverageCommands::Migrate {
            file,
            root,
            all,
            yes,
        } => handle_coverage_migrate(file, root, all, yes, session_manager).await,
        CoverageCommands::Prune {
            file,
            root,
            all,
            yes,
        } => handle_coverage_prune(file, root, all, yes, session_manager).await,
        CoverageCommands::Purge {
            file,
            root,
            all,
            yes,
        } => handle_coverage_purge(file, root, all, yes, session_manager).await,
        CoverageCommands::Guard { root, all, yes } => {
            handle_coverage_guard(root, all, yes, session_manager).await
        }
        CoverageCommands::Audit {
            verbose,
            format,
            verify_proofs,
            proof_sample,
            verify_all_proofs,
            skip_transparency,
        } => {
            handle_coverage_audit(
                verbose,
                format,
                verify_proofs,
                proof_sample,
                verify_all_proofs,
                skip_transparency,
                session_manager,
            )
            .await
        }
        CoverageCommands::Pending { verbose, epoch } => {
            handle_coverage_pending(verbose, epoch, session_manager).await
        }
        CoverageCommands::RecoverMarkers {
            search,
            max_depth,
            all,
            yes,
        } => handle_coverage_recover_markers(search, max_depth, all, yes, session_manager).await,
        CoverageCommands::Verify { file_id, verbose } => {
            handle_coverage_verify(file_id, verbose, session_manager).await
        }
    }
}

async fn handle_coverage_enroll(
    path: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Enroll Coverage Root");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage enroll")
        .await?;
    let path = match path {
        Some(path) => path,
        None => {
            let summaries =
                if let Some(stats) = try_coverage_ipc_root_stats(session_manager).await? {
                    stats
                } else {
                    let client: LocalClient = session_manager.create_client().await?;
                    client.coverage_root_stats().await.map_err(|err| {
                        CliError::coverage(format!("Failed to load coverage roots: {}", err))
                    })?
                };
            if summaries.is_empty() {
                ui::info("No coverage roots enrolled yet.");
            } else {
                ui::info("Currently enrolled roots:");
                for summary in summaries.iter() {
                    ui::info(&format!(
                        "  - {} ({}, id {})",
                        summary.root.path.display(),
                        describe_root_kind(summary.root.kind),
                        summary.root.root_id
                    ));
                }
            }
            ui::info("Usage: hybridcipher coverage enroll <PATH> to enroll a new folder.");
            ui::info("Use --all-group to list enrolled roots across all groups.");
            return Ok(());
        }
    };

    ui::warning("Auto-enrollment will encrypt every file under this folder in place.");
    ui::warning("Ensure recovery backups are healthy. Otherwise, encrypted data is unrecoverable if this device is lost.");
    if !ui::prompts::confirm_with_default(
        "Proceed with folder enrollment and automatic encryption?",
        false,
    )? {
        ui::info("Operation cancelled.");
        return Ok(());
    }
    let display = path.display().to_string();
    let mut local_client: Option<LocalClient> = None;
    let active_epoch = match try_coverage_ipc_current_epoch(session_manager).await? {
        Some(epoch) => epoch.ok_or_else(|| {
            CliError::coverage(
                "Active epoch is unavailable; initialize the group before enrolling coverage.",
            )
        })?,
        None => {
            let client: LocalClient = session_manager.create_client().await?;
            let epoch = client.current_epoch_id().await.ok_or_else(|| {
                CliError::coverage(
                    "Active epoch is unavailable; initialize the group before enrolling coverage.",
                )
            })?;
            local_client = Some(client);
            epoch
        }
    };
    if path.is_dir() {
        guard_folder_enrollment_against_mixed_ciphertexts(&path, active_group, active_epoch)?;
    }
    let mut progress_bar: Option<indicatif::ProgressBar> = None;
    let mut progress_total: u64 = 0;
    let mut last_progress: Option<CoverageEnrollProgress> = None;
    let mut on_progress = |progress: CoverageEnrollProgress| {
        last_progress = Some(progress);
        update_enroll_progress_ui(&mut progress_bar, &mut progress_total, progress);
    };

    if let Some(outcome) = try_coverage_ipc_enroll_and_hydrate_with_progress(
        session_manager,
        path.clone(),
        &mut on_progress,
    )
    .await?
    {
        finish_enroll_progress_ui(&mut progress_bar, last_progress, &outcome.hydration);
        ui::success(&format!(
            "Enrolled {} ({}, id {})",
            outcome.root.path.display(),
            describe_root_kind(outcome.root.kind),
            outcome.root.root_id
        ));

        if outcome.scan.roots_scanned > 0 {
            ui::success("Initial scan complete");
        } else {
            ui::warning("Initial scan did not match any active roots.");
        }

        if let Some(entries) = try_coverage_ipc_registry_entries(session_manager).await? {
            sync_coverage_registry_snapshot_entries(entries, session_manager, "enrollment").await;
        } else {
            ui::warning(
                "Coverage registry upload skipped after enrollment (IPC registry unavailable).",
            );
        }
        return Ok(());
    }

    let client = if let Some(client) = local_client {
        client
    } else {
        session_manager.create_client().await?
    };
    let outcome = hybridcipher_client::ipc::coverage_workflows::enroll_and_hydrate_with_progress(
        &client,
        path.clone(),
        &mut on_progress,
    )
    .await
    .map_err(|err| CliError::coverage(format!("Failed to enroll '{}': {}", display, err)))?;

    finish_enroll_progress_ui(&mut progress_bar, last_progress, &outcome.hydration);
    ui::success(&format!(
        "Enrolled {} ({}, id {})",
        outcome.root.path.display(),
        describe_root_kind(outcome.root.kind),
        outcome.root.root_id
    ));

    if outcome.scan.roots_scanned > 0 {
        ui::success("Initial scan complete");
    } else {
        ui::warning("Initial scan did not match any active roots.");
    }

    // Upload coverage registry (synchronously) before background uploads begin.
    sync_coverage_registry_snapshot(&client, session_manager, "enrollment").await;
    Ok(())
}

async fn handle_coverage_enroll_list_all(session_manager: &SessionManager) -> Result<(), CliError> {
    ui::section("All Enrolled Coverage Roots");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage enroll")
        .await?;
    let (registry, mut roots) = match (
        try_coverage_ipc_registry_entries(session_manager).await?,
        try_coverage_ipc_roots(session_manager).await?,
    ) {
        (Some(registry), Some(roots)) => (registry, roots),
        _ => {
            let client: LocalClient = session_manager.create_client().await?;
            let registry = client
                .coverage_root_registry_entries()
                .await
                .map_err(|err| CliError::coverage(format!("Failed to load registry: {}", err)))?;
            let roots = client.coverage_roots().await.map_err(|err| {
                CliError::coverage(format!("Failed to load coverage roots: {}", err))
            })?;
            (registry, roots)
        }
    };
    roots.retain(|root| root.state == CoverageRootState::Active);
    let mut roots_by_path: HashMap<String, CoverageRoot> = HashMap::new();
    for root in roots {
        roots_by_path.insert(root.path.to_string_lossy().to_string(), root);
    }

    if registry.is_empty() {
        ui::info("No coverage roots enrolled yet.");
        return Ok(());
    }

    let current_group = session_manager.current_group_id().await?;
    ui::info("Enrolled roots across all groups:");
    for entry in registry {
        let (state, kind) = if let Some(root) = roots_by_path.get(&entry.path) {
            (root.state, describe_root_kind(root.kind))
        } else {
            (CoverageRootState::Unenrolled, "folder")
        };

        let current_marker = if current_group == Some(entry.group_id) {
            " (current group)"
        } else {
            ""
        };

        ui::info(&format!(
            "  - {} ({}, group {}, {}){}",
            entry.path,
            kind,
            entry.group_id,
            describe_root_state(state),
            current_marker
        ));
    }

    ui::info(
        "To manage a root from another group, run 'hybridcipher switch-group <GROUP_ID>' and rerun the coverage command.",
    );
    Ok(())
}

async fn handle_coverage_unenroll(
    path: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Unenroll Coverage Root");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage unenroll")
        .await?;
    let summaries = if let Some(stats) = try_coverage_ipc_root_stats(session_manager).await? {
        stats
    } else {
        let client: LocalClient = session_manager.create_client().await?;
        client
            .coverage_root_stats()
            .await
            .map_err(|err| CliError::coverage(format!("Failed to load coverage roots: {}", err)))?
    };

    if summaries.is_empty() {
        ui::info("No coverage roots enrolled yet.");
        ui::info("Usage: hybridcipher coverage unenroll <PATH> to unenroll one enrolled folder.");
        return Ok(());
    }

    ui::info("Enrolled roots:");
    for summary in summaries
        .iter()
        .filter(|s| s.root.state == CoverageRootState::Active)
    {
        ui::info(&format!(
            "  - {} ({}, id {})",
            summary.root.path.display(),
            describe_root_kind(summary.root.kind),
            summary.root.root_id
        ));
    }

    if path.is_none() {
        ui::info("Usage: hybridcipher coverage unenroll <PATH> to unenroll one enrolled folder.");
        return Ok(());
    }

    let path = path.unwrap();
    let absolute = if path.is_absolute() {
        path.clone()
    } else {
        std::env::current_dir()
            .map_err(|e| CliError::coverage(format!("Failed to resolve current directory: {}", e)))?
            .join(path)
    };

    let canonical = if absolute.exists() {
        Some(canonicalize_cli_path(absolute.clone()).await?)
    } else {
        None
    };
    let display = canonical
        .as_ref()
        .unwrap_or(&absolute)
        .display()
        .to_string();

    let matched_root = summaries.iter().find(|s| {
        s.root.state == CoverageRootState::Active
            && (canonical.as_ref().map_or(false, |c| s.root.path == *c)
                || (!canonical.is_some() && s.root.path == absolute))
    });
    let Some(matched_root) = matched_root else {
        return Err(CliError::invalid_input(format!(
            "No active enrolled root matches '{}'",
            display
        )));
    };

    let mount_status = mount::root_mount_status(session_manager, matched_root.root.root_id).await?;
    if mount_status.active {
        let mountpoint_display = mount_status
            .mountpoint
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let mount_type = if mount_status.fuse_mounted {
            "FUSE"
        } else {
            "sync"
        };

        ui::warning(&format!(
            "Root '{}' is currently mounted at {} ({mount_type} mount).",
            matched_root.root.path.display(),
            mountpoint_display
        ));
        ui::warning(
            "Unmount is required before unenroll/decrypt to avoid conflicting filesystem updates.",
        );
        if !ui::prompts::confirm_with_default("Unmount this root and continue unenroll?", true)? {
            ui::info("Operation cancelled.");
            return Ok(());
        }

        mount::handle_unmount(
            session_manager,
            Some(matched_root.root.root_id),
            false,
            false,
        )
        .await
        .map_err(|err| {
            CliError::coverage(format!(
                "Failed to unmount root '{}' before unenroll: {}",
                matched_root.root.path.display(),
                err
            ))
        })?;

        let mount_status =
            mount::root_mount_status(session_manager, matched_root.root.root_id).await?;
        if mount_status.active {
            return Err(CliError::coverage(format!(
                "Root '{}' is still mounted; aborting unenroll.",
                matched_root.root.path.display()
            )));
        }
    }

    if !absolute.exists() {
        ui::warning(&format!(
            "Path '{}' is missing. Remove it from the enrolled list without decrypting?",
            display
        ));
        if !ui::prompts::confirm_with_default("Remove missing root?", true)? {
            ui::info("Operation cancelled.");
            return Ok(());
        }
    } else {
        ui::warning("This will decrypt every encrypted file under the root (timestamps preserved) and remove it from coverage tracking.");
        if !ui::prompts::confirm_with_default("Proceed with unenroll and decrypt?", false)? {
            ui::info("Operation cancelled.");
            return Ok(());
        }
    }

    // First, unenroll the coverage root to stop tracking
    ui::info("Unenrolling coverage root...");
    let mut progress_bar: Option<indicatif::ProgressBar> = None;
    let mut progress_total: u64 = 0;
    let mut last_progress: Option<CoverageDecryptProgress> = None;
    let mut on_progress = |progress: CoverageDecryptProgress| {
        last_progress = Some(progress);
        update_decrypt_progress_ui(&mut progress_bar, &mut progress_total, progress);
    };

    if let Some(outcome) = try_coverage_ipc_unenroll_and_decrypt_with_progress(
        session_manager,
        canonical.as_ref().unwrap_or(&absolute).clone(),
        &mut on_progress,
    )
    .await?
    {
        finish_decrypt_progress_ui(&mut progress_bar, last_progress);
        ui::success(&format!(
            "Unenrolled {} (id {})",
            outcome.root.path.display(),
            outcome.root.root_id
        ));
        if outcome.decrypted_files > 0 {
            ui::info(&format!(
                "Decrypted {} encrypted file{}.",
                outcome.decrypted_files,
                if outcome.decrypted_files == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }
        if let Some(entries) = try_coverage_ipc_registry_entries(session_manager).await? {
            sync_coverage_registry_snapshot_entries(entries, session_manager, "unenroll").await;
        } else {
            ui::warning(
                "Coverage registry upload skipped after unenroll (IPC registry unavailable).",
            );
        }
        return Ok(());
    }

    let client: LocalClient = session_manager.create_client().await?;
    let mut local_progress_bar: Option<indicatif::ProgressBar> = None;
    let mut local_progress_total: u64 = 0;
    let mut local_last_progress: Option<CoverageDecryptProgress> = None;
    let mut on_progress = |progress: CoverageDecryptProgress| {
        local_last_progress = Some(progress);
        update_decrypt_progress_ui(&mut local_progress_bar, &mut local_progress_total, progress);
    };

    let outcome = hybridcipher_client::ipc::coverage_workflows::unenroll_and_decrypt_with_progress(
        &client,
        canonical.as_ref().unwrap_or(&absolute).clone(),
        &mut on_progress,
    )
    .await
    .map_err(|err| CliError::coverage(format!("Failed to unenroll '{}': {}", display, err)))?;

    finish_decrypt_progress_ui(&mut local_progress_bar, local_last_progress);
    ui::success(&format!(
        "Unenrolled {} (id {})",
        outcome.root.path.display(),
        outcome.root.root_id
    ));
    if outcome.decrypted_files > 0 {
        ui::info(&format!(
            "Decrypted {} encrypted file{}.",
            outcome.decrypted_files,
            if outcome.decrypted_files == 1 {
                ""
            } else {
                "s"
            }
        ));
    } else if !absolute.exists() {
        ui::info("Path is already missing; removed enrollment without decrypting.");
    }

    sync_coverage_registry_snapshot(&client, session_manager, "unenroll").await;
    Ok(())
}

async fn sync_coverage_registry_snapshot(
    client: &LocalClient,
    session_manager: &SessionManager,
    action: &str,
) {
    let entry_count = client
        .coverage_root_registry_entries()
        .await
        .unwrap_or_default()
        .len();

    let session = match session_manager.require_auth() {
        Ok(session) => session,
        Err(err) => {
            ui::warning(&format!(
                "Coverage registry upload skipped after {} (session unavailable): {}",
                action, err
            ));
            return;
        }
    };

    let export_key = match session_manager.opaque_export_key().await {
        Ok(key) => key,
        Err(err) => {
            ui::warning(&format!(
                "Coverage registry upload skipped after {} (OPAQUE export key unavailable): {}",
                action, err
            ));
            return;
        }
    };

    match upload_coverage_registry_snapshot(client, &session, session_manager, &*export_key).await {
        Ok(_) => ui::dim(&format!(
            "Coverage registry uploaded ({} enrolled folder{}).",
            entry_count,
            if entry_count == 1 { "" } else { "s" }
        )),
        Err(err) => ui::warning(&format!(
            "Coverage registry upload skipped after {}: {}",
            action, err
        )),
    }
}

async fn sync_coverage_registry_snapshot_entries(
    entries: Vec<CoverageRegistryEntry>,
    session_manager: &SessionManager,
    action: &str,
) {
    let entry_count = entries.len();

    let session = match session_manager.require_auth() {
        Ok(session) => session,
        Err(err) => {
            ui::warning(&format!(
                "Coverage registry upload skipped after {} (session unavailable): {}",
                action, err
            ));
            return;
        }
    };

    let export_key = match session_manager.opaque_export_key().await {
        Ok(key) => key,
        Err(err) => {
            ui::warning(&format!(
                "Coverage registry upload skipped after {} (OPAQUE export key unavailable): {}",
                action, err
            ));
            return;
        }
    };

    match upload_coverage_registry_entries(&entries, &session, session_manager, &*export_key).await
    {
        Ok(_) => ui::dim(&format!(
            "Coverage registry uploaded ({} enrolled folder{}).",
            entry_count,
            if entry_count == 1 { "" } else { "s" }
        )),
        Err(err) => ui::warning(&format!(
            "Coverage registry upload skipped after {}: {}",
            action, err
        )),
    }
}

async fn handle_coverage_status(
    filter: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Coverage Status");
    let mut summaries = if let Some(stats) = try_coverage_ipc_root_stats(session_manager).await? {
        stats
    } else {
        let client: LocalClient = session_manager.create_client().await?;
        client
            .coverage_root_stats()
            .await
            .map_err(|err| CliError::coverage(format!("Failed to load coverage roots: {}", err)))?
    };

    if let Some(path) = filter {
        let canonical = canonicalize_cli_path(path).await?;
        summaries.retain(|summary| summary.root.path == canonical);
        if summaries.is_empty() {
            ui::warning("No enrolled roots matched the provided path.");
            return Ok(());
        }
    }

    if summaries.is_empty() {
        ui::info("No coverage roots enrolled yet.");
        return Ok(());
    }

    for summary in summaries {
        render_root_summary(&summary);
    }

    Ok(())
}

fn render_root_summary(summary: &CoverageRootStats) {
    let root = &summary.root;
    let total_files = summary.tracked_files + summary.orphaned_files + summary.unmanaged_files;
    let coverage_pct = (summary.coverage_ratio * 100.0).clamp(0.0, 100.0);

    ui::subsection(&root.path.display().to_string());
    ui::info(&format!("  state: {}", describe_root_state(root.state)));
    ui::info(&format!("  kind: {}", describe_root_kind(root.kind)));
    ui::info(&format!("  root_id: {}", root.root_id));
    ui::info(&format!(
        "  enrolled_at: {}",
        ui::formatting::format_local_datetime(&root.created_at)
    ));
    let last_scan = root
        .last_scan
        .map(|ts| ui::formatting::format_local_datetime(&ts))
        .unwrap_or_else(|| "never".to_string());
    ui::info(&format!("  last_scan: {}", last_scan));

    if total_files == 0 {
        ui::info("  coverage: no indexed files yet");
    } else {
        ui::info(&format!(
            "  coverage: {:.1}% ({}/{} files)",
            coverage_pct, summary.tracked_files, total_files
        ));
    }

    ui::info(&format!(
        "  tracked: {} files ({})",
        summary.tracked_files,
        format_bytes(summary.tracked_bytes)
    ));

    if summary.orphaned_files > 0 {
        ui::warning(&format!(
            "  orphaned: {} files ({})",
            summary.orphaned_files,
            format_bytes(summary.orphaned_bytes)
        ));
        if summary.orphan_wrong_epoch > 0 {
            ui::info(&format!(
                "    • migrate: {} (wrong/unknown epoch)",
                summary.orphan_wrong_epoch
            ));
        }
        if summary.orphan_missing_metadata > 0 {
            ui::info(&format!(
                "    • adopt: {} (ciphertext without metadata)",
                summary.orphan_missing_metadata
            ));
        }
        if summary.orphan_missing_file > 0 {
            ui::info(&format!(
                "    • prune: {} (metadata present, file missing)",
                summary.orphan_missing_file
            ));
        }
        if summary.orphan_outcast > 0 {
            ui::info(&format!(
                "    • purge: {} (belongs to another group)",
                summary.orphan_outcast
            ));
        }
    } else {
        ui::info("  orphaned: 0 files");
    }

    if summary.unmanaged_files > 0 {
        ui::warning(&format!(
            "  unmanaged: {} files ({})",
            summary.unmanaged_files,
            format_bytes(summary.unmanaged_bytes)
        ));
        ui::info("  ↳ encrypt those files (e.g. `hybridcipher encrypt <path>`) or move them outside the enrolled root if they shouldn't be covered.");
    }

    if !summary.recent_orphans.is_empty() {
        ui::info("  orphaned files:");
        for orphan in &summary.recent_orphans {
            ui::warning(&format!(
                "    [{}] {} – {} (last seen {})",
                describe_orphan_tag(orphan.orphan_kind.as_ref(), &orphan.state),
                orphan.relative_path,
                format_bytes(orphan.size),
                ui::formatting::format_local_datetime(&orphan.last_seen)
            ));
        }
    }

    if !summary.recent_unmanaged.is_empty() {
        ui::info("  unmanaged files:");
        for unmanaged in &summary.recent_unmanaged {
            ui::warning(&format!(
                "    [{}] {} – {} (last seen {})",
                describe_file_state(&unmanaged.state),
                unmanaged.relative_path,
                format_bytes(unmanaged.size),
                ui::formatting::format_local_datetime(&unmanaged.last_seen)
            ));
        }
    }

    if summary.orphaned_files > 0 {
        ui::info(
            "  ↳ use 'hybridcipher coverage migrate [--root <enrolled_folder_path>] [--all]' for [migrate] entries (active migration required), 'hybridcipher coverage adopt [--root <enrolled_folder_path>] --all' for [adopt] entries, 'hybridcipher coverage prune [--root <enrolled_folder_path>] [--all]' for [missing] entries, 'hybridcipher coverage purge [--root <enrolled_folder_path>] [--all]' for [outcast] entries, or 'hybridcipher coverage guard [--root <enrolled_folder_path>] --all' to run all remediations in one pass.",
        );
    }
}

async fn handle_coverage_adopt(
    path: Option<PathBuf>,
    all: bool,
    root: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Coverage Adopt");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage adopt")
        .await?;

    if all {
        if path.is_some() {
            return Err(CliError::invalid_input(
                "Provide either --all (optionally with --root) or a single file path.".to_string(),
            ));
        }
        let summary = if let Some(summary) =
            try_coverage_ipc_adopt_missing_metadata(session_manager, root.clone(), true).await?
        {
            summary
        } else {
            let client: LocalClient = session_manager.create_client().await?;
            client
                .coverage_adopt_missing_metadata(root, true)
                .await
                .map_err(|err| CliError::coverage(format!("Failed to adopt files: {}", err)))?
        };
        ui::success(&format!(
            "Adopted {} ciphertext(s) without metadata.",
            summary.adopted
        ));
        if !summary.adopt_failures.is_empty() {
            ui::warning("Some files could not be adopted:");
            for failure in summary.adopt_failures {
                ui::warning(&format!("  {}", failure));
            }
        }
        return Ok(());
    }

    let path = path.ok_or_else(|| {
        CliError::invalid_input(
            "Provide a file path to adopt, or use --all (optionally with --root).".to_string(),
        )
    })?;

    let result =
        if let Some(result) = try_coverage_ipc_adopt_path(session_manager, path.clone()).await? {
            result
        } else {
            let client: LocalClient = session_manager.create_client().await?;
            client.coverage_adopt_path(&path).await.map_err(|err| {
                CliError::coverage(format!("Failed to adopt '{}': {}", path.display(), err))
            })?
        };

    ui::success(&format!(
        "Adopted {} into coverage root {} ({})",
        result.entry.relative_path,
        result.root.path.display(),
        describe_root_kind(result.root.kind)
    ));
    let absolute_path = result.root.path.join(&result.entry.relative_path);
    ui::info(&format!("Full path: {}", absolute_path.display()));
    ui::info(&format!(
        "Tracked epoch: {}, size: {} bytes",
        result.entry.last_epoch, result.entry.size
    ));
    ui::info(&format!("File UUID: {}", result.entry.file_uuid));
    Ok(())
}

async fn handle_coverage_scan(
    root: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Coverage Scan");
    let active_user = session_manager
        .active_user_summary()
        .ok_or_else(|| CliError::coverage("No active user found. Please login first."))?;
    let active_group = session_manager
        .ensure_current_group()
        .await
        .map_err(|err| CliError::coverage(format!("Failed to resolve active group: {}", err)))?;
    let progress_bars: Arc<Mutex<HashMap<Uuid, indicatif::ProgressBar>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let progress_cb: CoverageScanProgress = {
        let bars = progress_bars.clone();
        Arc::new(move |root: &CoverageRoot, processed: usize, total: usize| {
            if total == 0 {
                return;
            }
            let mut map = bars.lock().unwrap();
            let pb = map.entry(root.root_id).or_insert_with(|| {
                let pb = ui::progress::create_file_progress(total as u64, "scan");
                ui::progress::update_progress_with_message(
                    &pb,
                    0,
                    &format!("Scanning {}", root.path.display()),
                );
                pb
            });

            let pos = std::cmp::min(processed, total) as u64;
            ui::progress::update_progress_with_message(
                pb,
                pos,
                &format!("{} ({}/{})", root.path.display(), processed, total),
            );

            if processed >= total && !pb.is_finished() {
                ui::progress::finish_progress_with_result(
                    pb,
                    true,
                    &format!("Scanned {}", root.path.display()),
                );
            }
        })
    };

    let mut on_progress = |progress: CoverageScanProgressEvent| {
        (progress_cb)(
            &progress.root,
            progress.progress.processed,
            progress.progress.total,
        );
    };

    let (summary, used_ipc) = match try_coverage_ipc_rescan_with_progress(
        session_manager,
        root.clone(),
        &mut on_progress,
    )
    .await?
    {
        Some(summary) => (summary, true),
        None => {
            let client: LocalClient = session_manager.create_client().await?;
            let summary = client
                .coverage_rescan_with_progress(root.clone(), Some(progress_cb))
                .await
                .map_err(|err| {
                    CliError::coverage(format!("Failed to scan coverage roots: {}", err))
                })?;
            (summary, false)
        }
    };

    if summary.roots_scanned > 0 {
        ui::success(&format!(
            "Scanned {} coverage root{}",
            summary.roots_scanned,
            if summary.roots_scanned == 1 { "" } else { "s" }
        ));
        ui::info(&format!("Tracked files updated: {}", summary.files_indexed));
        if summary.orphaned_files > 0 {
            ui::warning(&format!(
                "{} previously tracked file{} now look orphaned",
                summary.orphaned_files,
                if summary.orphaned_files == 1 { "" } else { "s" }
            ));
        } else {
            ui::info("No orphaned files detected during this scan.");
        }

        if summary.unmanaged_files > 0 {
            ui::warning(&format!(
                "{} new file{} under enrolled roots are unmanaged",
                summary.unmanaged_files,
                if summary.unmanaged_files == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        } else {
            ui::info("No unmanaged files detected.");
        }
    } else {
        ui::info("No active coverage roots matched the provided filters.");
    }

    if !summary.missing_roots.is_empty() {
        ui::warning(
            "The following enrolled roots could not be scanned because the paths are missing:",
        );
        for missing in &summary.missing_roots {
            ui::warning(&format!("  - {}", missing.display()));
        }
        ui::warning("If these folders were moved or renamed, unenroll the old path and enroll the new location.");
    }

    ui::info("Tip: run `hybridcipher coverage status` to review per-root KPIs and orphan details.");

    let records = if used_ipc {
        match try_coverage_ipc_file_records(session_manager, root.clone()).await? {
            Some(records) => records,
            None => {
                ui::warning(
                    "Scan completed via desktop coverage service, but scan records were unavailable.",
                );
                return Ok(());
            }
        }
    } else {
        let client: LocalClient = session_manager.create_client().await?;
        client
            .coverage_file_records(root.clone())
            .await
            .map_err(|err| CliError::coverage(format!("Failed to gather scan records: {}", err)))?
    };

    if !records.is_empty() {
        if let Ok(log_path) = write_scan_log(&active_user, active_group, &root, &summary, &records)
        {
            ui::info(&format!("Scan details saved to {}", log_path.display()));
        } else {
            ui::warning("Failed to persist scan log to disk.");
        }
    }

    Ok(())
}

async fn handle_coverage_sync(
    root: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Coverage Sync");

    if let Some(target) = &root {
        ui::info(&format!("Syncing coverage for {}", target.display()));
    }

    if let Some(summary) = try_coverage_ipc_sync(session_manager, root.clone()).await? {
        if summary.upserts_prepared == 0 && summary.removals_prepared == 0 {
            ui::info("No coverage deltas to upload.");
            return Ok(());
        }
        ui::info(&format!(
            "Prepared {} upsert{} and {} removal{}.",
            summary.upserts_prepared,
            if summary.upserts_prepared == 1 {
                ""
            } else {
                "s"
            },
            summary.removals_prepared,
            if summary.removals_prepared == 1 {
                ""
            } else {
                "s"
            }
        ));
        ui::success(&format!(
            "Uploaded {} delta{} across {} batch{}.",
            summary.uploaded_deltas,
            if summary.uploaded_deltas == 1 {
                ""
            } else {
                "s"
            },
            summary.uploaded_batches,
            if summary.uploaded_batches == 1 {
                ""
            } else {
                "s"
            }
        ));
        return Ok(());
    }

    let client: LocalClient = session_manager.create_client().await?;

    let progress_state: Arc<Mutex<Option<indicatif::ProgressBar>>> = Arc::new(Mutex::new(None));
    let progress_cb: CoverageSyncProgress = {
        let state = progress_state.clone();
        Arc::new(move |processed, total| {
            if total == 0 {
                return;
            }
            let mut guard = state.lock().unwrap();
            let pb = guard
                .get_or_insert_with(|| ui::progress::create_file_progress(total as u64, "sync"));
            ui::progress::update_progress_with_message(
                pb,
                processed as u64,
                &format!("Syncing coverage ({}/{})", processed, total),
            );
            if processed >= total && !pb.is_finished() {
                ui::progress::finish_progress_with_result(pb, true, "Coverage sync scan complete");
            }
        })
    };

    let upload_state: Arc<Mutex<Option<indicatif::ProgressBar>>> = Arc::new(Mutex::new(None));
    let upload_cb: CoverageUploadProgress = {
        let state = upload_state.clone();
        Arc::new(move |uploaded, total| {
            if total == 0 {
                return;
            }
            let mut guard = state.lock().unwrap();
            let pb = guard
                .get_or_insert_with(|| ui::progress::create_file_progress(total as u64, "upload"));
            ui::progress::update_progress_with_message(
                pb,
                uploaded as u64,
                &format!("Uploading coverage deltas ({}/{})", uploaded, total),
            );
            if uploaded >= total && !pb.is_finished() {
                ui::progress::finish_progress_with_result(
                    pb,
                    true,
                    "Coverage sync upload complete",
                );
            }
        })
    };

    let summary = client
        .coverage_sync_with_progress(root.clone(), Some(progress_cb), Some(upload_cb))
        .await
        .map_err(|err| CliError::coverage(format!("Coverage sync failed: {}", err)))?;

    if summary.upserts_prepared == 0 && summary.removals_prepared == 0 {
        ui::info("No coverage deltas to upload.");
        return Ok(());
    }

    ui::info(&format!(
        "Prepared {} upsert{} and {} removal{}.",
        summary.upserts_prepared,
        if summary.upserts_prepared == 1 {
            ""
        } else {
            "s"
        },
        summary.removals_prepared,
        if summary.removals_prepared == 1 {
            ""
        } else {
            "s"
        }
    ));

    if root.is_some() && summary.removals_prepared == 0 {
        ui::info("Removals are skipped when syncing a single root.");
    }

    if summary.skipped_entries > 0 {
        ui::warning(&format!(
            "Skipped {} entr{} without resolvable file IDs.",
            summary.skipped_entries,
            if summary.skipped_entries == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }

    if summary.baseline_entries > 0 {
        ui::success(&format!(
            "Uploaded coverage baseline with {} entr{}.",
            summary.baseline_entries,
            if summary.baseline_entries == 1 {
                "y"
            } else {
                "ies"
            }
        ));
        ui::info("Coverage sync fast-forwarded; delta upload skipped.");
        return Ok(());
    }

    if summary.uploaded_deltas > 0 {
        ui::success(&format!(
            "Uploaded {} delta{} in {} batch{}.",
            summary.uploaded_deltas,
            if summary.uploaded_deltas == 1 {
                ""
            } else {
                "s"
            },
            summary.uploaded_batches,
            if summary.uploaded_batches == 1 {
                ""
            } else {
                "es"
            }
        ));
    } else {
        ui::warning("Coverage sync completed, but no deltas were uploaded.");
    }

    Ok(())
}

fn update_migration_progress_ui(
    progress_bar: &mut Option<indicatif::ProgressBar>,
    progress_total: &mut u64,
    progress: CoverageMigrationProgress,
) {
    let total = progress.total_files as u64;
    if total == 0 {
        return;
    }
    if progress_bar.is_none() || *progress_total != total {
        if let Some(existing) = progress_bar.take() {
            existing.finish_and_clear();
        }
        let pb = ui::progress::create_progress_bar(total, "Migrating files");
        *progress_total = total;
        *progress_bar = Some(pb);
    }
    if let Some(pb) = progress_bar.as_ref() {
        let message = if progress.failed_files > 0 {
            format!(
                "Migrated {} of {} files ({} failed)",
                progress.migrated_files, progress.total_files, progress.failed_files
            )
        } else {
            format!(
                "Migrated {} of {} files",
                progress.migrated_files, progress.total_files
            )
        };
        ui::progress::update_progress_with_message(pb, progress.migrated_files as u64, &message);
    }
}

fn finish_migration_progress_ui(
    progress_bar: &mut Option<indicatif::ProgressBar>,
    progress: &CoverageMigrationProgress,
) {
    if let Some(pb) = progress_bar.take() {
        if progress.total_files > 0 {
            let success = progress.failed_files == 0;
            let message = if progress.failed_files > 0 {
                format!(
                    "Coverage migration completed with {} failure{}",
                    progress.failed_files,
                    if progress.failed_files == 1 { "" } else { "s" }
                )
            } else {
                "Coverage migration completed".to_string()
            };
            ui::progress::finish_progress_with_result(&pb, success, &message);
        } else {
            pb.finish_and_clear();
        }
    }
}

fn update_decrypt_progress_ui(
    progress_bar: &mut Option<indicatif::ProgressBar>,
    progress_total: &mut u64,
    progress: CoverageDecryptProgress,
) {
    let total = progress.total_files as u64;
    if total == 0 {
        return;
    }
    if progress_bar.is_none() || *progress_total != total {
        if let Some(existing) = progress_bar.take() {
            existing.finish_and_clear();
        }
        let pb = ui::progress::create_file_progress(total, "decrypt");
        *progress_total = total;
        *progress_bar = Some(pb);
    }
    if let Some(pb) = progress_bar.as_ref() {
        let message = if progress.failed_files > 0 {
            format!(
                "Decrypted {} of {} files ({} failed)",
                progress.decrypted_files, progress.total_files, progress.failed_files
            )
        } else {
            format!(
                "Decrypted {} of {} files",
                progress.decrypted_files, progress.total_files
            )
        };
        ui::progress::update_progress_with_message(pb, progress.decrypted_files as u64, &message);
    }
}

fn finish_decrypt_progress_ui(
    progress_bar: &mut Option<indicatif::ProgressBar>,
    progress: Option<CoverageDecryptProgress>,
) {
    if let Some(pb) = progress_bar.take() {
        let progress = progress.unwrap_or_default();
        if progress.total_files > 0 {
            let success = progress.failed_files == 0;
            let message = if progress.failed_files > 0 {
                format!(
                    "Decryption completed with {} failure{}",
                    progress.failed_files,
                    if progress.failed_files == 1 { "" } else { "s" }
                )
            } else {
                "Decryption completed".to_string()
            };
            ui::progress::finish_progress_with_result(&pb, success, &message);
        } else {
            pb.finish_and_clear();
        }
    }
}

fn update_enroll_progress_ui(
    progress_bar: &mut Option<indicatif::ProgressBar>,
    progress_total: &mut u64,
    progress: CoverageEnrollProgress,
) {
    let incoming_total = progress.total_files as u64;
    let total = if incoming_total > 0 {
        incoming_total
    } else {
        *progress_total
    };
    if total == 0 {
        return;
    }

    if progress_bar.is_none() || *progress_total != total {
        if let Some(existing) = progress_bar.take() {
            existing.finish_and_clear();
        }
        let pb = ui::progress::create_file_progress(total, "enroll");
        ui::progress::update_progress_with_message(&pb, 0, "Scanning and encrypting files...");
        *progress_total = total;
        *progress_bar = Some(pb);
    }

    if let Some(pb) = progress_bar.as_ref() {
        let message = match progress.phase {
            CoverageEnrollPhase::Hydrating => {
                if progress.processed_files == 0 {
                    "Scanning and encrypting files...".to_string()
                } else {
                    format!(
                        "Processed {} of {} files",
                        progress.processed_files, progress.total_files
                    )
                }
            }
            CoverageEnrollPhase::Finalizing => {
                "Finalizing enrollment (rescan/indexing)...".to_string()
            }
            CoverageEnrollPhase::Rescanning => {
                if progress.total_files > 0 {
                    format!(
                        "Finalizing enrollment (rescan/indexing): scanned {} of {} files",
                        progress.processed_files.min(progress.total_files),
                        progress.total_files
                    )
                } else {
                    "Finalizing enrollment (rescan/indexing)...".to_string()
                }
            }
        };

        let position = match progress.phase {
            CoverageEnrollPhase::Hydrating => progress.processed_files as u64,
            CoverageEnrollPhase::Finalizing => (progress.processed_files as u64).min(total),
            CoverageEnrollPhase::Rescanning => {
                if progress.total_files > 0 {
                    progress.processed_files.min(progress.total_files) as u64
                } else {
                    total
                }
            }
        };
        ui::progress::update_progress_with_message(pb, position.min(total), &message);
    }
}

fn finish_enroll_progress_ui(
    progress_bar: &mut Option<indicatif::ProgressBar>,
    progress: Option<CoverageEnrollProgress>,
    summary: &CoverageHydrationSummary,
) {
    let progress = progress.unwrap_or_default();
    let files_needing_work = summary.newly_encrypted + summary.skipped_due_to_errors;
    let success = if files_needing_work == 0 {
        summary.errors.is_empty()
    } else {
        let error_rate = summary.errors.len() as f64 / files_needing_work as f64;
        error_rate <= 0.05
    };

    if let Some(pb) = progress_bar.take() {
        if progress.total_files > 0 {
            let position = files_needing_work.min(progress.total_files) as u64;
            pb.set_position(position);
            ui::progress::finish_progress_with_result(
                &pb,
                success,
                "Enrollment hydration complete",
            );
        } else {
            pb.finish_and_clear();
        }
    }
}

async fn handle_coverage_migrate(
    file: Option<PathBuf>,
    root: Option<PathBuf>,
    all: bool,
    yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Migrate Orphaned Coverage Entries");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage migrate")
        .await?;

    if file.is_some() && root.is_some() {
        return Err(CliError::invalid_input(
            "--root cannot be combined with a positional file path. Specify either a file or a root sweep."
                .to_string(),
        ));
    }

    let description = if let Some(path) = file.as_ref() {
        format!("Migrate wrong-epoch orphan {} now?", path.display())
    } else if let Some(path) = root.as_ref() {
        format!(
            "Sweep {} and migrate wrong-epoch orphans now?",
            path.display()
        )
    } else if all {
        "Migrate wrong-epoch orphaned entries across all enrolled folders. Proceed?".to_string()
    } else {
        return Err(CliError::invalid_input(
            "Use --all or specify --root/FILE to migrate orphaned entries.".to_string(),
        ));
    };

    if !yes && !ui::prompts::confirm_with_default(&description, false)? {
        ui::info("Operation cancelled.");
        return Ok(());
    }

    let mut progress_bar: Option<indicatif::ProgressBar> = None;
    let mut progress_total: u64 = 0;
    let mut on_progress = |progress: CoverageMigrationProgress| {
        update_migration_progress_ui(&mut progress_bar, &mut progress_total, progress);
    };

    let progress = match try_coverage_ipc_migrate_orphans_with_progress(
        session_manager,
        file.clone(),
        root.clone(),
        all,
        &mut on_progress,
    )
    .await?
    {
        Some(progress) => progress,
        None => {
            let client: LocalClient = session_manager.create_client().await?;
            client
                .coverage_migrate_orphans_with_progress(file, root, all, |progress| {
                    on_progress(progress);
                })
                .await
                .map_err(|err| {
                    CliError::coverage(format!("Failed to migrate orphaned entries: {}", err))
                })?
        }
    };

    finish_migration_progress_ui(&mut progress_bar, &progress);

    if progress.total_files == 0 {
        ui::info("No wrong-epoch orphaned entries were migrated.");
    } else if progress.migrated_files == 0 {
        ui::warning("No files were migrated during this run.");
    } else {
        let suffix = if progress.migrated_files == 1 {
            ""
        } else {
            "s"
        };
        if progress.failed_files > 0 {
            ui::warning(&format!(
                "Migrated {} of {} file{} ({} failed).",
                progress.migrated_files, progress.total_files, suffix, progress.failed_files
            ));
        } else {
            ui::success(&format!(
                "Migrated {} of {} file{}.",
                progress.migrated_files, progress.total_files, suffix
            ));
        }
    }

    Ok(())
}

async fn handle_coverage_prune(
    file: Option<PathBuf>,
    root: Option<PathBuf>,
    all: bool,
    yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Prune Orphaned Coverage Entries");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage prune")
        .await?;

    if file.is_some() && root.is_some() {
        return Err(CliError::invalid_input(
            "--root cannot be combined with a positional file path. Specify either a file or a root sweep."
                .to_string(),
        ));
    }

    let description = if let Some(path) = file.as_ref() {
        format!("Remove the orphaned entry for {}?", path.display())
    } else if let Some(path) = root.as_ref() {
        format!(
            "Sweep {} and remove orphaned entries whose files no longer exist?",
            path.display()
        )
    } else if all {
        "Prune orphaned entries across all enrolled folders (this removes every missing file reference). Proceed?"
            .to_string()
    } else {
        return Err(CliError::invalid_input(
            "Use --all or specify --root/FILE to prune orphaned entries.".to_string(),
        ));
    };

    if !yes && !ui::prompts::confirm_with_default(&description, false)? {
        ui::info("Operation cancelled.");
        return Ok(());
    }

    if let Some(path) = file {
        if let Some(removed) =
            try_coverage_ipc_prune_orphan_file(session_manager, path.clone()).await?
        {
            if removed {
                ui::success("Removed the orphaned entry.");
            } else {
                ui::info("No orphaned entry matched the provided path.");
            }
            return Ok(());
        }
        let client: LocalClient = session_manager.create_client().await?;
        match client.coverage_prune_orphan_file(path.clone()).await {
            Ok(true) => ui::success("Removed the orphaned entry."),
            Ok(false) => ui::info("No orphaned entry matched the provided path."),
            Err(err) => {
                return Err(CliError::coverage(format!(
                    "Failed to prune orphaned entry for {}: {}",
                    path.display(),
                    err
                )))
            }
        }
        return Ok(());
    }

    if let Some(count) = try_coverage_ipc_prune_orphans(session_manager, root.clone(), all).await? {
        if count == 0 {
            ui::info("No orphaned entries were removed.");
        } else {
            ui::success(&format!(
                "Removed {} orphaned entr{} from the local index.",
                count,
                if count == 1 { "y" } else { "ies" }
            ));
        }
        return Ok(());
    }

    let client: LocalClient = session_manager.create_client().await?;
    match client.coverage_prune_orphans(root, all).await {
        Ok(0) => ui::info("No orphaned entries were removed."),
        Ok(count) => ui::success(&format!(
            "Removed {} orphaned entr{} from the local index.",
            count,
            if count == 1 { "y" } else { "ies" }
        )),
        Err(err) => {
            return Err(CliError::coverage(format!(
                "Failed to prune orphaned entries: {}",
                err
            )))
        }
    }
    Ok(())
}

async fn handle_coverage_purge(
    file: Option<PathBuf>,
    root: Option<PathBuf>,
    all: bool,
    yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Purge Outcast Coverage Entries");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage purge")
        .await?;

    if file.is_some() && root.is_some() {
        return Err(CliError::invalid_input(
            "--root cannot be combined with a positional file path. Specify either a file or a root sweep."
                .to_string(),
        ));
    }

    let description = if let Some(path) = file.as_ref() {
        format!("Purge the outcast entry for {}?", path.display())
    } else if let Some(path) = root.as_ref() {
        format!(
            "Sweep {} and purge outcast entries (ciphertexts from another group)?",
            path.display()
        )
    } else if all {
        "Purge outcast entries across all enrolled folders? This removes all entries that belong to other groups.".to_string()
    } else {
        return Err(CliError::invalid_input(
            "Use --all or specify --root/FILE to purge outcast entries.".to_string(),
        ));
    };

    if !yes && !ui::prompts::confirm_with_default(&description, false)? {
        ui::info("Operation cancelled.");
        return Ok(());
    }

    if let Some(path) = file {
        if let Some(removed) =
            try_coverage_ipc_purge_outcasts(session_manager, Some(path.clone()), None, false)
                .await?
        {
            if removed > 0 {
                ui::success("Purged the outcast entry.");
            } else {
                ui::info("No outcast entry matched the provided path.");
            }
            return Ok(());
        }
        let client: LocalClient = session_manager.create_client().await?;
        let removed = client
            .coverage_purge_outcasts(Some(path.clone()), None, false)
            .await
            .map_err(|err| CliError::coverage(format!("Failed to purge outcast entry: {}", err)))?;
        if removed > 0 {
            ui::success("Purged the outcast entry.");
        } else {
            ui::info("No outcast entry matched the provided path.");
        }
        return Ok(());
    }

    if let Some(removed) =
        try_coverage_ipc_purge_outcasts(session_manager, None, root.clone(), all).await?
    {
        if removed == 0 {
            ui::info("No outcast entries were purged.");
        } else {
            ui::success(&format!(
                "Purged {} outcast entr{} from the local index.",
                removed,
                if removed == 1 { "y" } else { "ies" }
            ));
        }
        return Ok(());
    }

    let client: LocalClient = session_manager.create_client().await?;
    let removed = client
        .coverage_purge_outcasts(None, root, all)
        .await
        .map_err(|err| CliError::coverage(format!("Failed to purge outcast entries: {}", err)))?;

    if removed == 0 {
        ui::info("No outcast entries were purged.");
    } else {
        ui::success(&format!(
            "Purged {} outcast entr{} from the local index.",
            removed,
            if removed == 1 { "y" } else { "ies" }
        ));
    }

    Ok(())
}

async fn handle_coverage_guard(
    root: Option<PathBuf>,
    all: bool,
    yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Coverage Guard");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage guard")
        .await?;

    if !all && root.is_none() {
        return Err(CliError::invalid_input(
            "Use --all or specify --root to run guard.".to_string(),
        ));
    }

    let description = if let Some(path) = root.as_ref() {
        format!(
            "Run guard on {} (migrate wrong-epoch, prune missing, adopt missing-metadata)?",
            path.display()
        )
    } else {
        "Run guard across all enrolled folders (migrate wrong-epoch, prune missing, adopt missing-metadata)?"
            .to_string()
    };

    if !yes && !ui::prompts::confirm_with_default(&description, false)? {
        ui::info("Operation cancelled.");
        return Ok(());
    }

    if let Some(summary) = try_coverage_ipc_guard(session_manager, root.clone(), all).await? {
        ui::info(&format!("Migrated (enqueued): {}", summary.migrated));
        ui::info(&format!("Pruned (missing files): {}", summary.pruned));
        ui::info(&format!("Adopted (missing metadata): {}", summary.adopted));
        ui::info(&format!(
            "Purged (outcast files): {}",
            summary.purged_outcast
        ));
        if !summary.adopt_failures.is_empty() {
            ui::warning("Adoption failures (likely missing metadata):");
            for failure in summary.adopt_failures {
                ui::warning(&format!("  {}", failure));
            }
            ui::info(
                "Tip: run `hybridcipher coverage scan` to refresh metadata, then re-run guard.",
            );
        }
        return Ok(());
    }

    let client: LocalClient = session_manager.create_client().await?;
    let summary = client
        .coverage_guard(root, all)
        .await
        .map_err(|err| CliError::coverage(format!("Coverage guard failed: {}", err)))?;

    ui::info(&format!("Migrated (enqueued): {}", summary.migrated));
    ui::info(&format!("Pruned (missing files): {}", summary.pruned));
    ui::info(&format!("Adopted (missing metadata): {}", summary.adopted));
    ui::info(&format!(
        "Purged (outcast files): {}",
        summary.purged_outcast
    ));
    if !summary.adopt_failures.is_empty() {
        ui::warning("Adoption failures (likely missing metadata):");
        for failure in summary.adopt_failures {
            ui::warning(&format!("  {}", failure));
        }
        ui::info("Tip: run `hybridcipher coverage scan` to refresh metadata, then re-run guard.");
    }

    Ok(())
}

fn guard_folder_enrollment_against_mixed_ciphertexts(
    path: &Path,
    active_group: Uuid,
    active_epoch: u64,
) -> Result<(), CliError> {
    let mut warnings = Vec::new();
    let ciphertext_groups =
        scan_directory_ciphertext_groups(path, TraversalMode::BestEffort, &mut warnings)?;
    for warning in warnings {
        ui::warning(&warning);
    }
    let matching_group = enforce_directory_ciphertext_policy(
        &ciphertext_groups,
        Some(active_group),
        Some(active_epoch),
    )
    .map_err(|err| handle_coverage_ciphertext_error(path, err))?;

    if let Some(group) = matching_group {
        ui::info(&format!(
            "{} already contains {} encrypted file(s) (group {}, epoch {}). They will be tracked but left as-is.",
            path.display(),
            group.files.len(),
            format_group_label(group.group_id),
            group.epoch_id
        ));
    }

    Ok(())
}

fn handle_coverage_ciphertext_error(path: &Path, err: DirectoryCiphertextPolicyError) -> CliError {
    match err {
        DirectoryCiphertextPolicyError::MissingActiveContext => CliError::coverage(
            "Active group or epoch is unknown; select a group and ensure it has an initialized epoch before enrolling coverage.",
        ),
        DirectoryCiphertextPolicyError::Mixed(groups) => {
            ui::warning(&format!(
                "{} contains encrypted files from multiple groups or epochs.",
                path.display()
            ));
            render_enrollment_ciphertext_groups(&groups);
            ui::warning(
                "This folder may belong to a different group or user. Move the encrypted files out before trying again.",
            );
            CliError::coverage(format!(
                "Aborting coverage enrollment for {} due to mixed ciphertext metadata",
                path.display()
            ))
        }
        DirectoryCiphertextPolicyError::ForeignContext {
            offending,
            expected_group,
            expected_epoch,
        } => {
            ui::warning(&format!(
                "{} already contains encrypted file(s) for group {} epoch {}, but your active context is group {} epoch {}.",
                path.display(),
                format_group_label(offending.group_id),
                offending.epoch_id,
                expected_group,
                expected_epoch
            ));
            render_enrollment_ciphertext_groups(&[offending.clone()]);
            ui::warning(
                "This folder may belong to a different group or user. Move the encrypted files out before trying again.",
            );
            CliError::coverage(format!(
                "Aborting coverage enrollment for {} due to conflicting ciphertext metadata",
                path.display()
            ))
        }
    }
}

fn render_enrollment_ciphertext_groups(groups: &[DirectoryCiphertextGroup]) {
    for group in groups {
        ui::warning(&format!(
            "- {} file(s) use group {} epoch {}",
            group.files.len(),
            format_group_label(group.group_id),
            group.epoch_id
        ));
        for sample in group.files.iter().take(3) {
            ui::dim(&format!("    {}", sample.absolute_path.display()));
        }
        if group.files.len() > 3 {
            ui::dim(&format!("    ... {} more", group.files.len() - 3));
        }
    }
}

fn format_group_label(group_id: Option<Uuid>) -> String {
    group_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn describe_root_kind(kind: CoverageRootKind) -> &'static str {
    match kind {
        CoverageRootKind::Folder => "folder",
        CoverageRootKind::SingleFile => "single-file",
    }
}

fn describe_root_state(state: CoverageRootState) -> &'static str {
    match state {
        CoverageRootState::Active => "active",
        CoverageRootState::Unenrolled => "unenrolled",
    }
}

fn describe_file_state(state: &FileCoverageState) -> &'static str {
    match state {
        FileCoverageState::Tracked => "tracked",
        FileCoverageState::Orphaned => "orphaned",
        FileCoverageState::Unmanaged => "unmanaged",
        FileCoverageState::Tombstoned => "tombstoned",
    }
}

fn describe_orphan_tag(kind: Option<&FileOrphanKind>, state: &FileCoverageState) -> &'static str {
    match (kind, state) {
        (Some(FileOrphanKind::WrongEpoch), _) => "[migrate]",
        (Some(FileOrphanKind::MissingFile), _) => "[missing]",
        (Some(FileOrphanKind::MissingMetadata), _) => "[adopt]",
        (Some(FileOrphanKind::Outcast), _) => "[outcast]",
        (None, FileCoverageState::Unmanaged) => "[encrypt]",
        _ => "[orphaned]",
    }
}

fn format_orphan_kind(kind: &Option<FileOrphanKind>) -> &'static str {
    match kind {
        Some(FileOrphanKind::WrongEpoch) => "wrong_epoch",
        Some(FileOrphanKind::MissingFile) => "missing_file",
        Some(FileOrphanKind::MissingMetadata) => "missing_metadata",
        Some(FileOrphanKind::Outcast) => "outcast",
        None => "-",
    }
}

fn write_scan_log(
    active_user: &ActiveUserSummary,
    group_id: Uuid,
    root_filter: &Option<PathBuf>,
    summary: &CoverageScanSummary,
    records: &[CoverageFileRecord],
) -> Result<PathBuf, CliError> {
    let home = dirs::home_dir().ok_or_else(|| {
        CliError::coverage("Failed to resolve home directory for scan log output.")
    })?;

    let log_dir = home
        .join(".hybridcipher")
        .join("users")
        .join(&active_user.user_id)
        .join("logs")
        .join("coverage_logs")
        .join(group_id.to_string())
        .join("scan_logs");

    stdfs::create_dir_all(&log_dir).map_err(|err| {
        CliError::coverage(format!(
            "Failed to create scan log directory {}: {}",
            log_dir.display(),
            err
        ))
    })?;

    let now = Utc::now();
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let display_timestamp = ui::formatting::format_local_datetime(&now);
    let log_path = log_dir.join(format!("scan-{}.txt", timestamp));
    let mut file = stdfs::File::create(&log_path).map_err(|err| {
        CliError::coverage(format!(
            "Failed to create scan log file {}: {}",
            log_path.display(),
            err
        ))
    })?;

    let mut write_line = |args: fmt::Arguments<'_>| -> Result<(), CliError> {
        file.write_fmt(args)
            .map_err(|err| CliError::coverage(format!("Failed to write scan log: {}", err)))
    };

    write_line(format_args!("HybridCipher Coverage Scan Report\n"))?;
    write_line(format_args!("Timestamp: {}\n", display_timestamp))?;
    write_line(format_args!(
        "User: {} (id: {})\n",
        active_user.username, active_user.user_id
    ))?;
    write_line(format_args!("Server: {}\n", active_user.server_url))?;
    match root_filter {
        Some(path) => write_line(format_args!("Scope: {}\n", path.display()))?,
        None => write_line(format_args!("Scope: all enrolled roots\n"))?,
    }
    write_line(format_args!("Roots scanned: {}\n", summary.roots_scanned))?;
    write_line(format_args!("Files indexed: {}\n", summary.files_indexed))?;
    write_line(format_args!("Orphaned files: {}\n", summary.orphaned_files))?;
    write_line(format_args!(
        "Unmanaged files: {}\n",
        summary.unmanaged_files
    ))?;
    if summary.missing_roots.is_empty() {
        write_line(format_args!("Missing roots: none\n"))?;
    } else {
        write_line(format_args!("Missing roots:\n"))?;
        for missing in &summary.missing_roots {
            write_line(format_args!("  - {}\n", missing.display()))?;
        }
    }
    write_line(format_args!("\n"))?;
    write_line(format_args!(
        "STATE      ORPHAN          SIZE(B)   LAST_EPOCH   LAST_SEEN                 FILE_UUID                              ROOT                           RELATIVE_PATH\n"
    ))?;
    write_line(format_args!(
        "---------------------------------------------------------------------------------------------------------------------------------------------------------------------\n"
    ))?;

    for record in records {
        let state = describe_file_state(&record.entry.state);
        let orphan = format_orphan_kind(&record.entry.orphan_kind);
        let size = record.entry.size;
        let last_epoch = record.entry.last_epoch;
        let last_seen = ui::formatting::format_local_datetime(&record.entry.last_seen);
        let uuid = record.entry.file_uuid;
        let root_path = record.root.path.display();
        let relative = &record.entry.relative_path;

        write_line(format_args!(
            "{:<10} {:<14} {:<8} {:<11} {:<23} {:<36} {:<30} {}\n",
            state, orphan, size, last_epoch, last_seen, uuid, root_path, relative
        ))?;
    }

    Ok(log_path)
}

async fn canonicalize_cli_path(path: PathBuf) -> Result<PathBuf, CliError> {
    let display = path.display().to_string();
    let canonical = std::fs::canonicalize(&path).map_err(|err| {
        CliError::coverage(format!("Path '{}' cannot be resolved: {}", display, err))
    })?;

    Ok(canonical)
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

/// Handle coverage audit command
async fn handle_coverage_audit(
    verbose: bool,
    format: String,
    verify_proofs: bool,
    proof_sample: Option<usize>,
    verify_all_proofs: bool,
    skip_transparency: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Coverage Audit");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage audit")
        .await?;
    ui::info("Performing comprehensive cryptographic coverage audit...");

    if let Some(summary) = session_manager.active_user_summary() {
        ui::info(&format!(
            "Authenticated as {} on {}",
            summary.username, summary.server_url
        ));
    }

    // Simulate comprehensive audit operation
    let audit_results = perform_coverage_audit(
        verify_proofs,
        proof_sample,
        verify_all_proofs,
        skip_transparency,
        verbose,
        session_manager,
    )
    .await?;

    // Display audit results based on format
    match format.as_str() {
        "json" => display_audit_results_json(&audit_results)?,
        "table" => display_audit_results_table(&audit_results, verbose)?,
        "summary" => display_audit_results_summary(&audit_results)?,
        _ => {
            return Err(CliError::invalid_input(format!(
                "Unsupported format: {}",
                format
            )))
        }
    }

    // Show warnings for any issues detected
    if !audit_results.byzantine_faults_detected.is_empty() {
        ui::subsection("⚠️  Byzantine Faults Detected");
        for fault in &audit_results.byzantine_faults_detected {
            ui::warning(fault);
        }
        ui::warning("Please investigate these faults and consider running repair operations");
    }

    // Verify integrity and provide security assessment
    display_security_assessment(&audit_results)?;

    // Show next steps if there are issues
    if !audit_results.log_integrity_valid
        || !audit_results.merkle_root_valid
        || matches!(
            audit_results.transparency_status,
            TransparencyVerificationStatus::Failed | TransparencyVerificationStatus::Unavailable
        )
    {
        ui::subsection("🔧 Recommended Actions");
        if !audit_results.log_integrity_valid {
            ui::info("• Run coverage log repair: hybridcipher coverage repair --log");
        }
        if !audit_results.merkle_root_valid {
            ui::info("• Verify Merkle tree consistency: hybridcipher coverage verify --merkle");
        }
        match audit_results.transparency_status {
            TransparencyVerificationStatus::Failed => {
                ui::info("• Check transparency log connectivity and trusted signing keys");
            }
            TransparencyVerificationStatus::Unavailable => {
                ui::info("• Configure transparency log URL and trusted signing keys");
            }
            _ => {}
        }
        ui::info("• Consider running full system verification: hybridcipher coverage audit --verify-proofs --verify-all-proofs");
    }

    Ok(())
}

/// Perform comprehensive coverage audit
async fn perform_coverage_audit(
    verify_proofs: bool,
    proof_sample: Option<usize>,
    verify_all_proofs: bool,
    skip_transparency: bool,
    verbose: bool,
    session_manager: &SessionManager,
) -> Result<CoverageAuditResults, CliError> {
    ui::info("Fetching server-side coverage snapshot...");
    let mut transparency_info = None;
    if (verify_proofs && !skip_transparency) || verbose {
        if let Some(summary) = session_manager.active_user_summary() {
            match session_manager
                .fetch_server_transparency_info(&summary.server_url)
                .await
            {
                Ok(info) => {
                    transparency_info = Some(info);
                }
                Err(err) => {
                    if verbose {
                        ui::warning(&format!("Transparency log details unavailable: {}", err));
                    }
                }
            }
        }
    }

    if let Some(info) = &transparency_info {
        let mut transparency_config = session_manager.transparency_config();
        if transparency_config.log_server_url.is_none() {
            if let Some(url) = info.log_url.clone() {
                transparency_config.log_server_url = Some(url);
                // Enable transparency verification when we discover the log URL
                // (unless explicitly disabled via config)
                if !transparency_config.enabled {
                    transparency_config.enabled = true;
                }
                session_manager.set_transparency_config(transparency_config)?;
            }
        }
    }

    let mut local_client: Option<LocalClient> = None;
    let (snapshot, root_stats, pending_files, migration, current_epoch, used_ipc) =
        if let Some(snapshot) = try_coverage_ipc_snapshot_artifact(session_manager).await? {
            let root_stats = try_coverage_ipc_root_stats(session_manager)
                .await?
                .ok_or_else(|| {
                    CliError::coverage("Coverage IPC failed to load root stats after snapshot.")
                })?;
            let pending_files = try_coverage_ipc_pending_files(session_manager)
                .await?
                .ok_or_else(|| {
                    CliError::coverage("Coverage IPC failed to load pending files after snapshot.")
                })?;
            let migration = match try_coverage_ipc_migration_snapshot(session_manager).await? {
                Some(snapshot) => snapshot,
                None => None,
            };
            let current_epoch = match try_coverage_ipc_current_epoch(session_manager).await? {
                Some(epoch) => epoch,
                None => None,
            };

            (
                snapshot,
                root_stats,
                pending_files,
                migration,
                current_epoch,
                true,
            )
        } else {
            let client: LocalClient = session_manager.create_client().await?;
            let snapshot = client
                .download_coverage_snapshot_artifact()
                .await
                .map_err(|err| {
                    CliError::coverage(format!("Failed to download snapshot: {}", err))
                })?;

            let root_stats = client
                .coverage_root_stats()
                .await
                .map_err(|err| CliError::coverage(format!("Failed to load root stats: {}", err)))?;

            let pending_files = client.pending_coverage_files().await.map_err(|err| {
                CliError::coverage(format!("Failed to enumerate pending files: {}", err))
            })?;

            let migration = client.migration_snapshot().await;
            let current_epoch = Some(client.current_epoch().await);
            local_client = Some(client);

            (
                snapshot,
                root_stats,
                pending_files,
                migration,
                current_epoch,
                false,
            )
        };

    if used_ipc && verify_proofs && !skip_transparency {
        let mut effective_config = session_manager.transparency_config();
        if let Some(ipc_config) = try_coverage_ipc_transparency_config(session_manager).await? {
            if effective_config.log_server_url.is_none() {
                effective_config.log_server_url = ipc_config.log_server_url;
            }
            if effective_config.trusted_signing_keys.is_empty() {
                effective_config.trusted_signing_keys = ipc_config.trusted_signing_keys;
            }
        }
        set_transparency_config(effective_config);
    }

    let latest_epoch = snapshot
        .entries
        .iter()
        .map(|entry| entry.epoch_number)
        .max()
        .or(current_epoch)
        .unwrap_or(0);
    let target_epoch = migration
        .as_ref()
        .map(|m| m.to_epoch)
        .or(current_epoch)
        .unwrap_or(latest_epoch);

    let verification =
        verify_snapshot_integrity(&snapshot, verify_proofs, proof_sample, verify_all_proofs)?;
    let mut transparency_status = TransparencyVerificationStatus::Skipped;
    let mut transparency_error = None;
    let mut transparency_metadata = snapshot.transparency_metadata.clone();

    if verify_proofs && !skip_transparency {
        let handles = if used_ipc {
            try_build_transparency_handles(Arc::new(MockNetwork::new()))
        } else {
            local_client
                .as_ref()
                .and_then(|client| try_build_transparency_handles(client.network()))
        };

        if let Some(handles) = handles {
            match verify_transparency_inclusion(
                &snapshot,
                &verification.computed_root,
                latest_epoch,
                handles.verifier.as_ref(),
            )
            .await
            {
                Ok(metadata) => {
                    transparency_status = TransparencyVerificationStatus::Verified;
                    transparency_metadata = Some(metadata);
                }
                Err(err) => {
                    transparency_status = TransparencyVerificationStatus::Failed;
                    transparency_error = Some(err.to_string());
                }
            };
        } else {
            transparency_status = TransparencyVerificationStatus::Unavailable;
            transparency_error = Some(
                "Transparency verification disabled or missing log URL/trusted keys".to_string(),
            );
        }
    }

    let total_files = snapshot.total_files;
    let entries_total = snapshot.entries.len() as u64;
    let covered_files = if total_files == 0 {
        0
    } else {
        snapshot
            .entries
            .iter()
            .filter(|entry| entry.epoch_number >= target_epoch)
            .count() as u64
    };

    let coverage_percentage = if total_files == 0 {
        100.0
    } else {
        (covered_files as f64 / total_files as f64) * 100.0
    };

    let mut epoch_stats = HashMap::new();
    for entry in &snapshot.entries {
        let stats = epoch_stats
            .entry(entry.epoch_number)
            .or_insert_with(|| EpochCoverageStats {
                epoch_id: entry.epoch_number,
                file_count: 0,
                coverage_percentage: 0.0,
                merkle_root: verification.computed_root_hex.clone(),
                verified: false,
            });
        stats.file_count = stats.file_count.saturating_add(1);
    }

    for stats in epoch_stats.values_mut() {
        stats.coverage_percentage = if total_files == 0 {
            0.0
        } else {
            (stats.file_count as f64 / total_files as f64) * 100.0
        };
        stats.verified = verification.log_integrity_valid;
    }

    let mut byzantine_faults = verification.anomalies;
    if entries_total != total_files {
        byzantine_faults.push(format!(
            "Coverage snapshot entries incomplete (got {}, expected {})",
            entries_total, total_files
        ));
    }
    if verify_proofs && !skip_transparency {
        match transparency_status {
            TransparencyVerificationStatus::Failed => {
                byzantine_faults.push("Transparency log verification failed".to_string());
            }
            TransparencyVerificationStatus::Unavailable => {
                byzantine_faults.push("Transparency log verification unavailable".to_string());
            }
            _ => {}
        }
    }

    Ok(CoverageAuditResults {
        total_files,
        covered_files,
        coverage_percentage,
        log_integrity_valid: verification.log_integrity_valid,
        merkle_root_valid: verification.merkle_root_valid,
        pending_files: pending_files.len() as u64,
        epoch_stats,
        audit_timestamp: Utc::now(),
        byzantine_faults_detected: byzantine_faults,
        per_root_stats: root_stats,
        merkle_root_hex: verification.computed_root_hex,
        proofs_checked: verification.proofs_checked,
        proofs_total: verification.proofs_total,
        transparency_status,
        transparency_log_url: transparency_info.and_then(|info| info.log_url),
        transparency_metadata,
        transparency_error,
    })
}

struct SnapshotVerificationOutcome {
    computed_root: [u8; 32],
    computed_root_hex: String,
    log_integrity_valid: bool,
    merkle_root_valid: bool,
    anomalies: Vec<String>,
    proofs_checked: u64,
    proofs_total: u64,
}

const DEFAULT_PROOF_SAMPLE: usize = 100;

fn verify_snapshot_integrity(
    snapshot: &CoverageSnapshotArtifact,
    verify_proofs: bool,
    proof_sample: Option<usize>,
    verify_all_proofs: bool,
) -> Result<SnapshotVerificationOutcome, CliError> {
    if snapshot.entries.is_empty() {
        return Err(CliError::coverage(
            "Coverage snapshot does not contain any file entries",
        ));
    }

    let (ordered_entries, mut tree) = ordered_snapshot_entries(&snapshot.entries);
    let computed_root = tree
        .root()
        .map_err(|err| CliError::coverage(format!("Failed to compute Merkle root: {}", err)))?;
    let computed_root_hex = hex::encode(computed_root);

    let merkle_root_valid = computed_root == snapshot.merkle_root;

    let verifying_key = VerifyingKey::from_bytes(&snapshot.verifying_key)
        .map_err(|err| CliError::coverage(format!("Invalid coverage verifying key: {}", err)))?;
    let signature = CoverageSignature::from_bytes(&snapshot.signature).map_err(|err| {
        CliError::coverage(format!("Invalid coverage snapshot signature: {}", err))
    })?;
    let log_integrity_valid =
        signatures::verify(&verifying_key, &computed_root, &signature).is_ok();

    let mut anomalies = Vec::new();
    if !merkle_root_valid {
        anomalies.push("Computed Merkle root does not match server snapshot".to_string());
    }
    if !log_integrity_valid {
        anomalies.push("Snapshot signature verification failed".to_string());
    }

    let mut proofs_checked = 0u64;
    let mut proofs_total = 0u64;

    if verify_proofs && merkle_root_valid {
        proofs_total = ordered_entries.len() as u64;
        let indices: Vec<usize> = if verify_all_proofs {
            (0..ordered_entries.len()).collect()
        } else if let Some(sample_size) = proof_sample {
            if sample_size == 0 || sample_size >= ordered_entries.len() {
                (0..ordered_entries.len()).collect()
            } else {
                let mut rng = rand::thread_rng();
                rand::seq::index::sample(&mut rng, ordered_entries.len(), sample_size).into_vec()
            }
        } else {
            let sample_size = DEFAULT_PROOF_SAMPLE.min(ordered_entries.len());
            let mut rng = rand::thread_rng();
            rand::seq::index::sample(&mut rng, ordered_entries.len(), sample_size).into_vec()
        };

        for index in indices {
            let (file_id, epoch) = &ordered_entries[index];
            let proof = tree.generate_proof(index).map_err(|err| {
                CliError::coverage(format!(
                    "Failed to generate Merkle proof for {}: {}",
                    file_id, err
                ))
            })?;
            let leaf = format!("{file_id}:{epoch}");
            let valid = proof
                .verify(&computed_root, leaf.as_bytes())
                .map_err(|err| {
                    CliError::coverage(format!(
                        "Failed to verify Merkle proof for {}: {}",
                        file_id, err
                    ))
                })?;
            if !valid {
                anomalies.push(format!("Merkle proof invalid for {}", file_id));
                break;
            }
            proofs_checked += 1;
        }
    }

    Ok(SnapshotVerificationOutcome {
        computed_root,
        computed_root_hex,
        log_integrity_valid,
        merkle_root_valid,
        anomalies,
        proofs_checked,
        proofs_total,
    })
}

async fn verify_transparency_inclusion(
    snapshot: &CoverageSnapshotArtifact,
    computed_root: &[u8; 32],
    latest_epoch: u64,
    verifier: &dyn CoverageTransparencyVerifier,
) -> Result<CoverageTransparencyMetadata, CliError> {
    let record = verifier
        .fetch_inclusion_proof(computed_root)
        .await
        .map_err(|err| CliError::coverage(format!("Transparency verification failed: {}", err)))?;

    let proof = &record.proof;
    let proof_valid = proof.verify().map_err(|err| {
        CliError::coverage(format!(
            "Transparency inclusion verification failed: {}",
            err
        ))
    })?;
    if !proof_valid {
        return Err(CliError::coverage(
            "Transparency inclusion proof invalid".to_string(),
        ));
    }

    if proof.entry.join_card_hash != *computed_root {
        return Err(CliError::coverage(
            "Transparency entry does not match coverage Merkle root".to_string(),
        ));
    }

    match &proof.entry.operation {
        TransparencyOperation::CoverageSnapshot {
            merkle_root,
            epoch_id,
            file_count,
            signing_key_id,
            verifying_key,
        } => {
            if merkle_root != computed_root {
                return Err(CliError::coverage(
                    "Transparency snapshot Merkle root mismatch".to_string(),
                ));
            }
            if *file_count != snapshot.total_files {
                return Err(CliError::coverage(format!(
                    "Transparency snapshot file count mismatch: expected {}, got {}",
                    snapshot.total_files, file_count
                )));
            }
            if *epoch_id != latest_epoch {
                return Err(CliError::coverage(format!(
                    "Transparency snapshot epoch mismatch: expected {}, got {}",
                    latest_epoch, epoch_id
                )));
            }
            if verifying_key != &snapshot.verifying_key {
                return Err(CliError::coverage(
                    "Transparency snapshot verifying key mismatch".to_string(),
                ));
            }
            match (&snapshot.signing_key_id, signing_key_id) {
                (Some(expected), Some(recorded)) if expected == recorded => {}
                (Some(expected), Some(recorded)) => {
                    return Err(CliError::coverage(format!(
                        "Transparency snapshot signing key mismatch: expected {}, got {}",
                        expected, recorded
                    )))
                }
                (Some(expected), None) => {
                    return Err(CliError::coverage(format!(
                        "Transparency snapshot missing signing key identifier (expected {})",
                        expected
                    )))
                }
                (None, Some(recorded)) => {
                    return Err(CliError::coverage(format!(
                        "Transparency snapshot unexpectedly contains signing key identifier {}",
                        recorded
                    )))
                }
                (None, None) => {}
            }
        }
        other => {
            return Err(CliError::coverage(format!(
                "Transparency entry operation mismatch: expected coverage snapshot, got {:?}",
                other
            )));
        }
    }

    Ok(CoverageTransparencyMetadata::from_record(&record))
}

/// Display audit results in table format
fn display_audit_results_table(
    results: &CoverageAuditResults,
    verbose: bool,
) -> Result<(), CliError> {
    ui::subsection("📊 Coverage Audit Results");

    // Overall statistics
    ui::info(&format!("📁 Total Files: {}", results.total_files));
    ui::info(&format!(
        "✅ Covered Files: {} ({:.1}%)",
        results.covered_files, results.coverage_percentage
    ));
    ui::info(&format!("⏳ Pending Files: {}", results.pending_files));
    ui::info(&format!("🌳 Merkle Root: {}", results.merkle_root_hex));

    // Integrity status
    ui::subsection("🔐 Cryptographic Integrity");
    let log_status = if results.log_integrity_valid {
        "✅ Valid"
    } else {
        "❌ Invalid"
    };
    let merkle_status = if results.merkle_root_valid {
        "✅ Valid"
    } else {
        "❌ Invalid"
    };
    let transparency_status = match results.transparency_status {
        TransparencyVerificationStatus::Verified => "✅ Verified",
        TransparencyVerificationStatus::Failed => "❌ Failed",
        TransparencyVerificationStatus::Unavailable => "⚠️  Unavailable",
        TransparencyVerificationStatus::Skipped => "⚠️  Skipped",
    };

    ui::info(&format!("📋 Coverage Log: {}", log_status));
    ui::info(&format!("🪵 Merkle Signature: {}", merkle_status));
    ui::info(&format!("🧾 Transparency Log: {}", transparency_status));
    if results.proofs_total > 0 {
        ui::info(&format!(
            "🧪 Proofs Checked: {}/{}",
            results.proofs_checked, results.proofs_total
        ));
    }

    if verbose {
        if let Some(url) = results.transparency_log_url.as_ref() {
            ui::dim(&format!("  Log URL: {}", url));
        }
        if let Some(metadata) = results.transparency_metadata.as_ref() {
            ui::dim(&format!(
                "  Transparency metadata: sequence={} log_size={} leaf_index={} timestamp={}",
                metadata.sequence_number,
                metadata.log_size,
                metadata.leaf_index,
                metadata.entry_timestamp
            ));
        }
        if let Some(error) = results.transparency_error.as_ref() {
            ui::warning(&format!("  Transparency verification error: {}", error));
        }
    }

    // Epoch-by-epoch breakdown
    if verbose && !results.epoch_stats.is_empty() {
        ui::subsection("📈 Epoch Statistics");
        for (epoch_id, stats) in &results.epoch_stats {
            ui::info(&format!(
                "Epoch {}: {} files ({:.1}% coverage) - {}",
                epoch_id,
                stats.file_count,
                stats.coverage_percentage,
                if stats.verified {
                    "✅ Verified"
                } else {
                    "❌ Unverified"
                }
            ));
            ui::dim(&format!("  Merkle Root: {}", stats.merkle_root));
        }
    }

    if verbose && !results.per_root_stats.is_empty() {
        ui::subsection("📁 Root KPIs");
        let mut roots = results.per_root_stats.clone();
        roots.sort_by(|a, b| {
            a.coverage_ratio
                .partial_cmp(&b.coverage_ratio)
                .unwrap_or(Ordering::Equal)
        });
        for root in roots.iter().take(5) {
            let coverage_pct = (root.coverage_ratio * 100.0).clamp(0.0, 100.0);
            ui::info(&format!(
                "{} – {:.1}% covered (tracked: {}, orphaned: {}, unmanaged: {})",
                root.root.path.display(),
                coverage_pct,
                root.tracked_files,
                root.orphaned_files,
                root.unmanaged_files
            ));
        }
    }

    // Audit metadata
    ui::subsection("ℹ️  Audit Information");
    ui::info(&format!(
        "🕒 Audit Time: {}",
        ui::formatting::format_local_and_utc(&results.audit_timestamp)
    ));

    Ok(())
}

/// Display audit results in JSON format
fn display_audit_results_json(results: &CoverageAuditResults) -> Result<(), CliError> {
    let json_output = serde_json::to_string_pretty(results)
        .map_err(|e| CliError::internal(format!("Failed to serialize audit results: {}", e)))?;

    println!("{}", json_output);
    Ok(())
}

/// Display audit results in summary format
fn display_audit_results_summary(results: &CoverageAuditResults) -> Result<(), CliError> {
    ui::subsection("📋 Coverage Audit Summary");

    // High-level status
    let overall_status = if results.log_integrity_valid && results.merkle_root_valid {
        "✅ PASS"
    } else {
        "❌ FAIL"
    };

    ui::highlight(&format!("Overall Status: {}", overall_status));
    ui::info(&format!(
        "Coverage: {:.1}% ({}/{})",
        results.coverage_percentage, results.covered_files, results.total_files
    ));
    ui::info(&format!("Merkle Root: {}", results.merkle_root_hex));
    if results.proofs_total > 0 {
        ui::info(&format!(
            "Proofs Checked: {}/{}",
            results.proofs_checked, results.proofs_total
        ));
    }
    ui::info(&format!(
        "Transparency: {}",
        match results.transparency_status {
            TransparencyVerificationStatus::Verified => "verified",
            TransparencyVerificationStatus::Failed => "failed",
            TransparencyVerificationStatus::Unavailable => "unavailable",
            TransparencyVerificationStatus::Skipped => "skipped",
        }
    ));

    if let Some(worst_root) = results.per_root_stats.iter().min_by(|a, b| {
        a.coverage_ratio
            .partial_cmp(&b.coverage_ratio)
            .unwrap_or(Ordering::Equal)
    }) {
        let coverage_pct = worst_root.coverage_ratio * 100.0;
        ui::info(&format!(
            "Lowest-performing root: {} ({:.1}% covered)",
            worst_root.root.path.display(),
            coverage_pct
        ));
    }

    if results.pending_files > 0 {
        ui::warning(&format!(
            "⚠️  {} files pending migration",
            results.pending_files
        ));
    }

    Ok(())
}

/// Display security assessment based on audit results
fn display_security_assessment(results: &CoverageAuditResults) -> Result<(), CliError> {
    ui::subsection("🔒 Security Assessment");

    let mut security_score = 100;
    let mut issues: Vec<String> = Vec::new();

    if !results.log_integrity_valid {
        security_score -= 30;
        issues.push("Coverage log integrity compromised".to_string());
    }

    if !results.merkle_root_valid {
        security_score -= 25;
        issues.push("Merkle tree verification failed".to_string());
    }

    match results.transparency_status {
        TransparencyVerificationStatus::Failed => {
            security_score -= 20;
            issues.push("Transparency log verification failed".to_string());
        }
        TransparencyVerificationStatus::Unavailable => {
            security_score -= 10;
            issues.push("Transparency log verification unavailable".to_string());
        }
        _ => {}
    }

    if results.coverage_percentage < 100.0 {
        security_score -= ((100.0 - results.coverage_percentage) * 0.2) as i32;
        issues.push("Incomplete file coverage detected".to_string());
    }

    if !results.byzantine_faults_detected.is_empty() {
        security_score -= 15;
        issues.push("Byzantine faults detected in coverage system".to_string());
    }

    if results.pending_files > 0 {
        security_score -= 5;
        issues.push("Pending files still queued for migration".to_string());
    }

    if let Some(worst_root) = results.per_root_stats.iter().min_by(|a, b| {
        a.coverage_ratio
            .partial_cmp(&b.coverage_ratio)
            .unwrap_or(Ordering::Equal)
    }) {
        if worst_root.coverage_ratio < 0.95 {
            issues.push(format!(
                "Root {} below target coverage ({:.1}%)",
                worst_root.root.path.display(),
                worst_root.coverage_ratio * 100.0
            ));
            security_score -= 10;
        }
    }

    // Display security score with color coding
    let score_color = if security_score >= 95 {
        "green"
    } else if security_score >= 80 {
        "yellow"
    } else {
        "red"
    };

    match score_color {
        "green" => ui::success(&format!(
            "Security Score: {}/100 - Excellent",
            security_score
        )),
        "yellow" => ui::warning(&format!("Security Score: {}/100 - Good", security_score)),
        "red" => ui::error(&format!(
            "Security Score: {}/100 - Requires Attention",
            security_score
        )),
        _ => unreachable!(),
    }

    if !issues.is_empty() {
        ui::subsection("⚠️  Security Issues Detected");
        for issue in issues {
            ui::warning(&format!("• {}", issue));
        }
    } else {
        ui::success("No security issues detected - system integrity verified");
    }

    Ok(())
}

/// Handle coverage pending command
async fn handle_coverage_pending(
    verbose: bool,
    epoch: Option<u64>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Pending Coverage Files");

    // Get migration info for context
    let migration_info = session_manager.migration_info();

    // Determine context based on migration state
    match migration_info {
        Some(ref info) if info.phase.is_active() => {
            ui::info(&format!(
                "🔄 Active migration from epoch {} to epoch {}",
                info.current_epoch,
                info.target_epoch.unwrap_or(info.current_epoch + 1)
            ));
        }
        _ => {
            ui::info("📊 Analyzing pending files across all epochs");
        }
    }

    // Fetch pending files information
    let pending_files = get_pending_files_info(epoch, session_manager).await?;

    if pending_files.is_empty() {
        ui::success("✅ No pending files found - all files have valid coverage");
        return Ok(());
    }

    // Display summary statistics
    display_pending_files_summary(&pending_files, epoch, migration_info.as_ref())?;

    // Display detailed file information if requested
    if verbose {
        display_pending_files_detailed(&pending_files)?;
    } else {
        display_pending_files_compact(&pending_files)?;
    }

    // Show recommendations for handling pending files
    display_pending_files_recommendations(&pending_files, migration_info.as_ref())?;

    Ok(())
}

async fn handle_coverage_recover_markers(
    mut search: Vec<PathBuf>,
    max_depth: usize,
    all: bool,
    yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Recover Coverage Roots From Markers");
    let active_group = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(active_group, "hybridcipher coverage recover-markers")
        .await?;

    if max_depth == 0 {
        return Err(CliError::invalid_input(
            "--max-depth must be greater than zero".to_string(),
        ));
    }

    if search.is_empty() {
        if let Some(home) = dirs::home_dir() {
            search.push(home);
        }
        if let Some(doc) = dirs::document_dir() {
            search.push(doc);
        }
        if let Some(desktop) = dirs::desktop_dir() {
            search.push(desktop);
        }
    }

    if !yes {
        if all {
            ui::info(
                "This scans for `.hybridcipher-root-*.json` marker files and lists matches for all groups. Only active-group markers are auto-enrolled.",
            );
        } else {
            ui::info(
                "This scans for `.hybridcipher-root-*.json` marker files and auto-enrolls matches for the active group.",
            );
        }
        ui::info(&format!(
            "Search roots: {} (max depth {})",
            search
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            max_depth
        ));
        if !ui::prompts::confirm_with_default("Proceed with marker-based recovery?", false)? {
            ui::info("Operation cancelled.");
            return Ok(());
        }
    }

    let result = if let Some(result) =
        try_coverage_ipc_recover_markers(session_manager, search.clone(), max_depth, true).await?
    {
        result
    } else {
        let client: LocalClient = session_manager.create_client().await?;
        client
            .coverage_recover_from_markers(search.clone(), max_depth, true)
            .await
            .map_err(|err| CliError::coverage(format!("Marker recovery failed: {}", err)))?
    };

    if all {
        ui::info(&format!(
            "Markers scanned: {}, eligible: {}, already enrolled: {}, mismatched group: {}",
            result.scanned, result.eligible, result.already_enrolled, result.group_mismatch
        ));
    } else {
        ui::info(&format!(
            "Markers scanned: {}, eligible: {}, already enrolled: {}",
            result.scanned, result.eligible, result.already_enrolled
        ));
    }

    // Show already enrolled details
    if !result.already_enrolled_markers.is_empty() {
        ui::section("Already Enrolled");
        for marker in &result.already_enrolled_markers {
            ui::info(&format!(
                "  {} - {} (root_id: {})",
                describe_root_kind(marker.kind),
                marker.root_path.display(),
                marker.root_id
            ));
            ui::dim(&format!("    marker: {}", marker.marker_path.display()));
        }
    }

    // Show group mismatch details
    if all && !result.group_mismatch_markers.is_empty() {
        ui::section("Group Mismatch");
        for marker in &result.group_mismatch_markers {
            ui::warning(&format!(
                "  {} - {} (root_id: {})",
                describe_root_kind(marker.kind),
                marker.root_path.display(),
                marker.root_id
            ));
            ui::dim(&format!("    marker: {}", marker.marker_path.display()));
        }
    }

    // Show eligible but not enrolled (if any)
    if !result.eligible_markers.is_empty() {
        ui::section("Eligible for Enrollment");
        for marker in &result.eligible_markers {
            ui::info(&format!(
                "  {} - {} (root_id: {})",
                describe_root_kind(marker.kind),
                marker.root_path.display(),
                marker.root_id
            ));
            ui::dim(&format!("    marker: {}", marker.marker_path.display()));
        }
    }

    if !result.enrolled.is_empty() {
        ui::success("Newly Enrolled Roots:");
        for path in &result.enrolled {
            ui::info(&format!("  - {}", path.display()));
        }
    } else {
        ui::info("No new roots enrolled from markers.");
    }

    if !result.missing_paths.is_empty() {
        ui::warning("Markers found but paths missing on disk:");
        for missing in &result.missing_paths {
            ui::warning(&format!("  - {}", missing.display()));
        }
    }

    Ok(())
}

/// Get pending files information
async fn get_pending_files_info(
    epoch_filter: Option<u64>,
    session_manager: &SessionManager,
) -> Result<Vec<PendingFileInfo>, CliError> {
    ui::info("🔍 Scanning for pending coverage files...");
    let mut pending = if let Some(pending) = try_coverage_ipc_pending_files(session_manager).await?
    {
        pending
    } else {
        let client = session_manager.create_client().await?;
        client.pending_coverage_files().await?
    };

    if let Some(filter) = epoch_filter {
        pending.retain(|entry| entry.target_epoch == filter || entry.current_epoch == filter);
    }

    let mut pending_files = Vec::with_capacity(pending.len());

    for entry in pending {
        pending_files.push(PendingFileInfo {
            file_path: entry.path,
            current_epoch: entry.current_epoch,
            target_epoch: entry.target_epoch,
            migration_progress: 0.0,
            last_updated: entry.last_modified,
            file_size: entry.file_size,
            attempts: entry.attempts,
            last_attempt: entry.last_attempt,
        });
    }

    pending_files.sort_by(|a, b| a.file_path.cmp(&b.file_path));

    Ok(pending_files)
}

/// Display summary statistics for pending files
fn display_pending_files_summary(
    pending_files: &[PendingFileInfo],
    epoch_filter: Option<u64>,
    migration_info: Option<&crate::session::MigrationInfo>,
) -> Result<(), CliError> {
    ui::subsection("📊 Summary Statistics");

    let total_files = pending_files.len();
    let total_size: u64 = pending_files.iter().map(|f| f.file_size).sum();

    // Calculate actual migration progress: (total - pending) / total
    let avg_progress: f64 = if let Some(info) = migration_info {
        if info.phase.is_active() && info.total_files > 0 {
            let migrated = info.total_files.saturating_sub(pending_files.len() as u64);
            migrated as f64 / info.total_files as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    ui::info(&format!("📁 Total Pending Files: {}", total_files));
    ui::info(&format!(
        "💾 Total Size: {}",
        ui::formatting::format_file_size(total_size)
    ));
    ui::info(&format!(
        "📈 Average Progress: {:.1}%",
        avg_progress * 100.0
    ));

    if let Some(epoch) = epoch_filter {
        ui::info(&format!("🎯 Filtered by Epoch: {}", epoch));
    }

    // Group by epochs
    let mut epoch_counts = std::collections::HashMap::new();
    for file in pending_files {
        let transition = format!("{} → {}", file.current_epoch, file.target_epoch);
        *epoch_counts.entry(transition).or_insert(0) += 1;
    }

    if epoch_counts.len() > 1 {
        ui::subsection("🔄 Migration Transitions");
        for (transition, count) in epoch_counts {
            ui::info(&format!("{}: {} files", transition, count));
        }
    }

    Ok(())
}

/// Display detailed pending files information
fn display_pending_files_detailed(pending_files: &[PendingFileInfo]) -> Result<(), CliError> {
    ui::subsection("📋 Detailed File Information");

    for (i, file) in pending_files.iter().enumerate() {
        ui::info(&format!("{}. {}", i + 1, file.file_path));
        ui::dim(&format!(
            "   Size: {}",
            ui::formatting::format_file_size(file.file_size)
        ));
        ui::dim(&format!(
            "   Migration: Epoch {} → {}",
            file.current_epoch, file.target_epoch
        ));
        ui::dim(&format!(
            "   Progress: {:.1}%",
            file.migration_progress * 100.0
        ));
        ui::dim(&format!(
            "   Last Updated: {}",
            ui::formatting::format_local_datetime(&file.last_updated)
        ));
        if file.attempts > 0 {
            let last_attempt = file
                .last_attempt
                .map(|ts| ui::formatting::format_local_datetime(&ts))
                .unwrap_or_else(|| "unknown".to_string());
            ui::dim(&format!(
                "   Rewrap attempts: {} (last {})",
                file.attempts, last_attempt
            ));
        } else {
            ui::dim("   Rewrap attempts: none recorded");
        }

        // Show progress bar for migration
        ui::progress::display::display_migration_status(
            file.current_epoch,
            file.target_epoch,
            file.migration_progress,
        );
        println!();

        if i < pending_files.len() - 1 {
            println!(); // Add spacing between files
        }
    }

    Ok(())
}

/// Display compact pending files information
fn display_pending_files_compact(pending_files: &[PendingFileInfo]) -> Result<(), CliError> {
    ui::subsection("📋 Pending Files");

    let display_count = std::cmp::min(pending_files.len(), 10);

    for (i, file) in pending_files.iter().take(display_count).enumerate() {
        let attempt_suffix = if file.attempts > 0 {
            let plural = if file.attempts == 1 { "" } else { "s" };
            format!(" – {} attempt{}", file.attempts, plural)
        } else {
            String::new()
        };

        ui::info(&format!(
            "🟡 {}. {}{}",
            i + 1,
            file.file_path,
            attempt_suffix
        ));
    }

    if pending_files.len() > display_count {
        ui::dim(&format!(
            "... and {} more files (use --verbose to see all)",
            pending_files.len() - display_count
        ));
    }

    Ok(())
}

/// Display recommendations for handling pending files
fn display_pending_files_recommendations(
    pending_files: &[PendingFileInfo],
    migration_info: Option<&crate::session::MigrationInfo>,
) -> Result<(), CliError> {
    if pending_files.is_empty() {
        return Ok(());
    }

    ui::subsection("💡 Recommendations");

    // Analyze files and provide recommendations
    let attempted_files = pending_files.iter().filter(|f| f.attempts > 0).count();
    let untouched_files = pending_files.len().saturating_sub(attempted_files);

    if attempted_files > 0 {
        ui::info(&format!(
            "• {} file{} already entered the rewrap loop – let the agent keep running",
            attempted_files,
            if attempted_files == 1 { "" } else { "s" }
        ));
    }

    if untouched_files > 0 {
        ui::warning(&format!(
            "• {} file{} have not triggered a rewrap yet – read or list them to enqueue work",
            untouched_files,
            if untouched_files == 1 { "" } else { "s" }
        ));
    }

    let stale_attempts = pending_files
        .iter()
        .filter(|f| {
            f.attempts > 0
                && f.last_attempt
                    .map(|ts| Utc::now().signed_duration_since(ts) > chrono::Duration::minutes(10))
                    .unwrap_or(false)
        })
        .count();

    if stale_attempts > 0 {
        ui::warning(&format!(
            "• {} queued file{} have not retried in the last 10 minutes – inspect heartbeat logs",
            stale_attempts,
            if stale_attempts == 1 { "" } else { "s" }
        ));
    }

    // Migration-specific recommendations
    if let Some(info) = migration_info {
        if info.phase.is_active() {
            ui::info("• Migration is active – monitor: hybridcipher rekey status --watch");
        } else {
            ui::info("• Migration is idle – run 'hybridcipher rekey start' to begin a new cycle when ready");
        }
    }

    // General recommendations
    ui::info("• For detailed coverage analysis: hybridcipher coverage audit --verify-proofs --verify-all-proofs");
    ui::info("• To spot problematic paths: hybridcipher coverage pending --verbose");

    Ok(())
}

/// Handle coverage verify command
async fn handle_coverage_verify(
    file_id: String,
    verbose: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section(&format!("Coverage Verification: {}", file_id));

    // Validate file ID format
    if !is_valid_file_id(&file_id) {
        return Err(CliError::coverage(
            "File ID must be a valid identifier (e.g., file_001, doc_abc123)",
        ));
    }

    // Perform comprehensive verification
    ui::info("🔍 Performing coverage verification...");
    let verification_result =
        perform_file_coverage_verification(&file_id, verbose, session_manager).await?;

    // Display verification results
    display_verification_results(&verification_result, verbose)?;

    // Show recommendations based on results
    display_verification_recommendations(&verification_result, &file_id)?;

    Ok(())
}

/// Perform comprehensive file coverage verification
async fn perform_file_coverage_verification(
    file_id: &str,
    _verbose: bool,
    session_manager: &SessionManager,
) -> Result<CoverageVerificationResult, CliError> {
    let mut result = CoverageVerificationResult {
        file_id: file_id.to_string(),
        verified: false,
        proof_chain: Vec::new(),
        coverage_entry: None,
        errors: Vec::new(),
        verification_timestamp: Utc::now(),
    };

    let proof = if let Some(proof) = try_coverage_ipc_file_proof(session_manager, file_id).await? {
        proof
    } else {
        let client: LocalClient = session_manager.create_client().await?;
        client
            .download_coverage_file_proof(file_id)
            .await
            .map_err(|err| CliError::coverage(format!("Failed to download proof: {}", err)))?
    };

    if proof.file_id != file_id {
        result
            .errors
            .push("Coverage proof response does not match requested file".to_string());
        return Ok(result);
    }

    let leaf = format!("{}:{}", file_id, proof.file_epoch);
    let proof_valid = proof
        .proof
        .verify(&proof.merkle_root, leaf.as_bytes())
        .map_err(|err| CliError::coverage(format!("Failed to verify Merkle proof: {}", err)))?;

    let verifying_key = VerifyingKey::from_bytes(&proof.verifying_key)
        .map_err(|err| CliError::coverage(format!("Invalid coverage verifying key: {}", err)))?;
    let signature = CoverageSignature::from_bytes(&proof.signature)
        .map_err(|err| CliError::coverage(format!("Invalid snapshot signature: {}", err)))?;
    let signature_valid =
        signatures::verify(&verifying_key, &proof.merkle_root, &signature).is_ok();

    if proof_valid {
        result.proof_chain.push("merkle_proof_valid".to_string());
    } else {
        result
            .errors
            .push("Merkle proof verification failed".to_string());
    }

    if signature_valid {
        result
            .proof_chain
            .push("snapshot_signature_valid".to_string());
    } else {
        result
            .errors
            .push("Snapshot signature verification failed".to_string());
    }

    let root_hex = hex::encode(proof.merkle_root);
    let signature_base64 = base64::engine::general_purpose::STANDARD.encode(signature.as_bytes());

    result.coverage_entry = Some(CoverageLogEntry {
        file_id: file_id.to_string(),
        epoch_id: proof.file_epoch,
        proof_hash: root_hex.clone(),
        timestamp: proof.generated_at,
        signature: signature_base64,
    });

    result.verified = proof_valid && signature_valid;

    ui::success("✅ Verification complete");

    Ok(result)
}

/// Display verification results
fn display_verification_results(
    result: &CoverageVerificationResult,
    verbose: bool,
) -> Result<(), CliError> {
    ui::subsection("🔍 Verification Results");

    // Overall status
    let status_icon = if result.verified {
        "✅"
    } else if result.errors.is_empty() {
        "⚠️"
    } else {
        "❌"
    };

    let status_text = if result.verified {
        "VERIFIED"
    } else if result.errors.is_empty() {
        "PARTIAL"
    } else {
        "FAILED"
    };

    ui::info(&format!("{} Overall Status: {}", status_icon, status_text));
    ui::info(&format!("📁 File ID: {}", result.file_id));

    // Verification checks
    ui::subsection("🔐 Security Verification");

    let has_merkle = result.proof_chain.iter().any(|p| p == "merkle_proof_valid");
    let has_signature = result
        .proof_chain
        .iter()
        .any(|p| p == "snapshot_signature_valid");

    display_check_result("Merkle Proof", has_merkle);
    display_check_result("Cryptographic Signature", has_signature);

    // Show coverage entry if present
    if let Some(entry) = &result.coverage_entry {
        ui::subsection("📋 Coverage Entry");
        ui::info(&format!("Epoch ID: {}", entry.epoch_id));
        ui::info(&format!("Merkle Root: {}", entry.proof_hash));
        ui::info(&format!(
            "Timestamp: {}",
            ui::formatting::format_local_datetime(&entry.timestamp)
        ));
        if verbose {
            ui::info(&format!("Signature: {}", entry.signature));
        }
    }

    // Show errors if any
    if !result.errors.is_empty() {
        ui::subsection("❌ Errors");
        for error in &result.errors {
            ui::error(error);
        }
    }

    // Show proof chain details if verbose
    if verbose && !result.proof_chain.is_empty() {
        ui::subsection("📋 Verification Checks");
        for check in &result.proof_chain {
            ui::info(&format!("• {}", check));
        }
    }

    ui::info(&format!(
        "🕐 Verification completed at: {}",
        ui::formatting::format_local_datetime(&result.verification_timestamp)
    ));

    Ok(())
}

/// Display verification recommendations
fn display_verification_recommendations(
    result: &CoverageVerificationResult,
    _file_id: &str,
) -> Result<(), CliError> {
    ui::subsection("💡 Recommendations");

    if result.verified {
        ui::success("✅ File coverage is fully verified and valid");
        ui::info("• No action required - file is properly protected");
        if result.coverage_entry.is_some() {
            ui::info("• File is ready for migration to target epoch");
        }
    } else if result.errors.is_empty() {
        ui::warning("⚠️ File coverage has warnings but is functional");
        ui::info("• Monitor file during next rekey cycle");
        ui::info("• Some verification steps may be incomplete");
    } else {
        ui::error("❌ File coverage verification failed");
        for error in &result.errors {
            if error.contains("proof chain") {
                ui::info("• Reconstruct proof chain: hybridcipher recovery rebuild-proofs");
            } else if error.contains("signature") {
                ui::info("• Investigate potential tampering or corruption");
            } else if error.contains("Merkle") {
                ui::info("• Regenerate Merkle proofs: hybridcipher coverage rebuild-merkle");
            } else if error.contains("not found") {
                ui::info("• Re-scan roots: hybridcipher coverage scan --root <path>");
                ui::info("• Adopt file if needed: hybridcipher coverage adopt <path>");
            }
        }
        if !result.errors.is_empty() {
            ui::warning("• Consider quarantining file until issues are resolved");
        }
    }

    // General recommendations
    ui::info("• For detailed root health: hybridcipher coverage audit --verify-proofs --verify-all-proofs");
    ui::info("• For migration status: hybridcipher rekey status --watch");

    Ok(())
}

/// Display a check result with appropriate formatting
fn display_check_result(check_name: &str, passed: bool) {
    let (icon, status) = if passed {
        ("✅", "PASSED")
    } else {
        ("❌", "FAILED")
    };
    ui::info(&format!("{} {}: {}", icon, check_name, status));
}

/// Validate file ID format
fn is_valid_file_id(file_id: &str) -> bool {
    // File ID should be alphanumeric with optional underscores
    file_id.len() >= 3
        && file_id.len() <= 64
        && file_id.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn ordered_snapshot_entries(entries: &[CoverageSnapshotEntry]) -> (Vec<(String, u64)>, MerkleTree) {
    let mut ordered: Vec<(String, u64)> = entries
        .iter()
        .map(|entry| (entry.file_id.clone(), entry.epoch_number))
        .collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));

    let mut tree = MerkleTree::new();
    for (file_id, epoch) in &ordered {
        let leaf = format!("{file_id}:{epoch}");
        tree.insert_leaf(leaf.as_bytes());
    }

    (ordered, tree)
}
