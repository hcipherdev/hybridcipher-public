//! Shared mount runner functions for both CLI and desktop applications
//!
//! This module provides generic mount functions that can be used by both
//! the CLI and desktop app, avoiding code duplication.

use crate::{
    conflict_path_for, ConflictKind, ConflictPolicyResolution, ConflictResolutionRequest,
    ConflictResolutionResponse, FileSignature, MountCrypto, MountSyncRuntimeStatus,
    ReconciliationAction, ReconciliationSummary, RecoveryCopyResolutionRequest,
    RecoveryCopyResolutionResponse, SyncTracker,
};
use hybridcipher_client::ClientError;
#[cfg(target_os = "linux")]
use hybridcipher_mount::{
    is_hybridcipher_mounted, mount_hybridcipher, unmount_hybridcipher, MountOptions,
};
use notify::{recommended_watcher, Event, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::{
    sync::{mpsc, watch},
    time::{interval, Duration, MissedTickBehavior},
};
use tracing::{debug, info, warn};
#[cfg(target_os = "linux")]
use which::which;

/// Strategy for mounting encrypted folders
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MountStrategy {
    Sync,
    #[cfg(target_os = "linux")]
    Fuse,
}

const CLEAN_MOUNT_MARKER_PREFIX: &str = "mount_clean_";
const CLEAN_MOUNT_MARKER_SUFFIX: &str = ".marker";
const SYNC_BASELINE_PREFIX: &str = "mount_baseline_";
const SYNC_BASELINE_SUFFIX: &str = ".json";

fn mount_clean_marker_path(config_dir: &Path, mountpoint: &Path, encrypted_dir: &Path) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(mountpoint.to_string_lossy().as_bytes());
    hasher.update(b"|");
    hasher.update(encrypted_dir.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{:02x}", byte);
    }
    config_dir.join(format!(
        "{}{}{}",
        CLEAN_MOUNT_MARKER_PREFIX, hex, CLEAN_MOUNT_MARKER_SUFFIX
    ))
}

fn mount_sync_baseline_path(config_dir: &Path, mountpoint: &Path, encrypted_dir: &Path) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(mountpoint.to_string_lossy().as_bytes());
    hasher.update(b"|");
    hasher.update(encrypted_dir.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{:02x}", byte);
    }
    config_dir.join(format!(
        "{}{}{}",
        SYNC_BASELINE_PREFIX, hex, SYNC_BASELINE_SUFFIX
    ))
}

fn take_clean_mount_marker(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    if let Err(err) = fs::remove_file(path) {
        warn!(
            "Failed to remove clean mount marker {}: {}",
            path.display(),
            err
        );
    }
    true
}

fn write_clean_mount_marker(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "Failed to create clean mount marker directory {}: {}",
                parent.display(),
                err
            )
        })?;
    }
    fs::write(path, b"clean\n").map_err(|err| {
        format!(
            "Failed to write clean mount marker {}: {}",
            path.display(),
            err
        )
    })
}

fn mountpoint_is_empty(path: &Path) -> io::Result<bool> {
    if !path.exists() {
        return Ok(true);
    }
    let mut entries = fs::read_dir(path)?;
    Ok(entries.next().is_none())
}

fn write_sync_runtime_status(path: &Path, status: &MountSyncRuntimeStatus) {
    let data = match serde_json::to_vec_pretty(status) {
        Ok(data) => data,
        Err(err) => {
            warn!(
                "Failed to serialize mount sync status {}: {}",
                path.display(),
                err
            );
            return;
        }
    };

    if let Err(err) = SyncTracker::write_atomic_bytes(path, &data) {
        warn!(
            "Failed to persist mount sync status {}: {}",
            path.display(),
            err
        );
    }
}

fn persist_sync_baseline(tracker: &SyncTracker) {
    if let Err(err) = tracker.persist_sync_baseline() {
        warn!("Failed to persist sync baseline: {}", err);
    }
}

fn path_matches_exclusion_patterns(patterns: &[glob::Pattern], path: &Path) -> bool {
    let path_candidates = exclusion_path_candidates(path);
    let file_name = path.file_name().and_then(|name| name.to_str());
    patterns.iter().any(|pattern| {
        pattern.matches_path(path)
            || path_candidates
                .iter()
                .any(|candidate| pattern.matches(candidate))
            || file_name.map(|name| pattern.matches(name)).unwrap_or(false)
    })
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

fn log_mount_exclusion_diagnostics(raw_patterns: &[String]) {
    if raw_patterns.is_empty() {
        info!("Mount exclusion diagnostics: no exclusion patterns configured");
        return;
    }

    let mut compiled_patterns = Vec::with_capacity(raw_patterns.len());
    let mut invalid_patterns = 0usize;
    for raw in raw_patterns {
        match glob::Pattern::new(raw) {
            Ok(pattern) => compiled_patterns.push(pattern),
            Err(err) => {
                invalid_patterns = invalid_patterns.saturating_add(1);
                warn!("Invalid mount exclusion pattern '{}': {}", raw, err);
            }
        }
    }

    info!(
        "Mount exclusion diagnostics: configured={}, valid={}, invalid={}",
        raw_patterns.len(),
        compiled_patterns.len(),
        invalid_patterns
    );

    for pattern in raw_patterns {
        debug!("Mount exclusion pattern: {}", pattern);
    }

    if compiled_patterns.is_empty() {
        return;
    }

    for sample in [
        Path::new(".obsidian"),
        Path::new("vault/.obsidian"),
        Path::new("vault/.obsidian/workspace.json"),
    ] {
        let matched = path_matches_exclusion_patterns(&compiled_patterns, sample);
        info!(
            "Mount exclusion sample: path='{}' matched={}",
            sample.display(),
            matched
        );
    }
}

fn spawn_sync_watcher(
    watch_path: PathBuf,
    label: &'static str,
    watcher_tx: mpsc::Sender<()>,
    watcher_pending: Arc<AtomicBool>,
    watcher_overflow: Arc<AtomicBool>,
    watcher_dropped: Arc<AtomicU64>,
) {
    std::thread::spawn(move || {
        let watcher_tx_clone = watcher_tx.clone();
        let mut watcher = match recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(_event) = res {
                if !watcher_pending.swap(true, Ordering::SeqCst) {
                    if watcher_tx_clone.try_send(()).is_err() {
                        watcher_overflow.store(true, Ordering::SeqCst);
                        watcher_dropped.fetch_add(1, Ordering::SeqCst);
                    }
                } else {
                    watcher_overflow.store(true, Ordering::SeqCst);
                    watcher_dropped.fetch_add(1, Ordering::SeqCst);
                }
            }
        }) {
            Ok(watcher) => watcher,
            Err(err) => {
                warn!("Failed to create {} watcher: {}", label, err);
                return;
            }
        };

        if let Err(err) = watcher.watch(&watch_path, RecursiveMode::Recursive) {
            warn!(
                "Failed to watch {} at {}: {}",
                label,
                watch_path.display(),
                err
            );
            return;
        }

        debug!("{} watcher started for {}", label, watch_path.display());

        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });
}

fn directory_has_entries(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }

    let mut entries = fs::read_dir(path)
        .map_err(|err| format!("Failed to read directory {}: {}", path.display(), err))?;
    Ok(entries
        .next()
        .transpose()
        .map_err(|err| {
            format!(
                "Failed to inspect directory {} for recovery: {}",
                path.display(),
                err
            )
        })?
        .is_some())
}

fn quarantine_unclean_mountpoint(
    config_dir: &Path,
    mountpoint: &Path,
    encrypted_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    if !directory_has_entries(mountpoint)? {
        if !mountpoint.exists() {
            fs::create_dir_all(mountpoint).map_err(|err| {
                format!(
                    "Failed to recreate mountpoint {} after recovery check: {}",
                    mountpoint.display(),
                    err
                )
            })?;
        }
        return Ok(None);
    }

    let recovery_root = config_dir.join("mount_recovery");
    fs::create_dir_all(&recovery_root).map_err(|err| {
        format!(
            "Failed to create mount recovery directory {}: {}",
            recovery_root.display(),
            err
        )
    })?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    let mut hasher = Sha256::new();
    hasher.update(mountpoint.to_string_lossy().as_bytes());
    hasher.update(b"|");
    hasher.update(encrypted_dir.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let suffix = digest
        .iter()
        .take(6)
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    let mount_name = mountpoint
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "mount".to_string());
    let recovery_path = recovery_root.join(format!("{}_{}_{}", timestamp, mount_name, suffix));

    fs::rename(mountpoint, &recovery_path).map_err(|err| {
        format!(
            "Failed to quarantine unclean mountpoint {} to {}: {}",
            mountpoint.display(),
            recovery_path.display(),
            err
        )
    })?;

    fs::create_dir_all(mountpoint).map_err(|err| {
        format!(
            "Failed to recreate fresh mountpoint {} after quarantine: {}",
            mountpoint.display(),
            err
        )
    })?;

    Ok(Some(recovery_path))
}

fn cleanup_old_mount_recovery_dirs(config_dir: &Path, retention_days: u64) -> Result<(), String> {
    let recovery_root = config_dir.join("mount_recovery");
    if !recovery_root.exists() {
        return Ok(());
    }
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let retention_secs = retention_days.saturating_mul(24 * 60 * 60);

    for entry in fs::read_dir(&recovery_root).map_err(|err| {
        format!(
            "Failed to read mount recovery directory {}: {}",
            recovery_root.display(),
            err
        )
    })? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                warn!(
                    "Skipping unreadable recovery directory entry in {}: {}",
                    recovery_root.display(),
                    err
                );
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|value| value.to_str()) {
            Some(name) => name,
            None => continue,
        };
        let Some(timestamp_prefix) = name.split('_').next() else {
            continue;
        };
        let Ok(dir_ts) = timestamp_prefix.parse::<u64>() else {
            continue;
        };
        if now_secs.saturating_sub(dir_ts) <= retention_secs {
            continue;
        }
        match fs::remove_dir_all(&path) {
            Ok(()) => {
                info!(
                    "Removed expired mount recovery directory {} (retention_days={})",
                    path.display(),
                    retention_days
                );
            }
            Err(err) => {
                warn!(
                    "Failed to remove expired mount recovery directory {}: {}",
                    path.display(),
                    err
                );
            }
        }
    }

    Ok(())
}

/// Per-file reconciliation for unclean mount recovery.
/// Instead of moving the entire mount folder, this function:
/// 1. Walks existing mount files and compares against stored signatures
/// 2. Categorizes each file: unchanged, local-modified, local-created, local-deleted, remote-modified, conflict
/// 3. Only moves conflicting/modified files to recovery, leaving unchanged files in place
///
/// Returns a summary of actions to take and populates the tracker with pending operations.
fn reconcile_unclean_mount(
    config_dir: &Path,
    mountpoint: &Path,
    encrypted_dir: &Path,
    tracker: &mut SyncTracker,
    startup_local_delete_max_actions: usize,
) -> Result<(ReconciliationSummary, Option<PathBuf>), String> {
    let mut summary = ReconciliationSummary::default();
    let mount_has_entries = directory_has_entries(mountpoint)?;
    if !mount_has_entries {
        if !mountpoint.exists() {
            fs::create_dir_all(mountpoint).map_err(|err| {
                format!(
                    "Failed to recreate mountpoint {} after recovery check: {}",
                    mountpoint.display(),
                    err
                )
            })?;
        }
    }

    // Get stored signatures from tracker for comparison
    let stored_mount_sigs = tracker.decrypted_signatures_snapshot();
    let stored_encrypted_sigs = tracker.encrypted_signatures_snapshot();

    // Build mapping from mount paths to encrypted paths using file_id xattrs
    let mount_to_encrypted = tracker.mount_to_encrypted_mapping();

    // Create recovery directory (only if we need it)
    let recovery_root = config_dir.join("mount_recovery");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    let mut hasher = Sha256::new();
    hasher.update(mountpoint.to_string_lossy().as_bytes());
    hasher.update(b"|");
    hasher.update(encrypted_dir.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let suffix = digest
        .iter()
        .take(6)
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    let mount_name = mountpoint
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "mount".to_string());
    let recovery_path = recovery_root.join(format!("{}_{}_{}", timestamp, mount_name, suffix));

    let mut recovery_created = false;
    let mut actions: Vec<ReconciliationAction> = Vec::new();

    // Walk current mount files
    let current_mount_files = walk_mount_files(mountpoint)?;

    for mount_path in &current_mount_files {
        let _relative_path = mount_path
            .strip_prefix(mountpoint)
            .map_err(|_| format!("Path {} not under mountpoint", mount_path.display()))?;

        let current_sig = match fs::metadata(mount_path) {
            Ok(meta) => FileSignature::from_metadata(&meta),
            Err(_) => continue, // File disappeared during scan
        };

        let stored_sig = stored_mount_sigs.get(mount_path);
        let encrypted_path = mount_to_encrypted.get(mount_path);

        let action = match (stored_sig, encrypted_path) {
            // File exists in stored signatures and has encrypted counterpart
            (Some(_stored), Some(enc_path)) => {
                let encrypted_changed = stored_encrypted_sigs
                    .get(enc_path)
                    .map(|enc_sig| {
                        // Check if encrypted file was modified (would need re-read)
                        fs::metadata(enc_path)
                            .map(|m| FileSignature::from_metadata(&m) != *enc_sig)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                let local_changed =
                    tracker.is_local_mount_path_dirty_with_signature(mount_path, current_sig);

                match (local_changed, encrypted_changed) {
                    (false, false) => ReconciliationAction::Unchanged {
                        path: mount_path.clone(),
                    },
                    (true, false) => ReconciliationAction::LocalModified {
                        mount_path: mount_path.clone(),
                    },
                    (false, true) => ReconciliationAction::RemoteModified {
                        mount_path: mount_path.clone(),
                        encrypted_path: enc_path.clone(),
                    },
                    (true, true) => ReconciliationAction::Conflict {
                        mount_path: mount_path.clone(),
                        encrypted_path: enc_path.clone(),
                        kind: ConflictKind::LocalRemoteBothModified,
                    },
                }
            }
            // File exists locally but has no encrypted counterpart - new local file
            (None, None) => ReconciliationAction::LocalCreated {
                mount_path: mount_path.clone(),
            },
            // File in stored sigs but no encrypted path - unusual, treat as local modified
            (Some(_), None) => ReconciliationAction::LocalModified {
                mount_path: mount_path.clone(),
            },
            // Not in stored sigs but has encrypted path - treat as new
            (None, Some(_)) => ReconciliationAction::LocalCreated {
                mount_path: mount_path.clone(),
            },
        };

        actions.push(action);
    }

    // Check for local deletions: files in stored signatures but not in current mount
    if mount_has_entries {
        for (stored_path, _) in &stored_mount_sigs {
            if !current_mount_files.contains(stored_path) {
                if let Some(enc_path) = mount_to_encrypted.get(stored_path) {
                    // Check if encrypted file still exists
                    if enc_path.exists() {
                        actions.push(ReconciliationAction::LocalDeleted {
                            mount_path: stored_path.clone(),
                            encrypted_path: enc_path.clone(),
                        });
                    }
                }
            }
        }
    } else if !stored_mount_sigs.is_empty() {
        warn!(
            "Mountpoint {} is empty during unclean-start reconciliation; suppressing {} potential local-delete action(s) to avoid bulk data loss.",
            mountpoint.display(),
            stored_mount_sigs.len()
        );
    }

    let pending_local_delete_count = actions
        .iter()
        .filter(|action| matches!(action, ReconciliationAction::LocalDeleted { .. }))
        .count();
    if pending_local_delete_count > startup_local_delete_max_actions {
        return Err(format!(
            "Startup reconciliation aborted: refusing to queue {} local deletions for mount {} (safety threshold {}).",
            pending_local_delete_count,
            mountpoint.display(),
            startup_local_delete_max_actions
        ));
    }

    // Process actions and move only necessary files to recovery
    let conflict_policy = tracker.conflict_policy().clone();

    for action in actions {
        match &action {
            ReconciliationAction::Unchanged { .. } => {
                summary.unchanged_count += 1;
            }
            ReconciliationAction::LocalModified { mount_path } => {
                summary.local_modified.push(mount_path.clone());
                tracker.queue_local_create(mount_path.clone());
            }
            ReconciliationAction::LocalCreated { mount_path } => {
                summary.local_created.push(mount_path.clone());
                tracker.queue_local_create(mount_path.clone());
            }
            ReconciliationAction::LocalDeleted {
                mount_path,
                encrypted_path,
            } => {
                summary.local_deleted.push(mount_path.clone());
                tracker.queue_local_delete(encrypted_path.clone());
            }
            ReconciliationAction::RemoteModified { mount_path, .. } => {
                summary.remote_modified.push(mount_path.clone());
                // Will be handled by normal sync - decrypt fresh from encrypted
            }
            ReconciliationAction::Conflict {
                mount_path,
                encrypted_path,
                kind,
            } => {
                summary.conflicts.push((mount_path.clone(), *kind));

                // Resolve conflict based on policy
                match conflict_policy.default_resolution {
                    ConflictPolicyResolution::KeepBoth => {
                        // Preserve local version in recovery for later conflict resolution
                        if !recovery_created {
                            fs::create_dir_all(&recovery_path).map_err(|err| {
                                format!(
                                    "Failed to create recovery directory {}: {}",
                                    recovery_path.display(),
                                    err
                                )
                            })?;
                            recovery_created = true;
                        }
                        move_file_to_recovery(mount_path, mountpoint, &recovery_path)?;
                    }
                    ConflictPolicyResolution::NewerWins => {
                        // Compare timestamps - newer file wins
                        let local_mtime = fs::metadata(mount_path).and_then(|m| m.modified()).ok();
                        let remote_mtime =
                            fs::metadata(encrypted_path).and_then(|m| m.modified()).ok();

                        match (local_mtime, remote_mtime) {
                            (Some(local), Some(remote)) => {
                                let diff = if local > remote {
                                    local.duration_since(remote).unwrap_or_default()
                                } else {
                                    remote.duration_since(local).unwrap_or_default()
                                };

                                let threshold =
                                    Duration::from_secs(conflict_policy.timestamp_threshold_secs);

                                // If within threshold, keep both (too close to call)
                                if diff <= threshold {
                                    info!(
                                        "Conflict {} within {:?} threshold, keeping both versions",
                                        mount_path.display(),
                                        threshold
                                    );
                                    if !recovery_created {
                                        fs::create_dir_all(&recovery_path).map_err(|err| {
                                            format!("Failed to create recovery directory: {}", err)
                                        })?;
                                        recovery_created = true;
                                    }
                                    move_file_to_recovery(mount_path, mountpoint, &recovery_path)?;
                                } else if local > remote {
                                    // Local is newer - queue for encryption (overwrites remote)
                                    info!(
                                        "Local file {} is newer, will overwrite remote",
                                        mount_path.display()
                                    );
                                    tracker.queue_local_create(mount_path.clone());
                                } else {
                                    // Remote is newer - delete local, sync will restore
                                    info!(
                                        "Remote file is newer for {}, using remote version",
                                        mount_path.display()
                                    );
                                    if let Err(err) = fs::remove_file(mount_path) {
                                        warn!(
                                            "Failed to remove older local file {}: {}",
                                            mount_path.display(),
                                            err
                                        );
                                    }
                                }
                            }
                            _ => {
                                // Can't determine timestamps, fall back to keep both
                                warn!(
                                    "Cannot compare timestamps for {}, keeping both",
                                    mount_path.display()
                                );
                                if !recovery_created {
                                    fs::create_dir_all(&recovery_path).map_err(|err| {
                                        format!("Failed to create recovery directory: {}", err)
                                    })?;
                                    recovery_created = true;
                                }
                                move_file_to_recovery(mount_path, mountpoint, &recovery_path)?;
                            }
                        }
                    }
                    ConflictPolicyResolution::LocalWins => {
                        // Keep local, queue for encryption (overwrites remote)
                        tracker.queue_local_create(mount_path.clone());
                    }
                    ConflictPolicyResolution::RemoteWins => {
                        // Just delete local, let sync restore from encrypted
                        // (legacy behavior - local changes lost)
                        if let Err(err) = fs::remove_file(mount_path) {
                            warn!(
                                "Failed to remove local file {} for remote-wins resolution: {}",
                                mount_path.display(),
                                err
                            );
                        }
                    }
                }
            }
        }
    }

    let recovery_result = if recovery_created {
        Some(recovery_path)
    } else {
        None
    };

    Ok((summary, recovery_result))
}

/// Walk mount directory and collect all file paths (non-recursive for directories handled separately)
fn walk_mount_files(mountpoint: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut stack = vec![mountpoint.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|err| {
            format!(
                "Failed to read directory {} during reconciliation: {}",
                dir.display(),
                err
            )
        })?;

        for entry in entries {
            let entry = entry
                .map_err(|err| format!("Failed to read entry in {}: {}", dir.display(), err))?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|err| {
                format!("Failed to get file type for {}: {}", path.display(), err)
            })?;

            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
            // Skip symlinks and other special files
        }
    }

    Ok(files)
}

/// Move a single file to the recovery directory, preserving relative path structure
fn move_file_to_recovery(
    file_path: &Path,
    mountpoint: &Path,
    recovery_dir: &Path,
) -> Result<PathBuf, String> {
    let relative = file_path.strip_prefix(mountpoint).map_err(|_| {
        format!(
            "Path {} not under mountpoint {}",
            file_path.display(),
            mountpoint.display()
        )
    })?;

    let conflict_relative = conflict_path_for(relative);
    let dest = recovery_dir.join(conflict_relative);

    // Create parent directories in recovery
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "Failed to create recovery parent directory {}: {}",
                parent.display(),
                err
            )
        })?;
    }

    // Move file to recovery
    fs::rename(file_path, &dest).map_err(|err| {
        format!(
            "Failed to move {} to recovery {}: {}",
            file_path.display(),
            dest.display(),
            err
        )
    })?;

    Ok(dest)
}

/// Trait for client operations needed by mount runners
#[async_trait::async_trait]
pub trait MountClient: Send + Sync {
    /// Check if a rekey migration is active
    async fn is_migrating(&self) -> bool;

    /// Get current rekey status
    async fn rekey_status(&self) -> Result<Option<()>, ClientError>;

    /// Emit a rekey heartbeat
    async fn emit_rekey_heartbeat(&self) -> Result<(), ClientError>;

    /// Schedule a rekey heartbeat via the rate-limited worker
    async fn schedule_rekey_heartbeat(&self);

    /// Snapshot local rewrap queue counts
    async fn rewrap_queue_snapshot(
        &self,
    ) -> Result<hybridcipher_client::LocalRewrapSnapshot, ClientError>;

    /// Populate the migration queue from the local file index
    async fn populate_migration_queue(&self) -> Result<(), ClientError>;

    /// Report rekey progress
    async fn report_rekey_progress(
        &self,
        status: Option<hybridcipher_client::rekey::RekeyProgressState>,
        progress: Option<u8>,
    ) -> Result<(), ClientError>;

    /// Ensure client state is loaded
    async fn ensure_state_loaded(&self) -> Result<(), ClientError>;

    /// Trigger rewrap processing
    async fn trigger_rewrap_processing(&self);

    /// Start coverage watchers
    async fn start_coverage_watchers(&self) -> Result<(), ClientError>;

    /// Check if migration automation is enabled
    fn migration_automation_enabled(&self) -> bool;

    /// Check if coverage watchers are enabled
    fn coverage_watchers_enabled(&self) -> bool;

    /// Get configured file exclusion patterns
    fn excluded_file_patterns(&self) -> Vec<String>;
}

// Implement MountClient for hybridcipher_client::Client
#[async_trait::async_trait]
impl<S, N> MountClient for hybridcipher_client::Client<S, N>
where
    S: hybridcipher_client::storage::Storage + Send + Sync,
    N: hybridcipher_client::network::Network + Send + Sync,
{
    async fn is_migrating(&self) -> bool {
        self.is_migrating().await
    }

    async fn rekey_status(&self) -> Result<Option<()>, ClientError> {
        self.rekey_status().await.map(|opt| opt.map(|_| ()))
    }

    async fn emit_rekey_heartbeat(&self) -> Result<(), ClientError> {
        self.emit_rekey_heartbeat().await.map(|_| ())
    }

    async fn schedule_rekey_heartbeat(&self) {
        hybridcipher_client::Client::<S, N>::schedule_rekey_heartbeat(self).await;
    }

    async fn rewrap_queue_snapshot(
        &self,
    ) -> Result<hybridcipher_client::LocalRewrapSnapshot, ClientError> {
        hybridcipher_client::Client::<S, N>::rewrap_queue_snapshot(self).await
    }

    async fn populate_migration_queue(&self) -> Result<(), ClientError> {
        hybridcipher_client::Client::<S, N>::populate_migration_queue(self).await
    }

    async fn report_rekey_progress(
        &self,
        status: Option<hybridcipher_client::rekey::RekeyProgressState>,
        progress: Option<u8>,
    ) -> Result<(), ClientError> {
        self.report_rekey_progress(status, progress)
            .await
            .map(|_| ())
    }

    async fn ensure_state_loaded(&self) -> Result<(), ClientError> {
        self.ensure_state_loaded().await
    }

    async fn trigger_rewrap_processing(&self) {
        self.trigger_rewrap_processing().await;
    }

    async fn start_coverage_watchers(&self) -> Result<(), ClientError> {
        self.start_coverage_watchers().await
    }

    fn migration_automation_enabled(&self) -> bool {
        self.migration_automation_enabled()
    }

    fn coverage_watchers_enabled(&self) -> bool {
        self.coverage_watchers_enabled()
    }

    fn excluded_file_patterns(&self) -> Vec<String> {
        self.excluded_file_patterns()
    }
}

/// Run a FUSE mount with stop signal handling
#[cfg(target_os = "linux")]
pub async fn run_fuse_mount<S, N>(
    client: hybridcipher_client::Client<S, N>,
    encrypted_dir: PathBuf,
    mountpoint: PathBuf,
    options: MountOptions,
    mut stop_rx: watch::Receiver<bool>,
    ready: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(), String>
where
    S: hybridcipher_client::storage::Storage + Send + Sync + 'static,
    N: hybridcipher_client::network::Network + Send + Sync + 'static,
{
    let mountpoint_for_mount = mountpoint.clone();
    let encrypted_root_for_mount = encrypted_dir.clone();
    let mount_future = async move {
        mount_hybridcipher(
            &mountpoint_for_mount,
            &encrypted_root_for_mount,
            client,
            None,
            options,
        )
        .await
        .map_err(|e| format!("Failed to mount filesystem: {}", e))
    };
    tokio::pin!(mount_future);

    let mut unmounted = false;
    let mountpoint_for_unmount = mountpoint;

    loop {
        tokio::select! {
            res = &mut mount_future => {
                if let Some(ref ready_flag) = ready {
                    ready_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                if !unmounted {
                    return res;
                } else {
                    return res.or_else(|e| {
                        if e.contains("mount") {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    });
                }
            }
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    debug!("Stop signal received; unmounting FUSE mount");
                    if let Some(ref ready_flag) = ready {
                        ready_flag.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Err(err) = unmount_hybridcipher(&mountpoint_for_unmount, false).await {
                        warn!("Failed to unmount cleanly: {}", err);
                    }
                    unmounted = true;
                }
            }
        }
    }
}

/// Run a sync mount with stop signal handling
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub async fn run_sync_mount<C: MountClient>(
    client: &C,
    crypto: &dyn MountCrypto,
    encrypted_dir: PathBuf,
    mountpoint: PathBuf,
    stop_rx: watch::Receiver<bool>,
    ready: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(), String> {
    run_sync_mount_with_config(
        client,
        crypto,
        encrypted_dir,
        mountpoint,
        stop_rx,
        ready,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
}

/// Run a sync mount with stop signal handling and optional user config directory for retention
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub async fn run_sync_mount_with_config<C: MountClient>(
    client: &C,
    crypto: &dyn MountCrypto,
    encrypted_dir: PathBuf,
    mountpoint: PathBuf,
    mut stop_rx: watch::Receiver<bool>,
    ready: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    user_config_dir: Option<&Path>,
    mount_scope_id: Option<&str>,
    runtime_status_path: Option<&Path>,
    conflict_registry_path: Option<&Path>,
    conflict_request_dir: Option<&Path>,
    conflict_result_dir: Option<&Path>,
    recovery_registry_path: Option<&Path>,
    recovery_request_dir: Option<&Path>,
    recovery_result_dir: Option<&Path>,
) -> Result<(), String> {
    let mut tracker = SyncTracker::new();
    let migration_automation_enabled = client.migration_automation_enabled();
    let coverage_watchers_enabled = client.coverage_watchers_enabled();
    let excluded_patterns = client.excluded_file_patterns();
    tracker.set_excluded_patterns(excluded_patterns.clone());
    log_mount_exclusion_diagnostics(&excluded_patterns);
    let mut clean_marker_path: Option<PathBuf> = None;
    let mut quarantined_mount_recovery_path: Option<PathBuf> = None;
    let mut quarantined_pending_writeback_paths: Vec<PathBuf> = Vec::new();
    let mut startup_rehydrate_mode = false;
    let mut skip_startup_local_delete_processing = false;
    let runtime_status_path = runtime_status_path.map(Path::to_path_buf);
    let conflict_registry_path = conflict_registry_path.map(Path::to_path_buf);
    let conflict_request_dir = conflict_request_dir.map(Path::to_path_buf);
    let conflict_result_dir = conflict_result_dir.map(Path::to_path_buf);
    let recovery_registry_path = recovery_registry_path.map(Path::to_path_buf);
    let recovery_request_dir = recovery_request_dir.map(Path::to_path_buf);
    let recovery_result_dir = recovery_result_dir.map(Path::to_path_buf);
    // Load deletion config from config file
    let mount_config = SyncTracker::load_mount_config_from_file(None);
    tracker.set_deletion_config(mount_config.deletion);
    tracker.set_sparse_skip_size_bytes(mount_config.sparse_skip_size_bytes);
    tracker.set_stream_threshold_bytes(mount_config.stream_threshold_bytes);
    tracker.set_stream_chunk_size_bytes(mount_config.stream_chunk_size_bytes);
    tracker.set_stream_stability_age_secs(mount_config.stream_stability_age_secs);

    // Set retention folder if user config dir is provided
    // This should always be set for sync mounts to enable file retention
    if let Some(config_dir) = user_config_dir {
        if let Err(err) = cleanup_old_mount_recovery_dirs(config_dir, 30) {
            warn!("Failed to cleanup old mount recovery directories: {}", err);
        }
        tracker.set_retention_folder(config_dir);
        let scoped_journal = |base: &str| -> PathBuf {
            match mount_scope_id {
                Some(scope) if !scope.trim().is_empty() => {
                    config_dir.join(format!("{}_{}.json", base, scope))
                }
                _ => config_dir.join(format!("{}.json", base)),
            }
        };
        tracker.set_pending_deletion_path(scoped_journal("pending_deletions"));
        tracker.set_pending_orphan_path(scoped_journal("pending_orphans"));
        tracker.set_pending_writeback_path(scoped_journal("pending_writebacks"));
        tracker.set_pending_refresh_path(scoped_journal("pending_refreshes"));
        tracker.set_pending_open_unlinked_path(scoped_journal("pending_open_unlinked"));
        tracker.set_pending_metadata_path(scoped_journal("pending_metadata"));
        tracker.set_sync_baseline_path(mount_sync_baseline_path(
            config_dir,
            &mountpoint,
            &encrypted_dir,
        ));
        if let Some(path) = conflict_registry_path.as_ref() {
            tracker.set_conflict_registry_path(path.clone());
        }
        if let Some(path) = recovery_registry_path.as_ref() {
            tracker.set_recovery_registry_path(path.clone());
        }
        clean_marker_path = Some(mount_clean_marker_path(
            config_dir,
            &mountpoint,
            &encrypted_dir,
        ));
        info!(
            "Retention folder configured: {}",
            config_dir.join("retention").display()
        );
    } else {
        warn!("No user config directory provided - file retention will be disabled. Files will be deleted immediately after verification.");
    }

    if let Some(ref marker_path) = clean_marker_path {
        if take_clean_mount_marker(marker_path) {
            info!(
                "Clean mount marker found for {}; entering startup rehydrate mode",
                mountpoint.display()
            );
            tracker.enter_startup_rehydrate_mode();
            startup_rehydrate_mode = true;
        } else {
            let mount_is_empty = match mountpoint_is_empty(&mountpoint) {
                Ok(empty) => empty,
                Err(err) => {
                    warn!(
                        "Failed to inspect mountpoint {} emptiness: {}",
                        mountpoint.display(),
                        err
                    );
                    false
                }
            };
            if mount_is_empty {
                info!(
                    "Mountpoint {} is empty at startup; entering startup rehydrate mode and skipping startup delete processing",
                    mountpoint.display()
                );
                tracker.enter_startup_rehydrate_mode();
                startup_rehydrate_mode = true;
                skip_startup_local_delete_processing = true;
            } else if let Some(config_dir) = user_config_dir {
                // Use per-file reconciliation instead of whole-folder quarantine
                match reconcile_unclean_mount(
                    config_dir,
                    &mountpoint,
                    &encrypted_dir,
                    &mut tracker,
                    mount_config.startup_local_delete_max_actions,
                ) {
                    Ok((summary, Some(recovery_path))) => {
                        quarantined_pending_writeback_paths =
                            tracker.pending_writeback_mount_paths();
                        // Don't clear all writebacks - only clear ones that were successfully queued
                        quarantined_mount_recovery_path = Some(recovery_path.clone());

                        // Log reconciliation summary
                        info!(
                            "Reconciled unclean mount at {}: {} unchanged, {} local modified, {} local created, {} local deleted, {} remote modified, {} conflicts",
                            mountpoint.display(),
                            summary.unchanged_count,
                            summary.local_modified.len(),
                            summary.local_created.len(),
                            summary.local_deleted.len(),
                            summary.remote_modified.len(),
                            summary.conflicts.len()
                        );

                        if !summary.conflicts.is_empty() {
                            warn!(
                                "Found {} conflict(s) during reconciliation. Conflicting local files moved to {}",
                                summary.conflicts.len(),
                                recovery_path.display()
                            );
                        }
                    }
                    Ok((summary, None)) => {
                        // No recovery folder needed (no conflicts requiring backup)
                        if summary.local_modified.len()
                            + summary.local_created.len()
                            + summary.local_deleted.len()
                            > 0
                        {
                            info!(
                                "Reconciled unclean mount at {} with bidirectional changes: {} local modified, {} local created, {} local deleted (no conflicts)",
                                mountpoint.display(),
                                summary.local_modified.len(),
                                summary.local_created.len(),
                                summary.local_deleted.len()
                            );
                        }
                    }
                    Err(err) => {
                        // Fall back to legacy quarantine behavior on reconciliation failure
                        warn!(
                            "Per-file reconciliation failed, falling back to full quarantine: {}",
                            err
                        );
                        match quarantine_unclean_mountpoint(config_dir, &mountpoint, &encrypted_dir)
                        {
                            Ok(Some(recovery_path)) => {
                                quarantined_pending_writeback_paths =
                                    tracker.pending_writeback_mount_paths();
                                tracker.clear_pending_writebacks();
                                quarantined_mount_recovery_path = Some(recovery_path.clone());
                                warn!(
                                    "Previous sync mount at {} was not cleanly closed. Quarantined stale plaintext to {} and rebuilt a fresh mount root.",
                                    mountpoint.display(),
                                    recovery_path.display()
                                );
                            }
                            Ok(None) => {}
                            Err(err) => {
                                return Err(format!(
                                    "Failed to quarantine stale mountpoint {}: {}",
                                    mountpoint.display(),
                                    err
                                ));
                            }
                        }
                    }
                }
            } else if let Err(err) = tracker.seed_mountpoint_signatures(&mountpoint) {
                warn!(
                    "Failed to seed mount signatures for {}: {}",
                    mountpoint.display(),
                    err
                );
            }
        }
    }

    if let Some(ref status_path) = runtime_status_path {
        write_sync_runtime_status(status_path, &tracker.runtime_status());
    }
    persist_sync_baseline(&tracker);

    info!("Performing initial synchronization...");
    tracker
        .sync(crypto, &encrypted_dir, &mountpoint)
        .await
        .map_err(|e| e.to_string())?;
    if startup_rehydrate_mode {
        tracker.exit_startup_rehydrate_mode();
    }
    if let Some(recovery_path) = quarantined_mount_recovery_path.as_ref() {
        match tracker.materialize_conflict_copies(recovery_path, &mountpoint) {
            Ok(created_paths) if !created_paths.is_empty() => {
                warn!(
                    "Recovered {} unresolved conflict file(s) from {} back into {}",
                    created_paths.len(),
                    recovery_path.display(),
                    mountpoint.display()
                );
            }
            Ok(_) => {}
            Err(err) => {
                warn!(
                    "Failed to materialize unresolved conflict files from {}: {}",
                    recovery_path.display(),
                    err
                );
            }
        }
        match tracker.materialize_existing_recovered_pending_copies(recovery_path, &mountpoint) {
            Ok(created_paths) if !created_paths.is_empty() => {
                warn!(
                    "Recovered {} existing recovery copy/copies from {} back into {}",
                    created_paths.len(),
                    recovery_path.display(),
                    mountpoint.display()
                );
            }
            Ok(_) => {}
            Err(err) => {
                warn!(
                    "Failed to rematerialize existing recovery copies from {}: {}",
                    recovery_path.display(),
                    err
                );
            }
        }
        match tracker.materialize_recovered_pending_copies(
            recovery_path,
            &mountpoint,
            &quarantined_pending_writeback_paths,
        ) {
            Ok(created_paths) if !created_paths.is_empty() => {
                warn!(
                    "Recovered {} pending-work file(s) from {} into local-only read-only recovery copies under {}",
                    created_paths.len(),
                    recovery_path.display(),
                    mountpoint.display()
                );
            }
            Ok(_) => {}
            Err(err) => {
                warn!(
                    "Failed to materialize recovered pending-work copies from {}: {}",
                    recovery_path.display(),
                    err
                );
            }
        }
    }
    if let Some(ref status_path) = runtime_status_path {
        write_sync_runtime_status(status_path, &tracker.runtime_status());
    }
    persist_sync_baseline(&tracker);

    if let Some(ref ready_flag) = ready {
        ready_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    if migration_automation_enabled {
        initialize_sync_migration_reporting(client).await;
    }

    if coverage_watchers_enabled {
        if let Err(err) = client.start_coverage_watchers().await {
            warn!("Failed to start coverage watchers: {}", err);
        }
    }

    let (watcher_tx, mut watcher_rx) = mpsc::channel(1);
    let watcher_pending = Arc::new(AtomicBool::new(false));
    let watcher_overflow = Arc::new(AtomicBool::new(false));
    let watcher_dropped = Arc::new(AtomicU64::new(0));
    spawn_sync_watcher(
        encrypted_dir.clone(),
        "encrypted directory",
        watcher_tx.clone(),
        Arc::clone(&watcher_pending),
        Arc::clone(&watcher_overflow),
        Arc::clone(&watcher_dropped),
    );
    spawn_sync_watcher(
        mountpoint.clone(),
        "mountpoint",
        watcher_tx,
        Arc::clone(&watcher_pending),
        Arc::clone(&watcher_overflow),
        Arc::clone(&watcher_dropped),
    );

    info!("Decrypted view is ready.");

    // Process any pending background operations from reconciliation
    if tracker.has_pending_background_ops() {
        info!("Processing pending background operations from unclean mount recovery...");

        // Process local creates (files created while unmounted)
        match tracker
            .process_pending_local_creates(crypto, &encrypted_dir, &mountpoint)
            .await
        {
            Ok(count) if count > 0 => {
                info!("Queued {} local file(s) for encryption", count);
            }
            Ok(_) => {}
            Err(err) => {
                warn!("Error processing pending local creates: {}", err);
            }
        }

        // Process local deletes (files deleted while unmounted)
        if skip_startup_local_delete_processing {
            warn!(
                "Skipping startup local-delete processing for {} because mountpoint was empty at mount time",
                mountpoint.display()
            );
        } else {
            match tracker
                .process_pending_local_deletes(crypto, &encrypted_dir)
                .await
            {
                Ok(count) if count > 0 => {
                    info!("Processed {} local deletion(s)", count);
                }
                Ok(_) => {}
                Err(err) => {
                    warn!("Error processing pending local deletes: {}", err);
                }
            }
        }

        // Run a sync to pick up any files that were prepared for encryption
        if let Err(err) = tracker.sync(crypto, &encrypted_dir, &mountpoint).await {
            warn!("Error during post-reconciliation sync: {}", err);
        }

        if let Some(ref status_path) = runtime_status_path {
            write_sync_runtime_status(status_path, &tracker.runtime_status());
        }
        persist_sync_baseline(&tracker);
    }

    let mut poll = interval(Duration::from_secs(2));
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut fast_drain = interval(Duration::from_millis(350));
    fast_drain.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut state_refresh = interval(Duration::from_secs(5));
    state_refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut rekey_status_refresh = interval(Duration::from_secs(30));
    rekey_status_refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut conflict_action_refresh = interval(Duration::from_millis(500));
    conflict_action_refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut last_discovery_at: Option<Instant> = None;
    let discovery_cooldown = Duration::from_secs(60);

    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    debug!("Stop signal received; cleaning up sync mount");
                    if let Some(ref ready_flag) = ready {
                        ready_flag.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                    // Final sync to process any pending changes
                    tracker
                        .sync(crypto, &encrypted_dir, &mountpoint)
                        .await
                        .map_err(|e| e.to_string())?;
                    if let Some(ref status_path) = runtime_status_path {
                        write_sync_runtime_status(status_path, &tracker.runtime_status());
                    }
                    persist_sync_baseline(&tracker);

                    // Clean up all decrypted files from mountpoint before exit
                    // This ensures the mountpoint directory is empty for cleanup
                    if tracker.can_cleanup_mountpoint() {
                        if let Err(err) = tracker.prepare_mountpoint_cleanup() {
                            warn!(
                                "Failed to restore mountpoint permissions for cleanup {}: {}",
                                mountpoint.display(),
                                err
                            );
                        }
                        if let Err(e) = cleanup_mountpoint_files(&mountpoint) {
                            warn!("Failed to clean up all files from mountpoint {}: {}. Directory may need manual cleanup.", mountpoint.display(), e);
                        } else {
                            info!("Successfully cleaned up all files from mountpoint {}", mountpoint.display());
                            if let Some(ref marker_path) = clean_marker_path {
                                if let Err(err) = write_clean_mount_marker(marker_path) {
                                    warn!(
                                        "Failed to write clean mount marker {}: {}",
                                        marker_path.display(),
                                        err
                                    );
                                }
                            }
                        }
                    } else {
                        warn!(
                            "Skipping mountpoint cleanup for {} due to pending sync work or conflicts",
                            mountpoint.display()
                        );
                    }

                    if migration_automation_enabled {
                        drive_sync_migration_reporting(client).await;
                    }
                    return Ok(());
                }
            }
            Some(_event) = watcher_rx.recv() => {
                watcher_pending.store(false, Ordering::SeqCst);
                // File change detected, trigger immediate sync
                tracker
                    .sync(crypto, &encrypted_dir, &mountpoint)
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(ref status_path) = runtime_status_path {
                    write_sync_runtime_status(status_path, &tracker.runtime_status());
                }
                persist_sync_baseline(&tracker);
                if watcher_overflow.swap(false, Ordering::SeqCst) {
                    let dropped = watcher_dropped.swap(0, Ordering::SeqCst);
                    warn!(
                        "Encrypted watcher queue overflowed ({} drops); forcing full sync",
                        dropped
                    );
                    tracker
                        .sync(crypto, &encrypted_dir, &mountpoint)
                        .await
                        .map_err(|e| e.to_string())?;
                    if let Some(ref status_path) = runtime_status_path {
                        write_sync_runtime_status(status_path, &tracker.runtime_status());
                    }
                    persist_sync_baseline(&tracker);
                }
                if migration_automation_enabled {
                    drive_sync_migration_reporting(client).await;
                }
            }
            _ = poll.tick() => {
                tracker
                    .sync(crypto, &encrypted_dir, &mountpoint)
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(ref status_path) = runtime_status_path {
                    write_sync_runtime_status(status_path, &tracker.runtime_status());
                }
                persist_sync_baseline(&tracker);
                if watcher_overflow.swap(false, Ordering::SeqCst) {
                    let dropped = watcher_dropped.swap(0, Ordering::SeqCst);
                    warn!(
                        "Encrypted watcher queue overflowed ({} drops); forcing full sync",
                        dropped
                    );
                    tracker
                        .sync(crypto, &encrypted_dir, &mountpoint)
                        .await
                        .map_err(|e| e.to_string())?;
                    if let Some(ref status_path) = runtime_status_path {
                        write_sync_runtime_status(status_path, &tracker.runtime_status());
                    }
                    persist_sync_baseline(&tracker);
                }
                if migration_automation_enabled {
                    drive_sync_migration_reporting(client).await;
                }
            }
            _ = fast_drain.tick(), if tracker.has_fast_drain_work() => {
                tracker
                    .sync(crypto, &encrypted_dir, &mountpoint)
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(ref status_path) = runtime_status_path {
                    write_sync_runtime_status(status_path, &tracker.runtime_status());
                }
                persist_sync_baseline(&tracker);
            }
            _ = conflict_action_refresh.tick(), if (conflict_request_dir.is_some() && conflict_result_dir.is_some()) || (recovery_request_dir.is_some() && recovery_result_dir.is_some()) => {
                let mut processed_actions = false;
                if let (Some(request_dir), Some(result_dir)) = (
                    conflict_request_dir.as_ref(),
                    conflict_result_dir.as_ref(),
                ) {
                    if let Err(err) = fs::create_dir_all(request_dir) {
                        warn!(
                            "Failed to create mount conflict request directory {}: {}",
                            request_dir.display(),
                            err
                        );
                    }
                    if let Err(err) = fs::create_dir_all(result_dir) {
                        warn!(
                            "Failed to create mount conflict result directory {}: {}",
                            result_dir.display(),
                            err
                        );
                    }

                    let mut request_paths = match fs::read_dir(request_dir) {
                        Ok(entries) => entries
                            .flatten()
                            .map(|entry| entry.path())
                            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
                            .collect::<Vec<_>>(),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                        Err(err) => {
                            warn!(
                                "Failed to read mount conflict request directory {}: {}",
                                request_dir.display(),
                                err
                            );
                            Vec::new()
                        }
                    };
                    request_paths.sort();

                    for request_path in request_paths {
                        let request = match fs::read(&request_path)
                            .ok()
                            .and_then(|data| serde_json::from_slice::<ConflictResolutionRequest>(&data).ok())
                        {
                            Some(request) => request,
                            None => {
                                warn!(
                                    "Skipping malformed conflict request {}",
                                    request_path.display()
                                );
                                let _ = fs::remove_file(&request_path);
                                continue;
                            }
                        };

                        let response = match tracker.resolve_conflict_action(&mountpoint, &request) {
                            Ok(result) => {
                                processed_actions = true;
                                ConflictResolutionResponse {
                                    request_id: request.request_id,
                                    success: true,
                                    result: Some(result),
                                    error: None,
                                }
                            }
                            Err(err) => ConflictResolutionResponse {
                                request_id: request.request_id,
                                success: false,
                                result: None,
                                error: Some(err.to_string()),
                            },
                        };

                        let result_path = result_dir.join(format!("{}.json", request.request_id));
                        match serde_json::to_vec_pretty(&response) {
                            Ok(data) => {
                                if let Err(err) = SyncTracker::write_atomic_bytes(&result_path, &data) {
                                    warn!(
                                        "Failed to persist conflict resolution result {}: {}",
                                        result_path.display(),
                                        err
                                    );
                                }
                            }
                            Err(err) => {
                                warn!(
                                    "Failed to serialize conflict resolution response for {}: {}",
                                    request.request_id,
                                    err
                                );
                            }
                        }

                        let _ = fs::remove_file(&request_path);
                    }
                }

                if let (Some(request_dir), Some(result_dir)) = (
                    recovery_request_dir.as_ref(),
                    recovery_result_dir.as_ref(),
                ) {
                    if let Err(err) = fs::create_dir_all(request_dir) {
                        warn!(
                            "Failed to create mount recovery request directory {}: {}",
                            request_dir.display(),
                            err
                        );
                    }
                    if let Err(err) = fs::create_dir_all(result_dir) {
                        warn!(
                            "Failed to create mount recovery result directory {}: {}",
                            result_dir.display(),
                            err
                        );
                    }

                    let mut request_paths = match fs::read_dir(request_dir) {
                        Ok(entries) => entries
                            .flatten()
                            .map(|entry| entry.path())
                            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
                            .collect::<Vec<_>>(),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                        Err(err) => {
                            warn!(
                                "Failed to read mount recovery request directory {}: {}",
                                request_dir.display(),
                                err
                            );
                            Vec::new()
                        }
                    };
                    request_paths.sort();

                    for request_path in request_paths {
                        let request = match fs::read(&request_path)
                            .ok()
                            .and_then(|data| serde_json::from_slice::<RecoveryCopyResolutionRequest>(&data).ok())
                        {
                            Some(request) => request,
                            None => {
                                warn!(
                                    "Skipping malformed recovery request {}",
                                    request_path.display()
                                );
                                let _ = fs::remove_file(&request_path);
                                continue;
                            }
                        };

                        let response = match tracker.resolve_recovery_copy_action(&mountpoint, &request) {
                            Ok(result) => {
                                processed_actions = true;
                                RecoveryCopyResolutionResponse {
                                    request_id: request.request_id,
                                    success: true,
                                    result: Some(result),
                                    error: None,
                                }
                            }
                            Err(err) => RecoveryCopyResolutionResponse {
                                request_id: request.request_id,
                                success: false,
                                result: None,
                                error: Some(err.to_string()),
                            },
                        };

                        let result_path = result_dir.join(format!("{}.json", request.request_id));
                        match serde_json::to_vec_pretty(&response) {
                            Ok(data) => {
                                if let Err(err) = SyncTracker::write_atomic_bytes(&result_path, &data) {
                                    warn!(
                                        "Failed to persist recovery resolution result {}: {}",
                                        result_path.display(),
                                        err
                                    );
                                }
                            }
                            Err(err) => {
                                warn!(
                                    "Failed to serialize recovery resolution response for {}: {}",
                                    request.request_id,
                                    err
                                );
                            }
                        }

                        let _ = fs::remove_file(&request_path);
                    }
                }

                if processed_actions {
                    tracker
                        .sync(crypto, &encrypted_dir, &mountpoint)
                        .await
                        .map_err(|e| e.to_string())?;
                    if let Some(ref status_path) = runtime_status_path {
                        write_sync_runtime_status(status_path, &tracker.runtime_status());
                    }
                    persist_sync_baseline(&tracker);
                }
            }
            _ = state_refresh.tick() => {
                if migration_automation_enabled {
                    // Periodically reload client state to detect external rekey operations
                    if let Err(err) = client.ensure_state_loaded().await {
                        debug!("Failed to reload client state: {}", err);
                    } else {
                        // After reloading state, trigger rewrap processing if there are pending tasks
                        client.trigger_rewrap_processing().await;

                        if client.is_migrating().await {
                            let should_attempt = match last_discovery_at {
                                Some(at) => at.elapsed() >= discovery_cooldown,
                                None => true,
                            };

                            if should_attempt {
                                match client.rewrap_queue_snapshot().await {
                                    Ok(snapshot) if snapshot.pending_rewraps == 0 => {
                                        info!("Auto-discovering migration work (empty queue detected)");
                                        match client.populate_migration_queue().await {
                                            Ok(()) => {
                                                last_discovery_at = Some(Instant::now());
                                            }
                                            Err(err) => {
                                                last_discovery_at = Some(Instant::now());
                                                warn!("Auto-discovery failed: {}", err);
                                            }
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(err) => {
                                        last_discovery_at = Some(Instant::now());
                                        warn!("Failed to read rewrap queue snapshot: {}", err);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ = rekey_status_refresh.tick() => {
                if migration_automation_enabled && !client.is_migrating().await {
                    if let Err(err) = client.rekey_status().await {
                        debug!("Rekey status refresh skipped: {}", err);
                    }
                }
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn initialize_sync_migration_reporting<C: MountClient>(client: &C) {
    match client.rekey_status().await {
        Ok(Some(_)) => {
            // Schedule initial heartbeat to report file counts
            client.schedule_rekey_heartbeat().await;
        }
        Ok(None) => {
            // Even if no active rekey on server, we might have local migration state
            // Schedule heartbeat anyway - it will no-op if not applicable
            client.schedule_rekey_heartbeat().await;
        }
        Err(err) => log_sync_migration_error("rekey status bootstrap", &err),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn drive_sync_migration_reporting<C: MountClient>(client: &C) {
    if !client.is_migrating().await {
        return;
    }

    client.schedule_rekey_heartbeat().await;

    if let Err(err) = client.report_rekey_progress(None, None).await {
        log_sync_migration_error("progress update", &err);
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn log_sync_migration_error(context: &str, err: &ClientError) {
    use hybridcipher_client::ClientError::*;
    match err {
        InvalidState(_) | InvalidInput(_) | Migration(_) | SecurityViolation(_) => {
            debug!("Skipping mirror-mount {}: {}", context, err);
        }
        NetworkError { .. } | Network(_) | TimeoutError { .. } | Unauthorized(_) => {
            warn!("Mirror mount {} failed: {}", context, err);
        }
        _ => {
            warn!("Mirror mount {} error: {}", context, err);
        }
    }
}

/// Check FUSE prerequisites on Linux
#[cfg(target_os = "linux")]
pub fn fuse_prereqs() -> Result<(), String> {
    let fuse_device = Path::new("/dev/fuse");
    if !fuse_device.exists() {
        return Err(
            "FUSE device /dev/fuse not found. Install fuse3/fuse and ensure the kernel module is loaded.".to_string()
        );
    }

    if let Err(err) = OpenOptions::new().read(true).write(true).open(fuse_device) {
        return Err(format!(
            "Cannot access /dev/fuse: {err}. Add your user to the 'fuse' group and adjust permissions.",
        ));
    }

    if which("fusermount3").is_err() && which("fusermount").is_err() {
        return Err(
            "Neither fusermount3 nor fusermount found in PATH. Install the fuse3 (preferred) or fuse packages.".to_string()
        );
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn fuse_prereqs() -> Result<(), String> {
    Err("FUSE mounts are only available on Linux in this build.".to_string())
}

#[cfg(target_os = "linux")]
pub fn build_mount_options(volume_label: &str) -> MountOptions {
    MountOptions {
        allow_other: false,
        readonly: false,
        volume_name: Some(volume_label.to_string()),
        cache_size_mb: 256,
        max_operations: 64,
        debug: false,
    }
}

/// Determine the effective mount strategy based on platform and FUSE availability
pub fn determine_mount_strategy() -> MountStrategy {
    #[cfg(target_os = "linux")]
    {
        // Linux: Auto-detect FUSE availability, fall back to Sync
        match fuse_prereqs() {
            Ok(_) => {
                info!("Auto-select: FUSE support detected, using FUSE strategy.");
                MountStrategy::Fuse
            }
            Err(err) => {
                warn!("Auto-select: {}. Falling back to sync strategy.", err);
                MountStrategy::Sync
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        MountStrategy::Sync
    }
}

/// Clean up all files from mountpoint directory (for sync mounts)
/// CRITICAL: Only operates on mountpoint directories under ~/.hybridcipher/*_mount
fn cleanup_mountpoint_files(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    // Safety check: ensure this is a mountpoint directory
    let home = dirs::home_dir()
        .ok_or_else(|| "Unable to resolve home directory for safety check".to_string())?;
    let hybridcipher_base = home.join(".hybridcipher");

    // Ensure path is under .hybridcipher
    if !path.starts_with(&hybridcipher_base) {
        return Err(format!(
            "CRITICAL: Refusing to clean path {} - not a mountpoint directory (not under ~/.hybridcipher)",
            path.display()
        ));
    }

    // Additional safety: check if path looks like a mountpoint (contains _mount)
    let path_str = path.to_string_lossy();
    if !path_str.contains("_mount") && !path_str.ends_with("mount") {
        return Err(format!(
            "CRITICAL: Path {} does not look like a mountpoint directory. Refusing to clean.",
            path.display()
        ));
    }

    // Recursively remove all files and subdirectories
    if path.is_dir() {
        let entries = fs::read_dir(path).map_err(|e| {
            format!(
                "Failed to read mountpoint directory {}: {}",
                path.display(),
                e
            )
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                format!(
                    "Failed to read directory entry in {}: {}",
                    path.display(),
                    e
                )
            })?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                // Recursively remove subdirectory
                fs::remove_dir_all(&entry_path).map_err(|e| {
                    format!(
                        "Failed to remove subdirectory {}: {}",
                        entry_path.display(),
                        e
                    )
                })?;
            } else {
                // Remove file
                fs::remove_file(&entry_path).map_err(|e| {
                    format!("Failed to remove file {}: {}", entry_path.display(), e)
                })?;
            }
        }
    }

    Ok(())
}

/// Unmount a mountpoint, handling both FUSE and sync mounts
#[cfg(target_os = "linux")]
pub async fn unmount_mountpoint(
    mountpoint: &Path,
    strategy: MountStrategy,
    force: bool,
) -> Result<(), String> {
    match strategy {
        MountStrategy::Fuse => {
            if is_hybridcipher_mounted(mountpoint) {
                unmount_hybridcipher(mountpoint, force)
                    .await
                    .map_err(|e| format!("Failed to unmount FUSE mount: {}", e))
            } else {
                Ok(())
            }
        }
        MountStrategy::Sync => {
            // Sync mounts don't need special unmounting
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn unmount_mountpoint(
    _mountpoint: &Path,
    _strategy: MountStrategy,
    _force: bool,
) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConflictPolicy;
    use tempfile::TempDir;

    #[test]
    fn unclean_mountpoint_is_quarantined_and_recreated() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("demo_mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();
        fs::write(mountpoint.join("stale.txt"), b"stale plaintext").unwrap();

        let recovery_path =
            quarantine_unclean_mountpoint(&config_dir, &mountpoint, &encrypted_dir).unwrap();

        let recovery_path = recovery_path.expect("expected stale mountpoint to be quarantined");
        assert!(mountpoint.exists());
        assert!(!directory_has_entries(&mountpoint).unwrap());
        assert_eq!(
            fs::read(recovery_path.join("stale.txt")).unwrap(),
            b"stale plaintext"
        );
    }

    #[test]
    fn walk_mount_files_finds_all_files() {
        let temp = TempDir::new().unwrap();
        let mount = temp.path().join("mount");
        fs::create_dir_all(&mount).unwrap();
        fs::create_dir_all(mount.join("subdir")).unwrap();
        fs::write(mount.join("file1.txt"), b"content1").unwrap();
        fs::write(mount.join("file2.txt"), b"content2").unwrap();
        fs::write(mount.join("subdir/file3.txt"), b"content3").unwrap();

        let files = walk_mount_files(&mount).unwrap();

        assert_eq!(files.len(), 3);
        assert!(files.contains(&mount.join("file1.txt")));
        assert!(files.contains(&mount.join("file2.txt")));
        assert!(files.contains(&mount.join("subdir/file3.txt")));
    }

    #[test]
    fn move_file_to_recovery_preserves_structure() {
        let temp = TempDir::new().unwrap();
        let mount = temp.path().join("mount");
        let recovery = temp.path().join("recovery");
        fs::create_dir_all(&mount).unwrap();
        fs::create_dir_all(mount.join("subdir")).unwrap();
        fs::write(mount.join("subdir/file.txt"), b"content").unwrap();

        let dest =
            move_file_to_recovery(&mount.join("subdir/file.txt"), &mount, &recovery).unwrap();

        assert!(dest.starts_with(recovery.join("subdir")));
        let file_name = dest.file_name().and_then(|n| n.to_str()).unwrap();
        assert!(file_name.starts_with("file.txt.conflict-"));
        assert!(dest.exists());
        assert!(!mount.join("subdir/file.txt").exists());
        assert_eq!(fs::read(&dest).unwrap(), b"content");
    }

    #[test]
    fn cleanup_old_mount_recovery_dirs_removes_expired_entries() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let recovery_root = config_dir.join("mount_recovery");
        fs::create_dir_all(&recovery_root).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old = now.saturating_sub(40 * 24 * 60 * 60);
        let fresh = now.saturating_sub(2 * 24 * 60 * 60);

        let old_dir = recovery_root.join(format!("{}_mount_aaaaaa", old));
        let fresh_dir = recovery_root.join(format!("{}_mount_bbbbbb", fresh));
        fs::create_dir_all(&old_dir).unwrap();
        fs::create_dir_all(&fresh_dir).unwrap();
        fs::write(old_dir.join("file.txt"), b"old").unwrap();
        fs::write(fresh_dir.join("file.txt"), b"fresh").unwrap();

        cleanup_old_mount_recovery_dirs(&config_dir, 30).unwrap();

        assert!(!old_dir.exists());
        assert!(fresh_dir.exists());
    }

    #[test]
    fn reconcile_empty_mount_returns_no_recovery() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_policy(ConflictPolicy::default());

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        assert!(recovery_path.is_none());
        assert_eq!(summary.unchanged_count, 0);
        assert!(summary.local_created.is_empty());
        assert!(summary.conflicts.is_empty());
    }

    #[test]
    fn reconcile_detects_new_local_file() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        // Create a new file that wasn't there before (no stored signature)
        fs::write(mountpoint.join("new_file.txt"), b"new content").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_policy(ConflictPolicy::default());

        let (summary, _recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        // File should be detected as locally created (needs encryption)
        assert_eq!(summary.local_created.len(), 1);
        assert!(summary.local_created[0].ends_with("new_file.txt"));

        // Should be queued for background encryption
        assert_eq!(tracker.pending_local_creates().len(), 1);
    }

    #[test]
    fn reconcile_detects_multiple_new_files_in_subdirs() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(mountpoint.join("subdir")).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        // Create multiple new files
        fs::write(mountpoint.join("file1.txt"), b"content1").unwrap();
        fs::write(mountpoint.join("subdir/file2.txt"), b"content2").unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_policy(ConflictPolicy::default());

        let (summary, _) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        assert_eq!(summary.local_created.len(), 2);
        assert_eq!(tracker.pending_local_creates().len(), 2);
    }

    #[test]
    fn reconcile_detects_local_delete_and_queues_encrypted_delete() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        let deleted_mount = mountpoint.join("deleted.txt");
        fs::write(&deleted_mount, b"initial").unwrap();
        let deleted_mount_sig =
            FileSignature::from_metadata(&fs::metadata(&deleted_mount).unwrap());
        let deleted_encrypted = encrypted_dir.join("deleted.txt.encrypted");
        fs::write(&deleted_encrypted, b"enc").unwrap();
        let deleted_encrypted_sig =
            FileSignature::from_metadata(&fs::metadata(&deleted_encrypted).unwrap());

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_policy(ConflictPolicy::default());
        tracker.inject_decrypted_signature(deleted_mount.clone(), deleted_mount_sig);
        tracker.inject_encrypted_signature(deleted_encrypted.clone(), deleted_encrypted_sig);
        tracker.inject_path_mapping(deleted_encrypted.clone(), deleted_mount.clone());

        fs::remove_file(&deleted_mount).unwrap();
        // Keep mountpoint non-empty so this test exercises local-delete detection
        // instead of the empty-mount startup suppression guard.
        fs::write(mountpoint.join("sentinel.txt"), b"keep").unwrap();

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        assert!(recovery_path.is_none());
        assert_eq!(summary.local_deleted.len(), 1);
        assert_eq!(summary.local_deleted[0], deleted_mount);
        assert_eq!(tracker.pending_local_deletes().len(), 1);
        assert_eq!(tracker.pending_local_deletes()[0], deleted_encrypted);
    }

    #[test]
    fn reconcile_empty_mount_suppresses_mass_local_deletes() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        let tracked_mount = mountpoint.join("tracked.txt");
        fs::write(&tracked_mount, b"initial").unwrap();
        let tracked_mount_sig =
            FileSignature::from_metadata(&fs::metadata(&tracked_mount).unwrap());
        let tracked_encrypted = encrypted_dir.join("tracked.txt.encrypted");
        fs::write(&tracked_encrypted, b"enc").unwrap();
        let tracked_encrypted_sig =
            FileSignature::from_metadata(&fs::metadata(&tracked_encrypted).unwrap());

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_policy(ConflictPolicy::default());
        tracker.inject_decrypted_signature(tracked_mount.clone(), tracked_mount_sig);
        tracker.inject_encrypted_signature(tracked_encrypted.clone(), tracked_encrypted_sig);
        tracker.inject_path_mapping(tracked_encrypted.clone(), tracked_mount.clone());

        fs::remove_file(&tracked_mount).unwrap();

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        assert!(recovery_path.is_none());
        assert!(summary.local_deleted.is_empty());
        assert!(tracker.pending_local_deletes().is_empty());
    }

    #[test]
    fn reconcile_rejects_excessive_startup_local_deletes() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_policy(ConflictPolicy::default());

        for i in 0..=20 {
            let mount_path = mountpoint.join(format!("tracked_{}.txt", i));
            fs::write(&mount_path, b"initial").unwrap();
            let mount_sig = FileSignature::from_metadata(&fs::metadata(&mount_path).unwrap());
            let enc_path = encrypted_dir.join(format!("tracked_{}.txt.encrypted", i));
            fs::write(&enc_path, b"enc").unwrap();
            let enc_sig = FileSignature::from_metadata(&fs::metadata(&enc_path).unwrap());
            tracker.inject_decrypted_signature(mount_path.clone(), mount_sig);
            tracker.inject_encrypted_signature(enc_path.clone(), enc_sig);
            tracker.inject_path_mapping(enc_path, mount_path.clone());
            fs::remove_file(&mount_path).unwrap();
        }
        // Keep mountpoint non-empty so reconciliation does not take the
        // empty-mount suppression path and can exercise the threshold guard.
        fs::write(mountpoint.join("sentinel.txt"), b"keep").unwrap();

        let err =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap_err();
        assert!(err.contains("refusing to queue"));
    }

    #[test]
    fn reconcile_nested_create_and_delete_in_single_pass() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();
        fs::create_dir_all(mountpoint.join("old/sub")).unwrap();
        fs::create_dir_all(mountpoint.join("new/deep")).unwrap();

        let deleted_mount = mountpoint.join("old/sub/gone.txt");
        fs::write(&deleted_mount, b"before").unwrap();
        let deleted_mount_sig =
            FileSignature::from_metadata(&fs::metadata(&deleted_mount).unwrap());
        let deleted_encrypted = encrypted_dir.join("old/sub/gone.txt.encrypted");
        if let Some(parent) = deleted_encrypted.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&deleted_encrypted, b"enc-before").unwrap();
        let deleted_encrypted_sig =
            FileSignature::from_metadata(&fs::metadata(&deleted_encrypted).unwrap());

        let mut tracker = SyncTracker::new();
        tracker.set_conflict_policy(ConflictPolicy::default());
        tracker.inject_decrypted_signature(deleted_mount.clone(), deleted_mount_sig);
        tracker.inject_encrypted_signature(deleted_encrypted.clone(), deleted_encrypted_sig);
        tracker.inject_path_mapping(deleted_encrypted.clone(), deleted_mount.clone());

        fs::remove_file(&deleted_mount).unwrap();
        let created_mount = mountpoint.join("new/deep/created.txt");
        fs::write(&created_mount, b"new-content").unwrap();

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        assert!(recovery_path.is_none());
        assert_eq!(summary.local_created.len(), 1);
        assert_eq!(summary.local_created[0], created_mount);
        assert_eq!(summary.local_deleted.len(), 1);
        assert_eq!(summary.local_deleted[0], deleted_mount);
        assert_eq!(tracker.pending_local_creates().len(), 1);
        assert_eq!(tracker.pending_local_deletes().len(), 1);
    }

    #[test]
    fn reconcile_with_keep_both_policy_moves_conflicts_to_recovery() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        // Create initial local file
        let mount_file = mountpoint.join("conflict.txt");
        fs::write(&mount_file, b"original local").unwrap();
        let original_local_sig = FileSignature::from_metadata(&fs::metadata(&mount_file).unwrap());

        // Create corresponding encrypted file
        let encrypted_file = encrypted_dir.join("conflict.txt.encrypted");
        fs::write(&encrypted_file, b"original encrypted").unwrap();
        let original_enc_sig =
            FileSignature::from_metadata(&fs::metadata(&encrypted_file).unwrap());

        let mut tracker = SyncTracker::new();

        // Store original signatures (as if we had a clean mount before)
        tracker.inject_decrypted_signature(mount_file.clone(), original_local_sig);
        tracker.inject_encrypted_signature(encrypted_file.clone(), original_enc_sig);
        tracker.inject_path_mapping(encrypted_file.clone(), mount_file.clone());

        // Now simulate both sides changing:
        // 1. Local file is modified
        std::thread::sleep(std::time::Duration::from_millis(50)); // Ensure different mtime
        fs::write(&mount_file, b"modified local version").unwrap();

        // 2. Encrypted file is modified (simulating remote change)
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(&encrypted_file, b"modified encrypted content").unwrap();

        // Use KeepBoth policy (default)
        tracker.set_conflict_policy(ConflictPolicy::default());

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        // Should detect as conflict
        assert_eq!(
            summary.conflicts.len(),
            1,
            "Expected 1 conflict, got {:?}",
            summary
        );
        assert_eq!(
            summary.conflicts[0].1,
            ConflictKind::LocalRemoteBothModified
        );

        // With KeepBoth, local file should be moved to recovery
        assert!(
            recovery_path.is_some(),
            "Expected recovery path for KeepBoth policy"
        );
        let recovery = recovery_path.unwrap();
        let mut entries = fs::read_dir(&recovery).unwrap();
        let entry = entries.next().unwrap().unwrap().path();
        assert!(entry
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap()
            .starts_with("conflict.txt.conflict-"));
        assert_eq!(fs::read(entry).unwrap(), b"modified local version");
    }

    #[test]
    fn reconcile_with_local_wins_policy_queues_encryption() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        let mount_file = mountpoint.join("conflict.txt");
        fs::write(&mount_file, b"original local").unwrap();
        let original_local_sig = FileSignature::from_metadata(&fs::metadata(&mount_file).unwrap());

        let encrypted_file = encrypted_dir.join("conflict.txt.encrypted");
        fs::write(&encrypted_file, b"original encrypted").unwrap();
        let original_enc_sig =
            FileSignature::from_metadata(&fs::metadata(&encrypted_file).unwrap());

        let mut tracker = SyncTracker::new();

        tracker.inject_decrypted_signature(mount_file.clone(), original_local_sig);
        tracker.inject_encrypted_signature(encrypted_file.clone(), original_enc_sig);
        tracker.inject_path_mapping(encrypted_file.clone(), mount_file.clone());

        // Modify both sides
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(&mount_file, b"modified local version").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(&encrypted_file, b"modified encrypted").unwrap();

        // Use LocalWins policy
        tracker.set_conflict_policy(ConflictPolicy {
            default_resolution: crate::ConflictPolicyResolution::LocalWins,
            timestamp_threshold_secs: 5,
        });

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        // Should detect as conflict
        assert_eq!(summary.conflicts.len(), 1, "Expected 1 conflict");

        // With LocalWins, no recovery folder needed - file stays in place and queued for encryption
        assert!(
            recovery_path.is_none(),
            "LocalWins should not create recovery"
        );
        assert!(mount_file.exists(), "Local file should still exist");
        assert_eq!(
            tracker.pending_local_creates().len(),
            1,
            "Should queue for encryption"
        );
    }

    #[test]
    fn reconcile_with_remote_wins_policy_removes_local() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        let mount_file = mountpoint.join("conflict.txt");
        fs::write(&mount_file, b"original local").unwrap();
        let original_local_sig = FileSignature::from_metadata(&fs::metadata(&mount_file).unwrap());

        let encrypted_file = encrypted_dir.join("conflict.txt.encrypted");
        fs::write(&encrypted_file, b"original encrypted").unwrap();
        let original_enc_sig =
            FileSignature::from_metadata(&fs::metadata(&encrypted_file).unwrap());

        let mut tracker = SyncTracker::new();

        tracker.inject_decrypted_signature(mount_file.clone(), original_local_sig);
        tracker.inject_encrypted_signature(encrypted_file.clone(), original_enc_sig);
        tracker.inject_path_mapping(encrypted_file.clone(), mount_file.clone());

        // Modify both sides
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(&mount_file, b"modified local version").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(&encrypted_file, b"modified encrypted").unwrap();

        // Use RemoteWins policy (legacy behavior)
        tracker.set_conflict_policy(ConflictPolicy {
            default_resolution: crate::ConflictPolicyResolution::RemoteWins,
            timestamp_threshold_secs: 5,
        });

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        assert_eq!(summary.conflicts.len(), 1, "Expected 1 conflict");

        // With RemoteWins, local file should be deleted (will be restored from encrypted)
        assert!(
            recovery_path.is_none(),
            "RemoteWins should not create recovery"
        );
        assert!(
            !mount_file.exists(),
            "Local file should be deleted with RemoteWins"
        );
    }

    #[test]
    fn reconcile_with_newer_wins_uses_local_when_newer() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        // Create encrypted file FIRST (older)
        let encrypted_file = encrypted_dir.join("conflict.txt.encrypted");
        fs::write(&encrypted_file, b"original encrypted").unwrap();
        let original_enc_sig =
            FileSignature::from_metadata(&fs::metadata(&encrypted_file).unwrap());

        // Wait and create local file (newer)
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mount_file = mountpoint.join("conflict.txt");
        fs::write(&mount_file, b"original local").unwrap();
        let original_local_sig = FileSignature::from_metadata(&fs::metadata(&mount_file).unwrap());

        let mut tracker = SyncTracker::new();

        tracker.inject_decrypted_signature(mount_file.clone(), original_local_sig);
        tracker.inject_encrypted_signature(encrypted_file.clone(), original_enc_sig);
        tracker.inject_path_mapping(encrypted_file.clone(), mount_file.clone());

        // Modify both sides - local modified last (will be newer)
        std::thread::sleep(std::time::Duration::from_millis(100));
        fs::write(&encrypted_file, b"modified encrypted").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        fs::write(&mount_file, b"modified local - NEWER").unwrap();

        // Use NewerWins policy with 0 threshold (so it actually picks a winner)
        tracker.set_conflict_policy(ConflictPolicy {
            default_resolution: crate::ConflictPolicyResolution::NewerWins,
            timestamp_threshold_secs: 0,
        });

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        assert_eq!(summary.conflicts.len(), 1, "Expected 1 conflict");

        // Local is newer, should be queued for encryption (no recovery needed)
        assert!(
            recovery_path.is_none(),
            "NewerWins with newer local should not need recovery"
        );
        assert!(mount_file.exists(), "Local file should still exist");
        assert_eq!(
            tracker.pending_local_creates().len(),
            1,
            "Should queue newer local for encryption"
        );
    }

    #[test]
    fn reconcile_with_newer_wins_uses_remote_when_newer() {
        let temp = TempDir::new().unwrap();
        let config_dir = temp.path().join("config");
        let mountpoint = temp.path().join("mount");
        let encrypted_dir = temp.path().join("encrypted");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&mountpoint).unwrap();
        fs::create_dir_all(&encrypted_dir).unwrap();

        // Create local file FIRST (older)
        let mount_file = mountpoint.join("conflict.txt");
        fs::write(&mount_file, b"original local").unwrap();
        let original_local_sig = FileSignature::from_metadata(&fs::metadata(&mount_file).unwrap());

        // Wait and create encrypted file (newer)
        std::thread::sleep(std::time::Duration::from_millis(100));
        let encrypted_file = encrypted_dir.join("conflict.txt.encrypted");
        fs::write(&encrypted_file, b"original encrypted").unwrap();
        let original_enc_sig =
            FileSignature::from_metadata(&fs::metadata(&encrypted_file).unwrap());

        let mut tracker = SyncTracker::new();

        tracker.inject_decrypted_signature(mount_file.clone(), original_local_sig);
        tracker.inject_encrypted_signature(encrypted_file.clone(), original_enc_sig);
        tracker.inject_path_mapping(encrypted_file.clone(), mount_file.clone());

        // Modify both sides - encrypted modified last (will be newer)
        std::thread::sleep(std::time::Duration::from_millis(100));
        fs::write(&mount_file, b"modified local - OLDER").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        fs::write(&encrypted_file, b"modified encrypted - NEWER").unwrap();

        // Use NewerWins policy
        tracker.set_conflict_policy(ConflictPolicy {
            default_resolution: crate::ConflictPolicyResolution::NewerWins,
            timestamp_threshold_secs: 0,
        });

        let (summary, recovery_path) =
            reconcile_unclean_mount(&config_dir, &mountpoint, &encrypted_dir, &mut tracker, 20)
                .unwrap();

        assert_eq!(summary.conflicts.len(), 1, "Expected 1 conflict");

        // Remote is newer, local should be deleted
        assert!(
            recovery_path.is_none(),
            "NewerWins with newer remote should not need recovery"
        );
        assert!(!mount_file.exists(), "Older local file should be deleted");
    }

    #[test]
    fn mountpoint_is_empty_detects_empty_and_non_empty_states() {
        let temp = TempDir::new().unwrap();
        let mountpoint = temp.path().join("mount");
        fs::create_dir_all(&mountpoint).unwrap();

        assert!(mountpoint_is_empty(&mountpoint).unwrap());

        fs::write(mountpoint.join("file.txt"), b"data").unwrap();
        assert!(!mountpoint_is_empty(&mountpoint).unwrap());
    }
}
