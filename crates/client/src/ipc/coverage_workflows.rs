use crate::coverage::{CoverageRoot, CoverageRootKind};
use crate::errors::{ClientError, ErrorCode};
use crate::file::{
    encrypt::SparseFileMetadata,
    write_encrypted_file_atomic_for_coverage_with_sync as write_encrypted_file_with_header,
    SerializedEncryptedHeader,
};
use crate::ipc::coverage::{
    CoverageDecryptProgress, CoverageEnrollOutcome, CoverageEnrollPhase, CoverageEnrollProgress,
    CoverageHydrationSummary, CoverageUnenrollOutcome,
};
use crate::network::Network;
use crate::state::client::{Client, CoverageScanProgress};
use crate::storage::{AccessControlData, FileMetadataData, Storage};
use crate::EncryptedFileMetadata;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use filetime::{set_file_mtime, set_file_times, FileTime};
use log::warn;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs as async_fs;
use tokio::sync::mpsc;
use uuid::Uuid;

const METADATA_SCAN_LIMIT: usize = 64 * 1024;
const ENCRYPTED_FILE_SEPARATOR: &str = "\n---ENCRYPTED_DATA---\n";

#[derive(Debug)]
struct EncryptFileOutcome {
    encrypted_path: PathBuf,
    file_id: String,
    epoch_id: u64,
    group_id: Option<Uuid>,
    original_size: u64,
    encrypted_size: u64,
    created_at: chrono::DateTime<Utc>,
    header_version: u32,
    wrapped_file_key: Option<Vec<u8>>,
    key_wrap_nonce: Option<Vec<u8>>,
    key_wrap_aad_hash: Option<Vec<u8>>,
    content_nonce: Option<Vec<u8>>,
    content_chunk_size: Option<u64>,
    plaintext_hash: [u8; 32],
}

#[derive(Debug)]
struct ParsedEncryptedFile {
    metadata: EncryptedFileMetadata,
    original_name: Option<String>,
}

#[derive(Debug)]
struct ExistingEncryptionMetadata {
    #[allow(dead_code)]
    file_id: String,
    #[allow(dead_code)]
    group_id: Option<Uuid>,
    #[allow(dead_code)]
    epoch_id: u64,
}

pub async fn enroll_and_hydrate<S, N>(
    client: &Client<S, N>,
    path: PathBuf,
) -> Result<CoverageEnrollOutcome, ClientError>
where
    S: Storage,
    N: Network,
{
    let mut noop = |_progress: CoverageEnrollProgress| {};
    enroll_and_hydrate_with_progress(client, path, &mut noop).await
}

pub async fn enroll_and_hydrate_with_progress<S, N>(
    client: &Client<S, N>,
    path: PathBuf,
    on_progress: &mut (dyn FnMut(CoverageEnrollProgress) + Send),
) -> Result<CoverageEnrollOutcome, ClientError>
where
    S: Storage,
    N: Network,
{
    let root = client.coverage_enroll_root(&path).await?;
    client
        .mark_coverage_enrollment_in_progress(root.root_id)
        .await;
    let hydration_result = hydrate_root_after_enroll(client, &root, Some(on_progress)).await;
    client
        .clear_coverage_enrollment_in_progress(root.root_id)
        .await;
    let hydration = hydration_result?;
    on_progress(CoverageEnrollProgress {
        phase: CoverageEnrollPhase::Finalizing,
        total_files: hydration.scanned_files,
        processed_files: hydration.scanned_files,
        newly_encrypted: hydration.newly_encrypted,
        skipped_due_to_errors: hydration.skipped_due_to_errors,
    });
    let scan =
        coverage_rescan_after_enroll_with_progress(client, &root, &hydration, on_progress).await?;

    client.start_coverage_replication();
    client.start_coverage_watchers().await?;

    log_hydration_warning_summary(&root, &hydration);

    Ok(CoverageEnrollOutcome {
        root,
        hydration,
        scan,
    })
}

pub async fn unenroll_and_decrypt<S, N>(
    client: &Client<S, N>,
    path: PathBuf,
) -> Result<CoverageUnenrollOutcome, ClientError>
where
    S: Storage,
    N: Network,
{
    let mut noop = |_progress: CoverageDecryptProgress| {};
    unenroll_and_decrypt_with_progress(client, path, &mut noop).await
}

pub async fn unenroll_and_decrypt_with_progress<S, N>(
    client: &Client<S, N>,
    path: PathBuf,
    on_progress: &mut (dyn FnMut(CoverageDecryptProgress) + Send),
) -> Result<CoverageUnenrollOutcome, ClientError>
where
    S: Storage,
    N: Network,
{
    let root = client.coverage_unenroll_root(&path).await?;
    let decrypted_files = if root.path.exists() {
        match root.kind {
            CoverageRootKind::SingleFile => {
                decrypt_file_in_place_with_progress(client, &root.path, Some(on_progress)).await?
                    as usize
            }
            CoverageRootKind::Folder => {
                decrypt_directory_in_place_with_progress(client, &root.path, Some(on_progress))
                    .await?
            }
        }
    } else {
        0
    };

    Ok(CoverageUnenrollOutcome {
        root,
        decrypted_files,
    })
}

fn log_hydration_warning_summary(root: &CoverageRoot, summary: &CoverageHydrationSummary) {
    if summary.warnings.is_empty() && summary.errors.is_empty() {
        return;
    }

    warn!(
        "Coverage enrollment for {} produced {} warning(s) and {} error(s)",
        root.path.display(),
        summary.warnings.len(),
        summary.errors.len()
    );

    for warning in &summary.warnings {
        warn!("[coverage-enroll] {}", warning);
    }
    for error in &summary.errors {
        warn!("[coverage-enroll] {}", error);
    }
}

async fn coverage_rescan_after_enroll_with_progress<S, N>(
    client: &Client<S, N>,
    root: &CoverageRoot,
    hydration: &CoverageHydrationSummary,
    on_progress: &mut (dyn FnMut(CoverageEnrollProgress) + Send),
) -> Result<crate::state::client::CoverageScanSummary, ClientError>
where
    S: Storage,
    N: Network,
{
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<(usize, usize)>();
    let progress_cb: CoverageScanProgress = Arc::new(
        move |_root: &CoverageRoot, processed: usize, total: usize| {
            let _ = progress_tx.send((processed, total));
        },
    );
    let mut rescan_task =
        Box::pin(client.coverage_rescan_with_progress(Some(root.path.clone()), Some(progress_cb)));

    loop {
        tokio::select! {
            maybe_progress = progress_rx.recv() => {
                if let Some((processed, total)) = maybe_progress {
                    emit_rescan_enroll_progress(on_progress, hydration, processed, total);
                }
            }
            result = &mut rescan_task => {
                let summary = result?;
                while let Ok((processed, total)) = progress_rx.try_recv() {
                    emit_rescan_enroll_progress(on_progress, hydration, processed, total);
                }
                if summary.files_indexed > 0 {
                    on_progress(CoverageEnrollProgress {
                        phase: CoverageEnrollPhase::Rescanning,
                        total_files: summary.files_indexed,
                        processed_files: summary.files_indexed,
                        newly_encrypted: hydration.newly_encrypted,
                        skipped_due_to_errors: hydration.skipped_due_to_errors,
                    });
                }
                return Ok(summary);
            }
        }
    }
}

fn emit_rescan_enroll_progress(
    on_progress: &mut (dyn FnMut(CoverageEnrollProgress) + Send),
    hydration: &CoverageHydrationSummary,
    processed: usize,
    total: usize,
) {
    if total == 0 {
        return;
    }

    on_progress(CoverageEnrollProgress {
        phase: CoverageEnrollPhase::Rescanning,
        total_files: total,
        processed_files: processed.min(total),
        newly_encrypted: hydration.newly_encrypted,
        skipped_due_to_errors: hydration.skipped_due_to_errors,
    });
}

fn count_enrollment_candidates<S, N>(client: &Client<S, N>, root: &CoverageRoot) -> usize
where
    S: Storage,
    N: Network,
{
    match root.kind {
        CoverageRootKind::SingleFile => {
            if root.path.is_file() && !client.is_path_excluded(&root.path) {
                1
            } else {
                0
            }
        }
        CoverageRootKind::Folder => {
            let mut count = 0usize;
            let mut stack = vec![root.path.clone()];

            while let Some(current) = stack.pop() {
                let entries = match fs::read_dir(&current) {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };

                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(_) => continue,
                    };
                    let path = entry.path();

                    let file_type = match entry.file_type() {
                        Ok(kind) => kind,
                        Err(_) => continue,
                    };

                    if client.is_path_excluded(&path) {
                        continue;
                    }

                    if file_type.is_dir() {
                        stack.push(path);
                    } else if file_type.is_file() {
                        count += 1;
                    }
                }
            }

            count
        }
    }
}

fn dynamic_enroll_cadence(remaining_files: usize) -> usize {
    if remaining_files < 100 {
        1
    } else if remaining_files < 1_000 {
        10
    } else if remaining_files <= 10_000 {
        100
    } else {
        1_000
    }
}

async fn hydrate_root_after_enroll<S, N>(
    client: &Client<S, N>,
    root: &CoverageRoot,
    mut on_progress: Option<&mut (dyn FnMut(CoverageEnrollProgress) + Send)>,
) -> Result<CoverageHydrationSummary, ClientError>
where
    S: Storage,
    N: Network,
{
    let _bulk_guard = client.begin_coverage_bulk_operation().await;
    let mut summary = CoverageHydrationSummary::default();
    let total_files = count_enrollment_candidates(client, root);
    let mut last_reported = 0usize;
    let mut processed_since_sync = 0usize;

    match root.kind {
        CoverageRootKind::SingleFile => {
            if client.is_path_excluded(&root.path) {
                summary.warnings.push(format!(
                    "Skipped {} (excluded by configuration)",
                    root.path.display()
                ));
                maybe_send_enroll_progress(
                    &mut on_progress,
                    total_files,
                    &summary,
                    &mut last_reported,
                    true,
                );
                return Ok(summary);
            }

            process_candidate_file(client, &root.path, &mut summary, true).await?;
            maybe_send_enroll_progress(
                &mut on_progress,
                total_files,
                &summary,
                &mut last_reported,
                true,
            );
        }
        CoverageRootKind::Folder => {
            let mut stack = vec![root.path.clone()];
            while let Some(current) = stack.pop() {
                let read_dir = match fs::read_dir(&current) {
                    Ok(entries) => entries,
                    Err(err) => {
                        summary.errors.push(format!(
                            "Failed to enumerate {}: {}",
                            current.display(),
                            err
                        ));
                        continue;
                    }
                };

                for entry in read_dir {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            summary.errors.push(format!(
                                "Failed to read entry under {}: {}",
                                current.display(),
                                err
                            ));
                            continue;
                        }
                    };

                    let file_type = match entry.file_type() {
                        Ok(kind) => kind,
                        Err(err) => {
                            summary.errors.push(format!(
                                "Failed to inspect {}: {}",
                                entry.path().display(),
                                err
                            ));
                            continue;
                        }
                    };

                    let path = entry.path();
                    if client.is_path_excluded(&path) {
                        summary.warnings.push(format!(
                            "Skipped {} (excluded by configuration)",
                            path.display()
                        ));
                        continue;
                    }

                    if file_type.is_dir() {
                        stack.push(path);
                    } else if file_type.is_file() {
                        let remaining_before = total_files.saturating_sub(summary.scanned_files);
                        let sync_cadence = dynamic_enroll_cadence(remaining_before);
                        let should_sync =
                            processed_since_sync + 1 >= sync_cadence || remaining_before <= 1;
                        process_candidate_file(client, &path, &mut summary, should_sync).await?;
                        if should_sync {
                            processed_since_sync = 0;
                        } else {
                            processed_since_sync = processed_since_sync.saturating_add(1);
                        }
                        maybe_send_enroll_progress(
                            &mut on_progress,
                            total_files,
                            &summary,
                            &mut last_reported,
                            false,
                        );
                    }
                }
            }
        }
    }

    maybe_send_enroll_progress(
        &mut on_progress,
        total_files,
        &summary,
        &mut last_reported,
        true,
    );

    Ok(summary)
}

fn maybe_send_enroll_progress(
    on_progress: &mut Option<&mut (dyn FnMut(CoverageEnrollProgress) + Send)>,
    total_files: usize,
    summary: &CoverageHydrationSummary,
    last_reported: &mut usize,
    force: bool,
) {
    if total_files == 0 {
        return;
    }

    let processed_files = summary.scanned_files.min(total_files);
    let remaining_files = total_files.saturating_sub(processed_files);
    let progress_cadence = dynamic_enroll_cadence(remaining_files);
    let progress_delta = processed_files.saturating_sub(*last_reported);

    if !force && progress_delta < progress_cadence {
        return;
    }
    *last_reported = processed_files;

    if let Some(callback) = on_progress.as_mut() {
        (*callback)(CoverageEnrollProgress {
            phase: CoverageEnrollPhase::Hydrating,
            total_files,
            processed_files,
            newly_encrypted: summary.newly_encrypted,
            skipped_due_to_errors: summary.skipped_due_to_errors,
        });
    }
}

async fn process_candidate_file<S, N>(
    client: &Client<S, N>,
    file_path: &Path,
    summary: &mut CoverageHydrationSummary,
    sync_to_disk: bool,
) -> Result<(), ClientError>
where
    S: Storage,
    N: Network,
{
    if client.is_path_excluded(file_path) {
        summary.warnings.push(format!(
            "Skipped {} (excluded by configuration)",
            file_path.display()
        ));
        return Ok(());
    }

    summary.scanned_files += 1;

    match client.coverage_has_metadata_for_path(file_path).await {
        Ok(true) => {
            summary.already_tracked += 1;
            return Ok(());
        }
        Ok(false) => {}
        Err(err) => {
            summary.errors.push(format!(
                "Metadata lookup failed for {}: {}",
                file_path.display(),
                err
            ));
            summary.skipped_due_to_errors += 1;
            return Ok(());
        }
    }

    if extension_is_encrypted(file_path) {
        summary.already_encrypted_without_metadata += 1;
        summary.warnings.push(format!(
            "{} already looks encrypted but metadata is missing; run 'hybridcipher recovery fetch' if this device was reprovisioned.",
            file_path.display()
        ));
        return Ok(());
    }

    match detect_existing_encryption_metadata(file_path) {
        Ok(Some(_)) => {
            summary.already_encrypted_without_metadata += 1;
            summary.warnings.push(format!(
                "{} contains HybridCipher metadata but no local record; use 'hybridcipher recovery fetch' to restore coverage.",
                file_path.display()
            ));
            return Ok(());
        }
        Ok(None) => {}
        Err(err) => {
            summary.errors.push(format!(
                "Failed to inspect {} for HybridCipher metadata: {}",
                file_path.display(),
                err
            ));
            summary.skipped_due_to_errors += 1;
            return Ok(());
        }
    }

    let parent_dir = file_path.parent().map(|dir| dir.to_path_buf());
    let parent_mtime = parent_dir
        .as_ref()
        .and_then(|dir| capture_directory_mtime(dir));

    match encrypt_file_to_path(client, file_path, sync_to_disk).await {
        Ok(outcome) => {
            if let Err(err) = preserve_file_mtime(file_path, &outcome.encrypted_path) {
                summary.warnings.push(format!(
                    "Failed to preserve mtime for {}: {}",
                    file_path.display(),
                    err
                ));
            }

            if let Err(err) = async_fs::remove_file(file_path).await {
                summary.errors.push(format!(
                    "Failed to remove plaintext {} after encryption: {}",
                    file_path.display(),
                    err
                ));
                summary.skipped_due_to_errors += 1;
                return Ok(());
            }

            let canonical_path = match fs::canonicalize(&outcome.encrypted_path) {
                Ok(path) => path,
                Err(err) => {
                    summary.warnings.push(format!(
                        "Failed to canonicalize {}: {}",
                        outcome.encrypted_path.display(),
                        err
                    ));
                    outcome.encrypted_path.clone()
                }
            };

            let metadata_record = FileMetadataData {
                file_path: canonical_path.to_string_lossy().to_string(),
                file_id: Some(outcome.file_id.clone()),
                group_id: outcome.group_id,
                epoch_id: outcome.epoch_id,
                header_version: Some(outcome.header_version),
                wrapped_file_key: outcome.wrapped_file_key.clone(),
                key_wrap_nonce: outcome.key_wrap_nonce.clone(),
                key_wrap_aad_hash: outcome.key_wrap_aad_hash.clone(),
                content_nonce: outcome.content_nonce.clone(),
                content_chunk_size: outcome.content_chunk_size,
                algorithm: "ChaCha20-Poly1305".to_string(),
                file_size: outcome.original_size,
                modified_at: Utc::now(),
                integrity_hash: outcome.plaintext_hash,
                permissions: AccessControlData {
                    readers: Vec::new(),
                    writers: Vec::new(),
                    is_public: false,
                },
                version: 1,
                chunks: Vec::new(),
                encrypted_size: outcome.encrypted_size,
                encrypted_at: outcome.created_at,
            };

            match client.coverage_store_file_metadata(metadata_record).await {
                Ok(_) => {
                    summary.newly_encrypted += 1;
                }
                Err(err) => {
                    summary.errors.push(format!(
                        "Failed to store metadata for {}: {}",
                        canonical_path.display(),
                        err
                    ));
                    summary.skipped_due_to_errors += 1;
                }
            }

            if let Some(dir) = parent_dir.as_deref() {
                preserve_directory_mtime(dir, parent_mtime);
            }
        }
        Err(err) => {
            summary.errors.push(format!(
                "Auto-encryption failed for {}: {}",
                file_path.display(),
                err
            ));
            summary.skipped_due_to_errors += 1;
        }
    }

    Ok(())
}

async fn encrypt_file_to_path<S, N>(
    client: &Client<S, N>,
    source_path: &Path,
    sync_to_disk: bool,
) -> Result<EncryptFileOutcome, ClientError>
where
    S: Storage,
    N: Network,
{
    let plaintext = async_fs::read(source_path).await.map_err(|err| {
        storage_error(
            ErrorCode::StorageRead,
            format!(
                "Failed to read {} for encryption: {}",
                source_path.display(),
                err
            ),
            "coverage_encrypt_read",
        )
    })?;

    let mut plaintext_hash = [0u8; 32];
    plaintext_hash.copy_from_slice(&Sha256::digest(&plaintext));

    let aad_label = source_path.to_string_lossy().to_string();

    let encrypted = client
        .encrypt_file(&aad_label, &plaintext)
        .await
        .map_err(|err| ClientError::InvalidState(err.to_string()))?;

    let target_path = ensure_encrypted_suffix(default_encrypted_path(source_path), source_path);
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            storage_error(
                ErrorCode::StorageWrite,
                format!("Failed to create directory {}: {}", parent.display(), err),
                "coverage_encrypt_mkdir",
            )
        })?;
    }

    let original_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let wrapped_file_key = encrypted.wrapped_file_key.as_ref().ok_or_else(|| {
        ClientError::InvalidState("Missing wrapped_file_key in encryption metadata".to_string())
    })?;
    let key_wrap_nonce = encrypted.key_wrap_nonce.as_ref().ok_or_else(|| {
        ClientError::InvalidState("Missing key_wrap_nonce in encryption metadata".to_string())
    })?;
    let key_wrap_aad_hash = encrypted.key_wrap_aad_hash.as_ref().ok_or_else(|| {
        ClientError::InvalidState("Missing key_wrap_aad_hash in encryption metadata".to_string())
    })?;
    let content_nonce = encrypted.content_nonce.as_ref().ok_or_else(|| {
        ClientError::InvalidState("Missing content_nonce in encryption metadata".to_string())
    })?;

    let header = SerializedEncryptedHeader {
        file_id: &encrypted.file_id,
        file_path: &encrypted.file_path,
        group_id: encrypted.group_id,
        epoch_id: encrypted.epoch_id,
        header_version: encrypted.header_version.unwrap_or(1),
        wrapped_file_key,
        key_wrap_nonce,
        key_wrap_aad_hash,
        content_nonce,
        content_chunk_size: encrypted.content_chunk_size,
        original_size: encrypted.content_size,
        encrypted_size: encrypted.encrypted_size,
        encrypted_at: encrypted.created_at,
        original_name: original_name.as_deref(),
        platform_metadata: encrypted.platform_metadata.as_ref(),
        sparse_metadata: encrypted.sparse_metadata.as_ref(),
    };

    write_encrypted_file_with_header(
        &target_path,
        &header,
        &encrypted.encrypted_content,
        sync_to_disk,
    )
    .map_err(|err| {
        storage_error(
            ErrorCode::StorageWrite,
            format!(
                "Failed to write encrypted file {}: {}",
                target_path.display(),
                err
            ),
            "coverage_encrypt_write",
        )
    })?;

    Ok(EncryptFileOutcome {
        encrypted_path: target_path,
        file_id: encrypted.file_id.clone(),
        epoch_id: encrypted.epoch_id,
        group_id: encrypted.group_id,
        original_size: encrypted.content_size,
        encrypted_size: encrypted.encrypted_size,
        created_at: encrypted.created_at,
        header_version: encrypted.header_version.unwrap_or(1),
        wrapped_file_key: encrypted.wrapped_file_key.clone(),
        key_wrap_nonce: encrypted.key_wrap_nonce.clone(),
        key_wrap_aad_hash: encrypted.key_wrap_aad_hash.clone(),
        content_nonce: encrypted.content_nonce.clone(),
        content_chunk_size: encrypted.content_chunk_size,
        plaintext_hash,
    })
}

fn detect_existing_encryption_metadata(
    file_path: &Path,
) -> Result<Option<ExistingEncryptionMetadata>, ClientError> {
    let mut file = fs::File::open(file_path).map_err(|e| {
        storage_error(
            ErrorCode::StorageRead,
            format!(
                "Failed to open {} for metadata inspection: {}",
                file_path.display(),
                e
            ),
            "coverage_metadata_open",
        )
    })?;

    let mut buffer = Vec::new();
    file.by_ref()
        .take(METADATA_SCAN_LIMIT as u64)
        .read_to_end(&mut buffer)
        .map_err(|e| {
            storage_error(
                ErrorCode::StorageRead,
                format!(
                    "Failed to read {} for metadata inspection: {}",
                    file_path.display(),
                    e
                ),
                "coverage_metadata_read",
            )
        })?;

    let separator = ENCRYPTED_FILE_SEPARATOR.as_bytes();
    if buffer.len() < separator.len() {
        return Ok(None);
    }

    let Some(sep_pos) = buffer
        .windows(separator.len())
        .position(|window| window == separator)
    else {
        return Ok(None);
    };

    let metadata_bytes = &buffer[..sep_pos];
    if metadata_bytes.is_empty() {
        return Ok(None);
    }

    let json: Value = match serde_json::from_slice(metadata_bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let file_id = match json.get("file_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return Ok(None),
    };

    let epoch_id = match json.get("epoch_id").and_then(|v| v.as_u64()) {
        Some(id) => id,
        None => return Ok(None),
    };

    let group_id = json
        .get("group_id")
        .and_then(|v| v.as_str())
        .and_then(|raw| Uuid::parse_str(raw).ok());

    Ok(Some(ExistingEncryptionMetadata {
        file_id,
        group_id,
        epoch_id,
    }))
}

fn parse_encrypted_file(path: &Path) -> Result<ParsedEncryptedFile, ClientError> {
    let encrypted_content = fs::read(path).map_err(|e| {
        storage_error(
            ErrorCode::StorageRead,
            format!("Failed to read {}: {}", path.display(), e),
            "coverage_decrypt_read",
        )
    })?;
    let separator = ENCRYPTED_FILE_SEPARATOR.as_bytes();
    let sep_pos = encrypted_content
        .windows(separator.len())
        .position(|window| window == separator)
        .ok_or_else(|| {
            file_error(
                ErrorCode::FileInvalidFormat,
                "Invalid encrypted file format: separator not found".to_string(),
                "coverage_decrypt_parse",
                path,
            )
        })?;

    let metadata_bytes = &encrypted_content[..sep_pos];
    let ciphertext = encrypted_content[sep_pos + separator.len()..].to_vec();

    let json: Value = serde_json::from_slice(metadata_bytes).map_err(|e| {
        file_error(
            ErrorCode::FileInvalidFormat,
            format!("Failed to parse metadata: {}", e),
            "coverage_decrypt_parse",
            path,
        )
    })?;

    let file_id = json
        .get("file_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            file_error(
                ErrorCode::FileInvalidFormat,
                "Missing file_id in metadata".to_string(),
                "coverage_decrypt_parse",
                path,
            )
        })?
        .to_string();
    let epoch_id = json
        .get("epoch_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            file_error(
                ErrorCode::FileInvalidFormat,
                "Missing epoch_id in metadata".to_string(),
                "coverage_decrypt_parse",
                path,
            )
        })?;
    let content_size = json
        .get("file_size")
        .and_then(|v| v.as_u64())
        .or_else(|| json.get("original_size").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let original_name = json
        .get("original_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let stored_file_path = json
        .get("file_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            file_error(
                ErrorCode::FileInvalidFormat,
                "Missing file_path in metadata".to_string(),
                "coverage_decrypt_parse",
                path,
            )
        })?;

    let group_id = json
        .get("group_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    let header_version = json
        .get("header_version")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let wrapped_file_key = decode_bytes(json.get("wrapped_file_key"));
    let key_wrap_nonce = decode_bytes(json.get("key_wrap_nonce"));
    let key_wrap_aad_hash = decode_bytes(json.get("key_wrap_aad_hash"));
    let content_nonce = decode_bytes(json.get("content_nonce"));
    let content_chunk_size = json.get("chunk_size").and_then(|v| v.as_u64());

    let created_at = json
        .get("encrypted_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);
    let platform_metadata = json
        .get("platform_metadata")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .filter(|metadata: &crate::PlatformFileMetadata| !metadata.is_empty());
    let sparse_metadata = json
        .get("sparse_metadata")
        .and_then(|value| serde_json::from_value::<SparseFileMetadata>(value.clone()).ok())
        .filter(SparseFileMetadata::is_effectively_sparse);

    let metadata = EncryptedFileMetadata {
        file_id,
        file_path: stored_file_path,
        group_id,
        epoch_id,
        header_version,
        wrapped_file_key,
        key_wrap_nonce,
        key_wrap_aad_hash,
        content_nonce,
        content_chunk_size,
        content_size,
        encrypted_size: ciphertext.len() as u64,
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

fn decode_bytes(val: Option<&Value>) -> Option<Vec<u8>> {
    if let Some(v) = val {
        if let Some(s) = v.as_str() {
            if let Ok(bytes) = B64.decode(s) {
                return Some(bytes);
            }
        }
        if let Ok(vec_bytes) = serde_json::from_value::<Vec<u8>>(v.clone()) {
            return Some(vec_bytes);
        }
    }
    None
}

async fn decrypt_file_in_place<S, N>(client: &Client<S, N>, path: &Path) -> Result<u64, ClientError>
where
    S: Storage,
    N: Network,
{
    if path.extension() != Some(OsStr::new("encrypted")) {
        return Ok(0);
    }

    let parsed = parse_encrypted_file(path)?;
    let output_path = default_decrypted_path(path, parsed.original_name.as_deref());
    let parent_dir = output_path.parent().map(|dir| dir.to_path_buf());
    let parent_mtime = parent_dir
        .as_ref()
        .and_then(|dir| capture_directory_mtime(dir));

    decrypt_parsed_file_to_path(client, path, parsed, Some(output_path)).await?;

    if let Err(err) = async_fs::remove_file(path).await {
        if err.kind() != ErrorKind::NotFound {
            return Err(storage_error(
                ErrorCode::StorageDelete,
                format!(
                    "Failed to remove encrypted source {}: {}",
                    path.display(),
                    err
                ),
                "coverage_decrypt_cleanup",
            ));
        }
    }

    if let Some(dir) = parent_dir.as_deref() {
        preserve_directory_mtime(dir, parent_mtime);
    }

    Ok(1)
}

async fn decrypt_file_in_place_with_progress<S, N>(
    client: &Client<S, N>,
    path: &Path,
    mut on_progress: Option<&mut (dyn FnMut(CoverageDecryptProgress) + Send)>,
) -> Result<u64, ClientError>
where
    S: Storage,
    N: Network,
{
    let total = if path.extension() == Some(OsStr::new("encrypted")) {
        1
    } else {
        0
    };

    if total > 0 {
        if let Some(callback) = on_progress.as_mut() {
            (*callback)(CoverageDecryptProgress {
                total_files: total,
                decrypted_files: 0,
                failed_files: 0,
            });
        }
    }

    let decrypted = decrypt_file_in_place(client, path).await?;

    if total > 0 {
        if let Some(callback) = on_progress.as_mut() {
            (*callback)(CoverageDecryptProgress {
                total_files: total,
                decrypted_files: decrypted as usize,
                failed_files: 0,
            });
        }
    }

    Ok(decrypted)
}

async fn decrypt_directory_in_place_with_progress<S, N>(
    client: &Client<S, N>,
    root: &Path,
    mut on_progress: Option<&mut (dyn FnMut(CoverageDecryptProgress) + Send)>,
) -> Result<usize, ClientError>
where
    S: Storage,
    N: Network,
{
    let total_encrypted = count_encrypted_files(root)?;
    if total_encrypted > 0 {
        if let Some(callback) = on_progress.as_mut() {
            (*callback)(CoverageDecryptProgress {
                total_files: total_encrypted,
                decrypted_files: 0,
                failed_files: 0,
            });
        }
    }

    let mut stack = vec![root.to_path_buf()];
    let mut decrypted = 0usize;
    let mut failed = 0usize;
    let mut dir_mtimes: Vec<(PathBuf, Option<SystemTime>)> = Vec::new();

    while let Some(current) = stack.pop() {
        dir_mtimes.push((current.clone(), capture_directory_mtime(&current)));

        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(err) => {
                warn!("Failed to read directory {}: {}", current.display(), err);
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("Failed to read entry in {}: {}", current.display(), err);
                    continue;
                }
            };

            let file_type = match entry.file_type() {
                Ok(kind) => kind,
                Err(err) => {
                    warn!("Failed to inspect {}: {}", entry.path().display(), err);
                    continue;
                }
            };

            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                if path.extension() != Some(OsStr::new("encrypted")) {
                    continue;
                }

                match decrypt_file_in_place(client, &path).await {
                    Ok(count) => decrypted += count as usize,
                    Err(err) => {
                        failed += 1;
                        warn!("Failed to decrypt {}: {}", path.display(), err);
                    }
                }

                if total_encrypted > 0 {
                    if let Some(callback) = on_progress.as_mut() {
                        (*callback)(CoverageDecryptProgress {
                            total_files: total_encrypted,
                            decrypted_files: decrypted,
                            failed_files: failed,
                        });
                    }
                }
            }
        }
    }

    for (dir, mtime) in dir_mtimes {
        preserve_directory_mtime(&dir, mtime);
    }

    Ok(decrypted)
}

fn count_encrypted_files(root: &Path) -> Result<usize, ClientError> {
    if root.is_file() {
        return Ok(if root.extension() == Some(OsStr::new("encrypted")) {
            1
        } else {
            0
        });
    }

    let mut total = 0usize;
    let mut stack = vec![root.to_path_buf()];

    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(err) => {
                warn!("Failed to read directory {}: {}", current.display(), err);
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("Failed to read entry in {}: {}", current.display(), err);
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(kind) => kind,
                Err(err) => {
                    warn!("Failed to inspect {}: {}", entry.path().display(), err);
                    continue;
                }
            };
            let path = entry.path();

            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() && path.extension() == Some(OsStr::new("encrypted")) {
                total += 1;
            }
        }
    }

    Ok(total)
}

async fn decrypt_parsed_file_to_path<S, N>(
    client: &Client<S, N>,
    source_path: &Path,
    parsed: ParsedEncryptedFile,
    output_override: Option<PathBuf>,
) -> Result<PathBuf, ClientError>
where
    S: Storage,
    N: Network,
{
    let decrypted_data = client
        .decrypt_file(&parsed.metadata)
        .await
        .map_err(|e| ClientError::InvalidState(e.to_string()))?;

    let output_path = output_override
        .unwrap_or_else(|| default_decrypted_path(source_path, parsed.original_name.as_deref()));

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            storage_error(
                ErrorCode::StorageWrite,
                format!("Failed to create directory {}: {}", parent.display(), err),
                "coverage_decrypt_mkdir",
            )
        })?;
    }

    fs::write(&output_path, decrypted_data).map_err(|e| {
        storage_error(
            ErrorCode::StorageWrite,
            format!(
                "Failed to write decrypted file {}: {}",
                output_path.display(),
                e
            ),
            "coverage_decrypt_write",
        )
    })?;

    if let Err(err) = preserve_file_mtime(source_path, &output_path) {
        warn!(
            "Failed to preserve mtime for {}: {}",
            output_path.display(),
            err
        );
    }

    Ok(output_path)
}

fn extension_is_encrypted(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("encrypted"))
        .unwrap_or(false)
}

fn default_encrypted_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|s| s.to_str()) {
        Some(ext) if !ext.is_empty() => path.with_extension(format!("{ext}.encrypted")),
        _ => {
            let mut candidate = path.to_path_buf();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
            candidate.set_file_name(format!("{name}.encrypted"));
            candidate
        }
    }
}

fn ensure_encrypted_suffix(candidate: PathBuf, original: &Path) -> PathBuf {
    let has_suffix = candidate
        .extension()
        .map(|ext| ext == "encrypted")
        .unwrap_or(false);
    if has_suffix {
        return candidate;
    }

    let mut adjusted = candidate;
    let fallback = original
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("encrypted");

    if adjusted.file_name().is_some() {
        let name = adjusted
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| fallback.to_string());
        adjusted.set_file_name(format!("{name}.encrypted"));
    } else {
        adjusted.push(format!("{fallback}.encrypted"));
    }

    adjusted
}

fn default_decrypted_path(source: &Path, original_name: Option<&str>) -> PathBuf {
    if let Some(name) = original_name {
        source.parent().unwrap_or_else(|| Path::new(".")).join(name)
    } else {
        source.with_extension("decrypted")
    }
}

fn preserve_file_mtime(source: &Path, destination: &Path) -> Result<(), ClientError> {
    let metadata = fs::metadata(source).map_err(|e| {
        storage_error(
            ErrorCode::StorageRead,
            format!("Failed to read metadata from {}: {}", source.display(), e),
            "coverage_mtime_read",
        )
    })?;

    let mtime = metadata.modified().map_err(|e| {
        storage_error(
            ErrorCode::StorageRead,
            format!(
                "Failed to get modification time from {}: {}",
                source.display(),
                e
            ),
            "coverage_mtime_read",
        )
    })?;

    let atime = metadata.accessed().unwrap_or(mtime);

    let ft_mtime = FileTime::from_system_time(mtime);
    let ft_atime = FileTime::from_system_time(atime);
    set_file_times(destination, ft_atime, ft_mtime).map_err(|e| {
        storage_error(
            ErrorCode::StorageWrite,
            format!(
                "Failed to set modification time for {}: {}",
                destination.display(),
                e
            ),
            "coverage_mtime_write",
        )
    })
}

fn preserve_directory_mtime(path: &Path, original_mtime: Option<SystemTime>) {
    let Some(mtime) = original_mtime else {
        return;
    };

    let _ = set_file_mtime(path, FileTime::from_system_time(mtime));
}

fn capture_directory_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

fn storage_error(code: ErrorCode, message: String, operation: &str) -> ClientError {
    ClientError::storage_error(code, message, operation.to_string(), None, true)
}

fn file_error(code: ErrorCode, message: String, operation: &str, path: &Path) -> ClientError {
    ClientError::file_error(
        code,
        message,
        operation.to_string(),
        path.display().to_string(),
        None,
    )
}
