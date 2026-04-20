use super::*;

pub(super) async fn canonicalize_existing_path(path: PathBuf) -> Result<PathBuf, ClientError> {
    let display = path.display().to_string();
    let canonical = std::fs::canonicalize(&path).map_err(|err| {
        ClientError::file_error(
            ErrorCode::FilePathInvalid,
            format!("Coverage root '{}' cannot be resolved: {}", display, err),
            "coverage_root_canonicalize".to_string(),
            display.clone(),
            None,
        )
    })?;

    Ok(canonical)
}

pub(super) fn marker_filename(root_id: Uuid) -> String {
    format!(
        "{}{}{}",
        COVERAGE_MARKER_PREFIX, root_id, COVERAGE_MARKER_SUFFIX
    )
}

pub(super) fn marker_path_for_root(root: &CoverageRoot) -> Option<PathBuf> {
    match root.kind {
        CoverageRootKind::Folder => Some(root.path.join(marker_filename(root.root_id))),
        CoverageRootKind::SingleFile => root
            .path
            .parent()
            .map(|parent| parent.join(marker_filename(root.root_id))),
    }
}

pub(super) fn marker_payload_for_root(root: &CoverageRoot, group_id: Uuid) -> CoverageMarkerFile {
    let root_name = root
        .path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();
    CoverageMarkerFile {
        root_id: root.root_id,
        group_id,
        kind: root.kind,
        root_name,
        path_hint: Some(root.path.display().to_string()),
    }
}

pub(super) async fn write_marker_for_root(
    root: &CoverageRoot,
    group_id: Uuid,
) -> Result<(), ClientError> {
    let Some(marker_path) = marker_path_for_root(root) else {
        return Ok(());
    };

    let marker_dir = marker_path
        .parent()
        .ok_or_else(|| ClientError::InvalidInput("Invalid marker parent path".to_string()))?;
    fs::create_dir_all(marker_dir)
        .await
        .map_err(|err| ClientError::from(StorageError::Io(err)))?;

    let payload = marker_payload_for_root(root, group_id);
    let serialized = serde_json::to_vec_pretty(&payload).map_err(|err| {
        ClientError::SerializationError(format!(
            "Failed to serialize coverage marker for {}: {}",
            root.path.display(),
            err
        ))
    })?;
    fs::write(&marker_path, serialized)
        .await
        .map_err(|err| ClientError::from(StorageError::Io(err)))?;
    Ok(())
}

pub(super) async fn remove_marker_for_root(root: &CoverageRoot) -> Result<(), ClientError> {
    let Some(marker_path) = marker_path_for_root(root) else {
        return Ok(());
    };
    match fs::remove_file(&marker_path).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ClientError::from(StorageError::Io(err))),
    }
}

pub(super) fn read_marker_file(path: &Path) -> Option<CoverageMarkerFile> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
}

pub(super) fn find_marker_for_path(
    canonical: &Path,
    kind: CoverageRootKind,
    group_id: Uuid,
) -> Option<CoverageMarkerFile> {
    let (dir, expected_name) = match kind {
        CoverageRootKind::Folder => (canonical, canonical.file_name()?),
        CoverageRootKind::SingleFile => (canonical.parent()?, canonical.file_name()?),
    };
    let expected_name = expected_name.to_string_lossy();

    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with(COVERAGE_MARKER_PREFIX) || !name.ends_with(COVERAGE_MARKER_SUFFIX) {
            continue;
        }
        if let Some(marker) = read_marker_file(&path) {
            if marker.group_id == group_id && marker.root_name == expected_name {
                return Some(marker);
            }
        }
    }
    None
}

pub(super) fn marker_path_from_marker(
    marker_file_path: &Path,
    marker: &CoverageMarkerFile,
) -> Option<PathBuf> {
    match marker.kind {
        CoverageRootKind::Folder => marker_file_path.parent().map(|p| p.to_path_buf()),
        CoverageRootKind::SingleFile => {
            marker_file_path.parent().map(|p| p.join(&marker.root_name))
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct FileExclusionList {
    patterns: Vec<(Pattern, String)>,
}

impl FileExclusionList {
    pub(super) fn from_patterns(patterns: &[String]) -> Self {
        let mut compiled = Vec::new();
        for raw in patterns {
            match Pattern::new(raw) {
                Ok(pattern) => compiled.push((pattern, raw.clone())),
                Err(err) => {
                    log::warn!("Ignoring invalid exclusion pattern '{}': {}", raw, err);
                }
            }
        }
        Self { patterns: compiled }
    }

    pub(super) fn matches(&self, path: &Path) -> bool {
        if self.patterns.is_empty() {
            return false;
        }

        let path_candidates = exclusion_path_candidates(path);
        let file_name = path.file_name().and_then(|n| n.to_str());

        self.patterns.iter().any(|(pattern, _)| {
            pattern.matches_path(path)
                || path_candidates
                    .iter()
                    .any(|candidate| pattern.matches(candidate))
                || file_name.map(|name| pattern.matches(name)).unwrap_or(false)
        })
    }
}

pub(super) fn exclusion_path_candidates(path: &Path) -> Vec<String> {
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

#[derive(Clone)]
pub(super) struct PendingIndexEntry {
    pub(super) relative_path: String,
    pub(super) size: u64,
    pub(super) last_epoch: u64,
    pub(super) checksum_hint: Option<String>,
    pub(super) last_seen: DateTime<Utc>,
    pub(super) state: FileCoverageState,
    pub(super) orphan_kind: Option<FileOrphanKind>,
    pub(super) file_id: Option<String>,
}

#[derive(Clone)]
struct FilesystemScanEntry {
    canonical_path: PathBuf,
    size: u64,
    last_seen: DateTime<Utc>,
}

#[derive(Default)]
pub(super) struct RootScanStats {
    pub(super) tracked: usize,
    pub(super) orphaned: usize,
    pub(super) unmanaged: usize,
}

impl<S: Storage, N: Network> Client<S, N> {
    pub(super) async fn build_index_entries_from_filesystem(
        &self,
        root: &CoverageRoot,
        progress: Option<&CoverageScanProgress>,
    ) -> Result<Vec<PendingIndexEntry>, ClientError> {
        let mut filesystem_entries = self.enumerate_filesystem_entries(root.clone()).await?;
        let mut pending = Vec::with_capacity(filesystem_entries.len());
        let mut idx = 0usize;
        let mut total = filesystem_entries.len();

        if let Some(cb) = progress {
            cb(root, 0, total);
        }

        let (active_group_id, current_epoch, target_epoch) = {
            let state = self.state.read().await;
            let (group_id, epochs) = Self::active_group_epoch_ids(&state);
            let epoch_list: Vec<u64> = epochs.iter().copied().collect();
            let current_epoch = state.current_epoch;
            let target_epoch = state
                .migration
                .as_ref()
                .map(|m| m.to_epoch)
                .unwrap_or(current_epoch);
            self.logger.log(
                crate::logging::LogLevel::Debug,
                &format!(
                    "Coverage scan: active_group_id={:?}, current_epoch={}, target_epoch={}, known_epochs={:?}",
                    group_id, current_epoch, target_epoch, epoch_list
                ),
                Some("coverage_scan_context"),
            );

            (group_id, current_epoch, target_epoch)
        };

        while idx < filesystem_entries.len() {
            let entry = filesystem_entries[idx].clone();
            idx += 1;

            let Some(relative_path) =
                Self::relative_path_for_root(&root.path, root.kind, &entry.canonical_path)
            else {
                continue;
            };

            if self.is_path_excluded(&entry.canonical_path) {
                continue;
            }

            let canonical_path = entry.canonical_path.clone();
            let metadata = self.load_metadata_for_canonical(&canonical_path).await?;
            let header = Self::parse_encrypted_file_metadata(&canonical_path);
            let mut file_id = metadata.as_ref().and_then(|data| data.file_id.clone());
            if file_id.is_none() {
                if let Some(header) = header.as_ref() {
                    if !header.file_id.is_empty() {
                        file_id = Some(header.file_id.clone());
                    }
                }
            }

            if metadata.is_none() && !Self::path_has_encrypted_suffix(&canonical_path) {
                match self.auto_encrypt_plaintext_file(&canonical_path).await {
                    Ok(Some(encrypted_path)) => match fs::metadata(&encrypted_path).await {
                        Ok(meta) => {
                            let last_seen: DateTime<Utc> =
                                meta.modified().unwrap_or_else(|_| SystemTime::now()).into();
                            filesystem_entries.push(FilesystemScanEntry {
                                canonical_path: encrypted_path,
                                size: meta.len(),
                                last_seen,
                            });
                            continue;
                        }
                        Err(err) => {
                            self.logger.log(
                                crate::logging::LogLevel::Warn,
                                &format!(
                                    "Auto-encrypted file but failed to inspect ciphertext: {}",
                                    err
                                ),
                                Some("coverage_auto_encrypt_inspect"),
                            );
                            continue;
                        }
                    },
                    Ok(None) => {}
                    Err(err) => {
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Auto-encryption skipped for {}: {}",
                                canonical_path.display(),
                                err
                            ),
                            Some("coverage_auto_encrypt_failed"),
                        );
                    }
                }
            }

            let (last_epoch, checksum_hint, state, orphan_kind) = if let Some(metadata) = metadata {
                let effective_epoch = if let Some(ref h) = header {
                    if h.epoch_id != metadata.epoch_id && h.epoch_id > 0 {
                        self.logger.log(
                            crate::logging::LogLevel::Debug,
                            &format!(
                                "File {}: stored epoch_id={} differs from header epoch_id={}, using header",
                                relative_path, metadata.epoch_id, h.epoch_id
                            ),
                            Some("coverage_epoch_reconciliation"),
                        );
                        h.epoch_id
                    } else {
                        metadata.epoch_id
                    }
                } else {
                    metadata.epoch_id
                };

                let effective_group = if let Some(ref h) = header {
                    h.group_id.or(metadata.group_id)
                } else {
                    metadata.group_id
                };

                let is_current_or_target = effective_epoch > 0
                    && (effective_epoch == current_epoch || effective_epoch == target_epoch);
                let group_mismatch = active_group_id
                    .zip(effective_group)
                    .map(|(active, meta_group)| active != meta_group)
                    .unwrap_or(false);

                self.logger.log(
                    crate::logging::LogLevel::Debug,
                    &format!(
                        "File {}: effective_epoch={}, is_current_or_target={}, group_mismatch={}",
                        relative_path, effective_epoch, is_current_or_target, group_mismatch
                    ),
                    Some("coverage_file_classification"),
                );

                let (state, orphan_kind) = if group_mismatch {
                    (FileCoverageState::Orphaned, Some(FileOrphanKind::Outcast))
                } else if is_current_or_target {
                    (FileCoverageState::Tracked, None)
                } else {
                    (
                        FileCoverageState::Orphaned,
                        Some(FileOrphanKind::WrongEpoch),
                    )
                };
                (
                    effective_epoch,
                    Some(hex::encode(metadata.integrity_hash)),
                    state,
                    orphan_kind,
                )
            } else if Self::path_has_encrypted_suffix(&canonical_path)
                && Self::detect_hybridcipher_header(&canonical_path)
            {
                let (header_epoch, header_group) = header
                    .as_ref()
                    .map(|h| (h.epoch_id, h.group_id))
                    .unwrap_or((0, None));
                let group_mismatch = active_group_id
                    .zip(header_group)
                    .map(|(active, hdr_group)| active != hdr_group)
                    .unwrap_or(false);
                let is_current_or_target = header_epoch > 0
                    && (header_epoch == current_epoch || header_epoch == target_epoch);
                let orphan_kind = if group_mismatch {
                    Some(FileOrphanKind::Outcast)
                } else if !is_current_or_target {
                    Some(FileOrphanKind::WrongEpoch)
                } else {
                    Some(FileOrphanKind::MissingMetadata)
                };
                self.logger.log(
                    crate::logging::LogLevel::Debug,
                    &format!(
                        "File {}: ciphertext detected without metadata, marking orphaned",
                        relative_path
                    ),
                    Some("coverage_file_orphaned"),
                );
                (
                    if header_epoch > 0 { header_epoch } else { 0 },
                    None,
                    FileCoverageState::Orphaned,
                    orphan_kind,
                )
            } else {
                self.logger.log(
                    crate::logging::LogLevel::Debug,
                    &format!("File {}: no metadata found", relative_path),
                    Some("coverage_file_no_metadata"),
                );
                (0, None, FileCoverageState::Unmanaged, None)
            };

            pending.push(PendingIndexEntry {
                relative_path,
                size: entry.size,
                last_epoch,
                checksum_hint,
                last_seen: entry.last_seen,
                state,
                orphan_kind,
                file_id,
            });

            total = filesystem_entries.len();
            if let Some(cb) = progress {
                cb(root, idx, total);
            }
        }

        Ok(pending)
    }

    async fn enumerate_filesystem_entries(
        &self,
        root: CoverageRoot,
    ) -> Result<Vec<FilesystemScanEntry>, ClientError> {
        let exclusions = self.file_exclusions.clone();
        let logger = self.logger.clone();
        task::spawn_blocking(move || {
            Self::enumerate_filesystem_entries_blocking(root, exclusions, logger)
        })
        .await
        .map_err(|err| {
            ClientError::InvalidState(format!("Filesystem enumeration task failed: {}", err))
        })?
    }

    fn enumerate_filesystem_entries_blocking(
        root: CoverageRoot,
        exclusions: Arc<FileExclusionList>,
        logger: Arc<crate::logging::StructuredLogger>,
    ) -> Result<Vec<FilesystemScanEntry>, ClientError> {
        let mut entries = Vec::new();
        let root_display = root.path.display().to_string();
        let mut warning_count = 0usize;
        let mut warning_samples = 0usize;
        const MAX_WARNING_SAMPLES: usize = 5;

        fn warn(
            logger: &crate::logging::StructuredLogger,
            warning_count: &mut usize,
            warning_samples: &mut usize,
            message: String,
            context: &'static str,
        ) {
            *warning_count += 1;
            if *warning_samples < MAX_WARNING_SAMPLES {
                logger.log(crate::logging::LogLevel::Warn, &message, Some(context));
                *warning_samples += 1;
            }
        }

        if !root.path.exists() {
            return Err(ClientError::file_error(
                ErrorCode::FileNotFound,
                format!("Coverage root '{}' is unavailable", root_display),
                "coverage_rescan_enumerate".to_string(),
                root_display,
                None,
            ));
        }

        let mut push_entry =
            |path: PathBuf, warning_count: &mut usize, warning_samples: &mut usize| {
                let metadata = match std::fs::metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(err) => {
                        warn(
                            &logger,
                            warning_count,
                            warning_samples,
                            format!("Failed to read metadata for '{}': {}", path.display(), err),
                            "coverage_rescan_metadata",
                        );
                        return;
                    }
                };

                if !metadata.is_file() {
                    return;
                }

                if Self::is_directory_metadata_sidecar(&path) {
                    return;
                }

                if exclusions.matches(&path) {
                    return;
                }

                let modified = metadata.modified().unwrap_or_else(|_| SystemTime::now());
                let last_seen: DateTime<Utc> = modified.into();

                entries.push(FilesystemScanEntry {
                    canonical_path: path,
                    size: metadata.len(),
                    last_seen,
                });
            };

        match root.kind {
            CoverageRootKind::SingleFile => {
                push_entry(root.path.clone(), &mut warning_count, &mut warning_samples);
            }
            CoverageRootKind::Folder => {
                for entry in WalkDir::new(&root.path)
                    .follow_links(false)
                    .into_iter()
                    .filter_entry(|entry| !exclusions.matches(entry.path()))
                {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            warn(
                                &logger,
                                &mut warning_count,
                                &mut warning_samples,
                                format!(
                                    "Failed to traverse coverage root '{}': {}",
                                    root_display, err
                                ),
                                "coverage_rescan_walk",
                            );
                            continue;
                        }
                    };

                    if entry.file_type().is_file() {
                        push_entry(
                            entry.path().to_path_buf(),
                            &mut warning_count,
                            &mut warning_samples,
                        );
                    }
                }
            }
        }

        if warning_count > warning_samples {
            logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Coverage scan skipped {} entries due to filesystem errors (showing first {}).",
                    warning_count, warning_samples
                ),
                Some("coverage_rescan_warn_summary"),
            );
        }

        Ok(entries)
    }

    pub(super) fn path_matches_root(
        root_path: &Path,
        kind: CoverageRootKind,
        file_path: &Path,
    ) -> bool {
        match kind {
            CoverageRootKind::SingleFile => file_path == root_path,
            CoverageRootKind::Folder => file_path.starts_with(root_path),
        }
    }

    pub(super) fn relative_path_for_root(
        root_path: &Path,
        kind: CoverageRootKind,
        file_path: &Path,
    ) -> Option<String> {
        match kind {
            CoverageRootKind::SingleFile => file_path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .or_else(|| Some(file_path.to_string_lossy().to_string())),
            CoverageRootKind::Folder => {
                let stripped = file_path.strip_prefix(root_path).ok()?;
                if stripped.as_os_str().is_empty() {
                    None
                } else {
                    Some(
                        stripped
                            .to_string_lossy()
                            .trim_start_matches('/')
                            .to_string(),
                    )
                }
            }
        }
    }

    pub(super) fn encrypted_path_for_entry(root: &CoverageRoot, relative_path: &str) -> PathBuf {
        match root.kind {
            CoverageRootKind::SingleFile => root.path.clone(),
            CoverageRootKind::Folder => {
                if relative_path.to_ascii_lowercase().ends_with(".encrypted") {
                    root.path.join(relative_path)
                } else {
                    root.path.join(format!("{relative_path}.encrypted"))
                }
            }
        }
    }

    pub(super) fn normalized_relative_path(relative_path: &str) -> String {
        if let Some(stripped) = Self::strip_encrypted_suffix(relative_path) {
            stripped.to_string()
        } else {
            relative_path.to_string()
        }
    }

    pub(super) fn entry_exists_on_disk(root: &CoverageRoot, entry: &FileIndexEntry) -> bool {
        let mut candidates = Vec::new();
        match root.kind {
            CoverageRootKind::SingleFile => {
                candidates.push(root.path.clone());
            }
            CoverageRootKind::Folder => {
                candidates.push(root.path.join(&entry.relative_path));
            }
        }

        let rel = entry.relative_path.clone();
        if !rel.to_ascii_lowercase().ends_with(".encrypted") {
            match root.kind {
                CoverageRootKind::SingleFile => candidates.push(root.path.clone()),
                CoverageRootKind::Folder => {
                    candidates.push(root.path.join(format!("{}.encrypted", rel)));
                }
            }
        }

        if let Some(stripped) = Self::strip_encrypted_suffix(&rel) {
            match root.kind {
                CoverageRootKind::SingleFile => candidates.push(root.path.clone()),
                CoverageRootKind::Folder => {
                    candidates.push(root.path.join(stripped));
                    candidates.push(root.path.join(format!("{}.encrypted", stripped)));
                }
            }
        }

        candidates.iter().any(|path| path.exists())
            || matches!(root.kind, CoverageRootKind::Folder)
                && std::fs::read_dir(&root.path)
                    .ok()
                    .and_then(|iter| {
                        let target_plain = entry.relative_path.clone();
                        let target_enc = format!("{}.encrypted", entry.relative_path);
                        for entry_dir in iter.flatten() {
                            let name = entry_dir.file_name();
                            if let Some(name_str) = name.to_str() {
                                if name_str == target_plain || name_str == target_enc {
                                    return Some(true);
                                }
                            }
                        }
                        Some(false)
                    })
                    .unwrap_or(false)
    }

    pub(super) fn strip_encrypted_suffix(value: &str) -> Option<&str> {
        const SUFFIX: &str = ".encrypted";
        if value.len() <= SUFFIX.len() {
            return None;
        }

        let (body, suffix) = value.split_at(value.len() - SUFFIX.len());
        if suffix.eq_ignore_ascii_case(SUFFIX) {
            Some(body)
        } else {
            None
        }
    }

    pub(super) fn decode_header_bytes(val: Option<&serde_json::Value>) -> Option<Vec<u8>> {
        if let Some(v) = val {
            if let Some(s) = v.as_str() {
                if let Ok(bytes) = general_purpose::STANDARD.decode(s) {
                    return Some(bytes);
                }
            }
            if let Ok(vec_bytes) = serde_json::from_value::<Vec<u8>>(v.clone()) {
                return Some(vec_bytes);
            }
        }
        None
    }

    pub(super) fn parse_encrypted_metadata_from_parts(
        _path: &Path,
        header_json: &serde_json::Value,
        ciphertext: Vec<u8>,
    ) -> Option<EncryptedFileMetadata> {
        let file_id = header_json.get("file_id")?.as_str()?.to_string();
        let epoch_id = header_json.get("epoch_id")?.as_u64()?;
        let header_version = header_json
            .get("header_version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(1);

        let group_id = header_json
            .get("group_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let wrapped_file_key = Self::decode_header_bytes(header_json.get("wrapped_file_key"))?;
        let key_wrap_nonce = Self::decode_header_bytes(header_json.get("key_wrap_nonce"))?;
        let key_wrap_aad_hash = Self::decode_header_bytes(header_json.get("key_wrap_aad_hash"))?;
        let content_nonce = Self::decode_header_bytes(header_json.get("content_nonce"))?;

        let created_at = header_json
            .get("encrypted_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|| chrono::Utc::now());

        let content_size = header_json
            .get("file_size")
            .and_then(|v| v.as_u64())
            .or_else(|| header_json.get("original_size").and_then(|v| v.as_u64()))
            .unwrap_or(0);
        let content_chunk_size = header_json.get("chunk_size").and_then(|v| v.as_u64());
        let platform_metadata = header_json
            .get("platform_metadata")
            .and_then(|value| serde_json::from_value::<PlatformFileMetadata>(value.clone()).ok())
            .filter(|metadata| !metadata.is_empty());
        let sparse_metadata = header_json
            .get("sparse_metadata")
            .and_then(|value| serde_json::from_value::<SparseFileMetadata>(value.clone()).ok())
            .filter(SparseFileMetadata::is_effectively_sparse);

        let stored_file_path = header_json
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|value| !value.trim().is_empty())?;
        let aad_label = Self::normalize_file_identifier(&stored_file_path);

        Some(EncryptedFileMetadata {
            file_id,
            file_path: aad_label,
            group_id,
            epoch_id,
            header_version: Some(header_version),
            wrapped_file_key: Some(wrapped_file_key),
            key_wrap_nonce: Some(key_wrap_nonce),
            key_wrap_aad_hash: Some(key_wrap_aad_hash),
            content_nonce: Some(content_nonce),
            content_chunk_size,
            content_size,
            encrypted_size: ciphertext.len() as u64,
            created_at,
            platform_metadata,
            sparse_metadata,
            encrypted_content: ciphertext,
        })
    }

    pub(super) fn detect_hybridcipher_header(path: &Path) -> bool {
        use std::io::Read;

        let Ok(mut file) = std::fs::File::open(path) else {
            return false;
        };

        const SCAN_LIMIT: usize = 8192;
        let mut buffer = vec![0u8; SCAN_LIMIT];

        let Ok(bytes_read) = file.read(&mut buffer) else {
            return false;
        };
        buffer.truncate(bytes_read);

        buffer
            .windows(ENCRYPTED_FILE_SEPARATOR.len())
            .any(|window| window == ENCRYPTED_FILE_SEPARATOR)
    }

    pub(super) fn parse_encrypted_file_metadata(path: &Path) -> Option<EncryptedFileMetadata> {
        use std::io::Read;

        let mut file = std::fs::File::open(path).ok()?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).ok()?;
        let sep_pos = buffer
            .windows(ENCRYPTED_FILE_SEPARATOR.len())
            .position(|w| w == ENCRYPTED_FILE_SEPARATOR)?;
        let header_bytes = &buffer[..sep_pos];
        let ciphertext = buffer[sep_pos + ENCRYPTED_FILE_SEPARATOR.len()..].to_vec();

        let json: serde_json::Value = serde_json::from_slice(header_bytes).ok()?;

        Self::parse_encrypted_metadata_from_parts(path, &json, ciphertext)
    }

    pub(super) fn hash_root_ids(root_ids: &HashSet<Uuid>) -> u64 {
        let mut ids: Vec<Uuid> = root_ids.iter().copied().collect();
        ids.sort();
        let mut hasher = DefaultHasher::new();
        for id in ids {
            id.hash(&mut hasher);
        }
        hasher.finish()
    }

    pub(super) async fn invalidate_tracked_stats_cache(&self) {
        let mut cache = self.tracked_stats_cache.lock().await;
        cache.invalidated = true;
    }

    pub(super) async fn list_file_index_entries_for_root(
        &self,
        root_id: Uuid,
    ) -> Result<Vec<FileIndexEntry>, ClientError> {
        if self.config.file_index_cache_max_roots > 0 {
            let (cached, cache_size) = {
                let mut cache = self.file_index_cache.write().await;
                let entries = cache.get(root_id);
                let size = cache.size();
                (entries, size)
            };
            if let Some(entries) = cached {
                self.metrics.increment_counter("file_index.cache_hit");
                self.metrics
                    .set_gauge("file_index.cache_roots", cache_size as f64);
                return Ok(entries);
            }
        }

        self.metrics.increment_counter("file_index.cache_miss");
        let entries = self
            .storage
            .list_file_index_entries_by_root(root_id)
            .await
            .map_err(ClientError::from)?;
        self.metrics
            .add_to_counter("file_index.entries_loaded", entries.len() as u64);
        self.metrics
            .set_gauge("file_index.entries_loaded_last", entries.len() as f64);

        if self.config.file_index_cache_max_roots > 0 {
            let cache_size = {
                let mut cache = self.file_index_cache.write().await;
                cache.insert(root_id, entries.clone());
                cache.size()
            };
            self.metrics
                .set_gauge("file_index.cache_roots", cache_size as f64);
        }

        Ok(entries)
    }

    pub(super) async fn store_file_index_entry(
        &self,
        entry: &FileIndexEntry,
    ) -> Result<(), ClientError> {
        self.storage
            .store_file_index_entry(entry)
            .await
            .map_err(ClientError::from)?;
        self.metrics.increment_counter("file_index.entry_stored");

        if self.config.file_index_cache_max_roots > 0 {
            let cache_size = {
                let mut cache = self.file_index_cache.write().await;
                cache.update_entry(entry);
                cache.size()
            };
            self.metrics
                .set_gauge("file_index.cache_roots", cache_size as f64);
        }

        self.invalidate_tracked_stats_cache().await;

        Ok(())
    }

    pub(super) async fn store_file_index_entries(
        &self,
        entries: &[FileIndexEntry],
    ) -> Result<(), ClientError> {
        if entries.is_empty() {
            return Ok(());
        }

        self.storage
            .store_file_index_entries(entries)
            .await
            .map_err(ClientError::from)?;
        self.metrics
            .add_to_counter("file_index.entry_stored", entries.len() as u64);

        if self.config.file_index_cache_max_roots > 0 {
            let cache_size = {
                let mut cache = self.file_index_cache.write().await;
                for entry in entries {
                    cache.update_entry(entry);
                }
                cache.size()
            };
            self.metrics
                .set_gauge("file_index.cache_roots", cache_size as f64);
        }

        self.invalidate_tracked_stats_cache().await;

        Ok(())
    }

    pub(super) async fn replace_file_index_entries_for_root(
        &self,
        root_id: Uuid,
        entries: &[FileIndexEntry],
    ) -> Result<(), ClientError> {
        self.storage
            .replace_file_index_entries_for_root(root_id, entries)
            .await
            .map_err(ClientError::from)?;
        self.metrics.increment_counter("file_index.root_replaced");
        self.metrics
            .add_to_counter("file_index.entries_replaced", entries.len() as u64);

        if self.config.file_index_cache_max_roots > 0 {
            let cache_size = {
                let mut cache = self.file_index_cache.write().await;
                cache.insert(root_id, entries.to_vec());
                cache.size()
            };
            self.metrics
                .set_gauge("file_index.cache_roots", cache_size as f64);
        }

        self.invalidate_tracked_stats_cache().await;

        Ok(())
    }

    pub(super) async fn remove_file_index_entry_for_root(
        &self,
        root_id: Uuid,
        file_uuid: Uuid,
    ) -> Result<(), ClientError> {
        self.storage
            .remove_file_index_entry(file_uuid)
            .await
            .map_err(ClientError::from)?;
        self.metrics.increment_counter("file_index.entry_removed");

        if self.config.file_index_cache_max_roots > 0 {
            let cache_size = {
                let mut cache = self.file_index_cache.write().await;
                cache.remove_entry(root_id, file_uuid);
                cache.size()
            };
            self.metrics
                .set_gauge("file_index.cache_roots", cache_size as f64);
        }

        self.invalidate_tracked_stats_cache().await;

        Ok(())
    }

    pub(super) async fn find_file_index_entry_for_root_path(
        &self,
        root_id: Uuid,
        relative_path: &str,
    ) -> Result<Option<FileIndexEntry>, ClientError> {
        let normalized = Self::normalized_relative_path(relative_path);
        self.storage
            .load_file_index_entry_by_root_path(root_id, &normalized)
            .await
            .map_err(ClientError::from)
    }

    pub(super) async fn tracked_file_stats(
        &self,
        root_ids: &HashSet<Uuid>,
    ) -> Result<(u64, u64), ClientError> {
        let root_ids_hash = Self::hash_root_ids(root_ids);
        {
            let cache = self.tracked_stats_cache.lock().await;
            if !cache.invalidated {
                if let (Some(last_updated_at), Some(cached_hash)) =
                    (cache.last_updated_at, cache.root_ids_hash)
                {
                    if cached_hash == root_ids_hash
                        && last_updated_at.elapsed() < TRACKED_STATS_CACHE_TTL
                    {
                        return Ok((cache.tracked_files, cache.tracked_bytes));
                    }
                }
            }
        }

        let mut tracked_files = 0u64;
        let mut tracked_bytes = 0u64;

        for root_id in root_ids.iter().copied() {
            let entries = self.list_file_index_entries_for_root(root_id).await?;
            for entry in entries {
                if entry.state == FileCoverageState::Tracked {
                    tracked_files = tracked_files.saturating_add(1);
                    tracked_bytes = tracked_bytes.saturating_add(entry.size);
                }
            }
        }

        {
            let mut cache = self.tracked_stats_cache.lock().await;
            cache.last_updated_at = Some(Instant::now());
            cache.root_ids_hash = Some(root_ids_hash);
            cache.tracked_files = tracked_files;
            cache.tracked_bytes = tracked_bytes;
            cache.invalidated = false;
        }

        Ok((tracked_files, tracked_bytes))
    }

    pub(super) async fn persist_index_entries_for_root(
        &self,
        root: CoverageRoot,
        pending_entries: Vec<PendingIndexEntry>,
    ) -> Result<RootScanStats, ClientError> {
        let now = Utc::now();
        let existing_entries = self.list_file_index_entries_for_root(root.root_id).await?;
        let mut previous: HashMap<String, FileIndexEntry> = HashMap::new();
        for entry in existing_entries {
            let normalized = Self::normalized_relative_path(&entry.relative_path);
            previous.insert(normalized, entry);
        }

        let mut stats = RootScanStats::default();
        let mut next_entries = Vec::with_capacity(pending_entries.len() + previous.len());

        for entry in pending_entries {
            let PendingIndexEntry {
                relative_path,
                size,
                mut last_epoch,
                mut checksum_hint,
                last_seen,
                state: mut entry_state,
                mut orphan_kind,
                mut file_id,
            } = entry;

            let normalized_path = Self::normalized_relative_path(&relative_path);
            let previous_entry = previous.remove(&normalized_path);
            let file_uuid = previous_entry
                .as_ref()
                .map(|entry| entry.file_uuid)
                .unwrap_or_else(|| Uuid::new_v5(&root.root_id, normalized_path.as_bytes()));

            let should_promote = matches!(entry_state, FileCoverageState::Unmanaged)
                && relative_path.to_ascii_lowercase().ends_with(".encrypted");

            if should_promote {
                if let Some(prev) = previous_entry.as_ref() {
                    if prev.state == FileCoverageState::Tracked {
                        entry_state = FileCoverageState::Tracked;
                        if last_epoch == 0 {
                            last_epoch = prev.last_epoch;
                        }
                        if checksum_hint.is_none() {
                            checksum_hint = prev.checksum_hint.clone();
                        }
                        if file_id.is_none() {
                            file_id = prev.file_id.clone();
                        }
                        orphan_kind = None;
                    }
                }
            }

            if file_id.is_none() {
                if let Some(prev) = previous_entry.as_ref() {
                    file_id = prev.file_id.clone();
                }
            }

            if !matches!(entry_state, FileCoverageState::Orphaned) {
                orphan_kind = None;
            }

            match &entry_state {
                FileCoverageState::Tracked => stats.tracked += 1,
                FileCoverageState::Unmanaged => stats.unmanaged += 1,
                FileCoverageState::Orphaned => stats.orphaned += 1,
                _ => {}
            }

            let index_entry = FileIndexEntry {
                file_uuid,
                file_id,
                root_id: root.root_id,
                relative_path,
                size,
                last_epoch,
                checksum_hint,
                last_seen,
                state: entry_state,
                orphan_kind,
            };

            next_entries.push(index_entry);
        }

        for (_, mut entry) in previous {
            if Self::is_directory_metadata_sidecar_relative(&entry.relative_path) {
                continue;
            }
            stats.orphaned += 1;
            entry.state = FileCoverageState::Orphaned;
            entry.last_seen = now;
            entry.orphan_kind = Some(FileOrphanKind::MissingFile);
            next_entries.push(entry);
        }

        {
            let mut state = self.state.write().await;
            if let Some(root_entry) = state.coverage_roots.get_mut(&root.root_id) {
                root_entry.last_scan = Some(now);
                root_entry.updated_at = now;
            }
        }

        self.replace_file_index_entries_for_root(root.root_id, &next_entries)
            .await?;
        self.save_client_state().await?;

        Ok(stats)
    }

    pub(super) async fn load_metadata_for_canonical(
        &self,
        canonical: &Path,
    ) -> Result<Option<FileMetadataData>, ClientError> {
        let canonical_str = canonical.to_string_lossy().to_string();
        let normalized = Self::normalize_storage_path(&canonical_str);
        let mut candidates = vec![canonical_str];
        if normalized != candidates[0] {
            candidates.push(normalized);
        }

        for candidate in candidates {
            if let Some(metadata) = self
                .storage
                .load_file_metadata(&candidate)
                .await
                .map_err(ClientError::from)?
            {
                return Ok(Some(metadata));
            }
        }

        Ok(None)
    }

    pub(super) async fn active_root_for_path(
        &self,
        canonical: &Path,
    ) -> Result<Option<CoverageRoot>, ClientError> {
        let (_, _, roots) = self.active_group_roots_map().await?;
        Ok(roots
            .values()
            .find(|root| Self::path_matches_root(&root.path, root.kind, canonical))
            .cloned())
    }
}

pub(super) fn coverage_log_to_data(
    log: &CoverageLog,
    sequence: u64,
) -> Result<CoverageLogData, ClientError> {
    let serialized = serde_json::to_vec(log).map_err(|err| {
        ClientError::SerializationError(format!("Failed to serialize coverage log: {}", err))
    })?;

    let root_hash = log
        .latest_snapshot()
        .map(|snapshot| snapshot.merkle_root)
        .unwrap_or([0u8; 32]);

    Ok(CoverageLogData {
        root_hash,
        tree_nodes: serialized,
        file_epochs: HashMap::new(),
        sequence,
        updated_at: Utc::now(),
        version: 1,
    })
}

pub(super) fn coverage_log_from_data(data: &CoverageLogData) -> Result<CoverageLog, ClientError> {
    if !data.tree_nodes.is_empty() {
        match serde_json::from_slice::<CoverageLog>(&data.tree_nodes) {
            Ok(log) => return Ok(log),
            Err(err) => {
                log::warn!(
                    "Failed to deserialize coverage log from serialized form: {}. Falling back to legacy map.",
                    err
                );
            }
        }
    }

    if data.file_epochs.is_empty() {
        return Ok(CoverageLog::new());
    }

    let mut log = CoverageLog::new();
    for (file_id, epoch_id) in &data.file_epochs {
        log.add_entry(make_placeholder_file_epoch_entry(
            file_id.clone(),
            *epoch_id,
        ));
    }
    Ok(log)
}

pub(super) fn make_placeholder_file_epoch_entry(file_id: String, epoch_id: u64) -> FileEpochEntry {
    FileEpochEntry {
        file_id,
        epoch_id,
        proof: InclusionProof {
            leaf_index: 0,
            leaf_hash: [0u8; 32],
            sibling_hashes: Vec::new(),
            directions: Vec::new(),
        },
        merkle_root: [0u8; 32],
        signature: Vec::new(),
        verifying_key: [0u8; 32],
        signing_key_id: None,
    }
}

pub(super) fn rekey_debug_enabled() -> bool {
    match std::env::var("HYBRIDCIPHER_DEBUG_REKEY") {
        Ok(val) => {
            let lower = val.to_ascii_lowercase();
            !(lower.is_empty() || lower == "0" || lower == "false")
        }
        Err(_) => false,
    }
}

pub(super) fn paths_overlap(existing: &Path, candidate: &Path) -> bool {
    if existing == candidate {
        return true;
    }
    existing.starts_with(candidate) || candidate.starts_with(existing)
}
