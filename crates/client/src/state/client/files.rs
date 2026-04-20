use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    pub(super) fn path_has_encrypted_suffix(path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("encrypted"))
            .unwrap_or(false)
    }

    pub(super) fn is_directory_metadata_sidecar(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == DIRECTORY_METADATA_FILE_NAME)
            .unwrap_or(false)
    }

    pub(super) fn is_directory_metadata_sidecar_relative(relative_path: &str) -> bool {
        Self::is_directory_metadata_sidecar(Path::new(relative_path))
    }

    pub(super) fn default_encrypted_output_path(path: &Path) -> PathBuf {
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

    pub(super) fn capture_file_times(path: &Path) -> Option<(FileTime, FileTime, DateTime<Utc>)> {
        let meta = std::fs::metadata(path).ok()?;
        let mtime = meta.modified().ok()?;
        let mtime_ft = FileTime::from_system_time(mtime);
        let atime_ft = meta
            .accessed()
            .ok()
            .map(FileTime::from_system_time)
            .unwrap_or(mtime_ft);

        Some((atime_ft, mtime_ft, DateTime::<Utc>::from(mtime)))
    }

    pub(super) fn capture_directory_mtime(path: &Path) -> Option<FileTime> {
        std::fs::metadata(path)
            .ok()
            .and_then(|meta| meta.modified().ok())
            .map(FileTime::from_system_time)
    }

    pub(super) fn restore_file_times(
        path: &Path,
        atime: FileTime,
        mtime: FileTime,
    ) -> Result<(), ClientError> {
        set_file_times(path, atime, mtime).map_err(|err| {
            ClientError::file_error(
                ErrorCode::FileAccessDenied,
                format!(
                    "Failed to preserve timestamps for '{}': {}",
                    path.display(),
                    err
                ),
                "preserve_file_times".to_string(),
                path.display().to_string(),
                None,
            )
        })
    }

    pub(super) fn restore_directory_mtime(path: &Path, original_mtime: Option<FileTime>) {
        if let Some(mtime) = original_mtime {
            let _ = set_file_mtime(path, mtime);
        }
    }

    pub(super) async fn auto_encrypt_plaintext_file(
        &self,
        source_path: &Path,
    ) -> Result<Option<PathBuf>, ClientError> {
        let metadata = match fs::metadata(source_path).await {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(ClientError::file_error(
                    ErrorCode::FileAccessDenied,
                    format!(
                        "Failed to inspect '{}' for auto-encryption: {}",
                        source_path.display(),
                        err
                    ),
                    "coverage_auto_encrypt_stat".to_string(),
                    source_path.display().to_string(),
                    None,
                ))
            }
        };

        if !metadata.is_file() || Self::path_has_encrypted_suffix(source_path) {
            return Ok(None);
        }

        if self.is_path_excluded(source_path) {
            return Ok(None);
        }
        if self.path_is_under_enrollment_lock(source_path).await {
            return Ok(None);
        }

        let parent_dir = source_path.parent().map(|p| p.to_path_buf());
        let preserved_times = Self::capture_file_times(source_path);
        let parent_dir_mtime = parent_dir
            .as_ref()
            .and_then(|dir| Self::capture_directory_mtime(dir));

        let plaintext = match fs::read(source_path).await {
            Ok(data) => data,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(ClientError::file_error(
                    ErrorCode::FileAccessDenied,
                    format!(
                        "Failed to read '{}' for auto-encryption: {}",
                        source_path.display(),
                        err
                    ),
                    "coverage_auto_encrypt_read".to_string(),
                    source_path.display().to_string(),
                    None,
                ))
            }
        };

        let path_label = source_path.to_string_lossy().to_string();
        let original_name = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown_file")
            .to_string();
        let encrypted = self.encrypt_file(&path_label, &plaintext).await?;

        let encrypted_path = Self::default_encrypted_output_path(source_path);
        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent).await.map_err(|err| {
                ClientError::file_error(
                    ErrorCode::FileAccessDenied,
                    format!(
                        "Failed to prepare '{}' for auto-encryption output: {}",
                        parent.display(),
                        err
                    ),
                    "coverage_auto_encrypt_prepare".to_string(),
                    parent.display().to_string(),
                    None,
                )
            })?;
        }

        let wrapped_file_key = encrypted.wrapped_file_key.as_ref().ok_or_else(|| {
            ClientError::InvalidState(
                "Missing wrapped_file_key in auto-encryption metadata".to_string(),
            )
        })?;
        let key_wrap_nonce = encrypted.key_wrap_nonce.as_ref().ok_or_else(|| {
            ClientError::InvalidState(
                "Missing key_wrap_nonce in auto-encryption metadata".to_string(),
            )
        })?;
        let key_wrap_aad_hash = encrypted.key_wrap_aad_hash.as_ref().ok_or_else(|| {
            ClientError::InvalidState(
                "Missing key_wrap_aad_hash in auto-encryption metadata".to_string(),
            )
        })?;
        let content_nonce = encrypted.content_nonce.as_ref().ok_or_else(|| {
            ClientError::InvalidState(
                "Missing content_nonce in auto-encryption metadata".to_string(),
            )
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
            original_name: Some(&original_name),
            platform_metadata: encrypted.platform_metadata.as_ref(),
            sparse_metadata: encrypted.sparse_metadata.as_ref(),
        };

        write_encrypted_file_atomic_for_coverage(
            &encrypted_path,
            &header,
            &encrypted.encrypted_content,
        )
        .map_err(|err| {
            ClientError::file_error(
                ErrorCode::FileAccessDenied,
                format!(
                    "Failed to atomically write auto-encrypted file '{}': {}",
                    encrypted_path.display(),
                    err
                ),
                "coverage_auto_encrypt_write".to_string(),
                encrypted_path.display().to_string(),
                None,
            )
        })?;

        if let Some((atime, mtime, _)) = preserved_times.as_ref() {
            Self::restore_file_times(&encrypted_path, *atime, *mtime)?;
        }

        if let Err(err) = fs::remove_file(source_path).await {
            if err.kind() != ErrorKind::NotFound {
                return Err(ClientError::file_error(
                    ErrorCode::FileAccessDenied,
                    format!(
                        "Failed to remove plaintext '{}' after auto-encryption: {}",
                        source_path.display(),
                        err
                    ),
                    "coverage_auto_encrypt_cleanup".to_string(),
                    source_path.display().to_string(),
                    None,
                ));
            }
        }

        if let Some(dir) = parent_dir.as_deref() {
            Self::restore_directory_mtime(dir, parent_dir_mtime);
        }

        let canonical_output = match fs::canonicalize(&encrypted_path).await {
            Ok(path) => path,
            Err(_) => encrypted_path.clone(),
        };

        let mut hash = [0u8; 32];
        let digest = Sha256::digest(&plaintext);
        hash.copy_from_slice(&digest);

        let active_group = { self.state.read().await.active_group_id };
        let modified_at = preserved_times
            .as_ref()
            .map(|(_, _, recorded)| *recorded)
            .unwrap_or_else(Utc::now);
        let metadata_record = FileMetadataData {
            file_path: canonical_output.to_string_lossy().to_string(),
            file_id: Some(encrypted.file_id.clone()),
            group_id: active_group,
            epoch_id: encrypted.epoch_id,
            header_version: encrypted.header_version,
            wrapped_file_key: encrypted.wrapped_file_key.clone(),
            key_wrap_nonce: encrypted.key_wrap_nonce.clone(),
            key_wrap_aad_hash: encrypted.key_wrap_aad_hash.clone(),
            content_nonce: encrypted.content_nonce.clone(),
            content_chunk_size: encrypted.content_chunk_size,
            algorithm: "chacha20poly1305".to_string(),
            file_size: encrypted.content_size,
            modified_at,
            integrity_hash: hash,
            permissions: AccessControlData {
                readers: Vec::new(),
                writers: Vec::new(),
                is_public: false,
            },
            version: 1,
            chunks: Vec::new(),
            encrypted_size: encrypted.encrypted_size,
            encrypted_at: encrypted.created_at,
        };

        self.coverage_store_file_metadata(metadata_record).await?;

        self.logger.log(
            crate::logging::LogLevel::Debug,
            &format!("Auto-encrypted new file at {}", canonical_output.display()),
            Some("coverage_auto_encrypt"),
        );

        Ok(Some(canonical_output))
    }

    #[cfg(feature = "mount-fs")]
    pub(super) fn candidate_file_paths(parent_id: &str, name: &str) -> Vec<String> {
        let mut paths = Vec::new();

        let trimmed_name = name.trim_matches('/');
        if trimmed_name.is_empty() {
            return vec!["/".to_string()];
        }

        let parent_normalized = match parent_id {
            "" | "/" | "root" => "".to_string(),
            other => {
                let trimmed = other.trim_matches('/');
                if trimmed.is_empty() {
                    "".to_string()
                } else {
                    format!("/{}", trimmed)
                }
            }
        };

        paths.push(format!("{}/{}", parent_normalized, trimmed_name).replace("//", "/"));

        // Fallback candidate without parent prefix for legacy entries
        paths.push(format!("/{}", trimmed_name));
        paths.push(trimmed_name.to_string());

        paths.sort();
        paths.dedup();
        paths
    }

    #[cfg(feature = "mount-fs")]
    pub(super) fn convert_file_metadata(metadata: FileMetadataData) -> crate::file::FileMetadata {
        crate::file::FileMetadata {
            path: metadata.file_path.clone(),
            size: metadata.file_size,
            epoch_id: metadata.epoch_id,
            last_access: metadata.modified_at,
            last_modified: metadata.modified_at,
            access_count: 0,
            pending_rewrap: false,
            checksum: metadata.integrity_hash.to_vec(),
        }
    }

    pub(super) fn normalize_storage_path(path: &str) -> String {
        if path.is_empty() {
            "/".to_string()
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path.trim_matches('/'))
        }
    }

    #[cfg(feature = "mount-fs")]
    pub(super) fn normalize_mount_path(path: &str) -> String {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed == "/" {
            "/".to_string()
        } else if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("/{}", trimmed.trim_matches('/'))
        }
    }

    #[cfg(feature = "mount-fs")]
    pub(super) async fn resolve_rewrap_disk_path(&self, normalized_path: &str) -> Option<PathBuf> {
        let mut candidates = Vec::new();
        let raw_path = PathBuf::from(normalized_path);

        if !normalized_path.is_empty() && normalized_path != "/" {
            candidates.push(raw_path.clone());
            if !Self::path_has_encrypted_suffix(&raw_path) {
                candidates.push(Self::default_encrypted_output_path(&raw_path));
            }
        }

        let rel = normalized_path.trim_start_matches('/');
        if !rel.is_empty() {
            let state = self.state.read().await;
            for root in state.coverage_roots.values() {
                match root.kind {
                    CoverageRootKind::SingleFile => {
                        candidates.push(root.path.clone());
                    }
                    CoverageRootKind::Folder => {
                        candidates.push(root.path.join(rel));
                        if !rel.to_ascii_lowercase().ends_with(".encrypted") {
                            candidates.push(root.path.join(format!("{rel}.encrypted")));
                        }
                    }
                }
            }
        }

        let mut seen = HashSet::new();
        for candidate in candidates {
            if !seen.insert(candidate.clone()) {
                continue;
            }
            if let Ok(metadata) = std::fs::metadata(&candidate) {
                if metadata.is_file() {
                    return Some(candidate);
                }
            }
        }

        None
    }

    #[cfg(feature = "mount-fs")]
    pub(super) async fn active_group_id(&self) -> Result<Uuid, ClientError> {
        let state = self.state.read().await;
        state.active_group_id.ok_or_else(|| {
            ClientError::InvalidState(
                "No active group selected. Run 'hybridcipher switch-group <group-id>' and retry the file operation."
                    .to_string(),
            )
        })
    }

    #[cfg(feature = "mount-fs")]
    pub(super) async fn load_file_metadata_data(
        &self,
        path: &str,
    ) -> Result<FileMetadataData, ClientError> {
        self.storage
            .load_file_metadata(path)
            .await
            .map_err(ClientError::from)?
            .ok_or_else(|| {
                ClientError::InvalidState(format!("File metadata not found for path: {}", path))
            })
    }

    #[cfg(feature = "mount-fs")]
    pub(super) async fn load_encrypted_file_bytes(
        &self,
        path: &str,
    ) -> Result<Vec<u8>, ClientError> {
        self.storage
            .get_file(path)
            .await
            .map_err(ClientError::from)?
            .ok_or_else(|| {
                ClientError::InvalidState(format!("Encrypted data not found for path: {}", path))
            })
    }

    #[cfg(feature = "mount-fs")]
    pub(super) async fn build_encrypted_metadata(
        &self,
        metadata: &FileMetadataData,
        encrypted_content: Vec<u8>,
        group_id: Uuid,
    ) -> Result<EncryptedFileMetadata, ClientError> {
        let file_id = metadata.file_id.clone().ok_or_else(|| {
            ClientError::InvalidState(format!(
                "Missing file_id for stored metadata at {}",
                metadata.file_path
            ))
        })?;

        Ok(EncryptedFileMetadata {
            file_id,
            file_path: metadata.file_path.clone(),
            group_id: Some(group_id),
            epoch_id: metadata.epoch_id,
            header_version: metadata.header_version,
            wrapped_file_key: metadata.wrapped_file_key.clone(),
            key_wrap_nonce: metadata.key_wrap_nonce.clone(),
            key_wrap_aad_hash: metadata.key_wrap_aad_hash.clone(),
            content_nonce: metadata.content_nonce.clone(),
            content_chunk_size: metadata.content_chunk_size,
            content_size: metadata.file_size,
            encrypted_size: encrypted_content.len() as u64,
            created_at: metadata.modified_at,
            platform_metadata: None,
            sparse_metadata: None,
            encrypted_content,
        })
    }

    /// Default interval between background membership/Welcome sync attempts
    pub(super) const AUTO_SYNC_INTERVAL_SECS: i64 = 300;

    /// Encrypt a file with the current epoch key
    ///
    /// This is the main file encryption workflow that integrates:
    /// - Current epoch key derivation
    /// - File encryption using ChaCha20-Poly1305
    /// - Coverage log updates
    /// - Metadata management
    ///
    /// # Arguments
    /// * `file_path` - Path identifier for the file
    /// * `content` - File content to encrypt
    ///
    /// # Returns
    /// Encrypted file metadata on success
    ///
    /// # Errors
    /// - `InvalidState` if no current epoch available
    /// - `EncryptionError` if encryption fails
    /// - `StorageError` if state cannot be persisted
    pub async fn encrypt_file(
        &self,
        file_path: &str,
        content: &[u8],
    ) -> Result<EncryptedFileMetadata, ClientError> {
        use hybridcipher_crypto::kdf::{hkdf_expand, HkdfContext};
        use hybridcipher_crypto::AeadKey;
        use rand::RngCore;

        Self::validate_encrypt_path_label(file_path)?;

        if self.is_path_excluded(file_path) {
            return Err(ClientError::PathExcluded(file_path.to_string()));
        }

        // Ensure client state is loaded
        self.ensure_state_loaded().await?;

        if let Err(err) = self.auto_sync_welcome_messages("encrypt_file").await {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Automatic Welcome sync before encryption failed: {}", err),
                Some("auto_sync"),
            );
        }

        let active_group = {
            let state = self.state.read().await;
            state.active_group_id
        };
        let active_group = match active_group {
            Some(group_id) => group_id,
            None => self.get_or_create_default_group().await?,
        };

        // First, ensure we have a proper current epoch (not 0)
        let current_epoch_id = {
            let state = self.state.read().await;
            state
                .group_memberships
                .get(&active_group)
                .and_then(|m| m.current_epoch_id)
                .unwrap_or(state.current_epoch)
        };

        // If current epoch is 0 (uninitialized), we need to establish proper epoch coordination
        if current_epoch_id == 0 {
            if let Err(e) = self
                .fetch_any_available_epoch_from_server(active_group)
                .await
            {
                match &e {
                    ClientError::InvalidState(_) => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            "No active epoch available for this group.",
                            Some(
                                "Ask a group admin to run 'hybridcipher initialize-group --group-id <group-id>' before encrypting files.",
                            ),
                        );
                    }
                    _ => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            &format!("Failed to fetch initial epoch from server: {}", e),
                            None,
                        );
                    }
                }
                return Err(e);
            }
        } else if let Err(e) = self
            .ensure_epoch_key_available(active_group, current_epoch_id)
            .await
        {
            match &e {
                ClientError::InvalidState(_) => {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Epoch {} is unavailable from the server for this device.",
                            current_epoch_id
                        ),
                        Some(
                            "Ask a group admin to run 'hybridcipher initialize-group --group-id <group-id>' before encrypting files.",
                        ),
                    );
                }
                _ => {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Failed to reconcile epoch {} with server: {}",
                            current_epoch_id, e
                        ),
                        None,
                    );
                }
            }
            return Err(e);
        }

        // Get the final current epoch after initialization
        let final_epoch_id = {
            let state = self.state.read().await;
            state
                .group_memberships
                .get(&active_group)
                .and_then(|m| m.current_epoch_id)
                .unwrap_or(state.current_epoch)
        };

        let state = self.state.read().await;

        // Get current epoch (should now be available)
        let epoch_state =
            Self::get_epoch_state(&state, active_group, final_epoch_id).ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Current epoch {} not found after ensure_epoch_key_available",
                    final_epoch_id
                ))
            })?;

        let is_migration_target = state
            .migration
            .as_ref()
            .map(|migration| migration.to_epoch == final_epoch_id)
            .unwrap_or(false);
        if is_migration_target && !epoch_state.key_source.is_verified() {
            return Err(ClientError::InvalidState(format!(
                "Rekey in progress; epoch {} key is not verified yet",
                final_epoch_id
            )));
        }

        // Derive a key-encrypting key (KEK) from the epoch key for wrapping the random DEK
        let kek_bytes = hkdf_expand(&epoch_state.encryption_key, HkdfContext::KeyWrapping, 32)
            .map_err(|e| {
                ClientError::EncryptionError(format!("HKDF(KeyWrapping) failed: {:?}", e))
            })?;
        let kek = AeadKey::from_bytes(&kek_bytes)
            .map_err(|e| ClientError::EncryptionError(format!("Failed to create KEK: {:?}", e)))?;

        // Generate a random per-file DEK
        let mut file_key_raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut file_key_raw);
        let file_key = AeadKey::from_bytes(&file_key_raw)
            .map_err(|e| ClientError::EncryptionError(format!("Failed to create DEK: {:?}", e)))?;

        // Normalize file label to ensure consistent identifiers across platforms
        let normalized_file_path = Self::normalize_file_identifier(file_path);

        // Create encrypted file metadata using the actual established epoch
        let file_id = self.generate_random_file_id();

        // Auth data for key wrap binds to file identity, epoch, group, and format version
        let header_version = 1u32;
        let wrap_aad = build_wrap_aad(
            &file_id,
            &normalized_file_path,
            Some(active_group),
            final_epoch_id,
            header_version,
        );
        let wrap_aad_hash = hash_wrap_aad(&wrap_aad);

        // Wrap the DEK with the KEK
        let (wrapped_file_key, key_wrap_nonce_bytes) = wrap_file_key(&file_key, &kek, &wrap_aad)
            .map_err(|e| ClientError::EncryptionError(format!("Key wrap failed: {:?}", e)))?;

        // Encrypt file content
        let (ciphertext, content_nonce_bytes) = encrypt_content(content, &file_key, &file_id)
            .map_err(|e| ClientError::EncryptionError(format!("Encryption failed: {:?}", e)))?;

        let mut encrypted_content = Vec::with_capacity(12 + ciphertext.len());
        encrypted_content.extend_from_slice(&content_nonce_bytes);
        encrypted_content.extend_from_slice(&ciphertext);

        let metadata = EncryptedFileMetadata {
            file_id: file_id.clone(),
            file_path: normalized_file_path.clone(),
            group_id: Some(active_group),
            epoch_id: final_epoch_id,
            content_size: content.len() as u64,
            encrypted_size: encrypted_content.len() as u64,
            created_at: chrono::Utc::now(),
            encrypted_content,
            header_version: Some(header_version),
            wrapped_file_key: Some(wrapped_file_key),
            key_wrap_nonce: Some(key_wrap_nonce_bytes),
            key_wrap_aad_hash: Some(wrap_aad_hash),
            content_nonce: Some(content_nonce_bytes),
            content_chunk_size: None,
            platform_metadata: None,
            sparse_metadata: None,
        };

        // Update coverage log
        drop(state); // Release read lock before write operations
        self.update_coverage_for_file(&file_id, final_epoch_id)
            .await?;

        Ok(metadata)
    }

    /// Encrypt a file using a caller-supplied file_id (stable identity across edits/renames).
    pub async fn encrypt_file_with_id(
        &self,
        file_path: &str,
        content: &[u8],
        file_id: &str,
    ) -> Result<EncryptedFileMetadata, ClientError> {
        use hybridcipher_crypto::kdf::{hkdf_expand, HkdfContext};
        use hybridcipher_crypto::AeadKey;
        use rand::RngCore;

        Self::validate_encrypt_path_label(file_path)?;

        if self.is_path_excluded(file_path) {
            return Err(ClientError::PathExcluded(file_path.to_string()));
        }

        let file_id = file_id.trim();
        if file_id.is_empty() {
            return Err(ClientError::InvalidInput(
                "file_id must be non-empty".to_string(),
            ));
        }

        // Ensure client state is loaded
        self.ensure_state_loaded().await?;

        if let Err(err) = self
            .auto_sync_welcome_messages("encrypt_file_with_id")
            .await
        {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Automatic Welcome sync before encryption failed: {}", err),
                Some("auto_sync"),
            );
        }

        let active_group = {
            let state = self.state.read().await;
            state.active_group_id
        };
        let active_group = match active_group {
            Some(group_id) => group_id,
            None => self.get_or_create_default_group().await?,
        };

        let current_epoch_id = {
            let state = self.state.read().await;
            state
                .group_memberships
                .get(&active_group)
                .and_then(|m| m.current_epoch_id)
                .unwrap_or(state.current_epoch)
        };

        if current_epoch_id == 0 {
            if let Err(e) = self
                .fetch_any_available_epoch_from_server(active_group)
                .await
            {
                match &e {
                    ClientError::InvalidState(_) => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            "No active epoch available for this group.",
                            Some(
                                "Ask a group admin to run 'hybridcipher initialize-group --group-id <group-id>' before encrypting files.",
                            ),
                        );
                    }
                    _ => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            &format!("Failed to fetch initial epoch from server: {}", e),
                            None,
                        );
                    }
                }
                return Err(e);
            }
        } else if let Err(e) = self
            .ensure_epoch_key_available(active_group, current_epoch_id)
            .await
        {
            match &e {
                ClientError::InvalidState(_) => {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Epoch {} is unavailable from the server for this device.",
                            current_epoch_id
                        ),
                        Some(
                            "Ask a group admin to run 'hybridcipher initialize-group --group-id <group-id>' before encrypting files.",
                        ),
                    );
                }
                _ => {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Failed to reconcile epoch {} with server: {}",
                            current_epoch_id, e
                        ),
                        None,
                    );
                }
            }
            return Err(e);
        }

        let final_epoch_id = {
            let state = self.state.read().await;
            state
                .group_memberships
                .get(&active_group)
                .and_then(|m| m.current_epoch_id)
                .unwrap_or(state.current_epoch)
        };

        let state = self.state.read().await;

        let epoch_state =
            Self::get_epoch_state(&state, active_group, final_epoch_id).ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Current epoch {} not found after ensure_epoch_key_available",
                    final_epoch_id
                ))
            })?;

        let is_migration_target = state
            .migration
            .as_ref()
            .map(|migration| migration.to_epoch == final_epoch_id)
            .unwrap_or(false);
        if is_migration_target && !epoch_state.key_source.is_verified() {
            return Err(ClientError::InvalidState(format!(
                "Rekey in progress; epoch {} key is not verified yet",
                final_epoch_id
            )));
        }

        let kek_bytes = hkdf_expand(&epoch_state.encryption_key, HkdfContext::KeyWrapping, 32)
            .map_err(|e| {
                ClientError::EncryptionError(format!("HKDF(KeyWrapping) failed: {:?}", e))
            })?;
        let kek = AeadKey::from_bytes(&kek_bytes)
            .map_err(|e| ClientError::EncryptionError(format!("Failed to create KEK: {:?}", e)))?;

        let mut file_key_raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut file_key_raw);
        let file_key = AeadKey::from_bytes(&file_key_raw)
            .map_err(|e| ClientError::EncryptionError(format!("Failed to create DEK: {:?}", e)))?;

        let normalized_file_path = Self::normalize_file_identifier(file_path);
        let file_id = file_id.to_string();

        let header_version = 1u32;
        let wrap_aad = build_wrap_aad(
            &file_id,
            &normalized_file_path,
            Some(active_group),
            final_epoch_id,
            header_version,
        );
        let wrap_aad_hash = hash_wrap_aad(&wrap_aad);

        let (wrapped_file_key, key_wrap_nonce_bytes) = wrap_file_key(&file_key, &kek, &wrap_aad)
            .map_err(|e| ClientError::EncryptionError(format!("Key wrap failed: {:?}", e)))?;

        let (ciphertext, content_nonce_bytes) = encrypt_content(content, &file_key, &file_id)
            .map_err(|e| ClientError::EncryptionError(format!("Encryption failed: {:?}", e)))?;

        let mut encrypted_content = Vec::with_capacity(12 + ciphertext.len());
        encrypted_content.extend_from_slice(&content_nonce_bytes);
        encrypted_content.extend_from_slice(&ciphertext);

        let metadata = EncryptedFileMetadata {
            file_id: file_id.clone(),
            file_path: normalized_file_path.clone(),
            group_id: Some(active_group),
            epoch_id: final_epoch_id,
            content_size: content.len() as u64,
            encrypted_size: encrypted_content.len() as u64,
            created_at: chrono::Utc::now(),
            encrypted_content,
            header_version: Some(header_version),
            wrapped_file_key: Some(wrapped_file_key),
            key_wrap_nonce: Some(key_wrap_nonce_bytes),
            key_wrap_aad_hash: Some(wrap_aad_hash),
            content_nonce: Some(content_nonce_bytes),
            content_chunk_size: None,
            platform_metadata: None,
            sparse_metadata: None,
        };

        drop(state);
        self.update_coverage_for_file(&file_id, final_epoch_id)
            .await?;

        Ok(metadata)
    }

    /// Encrypt a file to disk using streaming chunked encryption.
    pub async fn encrypt_file_streaming_to_path(
        &self,
        file_path: &str,
        source_path: &Path,
        output_path: &Path,
        original_name: Option<&str>,
        platform_metadata: Option<&PlatformFileMetadata>,
        chunk_size: usize,
    ) -> Result<(EncryptedFileMetadata, [u8; 32]), ClientError> {
        let file_id = self.generate_random_file_id();
        self.encrypt_file_streaming_with_id_to_path(
            file_path,
            source_path,
            output_path,
            original_name,
            platform_metadata,
            &file_id,
            chunk_size,
        )
        .await
    }

    /// Encrypt a file to disk using a caller-supplied file_id and streaming chunked encryption.
    pub async fn encrypt_file_streaming_with_id_to_path(
        &self,
        file_path: &str,
        source_path: &Path,
        output_path: &Path,
        original_name: Option<&str>,
        platform_metadata: Option<&PlatformFileMetadata>,
        file_id: &str,
        chunk_size: usize,
    ) -> Result<(EncryptedFileMetadata, [u8; 32]), ClientError> {
        use hybridcipher_crypto::kdf::{hkdf_expand, HkdfContext};
        use hybridcipher_crypto::AeadKey;
        use rand::RngCore;
        use std::io::{BufReader, BufWriter, Write};

        Self::validate_encrypt_path_label(file_path)?;

        if self.is_path_excluded(file_path) {
            return Err(ClientError::PathExcluded(file_path.to_string()));
        }

        let file_id = file_id.trim();
        if file_id.is_empty() {
            return Err(ClientError::InvalidInput(
                "file_id must be non-empty".to_string(),
            ));
        }

        if chunk_size == 0 {
            return Err(ClientError::InvalidInput(
                "chunk_size must be greater than 0".to_string(),
            ));
        }

        // Ensure client state is loaded
        self.ensure_state_loaded().await?;

        if let Err(err) = self
            .auto_sync_welcome_messages("encrypt_file_streaming_with_id")
            .await
        {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Automatic Welcome sync before encryption failed: {}", err),
                Some("auto_sync"),
            );
        }

        let active_group = {
            let state = self.state.read().await;
            state.active_group_id
        };
        let active_group = match active_group {
            Some(group_id) => group_id,
            None => self.get_or_create_default_group().await?,
        };

        let current_epoch_id = {
            let state = self.state.read().await;
            state
                .group_memberships
                .get(&active_group)
                .and_then(|m| m.current_epoch_id)
                .unwrap_or(state.current_epoch)
        };

        if current_epoch_id == 0 {
            if let Err(e) = self
                .fetch_any_available_epoch_from_server(active_group)
                .await
            {
                match &e {
                    ClientError::InvalidState(_) => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            "No active epoch available for this group.",
                            Some(
                                "Ask a group admin to run 'hybridcipher initialize-group --group-id <group-id>' before encrypting files.",
                            ),
                        );
                    }
                    _ => {
                        self.logger.log(
                            crate::logging::LogLevel::Error,
                            &format!("Failed to fetch initial epoch from server: {}", e),
                            None,
                        );
                    }
                }
                return Err(e);
            }
        } else if let Err(e) = self
            .ensure_epoch_key_available(active_group, current_epoch_id)
            .await
        {
            match &e {
                ClientError::InvalidState(_) => {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Epoch {} is unavailable from the server for this device.",
                            current_epoch_id
                        ),
                        Some(
                            "Ask a group admin to run 'hybridcipher initialize-group --group-id <group-id>' before encrypting files.",
                        ),
                    );
                }
                _ => {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Failed to reconcile epoch {} with server: {}",
                            current_epoch_id, e
                        ),
                        None,
                    );
                }
            }
            return Err(e);
        }

        let final_epoch_id = {
            let state = self.state.read().await;
            state
                .group_memberships
                .get(&active_group)
                .and_then(|m| m.current_epoch_id)
                .unwrap_or(state.current_epoch)
        };

        let state = self.state.read().await;
        let epoch_state =
            Self::get_epoch_state(&state, active_group, final_epoch_id).ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Current epoch {} not found after ensure_epoch_key_available",
                    final_epoch_id
                ))
            })?;

        let is_migration_target = state
            .migration
            .as_ref()
            .map(|migration| migration.to_epoch == final_epoch_id)
            .unwrap_or(false);
        if is_migration_target && !epoch_state.key_source.is_verified() {
            return Err(ClientError::InvalidState(format!(
                "Rekey in progress; epoch {} key is not verified yet",
                final_epoch_id
            )));
        }

        let kek_bytes = hkdf_expand(&epoch_state.encryption_key, HkdfContext::KeyWrapping, 32)
            .map_err(|e| {
                ClientError::EncryptionError(format!("HKDF(KeyWrapping) failed: {:?}", e))
            })?;
        let kek = AeadKey::from_bytes(&kek_bytes)
            .map_err(|e| ClientError::EncryptionError(format!("Failed to create KEK: {:?}", e)))?;

        let mut file_key_raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut file_key_raw);
        let file_key = AeadKey::from_bytes(&file_key_raw)
            .map_err(|e| ClientError::EncryptionError(format!("Failed to create DEK: {:?}", e)))?;

        let normalized_file_path = Self::normalize_file_identifier(file_path);
        let file_id = file_id.to_string();

        let header_version = CHUNKED_HEADER_VERSION;
        let wrap_aad = build_wrap_aad(
            &file_id,
            &normalized_file_path,
            Some(active_group),
            final_epoch_id,
            header_version,
        );
        let wrap_aad_hash = hash_wrap_aad(&wrap_aad);

        let (wrapped_file_key, key_wrap_nonce_bytes) = wrap_file_key(&file_key, &kek, &wrap_aad)
            .map_err(|e| ClientError::EncryptionError(format!("Key wrap failed: {:?}", e)))?;

        let mut content_nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut content_nonce_bytes);
        let content_nonce_vec = content_nonce_bytes.to_vec();

        let source_meta = std::fs::metadata(source_path).map_err(|e| {
            ClientError::EncryptionError(format!(
                "Failed to read source metadata for {}: {}",
                source_path.display(),
                e
            ))
        })?;
        if !source_meta.is_file() {
            return Err(ClientError::InvalidInput(format!(
                "Source path {} is not a file",
                source_path.display()
            )));
        }
        let content_size = source_meta.len();

        let encrypted_size = chunked_encrypted_size(content_size, chunk_size)
            .map_err(|e| ClientError::EncryptionError(e.to_string()))?;

        let header = SerializedEncryptedHeader {
            file_id: &file_id,
            file_path: &normalized_file_path,
            group_id: Some(active_group),
            epoch_id: final_epoch_id,
            header_version,
            wrapped_file_key: &wrapped_file_key,
            key_wrap_nonce: &key_wrap_nonce_bytes,
            key_wrap_aad_hash: &wrap_aad_hash,
            content_nonce: &content_nonce_bytes,
            content_chunk_size: Some(chunk_size as u64),
            original_size: content_size,
            encrypted_size,
            encrypted_at: chrono::Utc::now(),
            original_name,
            platform_metadata,
            sparse_metadata: None,
        };

        let parent = output_path.parent().ok_or_else(|| {
            ClientError::InvalidInput(format!(
                "Encrypted output path {} has no parent",
                output_path.display()
            ))
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            ClientError::EncryptionError(format!(
                "Failed to create output directory {}: {}",
                parent.display(),
                e
            ))
        })?;

        let file_name = output_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "encrypted".to_string());
        let tmp_dir = parent.join(".hybridcipher-tmp");
        std::fs::create_dir_all(&tmp_dir).map_err(|e| {
            ClientError::EncryptionError(format!(
                "Failed to create temp directory {}: {}",
                tmp_dir.display(),
                e
            ))
        })?;
        let tmp_path = tmp_dir.join(format!("tmp-{}.{}", Uuid::new_v4(), file_name));

        let mut writer = BufWriter::new(std::fs::File::create(&tmp_path).map_err(|e| {
            ClientError::EncryptionError(format!(
                "Failed to create temp file {}: {}",
                tmp_path.display(),
                e
            ))
        })?);

        let header_bytes = serialize_encrypted_header(&header)
            .map_err(|e| ClientError::EncryptionError(e.to_string()))?;
        if let Err(err) = writer.write_all(&header_bytes) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::EncryptionError(format!(
                "Failed to write encrypted header to {}: {}",
                tmp_path.display(),
                err
            )));
        }

        let reader = BufReader::new(std::fs::File::open(source_path).map_err(|e| {
            ClientError::EncryptionError(format!(
                "Failed to open plaintext {}: {}",
                source_path.display(),
                e
            ))
        })?);
        let (bytes_read, integrity_hash) = match encrypt_content_chunked(
            reader,
            &mut writer,
            &file_key,
            &file_id,
            &content_nonce_bytes,
            chunk_size,
        ) {
            Ok(result) => result,
            Err(err) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(ClientError::EncryptionError(err.to_string()));
            }
        };

        if bytes_read != content_size {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::EncryptionError(format!(
                "Plaintext size mismatch for {} (expected {}, read {})",
                source_path.display(),
                content_size,
                bytes_read
            )));
        }

        if let Err(err) = writer.flush() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::EncryptionError(format!(
                "Failed to flush ciphertext to {}: {}",
                tmp_path.display(),
                err
            )));
        }

        let tmp_file = match writer.into_inner() {
            Ok(file) => file,
            Err(err) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(ClientError::EncryptionError(format!(
                    "Failed to finalize ciphertext output {}: {}",
                    tmp_path.display(),
                    err
                )));
            }
        };

        if let Err(err) = tmp_file.sync_all() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::EncryptionError(format!(
                "Failed to fsync {}: {}",
                tmp_path.display(),
                err
            )));
        }

        #[cfg(target_os = "windows")]
        {
            if output_path.exists() {
                std::fs::remove_file(output_path).map_err(|e| {
                    ClientError::EncryptionError(format!(
                        "Failed to remove existing output {}: {}",
                        output_path.display(),
                        e
                    ))
                })?;
            }
        }

        if let Err(err) = std::fs::rename(&tmp_path, output_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::EncryptionError(format!(
                "Failed to move {} into place at {}: {}",
                tmp_path.display(),
                output_path.display(),
                err
            )));
        }

        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        let metadata = EncryptedFileMetadata {
            file_id: file_id.clone(),
            file_path: normalized_file_path.clone(),
            group_id: Some(active_group),
            epoch_id: final_epoch_id,
            content_size,
            encrypted_size,
            created_at: chrono::Utc::now(),
            platform_metadata: platform_metadata.cloned(),
            sparse_metadata: None,
            encrypted_content: Vec::new(),
            header_version: Some(header_version),
            wrapped_file_key: Some(wrapped_file_key),
            key_wrap_nonce: Some(key_wrap_nonce_bytes),
            key_wrap_aad_hash: Some(wrap_aad_hash),
            content_nonce: Some(content_nonce_vec),
            content_chunk_size: Some(chunk_size as u64),
        };

        drop(state);
        self.update_coverage_for_file(&file_id, final_epoch_id)
            .await?;

        Ok((metadata, integrity_hash))
    }

    /// Build AAD for wrapping the per-file DEK so headers are bound to identity + epoch + group.
    pub(super) fn build_wrap_aad(
        &self,
        file_id: &str,
        normalized_file_path: &str,
        group_id: Uuid,
        epoch_id: u64,
        header_version: u32,
    ) -> Vec<u8> {
        crate::file::encrypt::build_wrap_aad(
            file_id,
            normalized_file_path,
            Some(group_id),
            epoch_id,
            header_version,
        )
    }

    pub(super) fn compute_wrap_aad_bytes(
        file_id: &str,
        normalized_file_path: &str,
        group_id: Uuid,
        epoch_id: u64,
        header_version: u32,
    ) -> Vec<u8> {
        crate::file::encrypt::build_wrap_aad(
            file_id,
            normalized_file_path,
            Some(group_id),
            epoch_id,
            header_version,
        )
    }

    /// Decrypt a file using the appropriate epoch key
    ///
    /// This integrates:
    /// - Epoch key lookup from coverage log
    /// - Dual-epoch support during migration
    /// - File decryption using ChaCha20-Poly1305
    /// - Integrity verification
    /// - Automatic Welcome message processing for missing epochs
    ///
    /// # Arguments
    /// * `encrypted_file` - Encrypted file metadata
    ///
    /// # Returns
    /// Decrypted file content
    ///
    /// # Errors
    /// - `InvalidState` if epoch key not available
    /// - `DecryptionError` if decryption fails
    /// - `StorageError` if coverage log cannot be accessed
    pub async fn decrypt_file(
        &self,
        encrypted_file: &EncryptedFileMetadata,
    ) -> Result<Vec<u8>, ClientError> {
        use hybridcipher_crypto::aead::AeadContext;
        use hybridcipher_crypto::kdf::{hkdf_expand, HkdfContext};
        use hybridcipher_crypto::{open, AeadKey, AeadNonce};

        // Ensure client state is loaded
        self.ensure_state_loaded().await?;

        if let Err(err) = self.auto_sync_welcome_messages("decrypt_file").await {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Automatic Welcome sync before decryption failed: {}", err),
                Some("auto_sync"),
            );
        }

        let active_group = {
            let state = self.state.read().await;
            state
                .active_group_id
                .ok_or_else(|| {
                    ClientError::InvalidState(
                        "No active group selected. Run 'hybridcipher switch-group <group-id>' before decrypting."
                            .to_string(),
                    )
                })?
        };

        let file_group_id = encrypted_file.group_id.ok_or_else(|| {
            ClientError::InvalidState(
                "Encrypted file metadata is missing group information. Please re-encrypt the file with an updated client."
                    .to_string(),
            )
        })?;

        if file_group_id != active_group {
            return Err(ClientError::InvalidState(format!(
                "File belongs to group {}, but the active group is {}. Run 'hybridcipher switch-group {}' and retry.",
                file_group_id, active_group, file_group_id
            )));
        }

        match self.verify_file_coverage(&encrypted_file.file_path).await {
            Ok(coverage_epoch) => {
                if coverage_epoch != encrypted_file.epoch_id {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Coverage log reports epoch {} for file {}, but metadata references {}",
                            coverage_epoch, encrypted_file.file_path, encrypted_file.epoch_id
                        ),
                        None,
                    );
                }
            }
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Unable to verify coverage for {}: {}",
                        encrypted_file.file_path, err
                    ),
                    None,
                );
            }
        }

        // Use the epoch recorded in the file metadata for decryption
        // This avoids relying on local coverage state during cross-device access
        let file_epoch_id = encrypted_file.epoch_id;

        // Ensure we have at least the requested epoch; if missing, try to fetch
        {
            let state = self.state.read().await;
            if Self::get_epoch_state(&state, file_group_id, file_epoch_id).is_none() {
                drop(state);
                self.ensure_epoch_key_available(file_group_id, file_epoch_id)
                    .await?;
            } else {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "DEBUG: Found epoch {} locally for group {}",
                        file_epoch_id, file_group_id
                    ),
                    None,
                );
            }
        }

        // Wrapped-DEK header format only
        let wrapped_key = encrypted_file.wrapped_file_key.as_ref().ok_or_else(|| {
            ClientError::DecryptionError(
                "Encrypted file missing wrapped_file_key (legacy format unsupported)".to_string(),
            )
        })?;
        let wrap_nonce_bytes = encrypted_file.key_wrap_nonce.as_deref().ok_or_else(|| {
            ClientError::DecryptionError("Missing key wrap nonce in encrypted metadata".to_string())
        })?;
        let wrap_nonce = AeadNonce::from_bytes(wrap_nonce_bytes).map_err(|e| {
            ClientError::DecryptionError(format!("Invalid key wrap nonce: {:?}", e))
        })?;

        let header_version = encrypted_file.header_version.unwrap_or(1);
        let wrap_aad = self.build_wrap_aad(
            &encrypted_file.file_id,
            &encrypted_file.file_path,
            file_group_id,
            file_epoch_id,
            header_version,
        );
        if let Some(expected_hash) = encrypted_file.key_wrap_aad_hash.as_ref() {
            let actual = hash_wrap_aad(&wrap_aad);
            if &actual != expected_hash {
                return Err(ClientError::DecryptionError(
                    "Key wrap AAD hash mismatch".to_string(),
                ));
            }
        }

        let epoch_key_bytes = {
            let state = self.state.read().await;
            Self::get_epoch_state(&state, file_group_id, file_epoch_id)
                .map(|e| e.encryption_key)
                .ok_or_else(|| {
                    ClientError::InvalidState(format!(
                        "Epoch {} not available for key unwrap",
                        file_epoch_id
                    ))
                })?
        };

        let kek_bytes =
            hkdf_expand(&epoch_key_bytes, HkdfContext::KeyWrapping, 32).map_err(|e| {
                ClientError::DecryptionError(format!("HKDF(KeyWrapping) failed: {:?}", e))
            })?;
        let kek = AeadKey::from_bytes(&kek_bytes)
            .map_err(|e| ClientError::DecryptionError(format!("Invalid KEK: {:?}", e)))?;

        let file_key_bytes = open(
            &kek,
            &wrap_nonce,
            AeadContext::FileData,
            &wrap_aad,
            wrapped_key,
        )
        .map_err(|e| ClientError::DecryptionError(format!("Key unwrap failed: {:?}", e)))?;
        let file_key = AeadKey::from_bytes(&file_key_bytes)
            .map_err(|e| ClientError::DecryptionError(format!("Invalid DEK bytes: {:?}", e)))?;

        let header_version = encrypted_file.header_version.unwrap_or(1);
        let packed_content_size = Self::effective_packed_content_size(encrypted_file);
        let packed_plaintext = if header_version >= CHUNKED_HEADER_VERSION
            || encrypted_file.content_chunk_size.is_some()
        {
            let chunk_size = encrypted_file.content_chunk_size.ok_or_else(|| {
                ClientError::DecryptionError("Missing chunk_size in metadata".to_string())
            })? as usize;
            let content_nonce = encrypted_file.content_nonce.as_ref().ok_or_else(|| {
                ClientError::DecryptionError("Missing content nonce in metadata".to_string())
            })?;
            Self::decrypt_chunked_bytes(
                &file_key,
                &encrypted_file.file_id,
                content_nonce,
                chunk_size,
                packed_content_size,
                &encrypted_file.encrypted_content,
            )?
        } else {
            if encrypted_file.encrypted_content.len() < 12 {
                return Err(ClientError::DecryptionError(
                    "Invalid encrypted content length".to_string(),
                ));
            }
            let (nonce_bytes, ciphertext) = encrypted_file.encrypted_content.split_at(12);
            let content_nonce = AeadNonce::from_bytes(nonce_bytes).map_err(|e| {
                ClientError::DecryptionError(format!("Invalid content nonce: {:?}", e))
            })?;

            let aad = encrypted_file.file_id.as_bytes();
            open(
                &file_key,
                &content_nonce,
                AeadContext::FileData,
                aad,
                ciphertext,
            )
            .map_err(|e| ClientError::DecryptionError(format!("Decryption failed: {:?}", e)))?
        };

        let plaintext = if let Some(sparse_metadata) = encrypted_file.sparse_metadata.as_ref() {
            Self::rehydrate_sparse_plaintext(&packed_plaintext, sparse_metadata)?
        } else {
            packed_plaintext
        };

        // Accept when original size is unknown (0) or matches the decrypted length.
        if encrypted_file.content_size == 0
            || plaintext.len() == encrypted_file.content_size as usize
        {
            self.maybe_schedule_rewrap(&encrypted_file.file_path, file_epoch_id)
                .await;
            return Ok(plaintext);
        }

        Err(ClientError::DecryptionError(
            "Decryption failed (length mismatch)".to_string(),
        ))
    }

    /// Decrypt a file from disk using streaming chunked decryption.
    pub async fn decrypt_file_streaming_to_path(
        &self,
        encrypted_path: &Path,
        encrypted_file: &EncryptedFileMetadata,
        output_path: &Path,
    ) -> Result<(), ClientError> {
        use hybridcipher_crypto::aead::AeadContext;
        use hybridcipher_crypto::kdf::{hkdf_expand, HkdfContext};
        use hybridcipher_crypto::{open, AeadKey, AeadNonce};
        use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

        let header_version = encrypted_file.header_version.unwrap_or(1);
        let chunk_size = encrypted_file.content_chunk_size;
        if header_version < CHUNKED_HEADER_VERSION || chunk_size.is_none() {
            let plaintext = self.decrypt_file(encrypted_file).await?;
            return Self::write_plaintext_atomic(output_path, &plaintext);
        }

        // Ensure client state is loaded
        self.ensure_state_loaded().await?;

        if let Err(err) = self
            .auto_sync_welcome_messages("decrypt_file_streaming")
            .await
        {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Automatic Welcome sync before decryption failed: {}", err),
                Some("auto_sync"),
            );
        }

        let active_group = {
            let state = self.state.read().await;
            state
                .active_group_id
                .ok_or_else(|| {
                    ClientError::InvalidState(
                        "No active group selected. Run 'hybridcipher switch-group <group-id>' before decrypting."
                            .to_string(),
                    )
                })?
        };

        let file_group_id = encrypted_file.group_id.ok_or_else(|| {
            ClientError::InvalidState(
                "Encrypted file metadata is missing group information. Please re-encrypt the file with an updated client."
                    .to_string(),
            )
        })?;

        if file_group_id != active_group {
            return Err(ClientError::InvalidState(format!(
                "File belongs to group {}, but the active group is {}. Run 'hybridcipher switch-group {}' and retry.",
                file_group_id, active_group, file_group_id
            )));
        }

        match self.verify_file_coverage(&encrypted_file.file_path).await {
            Ok(coverage_epoch) => {
                if coverage_epoch != encrypted_file.epoch_id {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Coverage log reports epoch {} for file {}, but metadata references {}",
                            coverage_epoch, encrypted_file.file_path, encrypted_file.epoch_id
                        ),
                        None,
                    );
                }
            }
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "Unable to verify coverage for {}: {}",
                        encrypted_file.file_path, err
                    ),
                    None,
                );
            }
        }

        let file_epoch_id = encrypted_file.epoch_id;

        {
            let state = self.state.read().await;
            if Self::get_epoch_state(&state, file_group_id, file_epoch_id).is_none() {
                drop(state);
                self.ensure_epoch_key_available(file_group_id, file_epoch_id)
                    .await?;
            }
        }

        let wrapped_key = encrypted_file.wrapped_file_key.as_ref().ok_or_else(|| {
            ClientError::DecryptionError(
                "Encrypted file missing wrapped_file_key (legacy format unsupported)".to_string(),
            )
        })?;
        let wrap_nonce_bytes = encrypted_file.key_wrap_nonce.as_deref().ok_or_else(|| {
            ClientError::DecryptionError("Missing key wrap nonce in encrypted metadata".to_string())
        })?;
        let wrap_nonce = AeadNonce::from_bytes(wrap_nonce_bytes).map_err(|e| {
            ClientError::DecryptionError(format!("Invalid key wrap nonce: {:?}", e))
        })?;

        let wrap_aad = self.build_wrap_aad(
            &encrypted_file.file_id,
            &encrypted_file.file_path,
            file_group_id,
            file_epoch_id,
            header_version,
        );
        if let Some(expected_hash) = encrypted_file.key_wrap_aad_hash.as_ref() {
            let actual = hash_wrap_aad(&wrap_aad);
            if &actual != expected_hash {
                return Err(ClientError::DecryptionError(
                    "Key wrap AAD hash mismatch".to_string(),
                ));
            }
        }

        let epoch_key_bytes = {
            let state = self.state.read().await;
            Self::get_epoch_state(&state, file_group_id, file_epoch_id)
                .map(|e| e.encryption_key)
                .ok_or_else(|| {
                    ClientError::InvalidState(format!(
                        "Epoch {} not available for key unwrap",
                        file_epoch_id
                    ))
                })?
        };

        let kek_bytes =
            hkdf_expand(&epoch_key_bytes, HkdfContext::KeyWrapping, 32).map_err(|e| {
                ClientError::DecryptionError(format!("HKDF(KeyWrapping) failed: {:?}", e))
            })?;
        let kek = AeadKey::from_bytes(&kek_bytes)
            .map_err(|e| ClientError::DecryptionError(format!("Invalid KEK: {:?}", e)))?;

        let file_key_bytes = open(
            &kek,
            &wrap_nonce,
            AeadContext::FileData,
            &wrap_aad,
            wrapped_key,
        )
        .map_err(|e| ClientError::DecryptionError(format!("Key unwrap failed: {:?}", e)))?;
        let file_key = AeadKey::from_bytes(&file_key_bytes)
            .map_err(|e| ClientError::DecryptionError(format!("Invalid DEK bytes: {:?}", e)))?;

        let content_nonce = encrypted_file.content_nonce.as_ref().ok_or_else(|| {
            ClientError::DecryptionError("Missing content nonce in metadata".to_string())
        })?;
        if content_nonce.len() != 12 {
            return Err(ClientError::DecryptionError(
                "Invalid content nonce length".to_string(),
            ));
        }
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(content_nonce);

        let chunk_size = chunk_size.ok_or_else(|| {
            ClientError::DecryptionError("Missing chunk_size in metadata".to_string())
        })? as usize;
        if chunk_size == 0 {
            return Err(ClientError::DecryptionError(
                "chunk_size must be greater than 0".to_string(),
            ));
        }

        let packed_content_size = Self::effective_packed_content_size(encrypted_file);
        let expected_encrypted_size = chunked_encrypted_size(packed_content_size, chunk_size)
            .map_err(|e| ClientError::DecryptionError(e.to_string()))?;

        let ciphertext_offset = {
            let file = std::fs::File::open(encrypted_path).map_err(|e| {
                ClientError::DecryptionError(format!(
                    "Failed to open encrypted file {}: {}",
                    encrypted_path.display(),
                    e
                ))
            })?;
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            loop {
                line.clear();
                let bytes = reader.read_until(b'\n', &mut line).map_err(|e| {
                    ClientError::DecryptionError(format!(
                        "Failed to read encrypted header {}: {}",
                        encrypted_path.display(),
                        e
                    ))
                })?;
                if bytes == 0 {
                    return Err(ClientError::DecryptionError(
                        "Encrypted header separator not found".to_string(),
                    ));
                }
                if line == b"---ENCRYPTED_DATA---\n" || line == b"---ENCRYPTED_DATA---" {
                    break;
                }
            }
            reader.stream_position().map_err(|e| {
                ClientError::DecryptionError(format!(
                    "Failed to locate ciphertext offset for {}: {}",
                    encrypted_path.display(),
                    e
                ))
            })?
        };

        let file_len = std::fs::metadata(encrypted_path)
            .map_err(|e| {
                ClientError::DecryptionError(format!(
                    "Failed to stat encrypted file {}: {}",
                    encrypted_path.display(),
                    e
                ))
            })?
            .len();
        if file_len < ciphertext_offset {
            return Err(ClientError::DecryptionError(
                "Encrypted file is shorter than header offset".to_string(),
            ));
        }
        let actual_cipher_len = file_len - ciphertext_offset;
        if actual_cipher_len != expected_encrypted_size {
            return Err(ClientError::DecryptionError(format!(
                "Encrypted size mismatch (expected {}, found {})",
                expected_encrypted_size, actual_cipher_len
            )));
        }

        let parent = output_path.parent().ok_or_else(|| {
            ClientError::InvalidInput(format!(
                "Output path {} has no parent",
                output_path.display()
            ))
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            ClientError::DecryptionError(format!(
                "Failed to create output directory {}: {}",
                parent.display(),
                e
            ))
        })?;

        let mut input_file = std::fs::File::open(encrypted_path).map_err(|e| {
            ClientError::DecryptionError(format!(
                "Failed to open encrypted file {}: {}",
                encrypted_path.display(),
                e
            ))
        })?;
        input_file
            .seek(SeekFrom::Start(ciphertext_offset))
            .map_err(|e| {
                ClientError::DecryptionError(format!(
                    "Failed to seek to ciphertext {}: {}",
                    encrypted_path.display(),
                    e
                ))
            })?;

        let mut reader = BufReader::new(input_file);
        let mut packed_plaintext = Vec::with_capacity(packed_content_size as usize);

        let mut remaining = packed_content_size;
        let mut chunk_index = 0u64;
        let mut buffer = vec![0u8; chunk_size + AEAD_TAG_SIZE];

        while remaining > 0 {
            let plain_len = usize::min(chunk_size, remaining as usize);
            let cipher_len = plain_len + AEAD_TAG_SIZE;
            buffer.resize(cipher_len, 0);
            reader.read_exact(&mut buffer).map_err(|e| {
                ClientError::DecryptionError(format!("Failed to read ciphertext chunk: {}", e))
            })?;

            let nonce_bytes = derive_chunk_nonce(&base_nonce, chunk_index);
            let nonce = AeadNonce::from_bytes(&nonce_bytes).map_err(|e| {
                ClientError::DecryptionError(format!("Invalid chunk nonce: {:?}", e))
            })?;

            let mut aad = Vec::with_capacity(encrypted_file.file_id.len() + 8);
            aad.extend_from_slice(encrypted_file.file_id.as_bytes());
            aad.extend_from_slice(&chunk_index.to_le_bytes());

            let plaintext =
                open(&file_key, &nonce, AeadContext::FileData, &aad, &buffer).map_err(|e| {
                    ClientError::DecryptionError(format!("Chunk decrypt failed: {:?}", e))
                })?;
            packed_plaintext.extend_from_slice(&plaintext);

            remaining -= plain_len as u64;
            chunk_index += 1;
        }

        if let Some(sparse_metadata) = encrypted_file.sparse_metadata.as_ref() {
            Self::write_sparse_plaintext_atomic(output_path, &packed_plaintext, sparse_metadata)?;
        } else {
            Self::write_plaintext_atomic(output_path, &packed_plaintext)?;
        }

        self.maybe_schedule_rewrap(&encrypted_file.file_path, file_epoch_id)
            .await;

        Ok(())
    }

    pub(super) fn decrypt_chunked_bytes(
        file_key: &AeadKey,
        file_id: &str,
        content_nonce: &[u8],
        chunk_size: usize,
        content_size: u64,
        encrypted_content: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        use hybridcipher_crypto::{aead::AeadContext, open, AeadNonce};

        if chunk_size == 0 {
            return Err(ClientError::DecryptionError(
                "chunk_size must be greater than 0".to_string(),
            ));
        }
        if content_nonce.len() != 12 {
            return Err(ClientError::DecryptionError(
                "Invalid content nonce length".to_string(),
            ));
        }

        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(content_nonce);

        let mut output = Vec::with_capacity(content_size as usize);
        let mut offset = 0usize;
        let mut remaining = content_size;
        let mut chunk_index = 0u64;

        while remaining > 0 {
            let plain_len = usize::min(chunk_size, remaining as usize);
            let cipher_len = plain_len + AEAD_TAG_SIZE;
            if offset + cipher_len > encrypted_content.len() {
                return Err(ClientError::DecryptionError(
                    "Chunked ciphertext truncated".to_string(),
                ));
            }
            let chunk_cipher = &encrypted_content[offset..offset + cipher_len];

            let nonce_bytes = derive_chunk_nonce(&base_nonce, chunk_index);
            let nonce = AeadNonce::from_bytes(&nonce_bytes).map_err(|e| {
                ClientError::DecryptionError(format!("Invalid chunk nonce: {:?}", e))
            })?;

            let mut aad = Vec::with_capacity(file_id.len() + 8);
            aad.extend_from_slice(file_id.as_bytes());
            aad.extend_from_slice(&chunk_index.to_le_bytes());

            let plaintext = open(file_key, &nonce, AeadContext::FileData, &aad, chunk_cipher)
                .map_err(|e| {
                    ClientError::DecryptionError(format!("Chunk decrypt failed: {:?}", e))
                })?;
            output.extend_from_slice(&plaintext);

            offset += cipher_len;
            remaining -= plain_len as u64;
            chunk_index += 1;
        }

        if offset != encrypted_content.len() {
            return Err(ClientError::DecryptionError(
                "Chunked ciphertext size mismatch".to_string(),
            ));
        }

        Ok(output)
    }

    pub(super) fn effective_packed_content_size(encrypted_file: &EncryptedFileMetadata) -> u64 {
        encrypted_file
            .sparse_metadata
            .as_ref()
            .map(SparseFileMetadata::packed_size)
            .unwrap_or(encrypted_file.content_size)
    }

    pub(super) fn rehydrate_sparse_plaintext(
        packed: &[u8],
        sparse_metadata: &SparseFileMetadata,
    ) -> Result<Vec<u8>, ClientError> {
        let packed_size = sparse_metadata.packed_size();
        if packed.len() as u64 != packed_size {
            return Err(ClientError::DecryptionError(format!(
                "Sparse packed-size mismatch (expected {}, found {})",
                packed_size,
                packed.len()
            )));
        }

        let logical_len = usize::try_from(sparse_metadata.logical_size).map_err(|_| {
            ClientError::DecryptionError(
                "Sparse logical size exceeds addressable memory".to_string(),
            )
        })?;
        let mut output = vec![0u8; logical_len];
        let mut packed_offset = 0usize;
        for extent in &sparse_metadata.extents {
            let start = usize::try_from(extent.offset).map_err(|_| {
                ClientError::DecryptionError("Sparse extent offset overflow".to_string())
            })?;
            let len = usize::try_from(extent.length).map_err(|_| {
                ClientError::DecryptionError("Sparse extent length overflow".to_string())
            })?;
            let end = start.checked_add(len).ok_or_else(|| {
                ClientError::DecryptionError("Sparse extent overflow".to_string())
            })?;
            if end > output.len() || packed_offset + len > packed.len() {
                return Err(ClientError::DecryptionError(
                    "Sparse extent layout is inconsistent with plaintext size".to_string(),
                ));
            }
            output[start..end].copy_from_slice(&packed[packed_offset..packed_offset + len]);
            packed_offset += len;
        }

        Ok(output)
    }

    pub(super) fn write_sparse_plaintext_atomic(
        path: &Path,
        packed: &[u8],
        sparse_metadata: &SparseFileMetadata,
    ) -> Result<(), ClientError> {
        use std::io::{Seek, SeekFrom, Write};

        let parent = path.parent().ok_or_else(|| {
            ClientError::InvalidInput(format!("Output path {} has no parent", path.display()))
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            ClientError::DecryptionError(format!(
                "Failed to create output directory {}: {}",
                parent.display(),
                e
            ))
        })?;

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "decrypted".to_string());
        let tmp_path = parent.join(format!("{}.tmp-{}", file_name, Uuid::new_v4()));

        let packed_size = sparse_metadata.packed_size();
        if packed.len() as u64 != packed_size {
            return Err(ClientError::DecryptionError(format!(
                "Sparse packed-size mismatch (expected {}, found {})",
                packed_size,
                packed.len()
            )));
        }

        let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
            ClientError::DecryptionError(format!(
                "Failed to create sparse temp output {}: {}",
                tmp_path.display(),
                e
            ))
        })?;
        file.set_len(sparse_metadata.logical_size).map_err(|e| {
            ClientError::DecryptionError(format!(
                "Failed to size sparse temp output {}: {}",
                tmp_path.display(),
                e
            ))
        })?;

        let mut packed_offset = 0usize;
        for extent in &sparse_metadata.extents {
            file.seek(SeekFrom::Start(extent.offset)).map_err(|e| {
                ClientError::DecryptionError(format!(
                    "Failed to seek sparse temp output {}: {}",
                    tmp_path.display(),
                    e
                ))
            })?;
            let len = usize::try_from(extent.length).map_err(|_| {
                ClientError::DecryptionError("Sparse extent length overflow".to_string())
            })?;
            if packed_offset + len > packed.len() {
                return Err(ClientError::DecryptionError(
                    "Sparse extent layout exceeds packed plaintext".to_string(),
                ));
            }
            file.write_all(&packed[packed_offset..packed_offset + len])
                .map_err(|e| {
                    ClientError::DecryptionError(format!(
                        "Failed to write sparse temp output {}: {}",
                        tmp_path.display(),
                        e
                    ))
                })?;
            packed_offset += len;
        }

        if let Err(err) = file.sync_all() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::DecryptionError(format!(
                "Failed to fsync {}: {}",
                tmp_path.display(),
                err
            )));
        }

        #[cfg(target_os = "windows")]
        {
            if path.exists() {
                std::fs::remove_file(path).map_err(|e| {
                    ClientError::DecryptionError(format!(
                        "Failed to remove existing output {}: {}",
                        path.display(),
                        e
                    ))
                })?;
            }
        }

        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::DecryptionError(format!(
                "Failed to move {} into place at {}: {}",
                tmp_path.display(),
                path.display(),
                err
            )));
        }

        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    pub(super) fn write_plaintext_atomic(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
        use std::io::Write;

        let parent = path.parent().ok_or_else(|| {
            ClientError::InvalidInput(format!("Output path {} has no parent", path.display()))
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            ClientError::DecryptionError(format!(
                "Failed to create output directory {}: {}",
                parent.display(),
                e
            ))
        })?;

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "decrypted".to_string());
        let tmp_path = parent.join(format!("{}.tmp-{}", file_name, Uuid::new_v4()));

        let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
            ClientError::DecryptionError(format!(
                "Failed to create temp output {}: {}",
                tmp_path.display(),
                e
            ))
        })?;
        file.write_all(bytes).map_err(|e| {
            ClientError::DecryptionError(format!(
                "Failed to write plaintext to {}: {}",
                tmp_path.display(),
                e
            ))
        })?;
        if let Err(err) = file.sync_all() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::DecryptionError(format!(
                "Failed to fsync {}: {}",
                tmp_path.display(),
                err
            )));
        }

        #[cfg(target_os = "windows")]
        {
            if path.exists() {
                std::fs::remove_file(path).map_err(|e| {
                    ClientError::DecryptionError(format!(
                        "Failed to remove existing output {}: {}",
                        path.display(),
                        e
                    ))
                })?;
            }
        }

        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ClientError::DecryptionError(format!(
                "Failed to move {} into place at {}: {}",
                tmp_path.display(),
                path.display(),
                err
            )));
        }

        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    /// Batch encrypt multiple files
    ///
    /// # Arguments
    /// * `files` - Vector of (file_path, content) tuples
    ///
    /// # Returns
    /// Vector of encrypted file metadata
    pub async fn batch_encrypt_files(
        &self,
        files: Vec<(&str, &[u8])>,
    ) -> Result<Vec<EncryptedFileMetadata>, ClientError> {
        let mut results = Vec::with_capacity(files.len());

        for (file_path, content) in files {
            let encrypted = self.encrypt_file(file_path, content).await?;
            results.push(encrypted);
        }

        Ok(results)
    }

    /// Batch decrypt multiple files
    ///
    /// # Arguments
    /// * `files` - Vector of encrypted file metadata
    ///
    /// # Returns
    /// Vector of decrypted file contents
    pub async fn batch_decrypt_files(
        &self,
        files: Vec<&EncryptedFileMetadata>,
    ) -> Result<Vec<Vec<u8>>, ClientError> {
        let mut results = Vec::with_capacity(files.len());

        for encrypted_file in files {
            let decrypted = self.decrypt_file(encrypted_file).await?;
            results.push(decrypted);
        }

        Ok(results)
    }

    /// Generate a fresh random file identifier for new encryptions.
    pub(super) fn generate_random_file_id(&self) -> String {
        generate_file_id()
    }

    /// Resolve the persisted file_id for a path, falling back to the legacy derivation if needed.
    pub(super) async fn resolve_file_id_for_path(
        &self,
        file_path: &str,
        epoch_hint: u64,
    ) -> Result<String, ClientError> {
        let normalized = Self::normalize_file_identifier(file_path);
        let storage_normalized = Self::normalize_storage_path(&normalized);
        let mut candidates = vec![
            file_path.to_string(),
            normalized.clone(),
            storage_normalized.clone(),
        ];
        candidates.sort();
        candidates.dedup();

        for candidate in candidates.iter() {
            match self.storage.load_file_metadata(candidate).await {
                Ok(Some(metadata)) => {
                    if let Some(file_id) = metadata.file_id.clone() {
                        return Ok(file_id);
                    }
                }
                Ok(None) => {}
                Err(e) => return Err(ClientError::from(e)),
            }
        }

        for candidate in candidates.iter() {
            let path = PathBuf::from(candidate);
            if let Some(header) = Self::parse_encrypted_file_metadata(&path) {
                if !header.file_id.is_empty() {
                    return Ok(header.file_id);
                }
            }
        }

        Err(ClientError::InvalidState(format!(
            "No file_id found for path {} (epoch_hint={})",
            file_path, epoch_hint
        )))
    }

    pub(super) fn normalize_file_identifier(path: &str) -> String {
        crate::file::encrypt::normalize_file_identifier(path)
    }

    pub(super) fn appears_to_be_file_id_label(file_path: &str) -> bool {
        let trimmed = file_path.trim();
        if trimmed.len() != 64 {
            return false;
        }

        if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('.') {
            return false;
        }

        trimmed
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    pub(super) fn validate_encrypt_path_label(file_path: &str) -> Result<(), ClientError> {
        if Self::appears_to_be_file_id_label(file_path) {
            return Err(ClientError::InvalidInput(
                "encrypt_file expects a canonical or relative path label, received a file_id-like value"
                    .to_string(),
            ));
        }
        Ok(())
    }

    // FUSE filesystem interface methods (placeholder implementations)

    /// Look up a file in the current or previous epochs
    #[cfg(feature = "mount-fs")]
    pub async fn lookup_file(
        &self,
        parent_id: &str,
        name: &str,
    ) -> Result<Option<crate::file::FileMetadata>, ClientError> {
        for candidate in Self::candidate_file_paths(parent_id, name) {
            if candidate.is_empty() {
                continue;
            }

            match self.storage.load_file_metadata(&candidate).await {
                Ok(Some(metadata)) => {
                    return Ok(Some(Self::convert_file_metadata(metadata)));
                }
                Ok(None) => continue,
                Err(err) => return Err(ClientError::from(err)),
            }
        }

        Ok(None)
    }

    #[cfg(not(feature = "mount-fs"))]
    pub async fn lookup_file(
        &self,
        parent_id: &str,
        name: &str,
    ) -> Result<Option<crate::file::FileMetadata>, ClientError> {
        let _ = (parent_id, name);
        Err(Self::filesystem_feature_disabled("lookup_file"))
    }

    /// Read a chunk of a file with epoch-aware decryption
    #[cfg(feature = "mount-fs")]
    pub async fn read_file_chunk(
        &self,
        file_id: &str,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, ClientError> {
        if size == 0 {
            return Ok(Vec::new());
        }

        self.ensure_state_loaded().await?;

        let normalized_path = Self::normalize_mount_path(file_id);
        let group_id = self.active_group_id().await?;

        let metadata = self.load_file_metadata_data(&normalized_path).await?;
        let encrypted_bytes = self.load_encrypted_file_bytes(&normalized_path).await?;
        let encrypted_metadata = self
            .build_encrypted_metadata(&metadata, encrypted_bytes, group_id)
            .await?;

        let plaintext = self.decrypt_file(&encrypted_metadata).await?;
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }

        let file_len = plaintext.len() as u64;
        if offset >= file_len {
            return Ok(Vec::new());
        }

        let max_len = size.min(file_len - offset);
        let start = offset as usize;
        let end = start + max_len as usize;

        Ok(plaintext[start..end].to_vec())
    }

    #[cfg(not(feature = "mount-fs"))]
    pub async fn read_file_chunk(
        &self,
        file_id: &str,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let _ = (file_id, offset, size);
        Err(Self::filesystem_feature_disabled("read_file_chunk"))
    }

    /// Get file metadata for a given path
    #[cfg(feature = "mount-fs")]
    pub async fn get_file_metadata(
        &self,
        path: &str,
    ) -> Result<crate::file::FileMetadata, ClientError> {
        let normalized = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path.trim_matches('/'))
        };

        let metadata = self
            .storage
            .load_file_metadata(&normalized)
            .await
            .map_err(ClientError::from)?
            .ok_or_else(|| {
                ClientError::InvalidState(format!("File metadata not found for path: {normalized}"))
            })?;

        Ok(Self::convert_file_metadata(metadata))
    }

    #[cfg(not(feature = "mount-fs"))]
    pub async fn get_file_metadata(
        &self,
        path: &str,
    ) -> Result<crate::file::FileMetadata, ClientError> {
        let _ = path;
        Err(Self::filesystem_feature_disabled("get_file_metadata"))
    }

    /// Check if a file has been migrated to the current epoch
    #[cfg(feature = "mount-fs")]
    pub async fn is_file_migrated(&self, file_id: &str) -> Result<bool, ClientError> {
        self.ensure_state_loaded().await?;

        let normalized_path = Self::normalize_mount_path(file_id);
        let metadata = self.load_file_metadata_data(&normalized_path).await?;

        let state = self.state.read().await;
        if let Some(migration) = &state.migration {
            Ok(metadata.epoch_id == migration.to_epoch)
        } else {
            Ok(metadata.epoch_id == state.current_epoch)
        }
    }

    #[cfg(not(feature = "mount-fs"))]
    pub async fn is_file_migrated(&self, file_id: &str) -> Result<bool, ClientError> {
        let _ = file_id;
        Err(Self::filesystem_feature_disabled("is_file_migrated"))
    }

    /// Check if a file migration is currently in progress
    #[cfg(feature = "mount-fs")]
    pub async fn is_file_migration_in_progress(&self, file_id: &str) -> Result<bool, ClientError> {
        self.ensure_state_loaded().await?;

        let normalized_path = Self::normalize_mount_path(file_id);
        let metadata = self.load_file_metadata_data(&normalized_path).await?;

        let state = self.state.read().await;
        if let Some(migration) = &state.migration {
            Ok(metadata.epoch_id == migration.from_epoch)
        } else {
            Ok(false)
        }
    }

    #[cfg(not(feature = "mount-fs"))]
    pub async fn is_file_migration_in_progress(&self, file_id: &str) -> Result<bool, ClientError> {
        let _ = file_id;
        Err(Self::filesystem_feature_disabled(
            "is_file_migration_in_progress",
        ))
    }

    /// Get overall migration status for the group
    pub async fn get_migration_status(&self) -> Result<String, ClientError> {
        let is_migrating = self.is_migrating().await;
        let progress = self.migration_progress().await.unwrap_or(0.0);

        if is_migrating {
            Ok(format!(
                "Migration in progress: {:.1}% complete",
                progress * 100.0
            ))
        } else {
            Ok("No migration in progress".to_string())
        }
    }

    /// Migrate a specific file between epochs
    #[cfg(feature = "mount-fs")]
    pub async fn migrate_file(
        &self,
        file_id: &str,
        from_epoch: &str,
        to_epoch: &str,
    ) -> Result<u64, ClientError> {
        use hybridcipher_crypto::kdf::{hkdf_expand, HkdfContext};

        self.ensure_state_loaded().await?;

        let from_epoch_id = from_epoch.parse::<u64>().map_err(|_| {
            ClientError::InvalidState(format!("Invalid from_epoch identifier: {from_epoch}"))
        })?;
        let to_epoch_id = to_epoch.parse::<u64>().map_err(|_| {
            ClientError::InvalidState(format!("Invalid to_epoch identifier: {to_epoch}"))
        })?;

        if from_epoch_id == to_epoch_id {
            return Ok(0);
        }

        let normalized_path = Self::normalize_mount_path(file_id);
        let group_id = self.active_group_id().await?;

        let mut metadata = self.load_file_metadata_data(&normalized_path).await?;
        if metadata.epoch_id != from_epoch_id {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "File {} is recorded under epoch {}, not {}. Continuing migration.",
                    normalized_path, metadata.epoch_id, from_epoch_id
                ),
                Some("file_migration_epoch_mismatch"),
            );
        }

        let encrypted_bytes = self.load_encrypted_file_bytes(&normalized_path).await?;
        let encrypted_metadata = self
            .build_encrypted_metadata(&metadata, encrypted_bytes, group_id)
            .await?;
        let plaintext = self.decrypt_file(&encrypted_metadata).await?;

        if plaintext.is_empty() {
            return Ok(0);
        }

        let target_key = {
            let state = self.state.read().await;
            if let Some(epoch) = Self::get_epoch_state(&state, group_id, to_epoch_id) {
                epoch.encryption_key
            } else {
                drop(state);
                self.ensure_epoch_key_available(group_id, to_epoch_id)
                    .await?;
                let state = self.state.read().await;
                Self::get_epoch_state(&state, group_id, to_epoch_id)
                    .ok_or_else(|| {
                        ClientError::InvalidState(format!(
                            "Target epoch {} not available after synchronization",
                            to_epoch_id
                        ))
                    })?
                    .encryption_key
            }
        };

        let file_key_material = hkdf_expand(&target_key, HkdfContext::FileKey, 32)
            .map_err(|e| ClientError::EncryptionError(format!("HKDF failed: {e:?}")))?;
        let file_key = AeadKey::from_bytes(&file_key_material).map_err(|e| {
            ClientError::EncryptionError(format!("Invalid file key material: {e:?}"))
        })?;

        let new_file_id = metadata.file_id.clone().ok_or_else(|| {
            ClientError::InvalidState(format!(
                "Missing file_id for {} during migration",
                metadata.file_path
            ))
        })?;
        let (ciphertext, nonce_bytes) = encrypt_content(&plaintext, &file_key, &new_file_id)
            .map_err(|e| ClientError::EncryptionError(format!("File encryption failed: {e:?}")))?;

        let mut encrypted_output = Vec::with_capacity(12 + ciphertext.len());
        encrypted_output.extend_from_slice(&nonce_bytes);
        encrypted_output.extend_from_slice(&ciphertext);

        self.storage
            .store_file(&normalized_path, &encrypted_output)
            .await
            .map_err(ClientError::from)?;

        metadata.epoch_id = to_epoch_id;
        metadata.file_id = Some(new_file_id.clone());
        metadata.file_size = plaintext.len() as u64;
        metadata.encrypted_size = encrypted_output.len() as u64;
        metadata.modified_at = Utc::now();
        let integrity = Sha256::digest(&plaintext);
        metadata.integrity_hash.copy_from_slice(&integrity);

        self.storage
            .store_file_metadata(&normalized_path, &metadata)
            .await
            .map_err(ClientError::from)?;

        self.update_coverage_for_file(&new_file_id, to_epoch_id)
            .await?;

        Ok(plaintext.len() as u64)
    }

    /// Rewrap a file header from one epoch to another (no ciphertext rewrite).
    #[cfg(feature = "mount-fs")]
    pub async fn rewrap_file_header_only(
        &self,
        file_id: &str,
        from_epoch: &str,
        to_epoch: &str,
    ) -> Result<u64, ClientError> {
        self.ensure_state_loaded().await?;

        let from_epoch_id = from_epoch.parse::<u64>().map_err(|_| {
            ClientError::InvalidState(format!("Invalid from_epoch identifier: {from_epoch}"))
        })?;
        let to_epoch_id = to_epoch.parse::<u64>().map_err(|_| {
            ClientError::InvalidState(format!("Invalid to_epoch identifier: {to_epoch}"))
        })?;

        if from_epoch_id == to_epoch_id {
            return Ok(0);
        }

        let normalized_path = Self::normalize_mount_path(file_id);
        let group_id = self.active_group_id().await?;

        if let Some(metadata) = self
            .storage
            .load_file_metadata(&normalized_path)
            .await
            .map_err(ClientError::from)?
        {
            if metadata.wrapped_file_key.is_some() && metadata.key_wrap_nonce.is_some() {
                let effective_from_epoch = if metadata.epoch_id > 0 {
                    metadata.epoch_id
                } else {
                    from_epoch_id
                };
                if effective_from_epoch == to_epoch_id {
                    return Ok(0);
                }
                self.rewrap_file_internal(&normalized_path, effective_from_epoch, to_epoch_id)
                    .await?;
                return Ok(metadata.file_size);
            }
        }

        let disk_path = self
            .resolve_rewrap_disk_path(&normalized_path)
            .await
            .ok_or_else(|| {
                ClientError::InvalidState(format!(
                    "Unable to resolve encrypted path for rewrap: {}",
                    normalized_path
                ))
            })?;

        let (header_epoch, header_size) = Self::parse_encrypted_file_metadata(&disk_path)
            .map(|header| (header.epoch_id, Some(header.content_size)))
            .unwrap_or((0, None));
        let header_epoch = if header_epoch > 0 {
            header_epoch
        } else {
            from_epoch_id
        };

        if header_epoch == to_epoch_id {
            return Ok(0);
        }

        let pending = PendingRewrap {
            path: disk_path.to_string_lossy().to_string(),
            from_epoch: header_epoch,
            to_epoch: to_epoch_id,
            group_id,
            attempts: 0,
            last_attempt: None,
        };

        self.rewrap_pending_entry(&pending).await?;

        Ok(header_size.unwrap_or(0))
    }

    #[cfg(not(feature = "mount-fs"))]
    pub async fn migrate_file(
        &self,
        file_id: &str,
        from_epoch: &str,
        to_epoch: &str,
    ) -> Result<u64, ClientError> {
        let _ = (file_id, from_epoch, to_epoch);
        Err(Self::filesystem_feature_disabled("migrate_file"))
    }

    /// Rewrap a file from one epoch to another
    #[cfg(feature = "mount-fs")]
    pub async fn rewrap_file(
        &self,
        file_id: &str,
        from_epoch: &str,
        to_epoch: &str,
    ) -> Result<u64, ClientError> {
        self.rewrap_file_header_only(file_id, from_epoch, to_epoch)
            .await
    }

    #[cfg(not(feature = "mount-fs"))]
    pub async fn rewrap_file(
        &self,
        file_id: &str,
        from_epoch: &str,
        to_epoch: &str,
    ) -> Result<u64, ClientError> {
        let _ = (file_id, from_epoch, to_epoch);
        Err(Self::filesystem_feature_disabled("rewrap_file"))
    }
}
