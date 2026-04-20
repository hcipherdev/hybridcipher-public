use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// Get authentication token for server requests.
    ///
    /// Production flows must rely on the session-based JWT produced by
    /// `hybridcipher login`. Any legacy device-registration credentials are treated
    /// as conflicting state and removed after we confirm the presence of a
    /// session token.
    pub(super) async fn get_auth_token(&self) -> Result<String, ClientError> {
        let session_info = self.get_session_info().await?;
        let SessionInfo { token, .. } = session_info;
        Ok(token)
    }

    pub(super) fn log_auth_token_usage(&self, token: &str, source: &str) {
        let len = token.len();
        let head_len = std::cmp::min(8, len);
        let tail_len = if len > 8 {
            std::cmp::min(8, len - head_len)
        } else {
            0
        };
        let preview = if len == 0 {
            "<empty>".to_string()
        } else if tail_len > 0 {
            format!("{}...{}", &token[..head_len], &token[len - tail_len..])
        } else {
            token[..head_len].to_string()
        };

        self.logger.log(
            crate::logging::LogLevel::Debug,
            &format!("Using authentication token (source: {})", source),
            Some(&format!(
                "token_preview: {}, token_length: {}",
                preview, len
            )),
        );
    }

    pub(super) async fn cleanup_conflicting_auth_state(&self) -> Result<(), ClientError> {
        let home_dir = std::env::var("HOME").unwrap_or_default();
        let auth_creds_path =
            std::path::Path::new(&home_dir).join(".hybridcipher/auth_credentials.json");

        if auth_creds_path.exists() {
            match std::fs::remove_file(&auth_creds_path) {
                Ok(_) => {
                    self.logger.log(
                        crate::logging::LogLevel::Info,
                        "Removed conflicting temporary authentication credentials",
                        Some(&format!("path: {:?}", auth_creds_path)),
                    );
                }
                Err(err) => {
                    return Err(ClientError::storage_error(
                        ErrorCode::StorageWrite,
                        format!(
                            "Failed to remove temporary auth credentials at {:?}: {}",
                            auth_creds_path, err
                        ),
                        "cleanup_conflicting_auth_state".to_string(),
                        None,
                        false,
                    ));
                }
            }
        }

        {
            let mut state = self.state.write().await;
            if state.auth_credentials.is_some() {
                state.auth_credentials = None;
            }
        }

        Ok(())
    }

    pub(super) async fn get_session_info(&self) -> Result<SessionInfo, ClientError> {
        let session_info = self.load_session_info().await?;

        self.log_auth_token_usage(&session_info.token, "session.json");

        if let Err(err) = self.cleanup_conflicting_auth_state().await {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Failed to clean up legacy authentication credentials: {}",
                    err
                ),
                Some("Manual removal of ~/.hybridcipher/auth_credentials.json may be required"),
            );
        }

        Ok(session_info)
    }

    pub(super) async fn load_session_info(&self) -> Result<SessionInfo, ClientError> {
        // Try to find session file using the new per-user session management
        let session_path = self.find_session_file_path()?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Checking for session file at: {:?}", session_path),
            None,
        );

        let session_content_raw = match std::fs::read_to_string(&session_path) {
            Ok(content) => content,
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!(
                        "Authentication failed: unable to read session file at {:?}: {}",
                        session_path, err
                    ),
                    Some("Please run 'hybridcipher login' to authenticate"),
                );
                return Err(ClientError::InvalidState(
                    "No authentication token available. Please run 'hybridcipher login' to authenticate"
                        .to_string(),
                ));
            }
        };

        let session_content = self.decrypt_session_if_needed(&session_path, session_content_raw)?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Session file content length: {}", session_content.len()),
            Some(&format!(
                "first_100_chars: {}",
                &session_content[..std::cmp::min(100, session_content.len())]
            )),
        );

        // Try to parse as TOML first (new format), then JSON (legacy fallback)
        let session_info = if session_path.extension().and_then(|s| s.to_str()) == Some("toml") {
            self.parse_toml_session(&session_content)?
        } else {
            self.parse_json_session(&session_content)?
        };

        let clean_token = session_info
            .token
            .trim()
            .replace('\n', "")
            .replace('\r', "");
        if clean_token.is_empty() {
            self.logger.log(
                crate::logging::LogLevel::Error,
                "Authentication failed: session token is empty after sanitisation",
                Some("Please run 'hybridcipher login' to authenticate"),
            );
            return Err(ClientError::InvalidState(
                "Sanitised session token is empty. Please run 'hybridcipher login' to authenticate"
                    .to_string(),
            ));
        }

        Ok(SessionInfo {
            token: clean_token,
            user_id: session_info.user_id,
            device_id: session_info.device_id,
            server_url: session_info.server_url,
            expires_at: session_info.expires_at,
            device_status: session_info.device_status,
            device_verified: session_info.device_verified,
        })
    }

    pub(super) fn decrypt_session_if_needed(
        &self,
        session_path: &Path,
        content: String,
    ) -> Result<String, ClientError> {
        if let Ok(protected) = serde_json::from_str::<ProtectedData>(&content) {
            if protected.magic == PROTECTED_DATA_MAGIC {
                let user_dir = session_path.parent().ok_or_else(|| {
                    ClientError::InvalidState(
                        "Unable to determine user directory for the session file".to_string(),
                    )
                })?;

                // Session is encrypted with the state/device key, not the account key.
                // Load account key first, then use it to decrypt the device key.
                let state_key = self.load_state_key_from_cache(user_dir)?;

                let decrypted = decrypt_with_ad(&protected, state_key, SESSION_FILE_AAD).map_err(|e| {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Authentication failed: session decryption error: {}",
                            e
                        ),
                        Some("Please run 'hybridcipher login' to unlock your account"),
                    );
                    ClientError::InvalidState(
                        "Unable to decrypt session file. Please run 'hybridcipher login' to authenticate"
                            .to_string(),
                    )
                })?;

                let plaintext = String::from_utf8(decrypted).map_err(|e| {
                    self.logger.log(
                        crate::logging::LogLevel::Error,
                        &format!(
                            "Authentication failed: session file contained invalid UTF-8: {}",
                            e
                        ),
                        Some("Please run 'hybridcipher login' to refresh the session"),
                    );
                    ClientError::InvalidState(
                        "Session file is corrupted. Please re-authenticate with 'hybridcipher login'"
                            .to_string(),
                    )
                })?;

                return Ok(plaintext);
            }
        }

        Ok(content)
    }

    pub(super) fn load_account_key_from_cache(
        &self,
        user_dir: &Path,
    ) -> Result<[u8; 32], ClientError> {
        let cache_path = user_dir.join(ACCOUNT_KEY_CACHE_FILE);
        if !cache_path.exists() {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Account key cache not found at {:?}; session is locked",
                    cache_path
                ),
                Some("Please run 'hybridcipher login' to unlock your session"),
            );
            return Err(ClientError::InvalidState(
                "Account is locked. Please run 'hybridcipher login' to unlock it".to_string(),
            ));
        }

        let encoded = std::fs::read_to_string(&cache_path).map_err(|e| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Failed to read account key cache at {:?}: {}",
                    cache_path, e
                ),
                Some("Please run 'hybridcipher login' to refresh the session"),
            );
            ClientError::InvalidState(
                "Unable to load account key cache. Please re-authenticate.".to_string(),
            )
        })?;

        let decoded = general_purpose::STANDARD.decode(encoded.trim()).map_err(|e| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Account key cache at {:?} is corrupted: {}",
                    cache_path, e
                ),
                Some("Please run 'hybridcipher login' to refresh the session"),
            );
            let _ = std::fs::remove_file(&cache_path);
            ClientError::InvalidState(
                "Account key cache was corrupted. Please run 'hybridcipher login' to unlock your account"
                    .to_string(),
            )
        })?;

        if decoded.len() != 32 {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Account key cache at {:?} has invalid length {}",
                    cache_path,
                    decoded.len()
                ),
                Some("Please run 'hybridcipher login' to refresh the session"),
            );
            let _ = std::fs::remove_file(&cache_path);
            return Err(ClientError::InvalidState(
                "Account key cache was invalid. Please run 'hybridcipher login' to unlock your account"
                    .to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }

    /// Load the state/device key used for session encryption.
    /// The state key is stored in device_key.protected, encrypted with the account key.
    pub(super) fn load_state_key_from_cache(
        &self,
        user_dir: &Path,
    ) -> Result<[u8; 32], ClientError> {
        let account_key = self.load_account_key_from_cache(user_dir)?;

        let device_key_path = user_dir.join(DEVICE_KEY_FILE);
        if !device_key_path.exists() {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Device key file not found at {:?}; session cannot be decrypted",
                    device_key_path
                ),
                Some("Please run 'hybridcipher login' to initialize your device"),
            );
            return Err(ClientError::InvalidState(
                "Device key not found. Please run 'hybridcipher login' to initialize your device"
                    .to_string(),
            ));
        }

        let raw = std::fs::read_to_string(&device_key_path).map_err(|e| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Failed to read device key file at {:?}: {}",
                    device_key_path, e
                ),
                Some("Please run 'hybridcipher login' to refresh the session"),
            );
            ClientError::InvalidState(
                "Unable to load device key. Please re-authenticate.".to_string(),
            )
        })?;

        let protected: ProtectedData = serde_json::from_str(&raw).map_err(|e| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Device key file at {:?} has invalid format: {}",
                    device_key_path, e
                ),
                Some("Please run 'hybridcipher login' to refresh the session"),
            );
            ClientError::InvalidState(
                "Device key file is corrupted. Please run 'hybridcipher login' to fix it."
                    .to_string(),
            )
        })?;

        let decrypted =
            decrypt_with_ad(&protected, account_key, DEVICE_KEY_FILE_AAD).map_err(|e| {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!("Failed to decrypt device key: {}", e),
                    Some("Please run 'hybridcipher login' to unlock your account"),
                );
                ClientError::InvalidState(
                    "Unable to decrypt device key. Please run 'hybridcipher login' to authenticate"
                        .to_string(),
                )
            })?;

        if decrypted.len() != 32 {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Decrypted device key has invalid length {}",
                    decrypted.len()
                ),
                Some("Please run 'hybridcipher login' to refresh the session"),
            );
            return Err(ClientError::InvalidState(
                "Device key is invalid. Please run 'hybridcipher login' to fix it.".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Ok(key)
    }

    /// Find the session file path using the new per-user session management
    pub(super) fn find_session_file_path(&self) -> Result<std::path::PathBuf, ClientError> {
        let home_dir = std::env::var("HOME").map_err(|_| {
            ClientError::InvalidState("HOME environment variable not set".to_string())
        })?;

        let hybridcipher_dir = std::path::Path::new(&home_dir).join(".hybridcipher");

        // First check for active user
        let active_user_file = hybridcipher_dir.join("global/active_user.json");
        if active_user_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&active_user_file) {
                if let Ok(active_user) = serde_json::from_str::<serde_json::Value>(&content) {
                    // Try both 'email' and 'username' fields for compatibility
                    if let Some(user_email) = active_user
                        .get("email")
                        .or_else(|| active_user.get("username"))
                        .and_then(|v| v.as_str())
                    {
                        // Calculate user hash
                        let user_hash = {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(user_email.as_bytes());
                            format!("{:x}", hasher.finalize())
                        };

                        let user_session_path = hybridcipher_dir
                            .join("users")
                            .join(&user_hash)
                            .join("session.toml");

                        if user_session_path.exists() {
                            return Ok(user_session_path);
                        }
                    }

                    // Fallback: try using user_id if available
                    if let Some(user_id) = active_user.get("user_id").and_then(|v| v.as_str()) {
                        let user_session_path = hybridcipher_dir
                            .join("users")
                            .join(user_id)
                            .join("session.toml");

                        if user_session_path.exists() {
                            return Ok(user_session_path);
                        }
                    }
                }
            }
        }

        // Fallback: check old session.json location
        let legacy_session_path = hybridcipher_dir.join("session.json");
        if legacy_session_path.exists() {
            return Ok(legacy_session_path);
        }

        // If no session file found, return path where we expect it to be
        Err(ClientError::InvalidState(
            "No session file found. Please run 'hybridcipher login' to authenticate".to_string(),
        ))
    }

    /// Parse TOML session file (new format)
    pub(super) fn parse_toml_session(&self, content: &str) -> Result<SessionInfo, ClientError> {
        let session_data: toml::Value = toml::from_str(content).map_err(|e| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Authentication failed: session file TOML parsing error: {}",
                    e
                ),
                Some("Please run 'hybridcipher login' to refresh the session"),
            );
            ClientError::InvalidState(
                "Invalid session file format. Please run 'hybridcipher login' to authenticate"
                    .to_string(),
            )
        })?;

        let token = session_data
            .get("token")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    "Authentication failed: token missing from TOML session file",
                    Some("Please run 'hybridcipher login' to authenticate"),
                );
                ClientError::InvalidState(
                    "Session file missing token. Please run 'hybridcipher login' to authenticate"
                        .to_string(),
                )
            })?;

        let user_id = session_data
            .get("user_id")
            .and_then(|value| value.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let expires_at = session_data
            .get("expires_at")
            .and_then(|value| value.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        Ok(SessionInfo {
            token: token.to_string(),
            user_id,
            device_id: session_data
                .get("device_id")
                .and_then(|value| value.as_str())
                .map(|s| s.to_string()),
            server_url: session_data
                .get("server_url")
                .and_then(|value| value.as_str())
                .map(|s| s.to_string()),
            expires_at,
            device_status: session_data
                .get("device_status")
                .and_then(|value| value.as_str())
                .map(|s| s.to_string()),
            device_verified: session_data
                .get("security_metadata")
                .and_then(|value| value.as_table())
                .and_then(|table| table.get("flags"))
                .and_then(|value| value.as_table())
                .and_then(|table| table.get("device_verified"))
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
        })
    }

    /// Parse JSON session file (legacy format)
    pub(super) fn parse_json_session(&self, content: &str) -> Result<SessionInfo, ClientError> {
        let session_data: serde_json::Value = serde_json::from_str(content).map_err(|e| {
            self.logger.log(
                crate::logging::LogLevel::Error,
                &format!(
                    "Authentication failed: session file JSON parsing error: {}",
                    e
                ),
                Some("Please run 'hybridcipher login' to refresh the session"),
            );
            ClientError::InvalidState(
                "Invalid session file format. Please run 'hybridcipher login' to authenticate"
                    .to_string(),
            )
        })?;

        let token = session_data
            .get("session_token")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    "Authentication failed: session_token missing from JSON session file",
                    Some("Please run 'hybridcipher login' to authenticate"),
                );
                ClientError::InvalidState(
                    "Session file missing session_token. Please run 'hybridcipher login' to authenticate".to_string()
                )
            })?;

        let user_id = session_data
            .get("user_id")
            .and_then(|value| value.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let expires_at = session_data
            .get("expires_at")
            .and_then(|value| value.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        Ok(SessionInfo {
            token: token.to_string(),
            user_id,
            device_id: session_data
                .get("device_id")
                .and_then(|value| value.as_str())
                .map(|s| s.to_string()),
            server_url: session_data
                .get("server_url")
                .or_else(|| session_data.get("base_url"))
                .and_then(|value| value.as_str())
                .map(|s| s.to_string()),
            expires_at,
            device_status: session_data
                .get("device_status")
                .and_then(|value| value.as_str())
                .map(|s| s.to_string()),
            device_verified: session_data
                .get("security_metadata")
                .and_then(|value| value.get("flags"))
                .and_then(|value| value.get("device_verified"))
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
        })
    }

    pub(super) async fn validate_auth_token(&self, token: &str) -> Result<bool, ClientError> {
        let client = reqwest::Client::new();
        let server_url = self.active_server_base_url().await;
        let response = client
            .get(&format!("{}/api/v1/groups", server_url))
            .header("Authorization", format!("Bearer {}", token))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    Ok(true)
                } else {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Authentication token validation failed with status {}",
                            resp.status()
                        ),
                        Some("Token will be treated as invalid"),
                    );
                    Ok(false)
                }
            }
            Err(err) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Authentication token validation request failed: {}", err),
                    Some("Treating token as invalid"),
                );
                Ok(false)
            }
        }
    }

    /// Get or create a default group for the user using the server as the source of truth
    pub(super) async fn get_or_create_default_group(&self) -> Result<uuid::Uuid, ClientError> {
        let auth_token = self.get_auth_token().await?;
        self.resolve_group_id_with_token(&auth_token).await
    }

    pub(super) async fn resolve_group_id_with_token(
        &self,
        auth_token: &str,
    ) -> Result<uuid::Uuid, ClientError> {
        if let Some(active) = {
            let state = self.state.read().await;
            state.active_group_id
        } {
            return Ok(active);
        }

        if let Some(cached_id) = self.load_cached_group_id().await? {
            {
                let mut state = self.state.write().await;
                state.active_group_id = Some(cached_id);
            }
            return Ok(cached_id);
        }

        let server_group_id = match self.fetch_primary_group_id(auth_token).await {
            Ok(id) => id,
            Err(e) => {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("Failed to fetch groups from server: {:?}", e),
                    Some("Falling back to cached group ID if available"),
                );
                None
            }
        };

        if let Some(server_group_id) = server_group_id {
            self.cache_group_id(server_group_id).await;
            {
                let mut state = self.state.write().await;
                state.active_group_id = Some(server_group_id);
            }
            return Ok(server_group_id);
        }

        if let Some(cached_id) = self.load_cached_group_id().await? {
            {
                let mut state = self.state.write().await;
                state.active_group_id = Some(cached_id);
            }
            return Ok(cached_id);
        }

        self.logger.log(
            crate::logging::LogLevel::Info,
            "No existing group found on server or cache; creating default group",
            None,
        );

        let membership = self
            .create_new_group(
                "Default Group".to_string(),
                Some("Default group for file sharing".to_string()),
                auth_token.to_string(),
            )
            .await?;

        self.cache_group_id(membership.group_id).await;

        {
            let mut state = self.state.write().await;
            state.active_group_id = Some(membership.group_id);
            state
                .group_memberships
                .insert(membership.group_id, membership.clone());
        }

        self.save_group_membership(&membership).await?;

        Ok(membership.group_id)
    }

    pub(super) async fn fetch_primary_group_id(
        &self,
        auth_token: &str,
    ) -> Result<Option<uuid::Uuid>, ClientError> {
        let groups = self.fetch_group_list(auth_token).await?;
        Ok(groups.first().map(|g| g.id))
    }

    pub(super) async fn load_cached_group_id(&self) -> Result<Option<uuid::Uuid>, ClientError> {
        match self.storage.load_config("group_id").await {
            Ok(Some(id_str)) => match uuid::Uuid::parse_str(&id_str) {
                Ok(id) => Ok(Some(id)),
                Err(_) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        "Cached group_id.json contained invalid UUID",
                        Some(&id_str),
                    );
                    Ok(None)
                }
            },
            Ok(None) => Ok(None),
            Err(e) => Err(ClientError::storage_error(
                ErrorCode::StorageRead,
                format!("Failed to load cached group ID: {:?}", e),
                "load_cached_group_id".to_string(),
                None,
                false,
            )),
        }
    }

    pub(super) async fn cache_group_id(&self, group_id: uuid::Uuid) {
        if let Err(e) = self
            .storage
            .store_config("group_id", &group_id.to_string())
            .await
        {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!("Failed to cache group ID: {:?}", e),
                None,
            );
        }
    }

    pub(super) async fn require_active_group(&self, operation: &str) -> Result<Uuid, ClientError> {
        let state = self.state.read().await;
        state.active_group_id.ok_or_else(|| {
            ClientError::InvalidState(format!(
                "No active group selected. Run 'hybridcipher switch-group <group-id>' before {}.",
                operation
            ))
        })
    }

    /// Generate or refresh authentication credentials
    ///
    /// This method handles device registration with the HybridCipher server
    /// and generates JWT tokens for authenticated API access.
    pub async fn ensure_authentication(&self) -> Result<String, ClientError> {
        if let Ok(token) = self.get_auth_token().await {
            return Ok(token);
        }

        self.logger.log(
            crate::logging::LogLevel::Warn,
            "No session token found, falling back to device registration",
            Some("Consider running 'hybridcipher login' for session-based authentication"),
        );

        // Check if we have valid cached credentials
        {
            let state = self.state.read().await;
            if let Some(ref creds) = state.auth_credentials {
                if creds.expires_at > Utc::now() + chrono::Duration::minutes(5) {
                    return Ok(creds.access_token.clone());
                }
            }
        }

        // Generate new credentials
        self.logger.log(
            crate::logging::LogLevel::Info,
            "Generating new authentication credentials",
            Some("Device registration with HybridCipher server"),
        );

        let auth_credentials = self.register_device_with_server().await?;
        let access_token = auth_credentials.access_token.clone();

        // Store credentials in state
        {
            let mut state = self.state.write().await;
            state.auth_credentials = Some(auth_credentials.clone());
        }

        // Persist credentials to storage
        self.save_auth_credentials(&auth_credentials).await?;

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Authentication successful for device: {}",
                auth_credentials.device_id
            ),
            Some(&format!(
                "user_id: {}, expires_at: {}",
                auth_credentials.user_id, auth_credentials.expires_at
            )),
        );

        Ok(access_token)
    }

    /// Register this device with the HybridCipher server and obtain credentials
    pub(super) async fn register_device_with_server(&self) -> Result<AuthCredentials, ClientError> {
        // Generate device ID from device identity public key
        let device_public_key = self.device_identity.public_key_bytes();
        let device_id = format!("device_{}", hex::encode(&device_public_key[..8]));

        // Create registration request
        let registration_request = serde_json::json!({
            "device_id": device_id,
            "device_public_key": hex::encode(device_public_key),
            "device_type": "pqcrypt_client",
            "registration_timestamp": Utc::now().to_rfc3339()
        });

        // Send registration request to server
        let server_url = self.active_server_base_url().await;
        let register_url = format!("{}/api/v1/auth/register", server_url);

        let client = reqwest::Client::new();
        let response = client
            .post(&register_url)
            .header("Content-Type", "application/json")
            .json(&registration_request)
            .send()
            .await
            .map_err(|e| {
                ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    format!("Failed to register device: {}", e),
                    "register_device_with_server".to_string(),
                    1,
                    "rejected".to_string(),
                )
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            // For now, generate temporary credentials if server registration fails
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Server registration failed ({}), using temporary credentials",
                    status
                ),
                Some(&error_text),
            );

            return Ok(self.generate_temporary_credentials(device_id));
        }

        // Parse response
        let auth_response: serde_json::Value = response.json().await.map_err(|e| {
            ClientError::network_error(
                ErrorCode::NetworkConnection,
                format!("Failed to parse registration response: {}", e),
                "register_device_with_server".to_string(),
                1,
                "parsing_failed".to_string(),
            )
        })?;

        // Extract credentials from response
        let user_id = Uuid::parse_str(auth_response["user_id"].as_str().unwrap_or_default())
            .unwrap_or_else(|_| Uuid::new_v4());

        let access_token = auth_response["access_token"]
            .as_str()
            .unwrap_or("temp_token")
            .to_string();

        let expires_at = auth_response["expires_at"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));

        let credentials = AuthCredentials {
            access_token,
            refresh_token: auth_response["refresh_token"]
                .as_str()
                .map(|s| s.to_string()),
            user_id,
            device_id,
            expires_at,
            last_refreshed: Utc::now(),
        };

        Ok(credentials)
    }

    /// Generate temporary credentials for offline operation
    pub(super) fn generate_temporary_credentials(&self, device_id: String) -> AuthCredentials {
        AuthCredentials {
            access_token: format!("temp_{}_{}", device_id, Utc::now().timestamp()),
            refresh_token: None,
            user_id: Uuid::new_v4(),
            device_id,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            last_refreshed: Utc::now(),
        }
    }

    /// Save authentication credentials to persistent storage
    pub(super) async fn save_auth_credentials(
        &self,
        credentials: &AuthCredentials,
    ) -> Result<(), ClientError> {
        let credentials_json = serde_json::to_string(credentials).map_err(|e| {
            ClientError::storage_error(
                ErrorCode::StorageWrite,
                format!("Failed to serialize auth credentials: {}", e),
                "save_auth_credentials".to_string(),
                None,
                false,
            )
        })?;

        self.storage
            .store_config("auth_credentials", &credentials_json)
            .await
            .map_err(|e| {
                ClientError::storage_error(
                    ErrorCode::StorageWrite,
                    format!("Failed to save auth credentials: {:?}", e),
                    "save_auth_credentials".to_string(),
                    None,
                    false,
                )
            })?;

        Ok(())
    }
}
