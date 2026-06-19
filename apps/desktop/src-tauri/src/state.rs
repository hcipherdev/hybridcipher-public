use crate::{
    cli_schema::CliSchemaManager,
    client::HybridCipherClient,
    cloud_provider::DesktopCloudProviderManager,
    local_client::LocalClientProvider,
    mount::MountManager,
    session::{PersistedSession, SessionFlags, SessionSecurity},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::async_runtime::Mutex;

/// Application state shared across all Tauri commands
pub struct AppState {
    pub client: Arc<HybridCipherClient>,
    pub cli_schema: Arc<CliSchemaManager>,
    pub session: Arc<Mutex<Option<UserSession>>>,
    pub mount_manager: Arc<MountManager>,
    pub local_client: Arc<LocalClientProvider>,
    pub cloud_provider: Arc<DesktopCloudProviderManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub email: String,
    pub device_id: String,
    pub token: String,
    #[serde(default)]
    pub refresh_token: String,
    pub expires_at: i64,
    pub user_id: String,
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub opaque_export_key: Option<String>,
}

impl AppState {
    /// Check if user is authenticated
    pub async fn is_authenticated(&self) -> bool {
        let session = self.session.lock().await;
        if let Some(session) = session.as_ref() {
            let now = chrono::Utc::now().timestamp();
            return session.expires_at > now;
        }
        false
    }

    /// Get current user email
    pub async fn current_user(&self) -> Option<String> {
        let session = self.session.lock().await;
        session.as_ref().map(|s| s.email.clone())
    }

    /// Clear session (logout)
    pub async fn clear_session(&self) {
        // Get session info before clearing
        let session_info = {
            let session = self.session.lock().await;
            session
                .as_ref()
                .map(|s| (s.email.clone(), self.client.server_url().to_string()))
        };

        // Clear from memory
        {
            let mut session = self.session.lock().await;
            *session = None;
        }

        // Delete from disk and clear active_user.json
        if let Some((email, server_url)) = session_info {
            if let Ok(session_store) = crate::session::SessionStore::new() {
                let _ = session_store.delete_session(&email, &server_url);
                let _ = session_store.clear_active_user();
                tracing::info!("Deleted session and cleared active user for: {}", email);
            }
        }

        if let Err(err) = self.cloud_provider.stop_all(true, false).await {
            tracing::warn!(
                "Failed to stop Cloud Files roots during session clear: {}",
                err
            );
        }
        self.mount_manager.clear_manifest_scope().await;
        self.local_client.clear().await;
        self.client.clear_auth_cache();
    }

    /// Save session with password for first-time login (derives and caches account key)
    /// This should be called when logging in from the desktop app
    pub async fn save_session_with_password(
        &self,
        user_session: UserSession,
        password: &str,
    ) -> Result<(), String> {
        let server_url = self.client.server_url().to_string();

        // Create session store and initialize account protection with password
        let session_store = crate::session::SessionStore::new()
            .map_err(|e| format!("Failed to create session store: {}", e))?;

        // Build the persisted session
        let persisted = self.build_persisted_session(&user_session, &server_url);

        // Save with password-based encryption (initializes keys if needed)
        session_store
            .save_session_with_password(&persisted, password)
            .map_err(|e| format!("Failed to save session: {}", e))?;

        tracing::info!("Session saved with password for: {}", user_session.email);

        // Complete session setup
        self.complete_session_setup(user_session, &server_url).await
    }

    /// Save session when account key is already cached (from CLI or previous desktop login)
    pub async fn save_session(
        &self,
        user_session: UserSession,
        persist: bool,
    ) -> Result<(), String> {
        let server_url = self.client.server_url().to_string();

        // Save to disk in CLI-compatible format if requested
        if persist {
            let session_store = crate::session::SessionStore::new()
                .map_err(|e| format!("Failed to create session store: {}", e))?;

            // Check if account key is already cached (CLI logged in, or previous desktop login)
            if !session_store.has_account_key_cached(&user_session.email, &server_url) {
                return Err("No encryption keys found. Use save_session_with_password for first-time login.".to_string());
            }

            let persisted = self.build_persisted_session(&user_session, &server_url);

            session_store
                .save_session(&persisted)
                .map_err(|e| format!("Failed to save session to disk: {}", e))?;

            tracing::info!("Session saved (CLI compatible) for: {}", user_session.email);
        } else {
            // Just store in memory
            let mut session = self.session.lock().await;
            *session = Some(user_session.clone());
        }

        // Complete session setup
        self.complete_session_setup(user_session, &server_url).await
    }

    /// Build a PersistedSession from UserSession
    fn build_persisted_session(
        &self,
        user_session: &UserSession,
        server_url: &str,
    ) -> PersistedSession {
        let now = Utc::now();
        let expires_at = chrono::DateTime::from_timestamp(user_session.expires_at, 0)
            .unwrap_or(now + chrono::Duration::hours(24));

        PersistedSession {
            user_id: user_session.user_id.clone(),
            username: user_session.email.clone(),
            device_id: user_session.device_id.clone(),
            device_status: None,
            server_url: server_url.to_string(),
            token: user_session.token.clone(),
            refresh_token: user_session.refresh_token.clone(),
            opaque_export_key: user_session.opaque_export_key.clone(),
            device_binding: generate_device_binding(),
            device_keypair: None,
            created_at: now,
            expires_at,
            last_activity: now,
            migration_info: None,
            security_metadata: SessionSecurity {
                device_fingerprint: generate_device_fingerprint(),
                integrity_hash: compute_session_integrity(user_session, &now),
                version: 1,
                flags: SessionFlags {
                    device_verified: true,
                    migration_recovered: false,
                    auto_renewal: true,
                    enhanced_security: false,
                },
            },
            email: user_session.email.clone(),
        }
    }

    /// Complete session setup after storing credentials
    async fn complete_session_setup(
        &self,
        user_session: UserSession,
        server_url: &str,
    ) -> Result<(), String> {
        // Store in memory
        {
            let mut session = self.session.lock().await;
            *session = Some(user_session.clone());
        }

        // Initialize mount manager scope
        let scope_id = format!("{}::{}", user_session.email, user_session.device_id);
        self.mount_manager
            .activate_manifest_scope(&scope_id)
            .await?;

        // Initialize local client for this session
        self.local_client
            .initialize_for_session(&user_session, server_url)
            .await?;

        // Sync Welcome messages to load epoch keys (critical for decryption!)
        self.sync_welcome_messages_after_login().await;
        self.reconcile_file_provider_roots_after_session_setup(&user_session, server_url)
            .await;

        Ok(())
    }

    /// Persist refreshed session credentials without re-running full initialization.
    pub async fn persist_refreshed_session(&self, user_session: UserSession) -> Result<(), String> {
        let server_url = user_session
            .server_url
            .clone()
            .unwrap_or_else(|| self.client.server_url().to_string());
        let session_store = crate::session::SessionStore::new()
            .map_err(|e| format!("Failed to create session store: {}", e))?;

        if !session_store.has_account_key_cached(&user_session.email, &server_url) {
            return Err(
                "No encryption keys found. Please login again to restore session persistence."
                    .to_string(),
            );
        }

        let persisted = self.build_persisted_session(&user_session, &server_url);
        session_store
            .save_session(&persisted)
            .map_err(|e| format!("Failed to save refreshed session: {}", e))?;

        let mut session = self.session.lock().await;
        *session = Some(user_session);
        Ok(())
    }

    /// Check if account key is cached for a user (CLI already logged in)
    pub fn has_account_key_cached(&self, email: &str) -> bool {
        let server_url = self.client.server_url();
        if let Ok(session_store) = crate::session::SessionStore::new() {
            return session_store.has_account_key_cached(email, server_url);
        }
        false
    }

    /// Sync Welcome messages after login to ensure epoch keys are loaded
    async fn sync_welcome_messages_after_login(&self) {
        if let Ok(client) = self.local_client.client().await {
            match client.auto_sync_welcome_messages("desktop_login").await {
                Ok(results) => {
                    // Count results - WelcomeSyncStatus::Updated means keys were installed
                    let updated = results
                        .iter()
                        .filter(|r| {
                            // Check if status indicates update (using debug string match since type isn't exported)
                            format!("{:?}", r.status).contains("Updated")
                        })
                        .count();
                    tracing::info!(
                        "Welcome message sync completed: {} group(s) processed, {} updated",
                        results.len(),
                        updated
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to sync Welcome messages after login: {}. Mount may fail until keys are available.",
                        err
                    );
                }
            }
        }
    }

    /// Restore session from CLI-compatible storage
    pub async fn restore_session(&self) -> Result<Option<UserSession>, String> {
        tracing::debug!("Attempting to restore session from CLI-compatible storage");

        let session_store = crate::session::SessionStore::new()
            .map_err(|e| format!("Failed to create session store: {}", e))?;

        // List all sessions (reads from active_user.json)
        let sessions = session_store
            .list_sessions()
            .map_err(|e| format!("Failed to list sessions: {}", e))?;

        if sessions.is_empty() {
            tracing::debug!("No saved sessions found");
            return Ok(None);
        }

        // Try to load the most recent session
        for (email, server_url) in sessions {
            match session_store.load_session(&email, &server_url) {
                Ok(Some(persisted_session)) => {
                    if persisted_session.is_valid() {
                        tracing::info!("Restored valid session for user: {}", email);

                        let user_session = UserSession {
                            email: persisted_session.email.clone(),
                            device_id: persisted_session.device_id.clone(),
                            token: persisted_session.token.clone(),
                            refresh_token: persisted_session.refresh_token.clone(),
                            expires_at: persisted_session.expires_at.timestamp(),
                            user_id: persisted_session.user_id.clone(),
                            server_url: Some(server_url.clone()),
                            opaque_export_key: persisted_session.opaque_export_key.clone(),
                        };

                        // Store in memory
                        {
                            let mut session = self.session.lock().await;
                            *session = Some(user_session.clone());
                        }

                        // Initialize mount manager scope
                        let scope_id =
                            format!("{}::{}", user_session.email, user_session.device_id);
                        let _ = self.mount_manager.activate_manifest_scope(&scope_id).await;

                        // Initialize local client
                        self.local_client
                            .initialize_for_session(&user_session, &server_url)
                            .await?;

                        // Sync Welcome messages to load epoch keys
                        self.sync_welcome_messages_after_login().await;
                        self.reconcile_file_provider_roots_after_session_setup(
                            &user_session,
                            &server_url,
                        )
                        .await;

                        return Ok(Some(user_session));
                    }
                }
                Ok(None) => {
                    tracing::debug!("No session file found for: {}", email);
                }
                Err(e) => {
                    tracing::warn!("Failed to load session for {}: {}", email, e);
                }
            }
        }

        tracing::debug!("No valid sessions found");
        Ok(None)
    }

    #[cfg(target_os = "macos")]
    async fn reconcile_file_provider_roots_after_session_setup(
        &self,
        user_session: &UserSession,
        server_url: &str,
    ) {
        let Ok(client) = self.local_client.client().await else {
            tracing::warn!("Cannot reconcile macOS File Provider roots: local client unavailable");
            return;
        };
        let user_dir = self
            .local_client
            .user_dir_for_session(&user_session.email, server_url);
        if let Err(err) = self
            .cloud_provider
            .reconcile_file_provider_roots(user_dir, client)
            .await
        {
            tracing::warn!("macOS File Provider reconciliation failed: {}", err);
        }
    }

    #[cfg(not(target_os = "macos"))]
    async fn reconcile_file_provider_roots_after_session_setup(
        &self,
        _user_session: &UserSession,
        _server_url: &str,
    ) {
    }
}

/// Generate a device binding token for session security
fn generate_device_binding() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let binding_data: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(binding_data)
}

/// Generate a device fingerprint for session security
fn generate_device_fingerprint() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();

    // Include some device-specific information
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        hasher.update(hostname.as_bytes());
    }
    if let Ok(user) = std::env::var("USER") {
        hasher.update(user.as_bytes());
    }
    hasher.update(b"hybridcipher-desktop");

    hex::encode(hasher.finalize())
}

/// Compute session integrity hash (matches CLI implementation)
fn compute_session_integrity(
    session: &UserSession,
    created_at: &chrono::DateTime<chrono::Utc>,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(session.user_id.as_bytes());
    hasher.update(session.device_id.as_bytes());
    hasher.update(session.token.as_bytes());
    hasher.update(created_at.to_rfc3339().as_bytes());
    hex::encode(hasher.finalize())
}
