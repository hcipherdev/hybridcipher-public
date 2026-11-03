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
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tauri::async_runtime::Mutex;
use zeroize::Zeroize;

fn default_persistent_session() -> bool {
    true
}

/// Application state shared across all Tauri commands
pub struct AppState {
    pub client: Arc<HybridCipherClient>,
    pub cli_schema: Arc<CliSchemaManager>,
    pub session: Arc<Mutex<Option<UserSession>>>,
    pub auth_generation: AtomicU64,
    pub team_queue: Arc<Mutex<()>>,
    pub mount_manager: Arc<MountManager>,
    pub local_client: Arc<LocalClientProvider>,
    pub cloud_provider: Arc<DesktopCloudProviderManager>,
    /// The accountless vault while no account session is open.
    pub local_vault: Arc<Mutex<Option<crate::local_vault::LocalVaultContext>>>,
    /// When the group list last came from the server, and the newer group keys already
    /// reported to the app (see `commands::group_key_update_available`).
    pub group_key_watch: std::sync::Mutex<GroupKeyWatch>,
    /// Stops repeated refresh attempts after the server rejected or throttled a refresh token.
    pub session_refresh_hold: std::sync::Mutex<Option<SessionRefreshHold>>,
}

/// A refresh token the server refused (held until the next login) or asked us to retry later.
#[derive(Debug, Clone)]
pub struct SessionRefreshHold {
    /// SHA-256 of the refresh token, so a new login lifts the hold without storing the token twice.
    pub token_sha256: String,
    /// `None` while the token stays rejected; otherwise the earliest time to try again.
    pub until: Option<std::time::Instant>,
    pub message: String,
}

impl SessionRefreshHold {
    pub fn token_sha256(refresh_token: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(refresh_token.as_bytes()))
    }

    pub fn rejected(&self) -> bool {
        self.until.is_none()
    }

    /// The hold still applies to this refresh token.
    pub fn blocks(&self, refresh_token: &str) -> bool {
        self.token_sha256 == Self::token_sha256(refresh_token)
            && self
                .until
                .map_or(true, |until| std::time::Instant::now() < until)
    }
}

#[derive(Debug, Default)]
pub struct GroupKeyWatch {
    pub list_refreshed_at: Option<std::time::Instant>,
    /// (group, key version) pairs already reported, so a key this device is never sent (it was
    /// skipped in the rotation) triggers one early key check, not one every minute.
    pub announced: std::collections::HashSet<(uuid::Uuid, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub email: String,
    pub device_id: String,
    pub token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub team_entitlement: Option<String>,
    #[serde(default)]
    pub team_revoked: bool,
    #[serde(default)]
    pub pending_team_requests: Vec<hybridcipher_client::team_requests::PendingTeamRequest>,
    pub expires_at: i64,
    pub user_id: String,
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub opaque_export_key: Option<String>,
    /// Existing saved sessions predate this field and remain persistent.
    #[serde(default = "default_persistent_session")]
    pub persistent: bool,
}

impl Drop for UserSession {
    fn drop(&mut self) {
        self.token.zeroize();
        self.refresh_token.zeroize();
        if let Some(key) = &mut self.opaque_export_key {
            key.zeroize();
        }
    }
}

impl AppState {
    /// Distinguish separate logins while allowing normal token refresh.
    pub fn auth_generation(&self) -> u64 {
        self.auth_generation.load(Ordering::SeqCst)
    }

    pub fn has_cached_team_data_access(&self, session: &UserSession) -> bool {
        // The session was unlocked from protected account storage. Existing
        // ciphertext keys remain usable after an old licensing key is retired.
        // Every write still requires a currently verifiable signed entitlement;
        // every server request still requires normal, unexpired authentication.
        session
            .team_entitlement
            .as_deref()
            .is_some_and(|token| !token.is_empty())
    }

    /// The vault group while the app runs in local mode. An open account
    /// session always takes precedence over a vault record.
    pub async fn local_vault_group(&self) -> Option<uuid::Uuid> {
        if self.session.lock().await.is_some() {
            return None;
        }
        self.local_vault
            .lock()
            .await
            .as_ref()
            .map(|vault| vault.record.group_id)
    }

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
    pub async fn clear_session(&self) -> Result<(), String> {
        // Get session info before clearing
        let session_info = {
            let session = self.session.lock().await;
            session.as_ref().map(|s| {
                (
                    s.email.clone(),
                    s.server_url
                        .clone()
                        .unwrap_or_else(|| self.client.server_url().to_string()),
                )
            })
        };

        self.cloud_provider
            .stop_all(true, false)
            .await
            .map_err(|err| format!("Refusing to clear session while mounts are unsafe: {err}"))?;

        // Fail visibly if persistent credentials cannot be removed. Keep the
        // session identity available so the user can retry logout.
        if let Some((email, server_url)) = session_info.as_ref() {
            let session_store = crate::session::SessionStore::new()?;
            session_store.delete_session(email, server_url)?;
        }

        // Clear from memory
        crate::commands::clear_device_trust_confirmations().await;
        {
            let mut session = self.session.lock().await;
            self.auth_generation.fetch_add(1, Ordering::SeqCst);
            *session = None;
        }

        self.mount_manager.clear_manifest_scope().await;
        self.local_client.clear().await;
        self.client.clear_auth_cache();
        Ok(())
    }

    /// Save session with password for first-time login (derives and caches account key)
    /// This should be called when logging in from the desktop app
    pub async fn save_session_with_password(
        &self,
        mut user_session: UserSession,
        password: &str,
    ) -> Result<(), String> {
        user_session.persistent = true;
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
        user_session.pending_team_requests =
            session_store.load_team_requests(&user_session.email, &server_url)?;
        if !user_session.pending_team_requests.is_empty() {
            session_store
                .save_session(&self.build_persisted_session(&user_session, &server_url))?;
        }

        tracing::info!("Session saved with password for: {}", user_session.email);

        // Complete session setup
        self.complete_session_setup(user_session, &server_url).await
    }

    /// Start a desktop-only session. Stop same-account CLI mounts before
    /// removing the old shared session and automatic-unlock cache.
    pub async fn save_temporary_session(
        &self,
        mut user_session: UserSession,
    ) -> Result<(), String> {
        user_session.persistent = false;
        let server_url = self.client.server_url().to_string();
        self.client.session_keys()?;
        crate::commands::stop_cli_mounts_for_session_transition(self, &user_session.email).await?;
        let session_store = crate::session::SessionStore::new_without_key_cache_migration()?;
        session_store.delete_session(&user_session.email, &server_url)?;
        self.complete_session_setup(user_session, &server_url).await
    }

    /// Save session when account key is already cached (from CLI or previous desktop login)
    pub async fn save_session(
        &self,
        mut user_session: UserSession,
        persist: bool,
    ) -> Result<(), String> {
        let server_url = self.client.server_url().to_string();

        // Save to disk in CLI-compatible format if requested
        if persist {
            user_session.persistent = true;
            let session_store = crate::session::SessionStore::new()
                .map_err(|e| format!("Failed to create session store: {}", e))?;

            // Check if account key is already cached (CLI logged in, or previous desktop login)
            if !session_store.has_account_key_cached(&user_session.email, &server_url) {
                return Err("No encryption keys found. Use save_session_with_password for first-time login.".to_string());
            }

            let durable_requests =
                session_store.load_team_requests(&user_session.email, &server_url)?;
            if !durable_requests.is_empty() {
                user_session.pending_team_requests = durable_requests;
            }

            let persisted = self.build_persisted_session(&user_session, &server_url);

            session_store
                .save_session(&persisted)
                .map_err(|e| format!("Failed to save session to disk: {}", e))?;

            tracing::info!("Session saved (CLI compatible) for: {}", user_session.email);
        } else {
            return self.save_temporary_session(user_session).await;
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
            team_entitlement: user_session.team_entitlement.clone(),
            team_revoked: user_session.team_revoked,
            pending_team_requests: user_session.pending_team_requests.clone(),
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
        // Initialize mount manager scope
        let scope_id = format!("{}::{}", user_session.email, user_session.device_id);
        self.mount_manager
            .activate_manifest_scope(&scope_id)
            .await?;

        // Initialize local client for this session
        if user_session.persistent {
            self.local_client
                .initialize_for_session(&user_session, server_url)
                .await?;
        } else {
            let (account_key, state_key) = self.client.session_keys()?;
            self.local_client
                .initialize_for_session_with_keys(
                    &user_session,
                    server_url,
                    &account_key,
                    &state_key,
                )
                .await?;
        }

        // Publish authentication only after the local client can serve it.
        {
            let mut session = self.session.lock().await;
            self.auth_generation.fetch_add(1, Ordering::SeqCst);
            *session = Some(user_session.clone());
        }

        // Sync Welcome messages to load epoch keys (critical for decryption!)
        self.sync_welcome_messages_after_login().await;
        self.reconnect_mounts_for_session(&user_session, server_url)
            .await;

        Ok(())
    }

    /// Persist refreshed session credentials without re-running full initialization.
    pub async fn persist_refreshed_session(&self, user_session: UserSession) -> Result<(), String> {
        if !user_session.persistent {
            let mut session = self.session.lock().await;
            *session = Some(user_session);
            return Ok(());
        }
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

    pub async fn persist_team_queue(&self, user_session: UserSession) -> Result<(), String> {
        if !user_session.persistent {
            return Err("Offline Team requests require a saved account".into());
        }
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or(self.client.server_url());
        crate::session::SessionStore::new()?.save_team_requests(
            &user_session.email,
            server_url,
            &user_session.pending_team_requests,
        )?;
        self.persist_refreshed_session(user_session).await
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
            match session_store.load_session_for_offline(&email, &server_url) {
                Ok(Some(persisted_session)) => {
                    let offline_team_data = persisted_session
                        .team_entitlement
                        .as_deref()
                        .is_some_and(|token| !token.is_empty());
                    if persisted_session.is_valid() || offline_team_data {
                        tracing::info!("Restored valid session for user: {}", email);

                        let durable_requests =
                            session_store.load_team_requests(&email, &server_url)?;
                        let user_session = UserSession {
                            email: persisted_session.email.clone(),
                            device_id: persisted_session.device_id.clone(),
                            token: persisted_session.token.clone(),
                            refresh_token: persisted_session.refresh_token.clone(),
                            team_entitlement: persisted_session.team_entitlement.clone(),
                            team_revoked: persisted_session.team_revoked,
                            pending_team_requests: if durable_requests.is_empty() {
                                persisted_session.pending_team_requests.clone()
                            } else {
                                durable_requests
                            },
                            expires_at: persisted_session.expires_at.timestamp(),
                            user_id: persisted_session.user_id.clone(),
                            server_url: Some(server_url.clone()),
                            opaque_export_key: persisted_session.opaque_export_key.clone(),
                            persistent: true,
                        };

                        // Initialize mount manager scope
                        let scope_id =
                            format!("{}::{}", user_session.email, user_session.device_id);
                        let _ = self.mount_manager.activate_manifest_scope(&scope_id).await;

                        // Publish the session only once the local client can serve
                        // it: a failed restore must not leave a session that blocks
                        // the next login.
                        if let Err(err) = self
                            .local_client
                            .initialize_for_session(&user_session, &server_url)
                            .await
                        {
                            self.mount_manager.clear_manifest_scope().await;
                            return Err(err);
                        }
                        {
                            let mut session = self.session.lock().await;
                            self.auth_generation.fetch_add(1, Ordering::SeqCst);
                            *session = Some(user_session.clone());
                        }

                        // Sync Welcome messages to load epoch keys
                        if persisted_session.is_valid() {
                            self.sync_welcome_messages_after_login().await;
                        }
                        self.reconnect_mounts_for_session(&user_session, &server_url)
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

    /// Reconnect the account's mounts left by the last run. Without a valid
    /// token, only a Team entitlement that still verifies offline may serve
    /// them, as for a mount the user starts.
    async fn reconnect_mounts_for_session(&self, user_session: &UserSession, server_url: &str) {
        if user_session.expires_at <= Utc::now().timestamp() {
            if let Err(err) = crate::commands::team_write_allowed_offline(self, user_session) {
                tracing::warn!("Not reconnecting mounts left from the last run: {}", err);
                return;
            }
        }
        let user_dir = self
            .local_client
            .user_dir_for_session(&user_session.email, server_url);
        self.reconnect_left_mounts(user_dir).await;
    }

    /// Reconnect the mounts the last run left registered with Windows or macOS
    /// (after a crash, a kill or a reboot), so they show as mounted and serve
    /// files again. A clean Quit unmounts everything, so this finds nothing then.
    pub(crate) async fn reconnect_left_mounts(&self, user_dir: std::path::PathBuf) {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            let Ok(client) = self.local_client.client().await else {
                tracing::warn!("Cannot reconnect mounts: local client unavailable");
                return;
            };
            // A kept root's first sync can take an hour for a large folder; sign-in
            // and session restore must not wait for it.
            #[cfg(target_os = "macos")]
            {
                self.cloud_provider
                    .spawn_file_provider_reconcile(user_dir, client);
            }
            #[cfg(target_os = "windows")]
            {
                match self
                    .cloud_provider
                    .reconcile_windows_cloud_roots(user_dir.clone(), client)
                    .await
                {
                    Ok(report) => {
                        crate::commands::record_reconnected_mounts(&user_dir, &report).await;
                        self.cloud_provider.emit_mounts_reconnected(&report);
                    }
                    Err(err) => {
                        tracing::warn!("Windows Cloud Files reconciliation failed: {}", err);
                    }
                }
                self.cloud_provider.start_windows_health_supervisor();
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = user_dir;
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

#[cfg(test)]
#[path = "../tests/session/test_session_refresh_hold.rs"]
mod session_refresh_hold_tests;

#[cfg(test)]
mod session_policy_tests {
    use super::*;

    #[test]
    fn restored_legacy_desktop_session_defaults_to_persistent() {
        let session: UserSession = serde_json::from_value(serde_json::json!({
            "email": "saved@example.invalid",
            "device_id": "device-a",
            "token": "access",
            "refresh_token": "refresh",
            "expires_at": 123,
            "user_id": "user-a"
        }))
        .unwrap();
        assert!(session.persistent);
    }

    #[test]
    fn temporary_desktop_session_serializes_its_policy() {
        let session: UserSession = serde_json::from_value(serde_json::json!({
            "email": "temporary@example.invalid",
            "device_id": "device-a",
            "token": "access",
            "refresh_token": "refresh",
            "expires_at": 123,
            "user_id": "user-a",
            "persistent": false
        }))
        .unwrap();
        assert!(!session.persistent);
        assert_eq!(serde_json::to_value(&session).unwrap()["persistent"], false);
    }
}
