use crate::coverage_ipc::DesktopCoverageIpcHandler;
use crate::key_bundle;
use crate::state::UserSession;
use base64::engine::general_purpose;
use base64::Engine;
use hybridcipher_client::{
    config_loader,
    ipc::coverage::CoverageIpcServer,
    network::MockNetwork,
    storage::{LocalFsStorage, Storage},
    Client,
};
use hybridcipher_crypto::account_protection::{
    decrypt_with_ad, encrypt_with_ad, ProtectedData, PROTECTED_DATA_MAGIC,
};
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::async_runtime::Mutex;
use tracing::warn;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const USERS_DIR: &str = "users";
const GLOBAL_DIR: &str = "global";
const ACTIVE_USER_FILE: &str = "active_user.json";
const ACCOUNT_KEY_CACHE_FILE: &str = ".account_key_cache";
const DEVICE_KEYPAIR_FILE: &str = "device_keypair";
const DEVICE_KEYPAIR_FILE_AAD: &[u8] = b"hybridcipher/device_keypair";
const DEVICE_KEY_FILE: &str = "device_key.protected";
const DEVICE_KEY_FILE_AAD: &[u8] = b"hybridcipher/device_key_material";
const CANONICAL_PRODUCTION_SERVER: &str = "https://api.hybridcipher.com";
const LEGACY_SERVER_ALIASES: &[&str] = &[
    "http://108.175.8.121:8080",
    "https://108.175.8.121:8080",
    "http://108.175.8.121",
    "https://108.175.8.121",
];
const LEGACY_PRODUCTION_HTTP_ALIASES: &[&str] = &[
    "http://api.hybridcipher.com",
    "http://api.hybridcipher.com:8080",
];

/// Convenient alias for the in-process client type used by the desktop app.
pub type LocalClient = Client<LocalFsStorage, MockNetwork>;

#[derive(Debug, Deserialize)]
struct ActiveUserRecord {
    username: String,
    server_url: String,
    user_id: String,
}

#[derive(Debug)]
struct ResolvedSessionContext {
    storage_id: String,
}

/// Provides access to a lazily-instantiated local HybridCipher client.
pub struct LocalClientProvider {
    config_dir: PathBuf,
    client: Mutex<Option<Arc<LocalClient>>>,
    coverage_ipc: Mutex<Option<CoverageIpcServer>>,
}

impl LocalClientProvider {
    /// Create a new provider rooted in the user's ~/.hybridcipher directory.
    pub fn new() -> Result<Self, String> {
        let config_dir = default_config_dir()?;
        ensure_config_structure(&config_dir)?;
        Ok(Self {
            config_dir,
            client: Mutex::new(None),
            coverage_ipc: Mutex::new(None),
        })
    }

    /// Return the resolved HybridCipher home directory used for storage.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn user_dir_for_session(&self, email: &str, server_url: &str) -> PathBuf {
        let canonical_url = canonicalize_server_url(server_url);
        let storage_id = get_user_storage_id(email, &canonical_url);
        self.config_dir.join(USERS_DIR).join(storage_id)
    }

    pub fn user_storage_id_for_session(&self, email: &str, server_url: &str) -> String {
        let canonical_url = canonicalize_server_url(server_url);
        get_user_storage_id(email, &canonical_url)
    }

    pub fn coverage_ipc_socket_path_for_session(&self, email: &str, server_url: &str) -> PathBuf {
        self.user_dir_for_session(email, server_url)
            .join("coverage_ipc.sock")
    }

    pub fn coverage_registry_meta_path_for_session(
        &self,
        email: &str,
        server_url: &str,
    ) -> PathBuf {
        self.user_dir_for_session(email, server_url)
            .join("coverage_registry.meta.json")
    }

    /// Initialize (or replace) the local client using the supplied session.
    pub async fn initialize_for_session(
        &self,
        session: &UserSession,
        server_url: &str,
    ) -> Result<(), String> {
        self.initialize_for_session_impl(session, server_url, None)
            .await
    }

    pub async fn initialize_for_session_with_keys(
        &self,
        session: &UserSession,
        server_url: &str,
        account_key: &[u8; 32],
        state_key: &[u8; 32],
    ) -> Result<(), String> {
        self.initialize_for_session_impl(session, server_url, Some((account_key, state_key)))
            .await
    }

    async fn initialize_for_session_impl(
        &self,
        session: &UserSession,
        _server_url: &str,
        keys: Option<(&[u8; 32], &[u8; 32])>,
    ) -> Result<(), String> {
        let resolved = resolve_session_context(&self.config_dir, session)?;
        let client =
            build_local_client(&self.config_dir, &resolved.storage_id, keys, false).await?;

        let client = Arc::new(client);
        client
            .configure_local_write_access(
                hybridcipher_client::local_write_access::LocalWriteAccess {
                    issuer: session
                        .server_url
                        .as_deref()
                        .unwrap_or(_server_url)
                        .trim_end_matches('/')
                        .trim_end_matches("/api/v1")
                        .to_string(),
                    user_id: session.user_id.clone(),
                    entitlement: session.team_entitlement.clone(),
                    revoked: session.team_revoked,
                },
            )
            .await
            .map_err(|err| err.to_string())?;
        let user_dir = self.config_dir.join(USERS_DIR).join(&resolved.storage_id);
        let socket_path = user_dir.join("coverage_ipc.sock");

        {
            let mut ipc_guard = self.coverage_ipc.lock().await;
            if let Some(server) = ipc_guard.take() {
                server.shutdown().await;
            }
            if session.persistent {
                let handler = Arc::new(DesktopCoverageIpcHandler::new(client.clone()));
                match CoverageIpcServer::start(socket_path, handler).await {
                    Ok(server) => {
                        *ipc_guard = Some(server);
                    }
                    Err(err) => {
                        warn!("Failed to start coverage IPC server: {}", err);
                    }
                }
            }
        }

        self.replace_client(Some(client)).await;
        Ok(())
    }

    /// Open an accountless vault's storage with a client that never reads a
    /// login session or serves the CLI's coverage socket.
    pub async fn initialize_for_local_vault(
        &self,
        storage_id: &str,
    ) -> Result<Arc<LocalClient>, String> {
        // Opening must never create the vault's folder: an empty folder left by a
        // failed open would be taken for the vault on the next start.
        if !crate::local_vault::storage_present(&self.config_dir, storage_id) {
            return Err(crate::local_vault::STORAGE_MISSING_MESSAGE.into());
        }
        // The vault's loader checks the keychain against the folder's own key copy.
        let (account_key, state_key) =
            crate::local_vault::load_storage_keys(&self.config_dir, storage_id)?;
        let client = Arc::new(
            build_local_client(
                &self.config_dir,
                storage_id,
                Some((&account_key, &state_key)),
                true,
            )
            .await?,
        );
        {
            let mut ipc_guard = self.coverage_ipc.lock().await;
            if let Some(server) = ipc_guard.take() {
                server.shutdown().await;
            }
        }
        self.replace_client(Some(client.clone())).await;
        Ok(client)
    }

    /// Open a vault's storage beside the active client, which stays in place:
    /// moving the vault into a signed-in account needs both at once. The caller
    /// stops the returned client's folder watcher when done with it.
    pub async fn open_local_vault_detached(&self, storage_id: &str) -> Result<LocalClient, String> {
        if !crate::local_vault::storage_present(&self.config_dir, storage_id) {
            return Err(crate::local_vault::STORAGE_MISSING_MESSAGE.into());
        }
        let (account_key, state_key) =
            crate::local_vault::load_storage_keys(&self.config_dir, storage_id)?;
        build_local_client(
            &self.config_dir,
            storage_id,
            Some((&account_key, &state_key)),
            true,
        )
        .await
    }

    /// Drop the active client (typically during logout).
    pub async fn clear(&self) {
        let mut ipc_guard = self.coverage_ipc.lock().await;
        if let Some(server) = ipc_guard.take() {
            server.shutdown().await;
        }
        self.replace_client(None).await;
    }

    /// Swap the active client. The replaced client's folder watcher keeps its own
    /// copy of that client and would otherwise keep writing state to its storage,
    /// recreating it after a vault moves, so it is stopped here.
    async fn replace_client(&self, next: Option<Arc<LocalClient>>) {
        let previous = std::mem::replace(&mut *self.client.lock().await, next.clone());
        if let Some(previous) = previous {
            if !next.is_some_and(|next| Arc::ptr_eq(&next, &previous)) {
                previous.stop_coverage_watchers().await;
            }
        }
    }

    /// Return the current client or an error if no session is active.
    pub async fn update_write_access(&self, session: &UserSession) -> Result<(), String> {
        if let Some(client) = self.client_opt().await {
            client
                .record_online_write_access(
                    hybridcipher_client::local_write_access::LocalWriteAccess {
                        issuer: session
                            .server_url
                            .as_deref()
                            .unwrap_or(CANONICAL_PRODUCTION_SERVER)
                            .trim_end_matches('/')
                            .trim_end_matches("/api/v1")
                            .to_string(),
                        user_id: session.user_id.clone(),
                        entitlement: session.team_entitlement.clone(),
                        revoked: session.team_revoked,
                    },
                )
                .await
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    pub async fn client(&self) -> Result<Arc<LocalClient>, String> {
        let guard = self.client.lock().await;
        guard
            .clone()
            .ok_or_else(|| "No HybridCipher session is active. Please login.".to_string())
    }

    /// Return the current client if available without raising an error.
    pub async fn client_opt(&self) -> Option<Arc<LocalClient>> {
        self.client.lock().await.clone()
    }
}

fn default_config_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "Unable to locate home directory".to_string())?;
    Ok(home.join(hybridcipher_client::config_loader::account_data_location()))
}

fn ensure_config_structure(base_dir: &Path) -> Result<(), String> {
    if !base_dir.exists() {
        fs::create_dir_all(base_dir).map_err(|e| {
            format!(
                "Failed to create HybridCipher home {}: {}",
                base_dir.display(),
                e
            )
        })?;
    }

    let users_dir = base_dir.join(USERS_DIR);
    if !users_dir.exists() {
        fs::create_dir_all(&users_dir).map_err(|e| {
            format!(
                "Failed to create HybridCipher users directory {}: {}",
                users_dir.display(),
                e
            )
        })?;
    }

    let global_dir = base_dir.join(GLOBAL_DIR);
    if !global_dir.exists() {
        fs::create_dir_all(&global_dir).map_err(|e| {
            format!(
                "Failed to create HybridCipher global directory {}: {}",
                global_dir.display(),
                e
            )
        })?;
    }

    #[cfg(unix)]
    {
        let secure_dir = |path: &Path| -> Result<(), String> {
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(path, perms)
                .map_err(|e| format!("Failed to secure {}: {}", path.display(), e))
        };
        let _ = secure_dir(base_dir);
        let _ = secure_dir(&users_dir);
        let _ = secure_dir(&global_dir);
    }

    Ok(())
}

fn canonicalize_server_url(server_url: &str) -> String {
    let trimmed = server_url.trim();
    if trimmed.is_empty() {
        return CANONICAL_PRODUCTION_SERVER.to_string();
    }

    let lower = trimmed.to_ascii_lowercase();

    for alias in LEGACY_SERVER_ALIASES {
        let alias_lower = alias.to_ascii_lowercase();
        if lower == alias_lower || lower.starts_with(&(alias_lower.clone() + "/")) {
            let remainder = if lower == alias_lower {
                ""
            } else {
                &trimmed[alias.len()..]
            };

            let mut canonical = CANONICAL_PRODUCTION_SERVER.to_string();
            if !remainder.is_empty() {
                if canonical.ends_with('/') || remainder.starts_with('/') {
                    canonical.push_str(remainder);
                } else {
                    canonical.push('/');
                    canonical.push_str(remainder);
                }
            }

            return canonical;
        }
    }

    for alias in LEGACY_PRODUCTION_HTTP_ALIASES {
        let alias_lower = alias.to_ascii_lowercase();
        if lower == alias_lower || lower.starts_with(&(alias_lower.clone() + "/")) {
            let remainder = if lower == alias_lower {
                ""
            } else {
                &trimmed[alias.len()..]
            };

            let mut canonical = CANONICAL_PRODUCTION_SERVER.to_string();
            if !remainder.is_empty() {
                if canonical.ends_with('/') || remainder.starts_with('/') {
                    canonical.push_str(remainder);
                } else {
                    canonical.push('/');
                    canonical.push_str(remainder);
                }
            }

            return canonical;
        }
    }

    trimmed.to_string()
}

fn get_user_storage_id(username: &str, server_url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(username.to_lowercase().as_bytes());
    hasher.update(server_url.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn load_active_user_record(config_dir: &Path) -> Result<Option<ActiveUserRecord>, String> {
    let active_file = config_dir.join(GLOBAL_DIR).join(ACTIVE_USER_FILE);
    if !active_file.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&active_file).map_err(|e| {
        format!(
            "Failed to read active user file {}: {}",
            active_file.display(),
            e
        )
    })?;

    let record: ActiveUserRecord = serde_json::from_str(&content).map_err(|e| {
        format!(
            "Failed to parse active user file {}: {}",
            active_file.display(),
            e
        )
    })?;

    Ok(Some(record))
}

fn resolve_session_context(
    config_dir: &Path,
    session: &UserSession,
) -> Result<ResolvedSessionContext, String> {
    let session_email = session.email.trim();
    if session_email.is_empty() {
        return Err("Desktop session is missing an email identity".to_string());
    }

    if !session.persistent {
        let server_url = session.server_url.as_deref().ok_or_else(|| {
            "Temporary desktop session is missing its server identity".to_string()
        })?;
        return Ok(ResolvedSessionContext {
            storage_id: get_user_storage_id(session_email, &canonicalize_server_url(server_url)),
        });
    }

    let active = load_active_user_record(config_dir)?.ok_or_else(|| {
        "No active_user.json context found. Please log out and log in again before using desktop IPC."
            .to_string()
    })?;

    let active_email = active.username.trim();
    if active_email.is_empty() {
        return Err(
            "active_user.json is invalid (empty username). Please log out and log in again."
                .to_string(),
        );
    }

    if !active_email.eq_ignore_ascii_case(session_email) {
        return Err(format!(
            "Desktop session user '{}' does not match active_user.json user '{}'. \
             Please log out and log in again so desktop IPC and CLI mount share the same context.",
            session_email, active_email
        ));
    }

    let canonical_server = canonicalize_server_url(&active.server_url);
    let expected_storage_id = get_user_storage_id(active_email, &canonical_server);
    if !active.user_id.trim().is_empty()
        && !active
            .user_id
            .trim()
            .eq_ignore_ascii_case(&expected_storage_id)
    {
        warn!(
            "active_user.json user_id '{}' does not match canonical storage id '{}'; using canonical id",
            active.user_id.trim(),
            expected_storage_id
        );
    }
    Ok(ResolvedSessionContext {
        storage_id: expected_storage_id,
    })
}

fn load_device_key_from_keystore(storage_id: &str) -> Result<Option<[u8; 32]>, String> {
    key_bundle::load_state_key(storage_id).map_err(|e| {
        format!(
            "Unable to read device state key from secure desktop bundle: {}",
            e
        )
    })
}

fn store_device_key_in_keystore(storage_id: &str, key: &[u8; 32]) -> Result<(), String> {
    key_bundle::store_state_key(storage_id, key).map_err(|e| {
        format!(
            "Failed to persist device state key into secure desktop bundle for {}: {}",
            storage_id, e
        )
    })
}

async fn build_local_client(
    base_dir: &Path,
    storage_id: &str,
    keys: Option<(&[u8; 32], &[u8; 32])>,
    local_only: bool,
) -> Result<LocalClient, String> {
    let user_dir = base_dir.join(USERS_DIR).join(storage_id);
    fs::create_dir_all(&user_dir).map_err(|e| {
        format!(
            "Failed to create HybridCipher user directory {}: {}",
            user_dir.display(),
            e
        )
    })?;

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o700);
        if let Err(err) = fs::set_permissions(&user_dir, perms) {
            warn!(
                "Failed to secure HybridCipher user directory {}: {}",
                user_dir.display(),
                err
            );
        }
    }

    let storage = Arc::new(LocalFsStorage::new_for_user(base_dir, storage_id));
    let (account_key, state_key) = match keys {
        Some((account_key, state_key)) => {
            (Zeroizing::new(*account_key), Zeroizing::new(*state_key))
        }
        None => {
            let account_key = Zeroizing::new(load_account_key_from_cache(&user_dir)?);
            let state_key = Zeroizing::new(load_state_encryption_key(
                &user_dir,
                storage_id,
                &account_key,
            )?);
            (account_key, state_key)
        }
    };
    storage.enable_account_encryption(*state_key);

    let device_keypair = load_or_create_device_keypair(&user_dir, &state_key, &account_key)?;
    let network = Arc::new(MockNetwork::new());
    let client_config = config_loader::load_client_config_from_files();
    let client =
        Client::with_client_config(device_keypair, storage.clone(), network, client_config);
    // Set before any group selection, which may otherwise look up a login session.
    client.set_local_only(local_only);

    if let Some(group_id) = load_active_group_id(&storage).await? {
        if let Err(err) = client.use_group(group_id).await {
            warn!("Failed to apply cached group context {}: {}", group_id, err);
        }
    }

    Ok(client)
}

async fn load_active_group_id(storage: &LocalFsStorage) -> Result<Option<Uuid>, String> {
    let raw = storage
        .load_config("group_id")
        .await
        .map_err(|e| format!("Failed to load cached group ID: {}", e))?;

    let Some(raw) = raw else {
        return Ok(None);
    };

    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return Ok(None);
    }

    let parsed = Uuid::parse_str(trimmed)
        .map_err(|e| format!("Cached group ID '{}' is invalid: {}", trimmed, e))?;
    Ok(Some(parsed))
}

/// The device state key, and whether the keystore entry must be rewritten to it.
#[derive(Debug, PartialEq)]
enum StateKeyChoice {
    Use([u8; 32]),
    UseAndStore([u8; 32]),
}

/// Pick between the keystore's state key and the folder's own copy (wrapped by
/// the account key). The keystore entry outlives deleted folders, and login
/// writes the device keypair with the folder copy, so a disagreeing entry is
/// replaced — unless it is the one that opens the device keypair, which is
/// then kept rather than destroyed.
fn choose_state_key(
    keystore: Option<[u8; 32]>,
    folder: Option<[u8; 32]>,
    opens_device_keypair: impl Fn(&[u8; 32]) -> Option<bool>,
) -> Option<StateKeyChoice> {
    match (keystore, folder) {
        (Some(keystore), Some(folder)) if keystore == folder => Some(StateKeyChoice::Use(keystore)),
        (Some(keystore), Some(folder)) => {
            if opens_device_keypair(&folder) != Some(false) {
                Some(StateKeyChoice::UseAndStore(folder))
            } else if opens_device_keypair(&keystore) == Some(true) {
                Some(StateKeyChoice::Use(keystore))
            } else {
                Some(StateKeyChoice::Use(folder))
            }
        }
        (Some(keystore), None) => Some(StateKeyChoice::Use(keystore)),
        (None, Some(folder)) => Some(StateKeyChoice::UseAndStore(folder)),
        (None, None) => None,
    }
}

/// Whether `key` opens this folder's protected device keypair; `None` when
/// there is no protected keypair to test it against.
fn device_keypair_opens_with(user_dir: &Path, key: &[u8; 32]) -> Option<bool> {
    let raw = fs::read_to_string(user_dir.join(DEVICE_KEYPAIR_FILE)).ok()?;
    let protected: ProtectedData = serde_json::from_str(&raw).ok()?;
    if protected.magic != PROTECTED_DATA_MAGIC {
        return None;
    }
    Some(decrypt_with_ad(&protected, *key, DEVICE_KEYPAIR_FILE_AAD).is_ok())
}

fn load_state_encryption_key(
    user_dir: &Path,
    storage_id: &str,
    account_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    let keystore_result = load_device_key_from_keystore(storage_id);
    let folder_result = load_folder_state_key(user_dir, account_key);
    let keystore = keystore_result.as_ref().ok().copied().flatten();
    let folder = folder_result.as_ref().ok().copied().flatten();
    match choose_state_key(keystore, folder, |key| {
        device_keypair_opens_with(user_dir, key)
    }) {
        Some(StateKeyChoice::Use(key)) => Ok(key),
        Some(StateKeyChoice::UseAndStore(key)) => {
            if keystore.is_some() {
                warn!(
                    "OS keystore state key for {} did not match {}; replacing it",
                    storage_id, DEVICE_KEY_FILE
                );
            }
            if let Err(err) = store_device_key_in_keystore(storage_id, &key) {
                warn!(
                    "Could not persist device state key to OS keystore for {}: {}",
                    storage_id, err
                );
            }
            Ok(key)
        }
        None => {
            keystore_result?;
            folder_result?;
            Err(format!(
                "Device state key is unavailable (missing in OS keystore and {} is absent). \
                 Please log out and log in again to recover local encryption state.",
                user_dir.join(DEVICE_KEY_FILE).display()
            ))
        }
    }
}

/// The state key wrapped in the folder's `device_key.protected`; `None` when
/// that file is absent.
fn load_folder_state_key(
    user_dir: &Path,
    account_key: &[u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    let path = user_dir.join(DEVICE_KEY_FILE);
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read device state key {}: {}", path.display(), e))?;
    let protected: ProtectedData = serde_json::from_str(&raw).map_err(|e| {
        format!(
            "Device state key file at {} is invalid: {}",
            path.display(),
            e
        )
    })?;

    let decrypted =
        decrypt_with_ad(&protected, *account_key, DEVICE_KEY_FILE_AAD).map_err(|e| {
            format!(
                "Failed to decrypt device state key at {}: {}. \
             Please run explicit account recovery/re-login before mounting.",
                path.display(),
                e
            )
        })?;

    if decrypted.len() != 32 {
        return Err(format!(
            "Device state key at {} has invalid length. \
             Please log out and log in again to re-establish local encryption keys.",
            path.display()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted);
    Ok(Some(key))
}

fn load_account_key_from_cache(user_dir: &Path) -> Result<[u8; 32], String> {
    let cache_path = user_dir.join(ACCOUNT_KEY_CACHE_FILE);
    hybridcipher_crypto::local_key_cache::load(&cache_path)
        .map_err(|e| format!("Failed to unlock account key cache: {e}"))
}

#[cfg(test)]
mod session_context_tests {
    use super::*;

    #[test]
    fn temporary_session_uses_its_own_identity_without_active_cli_user() {
        let root = tempfile::tempdir().unwrap();
        let mut session = UserSession {
            email: "temporary@example.invalid".into(),
            device_id: "device-a".into(),
            token: "access".into(),
            refresh_token: "refresh".into(),
            team_entitlement: None,
            team_revoked: false,
            pending_team_requests: Vec::new(),
            expires_at: 0,
            user_id: "user-a".into(),
            server_url: Some("https://fixture.example.invalid".into()),
            opaque_export_key: None,
            persistent: false,
        };

        let resolved = resolve_session_context(root.path(), &session).unwrap();
        assert_eq!(
            resolved.storage_id,
            get_user_storage_id(&session.email, session.server_url.as_deref().unwrap())
        );

        // An existing CLI pointer for another account must not be adopted by
        // a temporary desktop session.
        fs::create_dir_all(root.path().join(GLOBAL_DIR)).unwrap();
        fs::write(
            root.path().join(GLOBAL_DIR).join(ACTIVE_USER_FILE),
            r#"{"username":"other@example.invalid","server_url":"https://fixture.example.invalid","user_id":"ignored"}"#,
        )
        .unwrap();
        assert_eq!(
            resolve_session_context(root.path(), &session)
                .unwrap()
                .storage_id,
            resolved.storage_id
        );
        session.persistent = true;
        assert!(resolve_session_context(root.path(), &session).is_err());
    }

    #[tokio::test]
    async fn local_client_accepts_temporary_keys_without_unlock_cache() {
        let root = tempfile::tempdir().unwrap();
        let server_url = "https://fixture.example.invalid";
        let email = "temporary@example.invalid";
        let storage_id = get_user_storage_id(email, server_url);
        let account_key = [11u8; 32];
        let state_key = [22u8; 32];
        let provider = LocalClientProvider {
            config_dir: root.path().to_path_buf(),
            client: Mutex::new(None),
            coverage_ipc: Mutex::new(None),
        };
        let session = UserSession {
            email: email.into(),
            device_id: "device-a".into(),
            token: "access".into(),
            refresh_token: "refresh".into(),
            team_entitlement: None,
            team_revoked: false,
            pending_team_requests: Vec::new(),
            expires_at: 0,
            user_id: "user-a".into(),
            server_url: Some(server_url.into()),
            opaque_export_key: None,
            persistent: false,
        };
        provider
            .initialize_for_session_with_keys(&session, server_url, &account_key, &state_key)
            .await
            .unwrap();
        assert!(provider.client().await.is_ok());
        assert!(provider.coverage_ipc.lock().await.is_none());
        let user_dir = root.path().join(USERS_DIR).join(storage_id);
        assert!(!user_dir.join(ACCOUNT_KEY_CACHE_FILE).exists());
        assert!(user_dir.join(DEVICE_KEYPAIR_FILE).exists());
    }

    #[test]
    fn stale_keystore_state_key_is_replaced_by_the_folder_copy() {
        let root = tempfile::tempdir().unwrap();
        let (stale, folder) = ([1u8; 32], [2u8; 32]);
        write_protected_string(
            &root.path().join(DEVICE_KEYPAIR_FILE),
            "keypair",
            DEVICE_KEYPAIR_FILE_AAD,
            &folder,
        )
        .unwrap();
        let opens = |key: &[u8; 32]| device_keypair_opens_with(root.path(), key);

        assert_eq!(opens(&folder), Some(true));
        assert_eq!(opens(&stale), Some(false));
        assert_eq!(
            choose_state_key(Some(stale), Some(folder), opens),
            Some(StateKeyChoice::UseAndStore(folder))
        );
        // A keystore entry that does open the keypair is kept, not destroyed.
        assert_eq!(
            choose_state_key(Some(folder), Some(stale), opens),
            Some(StateKeyChoice::Use(folder))
        );
    }

    #[test]
    fn state_key_choice_without_a_disagreement() {
        let key = [3u8; 32];
        let no_keypair = |_: &[u8; 32]| None;
        assert_eq!(
            choose_state_key(Some(key), Some(key), no_keypair),
            Some(StateKeyChoice::Use(key))
        );
        assert_eq!(
            choose_state_key(Some(key), None, no_keypair),
            Some(StateKeyChoice::Use(key))
        );
        assert_eq!(
            choose_state_key(None, Some(key), no_keypair),
            Some(StateKeyChoice::UseAndStore(key))
        );
        assert_eq!(
            choose_state_key(Some([4u8; 32]), Some(key), no_keypair),
            Some(StateKeyChoice::UseAndStore(key))
        );
        assert_eq!(choose_state_key(None, None, no_keypair), None);
    }

    #[test]
    fn folder_state_key_opens_with_the_account_key() {
        let root = tempfile::tempdir().unwrap();
        let (account_key, state_key) = ([5u8; 32], [6u8; 32]);
        assert_eq!(load_folder_state_key(root.path(), &account_key), Ok(None));
        let protected = encrypt_with_ad(&state_key, account_key, DEVICE_KEY_FILE_AAD).unwrap();
        fs::write(
            root.path().join(DEVICE_KEY_FILE),
            serde_json::to_string(&protected).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_folder_state_key(root.path(), &account_key),
            Ok(Some(state_key))
        );
        assert!(load_folder_state_key(root.path(), &[7u8; 32]).is_err());
    }
}

fn load_or_create_device_keypair(
    user_dir: &Path,
    state_key: &[u8; 32],
    account_key: &[u8; 32],
) -> Result<Ed25519KeyPair, String> {
    let path = user_dir.join(DEVICE_KEYPAIR_FILE);
    if let Some((raw, used_state_key)) =
        read_protected_string(&path, DEVICE_KEYPAIR_FILE_AAD, state_key, account_key)?
    {
        let trimmed = raw.trim();
        let decoded = general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|e| format!("Failed to decode device keypair: {}", e))?;
        let keypair = Ed25519KeyPair::from_bytes(&decoded)
            .map_err(|e| format!("Invalid device keypair data: {}", e))?;

        if !used_state_key {
            if let Err(err) =
                write_protected_string(&path, trimmed, DEVICE_KEYPAIR_FILE_AAD, state_key)
            {
                warn!(
                    "Failed to rewrap device keypair with device state key at {}: {}",
                    path.display(),
                    err
                );
            }
        }

        return Ok(keypair);
    }

    let keypair = Ed25519KeyPair::generate();
    let encoded = general_purpose::STANDARD.encode(keypair.private_key_bytes());
    write_protected_string(&path, &encoded, DEVICE_KEYPAIR_FILE_AAD, state_key)?;
    Ok(keypair)
}

fn read_protected_string(
    path: &Path,
    aad: &[u8],
    state_key: &[u8; 32],
    account_key: &[u8; 32],
) -> Result<Option<(String, bool)>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read protected file {}: {}", path.display(), e))?;

    match serde_json::from_str::<ProtectedData>(&raw) {
        Ok(protected) if protected.magic == PROTECTED_DATA_MAGIC => {
            if let Ok(decrypted) = decrypt_with_ad(&protected, *state_key, aad) {
                let value = String::from_utf8(decrypted).map_err(|e| {
                    format!(
                        "Protected file {} is not valid UTF-8: {}",
                        path.display(),
                        e
                    )
                })?;
                return Ok(Some((value, true)));
            }

            let decrypted = decrypt_with_ad(&protected, *account_key, aad).map_err(|e| {
                format!("Failed to decrypt protected file {}: {}", path.display(), e)
            })?;
            let value = String::from_utf8(decrypted).map_err(|e| {
                format!(
                    "Protected file {} is not valid UTF-8: {}",
                    path.display(),
                    e
                )
            })?;
            Ok(Some((value, false)))
        }
        _ => Ok(Some((raw, false))),
    }
}

fn write_protected_string(
    path: &Path,
    data: &str,
    aad: &[u8],
    state_key: &[u8; 32],
) -> Result<(), String> {
    let protected = encrypt_with_ad(data.as_bytes(), *state_key, aad)
        .map_err(|e| format!("Failed to encrypt protected file {}: {}", path.display(), e))?;

    let serialized = serde_json::to_string_pretty(&protected)
        .map_err(|e| format!("Failed to serialize protected data: {}", e))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to prepare directory {} for protected file: {}",
                parent.display(),
                e
            )
        })?;
    }

    fs::write(path, serialized)
        .map_err(|e| format!("Failed to write protected file {}: {}", path.display(), e))?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)
            .map(|m| m.permissions())
            .map_err(|e| format!("Failed to read permissions for {}: {}", path.display(), e))?;
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }

    Ok(())
}
