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
        _server_url: &str,
    ) -> Result<(), String> {
        let resolved = resolve_session_context(&self.config_dir, session)?;
        let client = build_local_client(&self.config_dir, &resolved.storage_id).await?;

        let client = Arc::new(client);
        let user_dir = self.config_dir.join(USERS_DIR).join(&resolved.storage_id);
        let socket_path = user_dir.join("coverage_ipc.sock");

        {
            let mut ipc_guard = self.coverage_ipc.lock().await;
            if let Some(server) = ipc_guard.take() {
                server.shutdown().await;
            }
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

        let mut guard = self.client.lock().await;
        *guard = Some(client);
        Ok(())
    }

    /// Drop the active client (typically during logout).
    pub async fn clear(&self) {
        let mut ipc_guard = self.coverage_ipc.lock().await;
        if let Some(server) = ipc_guard.take() {
            server.shutdown().await;
        }
        let mut guard = self.client.lock().await;
        *guard = None;
    }

    /// Return the current client or an error if no session is active.
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
    Ok(home.join(".hybridcipher"))
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

async fn build_local_client(base_dir: &Path, storage_id: &str) -> Result<LocalClient, String> {
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
    let account_key = load_account_key_from_cache(&user_dir)?;
    let state_key = load_state_encryption_key(&user_dir, storage_id, &account_key)?;
    storage.enable_account_encryption(state_key);

    let device_keypair = load_or_create_device_keypair(&user_dir, &state_key, &account_key)?;
    let network = Arc::new(MockNetwork::new());
    let client_config = config_loader::load_client_config_from_files();
    let client =
        Client::with_client_config(device_keypair, storage.clone(), network, client_config);

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

fn load_state_encryption_key(
    user_dir: &Path,
    storage_id: &str,
    account_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    if let Some(key) = load_device_key_from_keystore(storage_id)? {
        return Ok(key);
    }

    let path = user_dir.join(DEVICE_KEY_FILE);
    if !path.exists() {
        return Err(format!(
            "Device state key is unavailable (missing in OS keystore and {} is absent). \
             Please log out and log in again to recover local encryption state.",
            path.display()
        ));
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
    if let Err(err) = store_device_key_in_keystore(storage_id, &key) {
        warn!(
            "Could not persist device state key to OS keystore for {}: {}",
            storage_id, err
        );
    }
    Ok(key)
}

fn load_account_key_from_cache(user_dir: &Path) -> Result<[u8; 32], String> {
    let cache_path = user_dir.join(ACCOUNT_KEY_CACHE_FILE);
    let encoded = fs::read_to_string(&cache_path).map_err(|e| {
        format!(
            "Failed to read account key cache {}: {}",
            cache_path.display(),
            e
        )
    })?;

    let decoded = general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| format!("Failed to decode account key cache: {}", e))?;

    if decoded.len() != 32 {
        return Err("Account key cache is invalid".to_string());
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
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
