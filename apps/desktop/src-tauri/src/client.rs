use crate::session::SessionStore;
use base64::engine::general_purpose;
use base64::Engine;
use chrono::{Duration, Utc};
use hybridcipher_client::auth::opaque::{DeviceLoginMetadata, OpaqueAuth, OpaqueError};
use hybridcipher_client::invitation::{InvitationKeyPair, JoinCard as ClientJoinCard};
use hybridcipher_crypto::{
    account_protection::{decrypt_with_ad, encrypt_with_ad, ProtectedData, PROTECTED_DATA_MAGIC},
    hybridkem::HybridKeyPair,
    signatures::Ed25519KeyPair,
};
use hybridcipher_messages::join_card::JoinCard as MessagesJoinCard;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tracing::{info, warn};
use uuid::Uuid;

const ACCOUNT_KEY_CACHE_FILE: &str = ".account_key_cache";
const DEVICE_KEYPAIR_FILE: &str = "device_keypair";
const DEVICE_KEYPAIR_FILE_AAD: &[u8] = b"hybridcipher/device_keypair";
const INVITATION_KEYPAIR_FILE: &str = "invitation_keypair.json";
const INVITATION_KEYPAIR_FILE_AAD: &[u8] = b"hybridcipher/localfs/invitation_keypair";
const DEVICE_KEY_FILE: &str = "device_key.protected";
const DEVICE_KEY_FILE_AAD: &[u8] = b"hybridcipher/device_key_material";
const HYBRIDCIPHER_HOME: &str = ".hybridcipher";
const USERS_DIR: &str = "users";
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

#[derive(Clone)]
struct DeviceKeys {
    device_id: String,
    identity_public: Vec<u8>,
    identity_secret: Vec<u8>,
    invitation_public: Vec<u8>,
    invitation_secret: Vec<u8>,
    created_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
struct StoredInvitationKeyPair {
    device_id: String,
    hybrid_public_key: Vec<u8>,
    hybrid_secret_key: Vec<u8>,
    identity_public_key: Vec<u8>,
    identity_secret_key: Vec<u8>,
    created_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
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

fn user_storage_id(email: &str, server_url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.to_lowercase().as_bytes());
    hasher.update(server_url.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn cli_user_dir(email: &str, server_url: &str) -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Unable to locate home directory")?;
    let canonical_server = canonicalize_server_url(server_url);
    let storage_id = user_storage_id(email, &canonical_server);
    Ok(home
        .join(HYBRIDCIPHER_HOME)
        .join(USERS_DIR)
        .join(storage_id))
}

fn load_cached_account_key(user_dir: &Path) -> Result<Option<[u8; 32]>, String> {
    let cache_path = user_dir.join(ACCOUNT_KEY_CACHE_FILE);
    if !cache_path.exists() {
        return Ok(None);
    }

    let encoded = fs::read_to_string(&cache_path)
        .map_err(|e| format!("Failed to read account key cache: {}", e))?;
    let decoded = general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| format!("Failed to decode account key cache: {}", e))?;

    if decoded.len() != 32 {
        return Err("Cached account key is invalid length".to_string());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decoded);
    Ok(Some(key_bytes))
}

fn read_protected_string(
    path: &Path,
    aad: &[u8],
    state_key: Option<&[u8; 32]>,
    account_key: Option<&[u8; 32]>,
) -> Result<Option<String>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read protected file {}: {}", path.display(), e))?;

    match serde_json::from_str::<ProtectedData>(&raw) {
        Ok(protected) if protected.magic == PROTECTED_DATA_MAGIC => {
            // Try state_key first (device-specific)
            if let Some(state_key) = state_key {
                if let Ok(decrypted) = decrypt_with_ad(&protected, *state_key, aad) {
                    let value = String::from_utf8(decrypted).map_err(|e| {
                        format!(
                            "Decrypted data at {} is not valid UTF-8: {}",
                            path.display(),
                            e
                        )
                    })?;
                    return Ok(Some(value));
                }
            }

            // Fall back to account_key (password-derived)
            if let Some(account_key) = account_key {
                let decrypted = decrypt_with_ad(&protected, *account_key, aad).map_err(|e| {
                    format!("Failed to decrypt protected file {}: {}", path.display(), e)
                })?;
                let value = String::from_utf8(decrypted).map_err(|e| {
                    format!(
                        "Decrypted data at {} is not valid UTF-8: {}",
                        path.display(),
                        e
                    )
                })?;
                return Ok(Some(value));
            }

            Err(format!(
                "Failed to decrypt protected file {}: no keys available",
                path.display()
            ))
        }
        _ => Ok(Some(raw)),
    }
}

fn load_cli_device_keys(email: &str, server_url: &str) -> Result<Option<DeviceKeys>, String> {
    let user_dir = cli_user_dir(email, server_url)?;
    if !user_dir.exists() {
        return Ok(None);
    }

    let invitation_path = user_dir.join(INVITATION_KEYPAIR_FILE);
    if !invitation_path.exists() {
        return Ok(None);
    }

    let account_key = load_cached_account_key(&user_dir)?;

    // Try to load state_key if account_key is available
    let state_key = if let Some(ref acc_key) = account_key {
        load_device_key_from_fallback(&user_dir, acc_key)
            .ok()
            .flatten()
    } else {
        None
    };

    let serialized = if state_key.is_some() || account_key.is_some() {
        read_protected_string(
            &invitation_path,
            INVITATION_KEYPAIR_FILE_AAD,
            state_key.as_ref(),
            account_key.as_ref(),
        )?
        .ok_or_else(|| {
            format!(
                "Invitation keypair at {} missing despite existence",
                invitation_path.display()
            )
        })?
    } else {
        fs::read_to_string(&invitation_path)
            .map_err(|e| format!("Failed to read invitation keypair: {}", e))?
    };

    let stored: StoredInvitationKeyPair = serde_json::from_str(&serialized).map_err(|e| {
        format!(
            "Failed to parse invitation keypair at {}: {}",
            invitation_path.display(),
            e
        )
    })?;

    if stored.identity_public_key.is_empty() || stored.hybrid_public_key.is_empty() {
        return Err(format!(
            "Invitation keypair at {} is missing public key material",
            invitation_path.display()
        ));
    }

    Ok(Some(DeviceKeys {
        device_id: stored.device_id,
        identity_public: stored.identity_public_key,
        identity_secret: stored.identity_secret_key,
        invitation_public: stored.hybrid_public_key,
        invitation_secret: stored.hybrid_secret_key,
        created_at: stored.created_at,
        expires_at: stored.expires_at,
    }))
}

fn ensure_user_dirs(user_dir: &Path) -> Result<(), String> {
    if let Some(parent) = user_dir.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create users directory {}: {}",
                parent.display(),
                e
            )
        })?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }

    fs::create_dir_all(user_dir).map_err(|e| {
        format!(
            "Failed to create user directory {}: {}",
            user_dir.display(),
            e
        )
    })?;

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(user_dir, fs::Permissions::from_mode(0o700));
    }

    Ok(())
}

fn load_device_key_from_fallback(
    user_dir: &Path,
    account_key: &[u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    let path = user_dir.join(DEVICE_KEY_FILE);
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read device key fallback: {}", e))?;
    let protected: ProtectedData = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid device key fallback format: {}", e))?;

    let key = decrypt_with_ad(&protected, *account_key, DEVICE_KEY_FILE_AAD)
        .map_err(|e| format!("Failed to decrypt device key fallback: {}", e))?;

    if key.len() != 32 {
        return Err("Device key has unexpected length".to_string());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&key);
    Ok(Some(key_bytes))
}

fn write_protected_file(path: &Path, data: &str, aad: &[u8], key: &[u8; 32]) -> Result<(), String> {
    let protected = encrypt_with_ad(data.as_bytes(), *key, aad)
        .map_err(|e| format!("Failed to encrypt protected file {}: {}", path.display(), e))?;
    let serialized = serde_json::to_string_pretty(&protected).map_err(|e| {
        format!(
            "Failed to serialize protected file {}: {}",
            path.display(),
            e
        )
    })?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to prepare directory {}: {}", parent.display(), e))?;
    }

    fs::write(path, serialized)
        .map_err(|e| format!("Failed to write protected file {}: {}", path.display(), e))?;

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn persist_device_keys(
    email: &str,
    server_url: &str,
    keys: &DeviceKeys,
    state_key: Option<&[u8; 32]>,
) -> Result<(), String> {
    let user_dir = cli_user_dir(email, server_url)?;
    ensure_user_dirs(&user_dir)?;

    let stored = StoredInvitationKeyPair {
        device_id: keys.device_id.clone(),
        hybrid_public_key: keys.invitation_public.clone(),
        hybrid_secret_key: keys.invitation_secret.clone(),
        identity_public_key: keys.identity_public.clone(),
        identity_secret_key: keys.identity_secret.clone(),
        created_at: keys.created_at,
        expires_at: keys.expires_at,
    };

    let serialized = serde_json::to_string_pretty(&stored)
        .map_err(|e| format!("Failed to serialize invitation keypair: {}", e))?;

    let invitation_path = user_dir.join(INVITATION_KEYPAIR_FILE);
    let device_key_path = user_dir.join(DEVICE_KEYPAIR_FILE);
    let device_key_data = general_purpose::STANDARD.encode(&keys.identity_secret);

    // Use state_key if available, otherwise don't encrypt (will be encrypted on next login)
    if let Some(state_key) = state_key {
        write_protected_file(
            &invitation_path,
            &serialized,
            INVITATION_KEYPAIR_FILE_AAD,
            state_key,
        )?;
        write_protected_file(
            &device_key_path,
            &device_key_data,
            DEVICE_KEYPAIR_FILE_AAD,
            state_key,
        )?;
    } else {
        fs::write(&invitation_path, &serialized)
            .map_err(|e| format!("Failed to write invitation keypair: {}", e))?;
        fs::write(&device_key_path, &device_key_data)
            .map_err(|e| format!("Failed to write device keypair: {}", e))?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&invitation_path, fs::Permissions::from_mode(0o600));
            let _ = fs::set_permissions(&device_key_path, fs::Permissions::from_mode(0o600));
        }
    }

    Ok(())
}

fn generate_fresh_device_keys() -> Result<DeviceKeys, String> {
    let identity = Ed25519KeyPair::generate();
    let mut rng = OsRng;
    let invitation = HybridKeyPair::generate(&mut rng)
        .map_err(|e| format!("Failed to generate invitation keypair: {}", e))?;

    let device_id = format!("device_{}", hex::encode(&identity.public_key_bytes()[..8]));
    let created_at = Utc::now();
    let expires_at = created_at + Duration::days(30);

    Ok(DeviceKeys {
        device_id,
        identity_public: identity.public_key_bytes().to_vec(),
        identity_secret: identity.private_key_bytes().to_vec(),
        invitation_public: invitation.public.to_bytes().to_vec(),
        invitation_secret: invitation.secret.to_bytes().to_vec(),
        created_at,
        expires_at,
    })
}

fn invitation_keypair_from_device_keys(keys: &DeviceKeys) -> Result<InvitationKeyPair, String> {
    let stored = StoredInvitationKeyPair {
        device_id: keys.device_id.clone(),
        hybrid_public_key: keys.invitation_public.clone(),
        hybrid_secret_key: keys.invitation_secret.clone(),
        identity_public_key: keys.identity_public.clone(),
        identity_secret_key: keys.identity_secret.clone(),
        created_at: keys.created_at,
        expires_at: keys.expires_at,
    };

    let value = serde_json::to_value(&stored)
        .map_err(|e| format!("Failed to serialize invitation keypair: {}", e))?;
    serde_json::from_value(value)
        .map_err(|e| format!("Failed to hydrate invitation keypair: {}", e))
}

fn client_join_card_to_messages(join_card: &ClientJoinCard) -> Result<MessagesJoinCard, String> {
    let expires: u64 = join_card
        .expires_at
        .timestamp()
        .try_into()
        .map_err(|_| "Join card expiration timestamp is out of range".to_string())?;

    Ok(MessagesJoinCard {
        user_id: join_card.user_id.to_string(),
        device_id: join_card.device_id.clone(),
        identity_public: join_card.identity_public.clone(),
        invitation_public: join_card.invitation_public.clone(),
        expires,
        signature: join_card.signature.clone(),
    })
}

/// HybridCipher Client - Integration with core client library
pub struct HybridCipherClient {
    server_url: String,
    // Store the OpaqueAuth instance for authentication
    opaque_auth: Arc<Mutex<Option<OpaqueAuth>>>,
    // Store device keypairs
    device_keys: Arc<Mutex<Option<DeviceKeys>>>,
    // Store state key (device-specific encryption key)
    state_key: Arc<Mutex<Option<[u8; 32]>>>,
    // Cache scope for in-memory auth material (email + server)
    auth_scope: Arc<Mutex<Option<String>>>,
}

fn map_opaque_login_error(err: OpaqueError) -> LoginErrorInfo {
    match err {
        OpaqueError::MfaRequired(message) => LoginErrorInfo::new("MFA_REQUIRED", message),
        OpaqueError::MfaEnrollmentRequired(message) => {
            LoginErrorInfo::new("MFA_ENROLLMENT_REQUIRED", message)
        }
        OpaqueError::DeviceLimitReached(message) => {
            LoginErrorInfo::new("DEVICE_LIMIT_REACHED", message)
        }
        OpaqueError::EmailConfirmationRequired(message) => {
            LoginErrorInfo::new("EMAIL_CONFIRMATION_REQUIRED", message)
        }
        OpaqueError::RateLimited(message) => LoginErrorInfo::new("RATE_LIMITED", message),
        OpaqueError::LoginFailed(message) => LoginErrorInfo::new("LOGIN_FAILED", message),
        OpaqueError::NetworkError(message) => LoginErrorInfo::new("NETWORK_ERROR", message),
        OpaqueError::ProtocolError(message) => LoginErrorInfo::new("PROTOCOL_ERROR", message),
        OpaqueError::RegistrationFailed(message) => LoginErrorInfo::new("LOGIN_FAILED", message),
        OpaqueError::DeviceRecoveryFailed(message) => LoginErrorInfo::new("LOGIN_FAILED", message),
    }
}

impl HybridCipherClient {
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            opaque_auth: Arc::new(Mutex::new(None)),
            device_keys: Arc::new(Mutex::new(None)),
            state_key: Arc::new(Mutex::new(None)),
            auth_scope: Arc::new(Mutex::new(None)),
        }
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    fn auth_scope_for(&self, email: &str) -> String {
        let normalized_email = email.trim().to_ascii_lowercase();
        let canonical_server = canonicalize_server_url(&self.server_url);
        format!("{}::{}", normalized_email, canonical_server)
    }

    fn ensure_auth_scope(&self, email: &str) {
        let target_scope = self.auth_scope_for(email);
        let mut scope = self.auth_scope.lock().unwrap();
        if scope.as_deref() == Some(target_scope.as_str()) {
            return;
        }

        *self.opaque_auth.lock().unwrap() = None;
        *self.device_keys.lock().unwrap() = None;
        *self.state_key.lock().unwrap() = None;
        *scope = Some(target_scope);
    }

    pub fn clear_auth_cache(&self) {
        *self.opaque_auth.lock().unwrap() = None;
        *self.device_keys.lock().unwrap() = None;
        *self.state_key.lock().unwrap() = None;
        *self.auth_scope.lock().unwrap() = None;
    }

    /// Load device keys from the CLI state if present, otherwise generate ephemeral keys.
    fn ensure_device_keys(&self, email: &str) -> Result<DeviceKeys, String> {
        if let Some(keys) = self.device_keys.lock().unwrap().clone() {
            return Ok(keys);
        }

        if let Some(keys) = match load_cli_device_keys(email, &self.server_url) {
            Ok(keys) => keys,
            Err(err) => {
                warn!("Failed to load CLI device keys: {}", err);
                None
            }
        } {
            info!("Reusing CLI device keys for {}", email);
            *self.device_keys.lock().unwrap() = Some(keys.clone());
            return Ok(keys);
        }

        let mut keys = generate_fresh_device_keys()?;
        let state_key = self.state_key.lock().unwrap().as_ref().copied();
        if let Err(err) = persist_device_keys(email, &self.server_url, &keys, state_key.as_ref()) {
            warn!("Failed to persist device keys for {}: {}", email, err);
            // continue with in-memory keys to avoid blocking login
            // but regenerate created/expires to avoid drift if we retry
            keys.created_at = Utc::now();
            keys.expires_at = keys.created_at + Duration::days(30);
        } else {
            info!("Persisted device keys for {}", email);
        }
        *self.device_keys.lock().unwrap() = Some(keys.clone());
        Ok(keys)
    }

    /// Register a new user with OPAQUE
    pub async fn register(
        &self,
        email: String,
        password: String,
    ) -> Result<RegisterResult, String> {
        self.ensure_auth_scope(&email);

        // Initialize device keys
        let device_keys = self.ensure_device_keys(&email)?;

        // Generate device ID
        let device_id = device_keys.device_id.clone();

        // Create OPAQUE authenticator
        let opaque = OpaqueAuth::new(device_id.clone());

        // Perform OPAQUE registration start/finish with server
        let username = email.clone();
        let registration_result = opaque
            .register_with_server(&username, &email, &password, &self.server_url)
            .await
            .map_err(|e| format!("OPAQUE registration failed: {:?}", e))?;

        let registration_upload =
            general_purpose::STANDARD.encode(registration_result.registration_upload);
        let identity_public_key_hex = hex::encode(&device_keys.identity_public);
        let invitation_public_key_hex = hex::encode(&device_keys.invitation_public);

        #[derive(Serialize)]
        struct ServerRegisterRequest {
            username: String,
            email: String,
            identity_public_key: String,
            invitation_public_key: String,
            device_id: String,
            registration_upload: String,
            require_email_confirmation: bool,
        }

        #[derive(Deserialize)]
        struct ServerRegisterResponse {
            pending_confirmation: bool,
            confirmation_expires_at: Option<chrono::DateTime<chrono::Utc>>,
            #[serde(default)]
            user_id: Option<String>,
            #[serde(default)]
            access_token: Option<String>,
        }

        let trimmed = self.server_url.trim_end_matches('/');
        let endpoint = if trimmed.ends_with("/api/v1") {
            format!("{}/auth/register", trimmed)
        } else {
            format!("{}/api/v1/auth/register", trimmed)
        };

        let register_request = ServerRegisterRequest {
            username,
            email: email.clone(),
            identity_public_key: identity_public_key_hex,
            invitation_public_key: invitation_public_key_hex,
            device_id: device_id.clone(),
            registration_upload,
            require_email_confirmation: true,
        };

        let client = reqwest::Client::new();
        let response = client
            .post(endpoint)
            .json(&register_request)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Server registration failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Server registration failed ({}): {}",
                status,
                body.trim()
            ));
        }

        let server_response: ServerRegisterResponse = response
            .json()
            .await
            .map_err(|e| format!("Invalid registration response: {}", e))?;

        // Store the OpaqueAuth instance
        *self.opaque_auth.lock().unwrap() = Some(opaque);

        if !server_response.pending_confirmation {
            match (
                server_response.user_id.as_deref(),
                server_response.access_token.as_deref(),
            ) {
                (Some(user_id), Some(access_token)) => {
                    if let Err(err) = self
                        .publish_join_card_for_user(user_id, access_token, &device_keys)
                        .await
                    {
                        warn!("Join card publication skipped after registration: {}", err);
                    }
                }
                _ => {
                    warn!(
                        "Registration response missing user_id or access_token; join card not published"
                    );
                }
            }
        }

        let message = if server_response.pending_confirmation {
            if let Some(expires_at) = server_response.confirmation_expires_at {
                format!(
                    "Registration successful. Confirm your email before {}.",
                    expires_at
                )
            } else {
                "Registration successful. Check your email to confirm.".to_string()
            }
        } else {
            "Registration successful. You can log in now.".to_string()
        };

        Ok(RegisterResult {
            success: true,
            message,
        })
    }

    async fn publish_join_card_for_user(
        &self,
        user_id: &str,
        access_token: &str,
        device_keys: &DeviceKeys,
    ) -> Result<(), String> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| format!("Invalid user identifier '{}': {}", user_id, e))?;
        let invitation_keypair = invitation_keypair_from_device_keys(device_keys)?;
        let join_card = invitation_keypair
            .create_join_card(user_uuid)
            .map_err(|e| format!("Failed to create join card: {}", e))?;

        join_card
            .verify_signature()
            .map_err(|e| format!("Join card signature verification failed: {}", e))?;
        if !join_card.is_valid() {
            return Err("Join card expired; refresh device keys and retry.".to_string());
        }

        let payload = client_join_card_to_messages(&join_card)?;
        self.publish_join_card(access_token, &payload).await
    }

    async fn publish_join_card(
        &self,
        access_token: &str,
        join_card: &MessagesJoinCard,
    ) -> Result<(), String> {
        #[derive(Serialize)]
        struct DirectoryUploadJoinCardRequest {
            join_card: MessagesJoinCard,
        }

        let base_url = self.server_url.trim_end_matches('/');
        let endpoint = if base_url.ends_with("/api/v1") {
            format!("{}/directory/join-cards", base_url)
        } else {
            format!("{}/api/v1/directory/join-cards", base_url)
        };

        let client = reqwest::Client::new();
        let request = DirectoryUploadJoinCardRequest {
            join_card: join_card.clone(),
        };
        let response = client
            .post(endpoint)
            .bearer_auth(access_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Failed to publish join card: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Server rejected join card upload ({}): {}",
                status,
                body.trim()
            ));
        }

        Ok(())
    }

    /// Initialize or load state key (device-specific encryption key)
    fn ensure_state_key(&self, email: &str, password: &str) -> Result<[u8; 32], String> {
        // Check if already initialized
        if let Some(existing) = self.state_key.lock().unwrap().as_ref() {
            return Ok(*existing);
        }

        // Use the same account protection flow as the CLI (Argon2id + metadata)
        let session_store =
            SessionStore::new().map_err(|e| format!("Failed to create session store: {}", e))?;

        // This derives/validates the account key and ensures device key exists (CLI-compatible)
        let account_key_zeroized = session_store
            .initialize_account_protection(email, &self.server_url, password)
            .map_err(|e| format!("Failed to initialize account protection: {}", e))?;

        let mut account_key = [0u8; 32];
        account_key.copy_from_slice(account_key_zeroized.as_ref());

        let user_dir = cli_user_dir(email, &self.server_url)?;
        ensure_user_dirs(&user_dir)?;

        // Load device/state key (encrypted with account key)
        let device_key_path = user_dir.join(DEVICE_KEY_FILE);
        let state_key = if device_key_path.exists() {
            let raw = fs::read_to_string(&device_key_path)
                .map_err(|e| format!("Failed to read device key: {}", e))?;
            let protected: ProtectedData = serde_json::from_str(&raw)
                .map_err(|e| format!("Invalid device key format: {}", e))?;
            let decrypted = decrypt_with_ad(&protected, account_key, DEVICE_KEY_FILE_AAD)
                .map_err(|e| format!("Failed to decrypt device key: {}", e))?;

            if decrypted.len() != 32 {
                return Err("Device key has invalid length".to_string());
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&decrypted);
            key
        } else {
            // Should not happen because initialize_account_protection creates it, but keep fallback
            warn!("Device key missing, falling back to account key");
            account_key
        };

        *self.state_key.lock().unwrap() = Some(state_key);
        Ok(state_key)
    }

    /// Login with OPAQUE authentication
    pub async fn login(
        &self,
        email: String,
        password: String,
        mfa_code: Option<String>,
        backup_code: Option<String>,
    ) -> Result<LoginResult, LoginErrorInfo> {
        self.ensure_auth_scope(&email);

        // Initialize state key first (device-specific encryption key)
        let _state_key = self
            .ensure_state_key(&email, &password)
            .map_err(|message| LoginErrorInfo::new("LOGIN_FAILED", message))?;

        // Initialize or load device keys (prefer CLI device identity if present)
        let mut device_keys = self
            .ensure_device_keys(&email)
            .map_err(|message| LoginErrorInfo::new("LOGIN_FAILED", message))?;
        let mut opaque = OpaqueAuth::new(device_keys.device_id.clone());

        let mut login_result = opaque
            .login_with_server(
                &email,
                &password,
                &self.server_url,
                DeviceLoginMetadata {
                    identity_public_key_hex: hex::encode(&device_keys.identity_public),
                    invitation_public_key_hex: hex::encode(&device_keys.invitation_public),
                    device_display_name: Some(whoami::devicename()),
                    mfa_code: mfa_code.clone(),
                    backup_code: backup_code.clone(),
                },
            )
            .await;

        if let Err(OpaqueError::LoginFailed(message)) = &login_result {
            if message
                .to_ascii_lowercase()
                .contains("device belongs to a different user")
            {
                warn!(
                    "Detected stale device identity for {}. Rotating local device keys and retrying login once.",
                    email
                );
                self.rotate_local_device_identity(&email)
                    .map_err(|message| LoginErrorInfo::new("LOGIN_FAILED", message))?;
                device_keys = self
                    .ensure_device_keys(&email)
                    .map_err(|message| LoginErrorInfo::new("LOGIN_FAILED", message))?;
                opaque = OpaqueAuth::new(device_keys.device_id.clone());
                login_result = opaque
                    .login_with_server(
                        &email,
                        &password,
                        &self.server_url,
                        DeviceLoginMetadata {
                            identity_public_key_hex: hex::encode(&device_keys.identity_public),
                            invitation_public_key_hex: hex::encode(&device_keys.invitation_public),
                            device_display_name: Some(whoami::devicename()),
                            mfa_code: mfa_code.clone(),
                            backup_code: backup_code.clone(),
                        },
                    )
                    .await;
            }
        }

        let login_result = login_result.map_err(map_opaque_login_error)?;
        let device_keys_for_publish = device_keys.clone();

        // Store the OpaqueAuth instance
        *self.opaque_auth.lock().unwrap() = Some(opaque);
        *self.device_keys.lock().unwrap() = Some(device_keys);

        if let Err(err) = self
            .publish_join_card_for_user(
                &login_result.user_id.to_string(),
                &login_result.access_token,
                &device_keys_for_publish,
            )
            .await
        {
            warn!("Join card publication skipped after login: {}", err);
        }

        let export_key_b64 = general_purpose::STANDARD.encode(login_result.export_key);

        Ok(LoginResult {
            success: true,
            token: login_result.access_token,
            refresh_token: Some(login_result.refresh_token),
            device_id: login_result.device_id,
            email: login_result.username,
            user_id: login_result.user_id.to_string(),
            expires_in: login_result.expires_in,
            device_status: login_result.device_status,
            is_new_device: login_result.is_new_device,
            opaque_export_key: Some(export_key_b64),
            recovery_code: None,
        })
    }

    fn rotate_local_device_identity(&self, email: &str) -> Result<(), String> {
        let user_dir = cli_user_dir(email, &self.server_url)?;
        let invitation_path = user_dir.join(INVITATION_KEYPAIR_FILE);
        let device_keypair_path = user_dir.join(DEVICE_KEYPAIR_FILE);

        for path in [invitation_path, device_keypair_path] {
            if path.exists() {
                fs::remove_file(&path).map_err(|e| {
                    format!(
                        "Failed to rotate stale device identity at {}: {}",
                        path.display(),
                        e
                    )
                })?;
            }
        }

        *self.device_keys.lock().unwrap() = None;
        *self.opaque_auth.lock().unwrap() = None;
        Ok(())
    }

    /// Placeholder group and file operations remain centralized here until
    /// the desktop app is wired to the production backend APIs.
    ///
    /// Keeping the mocked behavior in this service layer avoids duplicating
    /// transport-level placeholder logic across the Tauri command handlers.

    /// Create a new group
    pub async fn create_group(&self, name: String) -> Result<CreateGroupResult, String> {
        Ok(CreateGroupResult {
            group_id: format!("group_{}", uuid::Uuid::new_v4()),
            name,
            created: true,
        })
    }

    /// List all groups
    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>, String> {
        Ok(vec![GroupInfo {
            id: "group_123".to_string(),
            name: "Engineering Team".to_string(),
            member_count: 5,
            epoch: 1,
        }])
    }

    /// Encrypt a file
    pub async fn encrypt_file(
        &self,
        file_path: String,
        _group_id: String,
    ) -> Result<EncryptFileResult, String> {
        Ok(EncryptFileResult {
            encrypted_path: format!("{}.encrypted", file_path),
            file_id: uuid::Uuid::new_v4().to_string(),
            success: true,
        })
    }

    /// Decrypt a file
    pub async fn decrypt_file(
        &self,
        file_path: String,
        output_path: Option<String>,
    ) -> Result<DecryptFileResult, String> {
        let output = output_path.unwrap_or_else(|| file_path.replace(".encrypted", ""));

        Ok(DecryptFileResult {
            decrypted_path: output,
            success: true,
        })
    }

    /// Get server information
    pub async fn server_info(&self) -> ServerInfo {
        ServerInfo {
            url: self.server_url.clone(),
            connected: !self.server_url.trim().is_empty(),
            version: "1.0.0".to_string(),
            fingerprint: Some("ABCD-EFGH-IJKL-MNOP".to_string()),
        }
    }

    /// Get user status
    pub async fn user_status(
        &self,
        current_session: Option<&crate::state::UserSession>,
    ) -> UserStatus {
        // Check if user has an active session
        if let Some(session) = current_session {
            // Check if session is still valid
            let now = chrono::Utc::now().timestamp();
            if session.expires_at > now {
                // Determine user role based on groups
                let user_role = self.determine_user_role().await;

                return UserStatus {
                    logged_in: true,
                    email: Some(session.email.clone()),
                    device_id: Some(session.device_id.clone()),
                    user_role,
                };
            }
        }

        // No valid session
        UserStatus {
            logged_in: false,
            email: None,
            device_id: None,
            user_role: UserRole::Individual,
        }
    }

    /// Determine user role based on group membership
    /// User is TeamAdmin if they have at least one group with 2+ members
    async fn determine_user_role(&self) -> UserRole {
        match self.list_groups().await {
            Ok(groups) => {
                // Check if user has any group with 2 or more members
                let has_admin_group = groups.iter().any(|g| g.member_count >= 2);

                if has_admin_group {
                    UserRole::TeamAdmin
                } else if !groups.is_empty() {
                    UserRole::TeamMember
                } else {
                    UserRole::Individual
                }
            }
            Err(_) => UserRole::Individual, // Default to Individual on error
        }
    }
}

// Result types
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResult {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginErrorInfo {
    pub code: String,
    pub message: String,
}

impl LoginErrorInfo {
    fn new(code: &str, message: String) -> Self {
        Self {
            code: code.to_string(),
            message,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResult {
    pub success: bool,
    pub token: String,
    pub refresh_token: Option<String>,
    pub device_id: String,
    pub email: String,
    pub user_id: String,
    pub expires_in: i64,
    pub device_status: Option<String>,
    pub is_new_device: bool,
    #[serde(default)]
    pub opaque_export_key: Option<String>,
    #[serde(default)]
    pub recovery_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupResult {
    pub group_id: String,
    pub name: String,
    pub created: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub member_count: usize,
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptFileResult {
    pub encrypted_path: String,
    pub file_id: String,
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptFileResult {
    pub decrypted_path: String,
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    pub url: String,
    pub connected: bool,
    pub version: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserStatus {
    pub logged_in: bool,
    pub email: Option<String>,
    pub device_id: Option<String>,
    pub user_role: UserRole, // Add this
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum UserRole {
    Individual, // Default, no groups
    TeamMember, // Part of teams, can't create/rekey
    TeamAdmin,  // Can create groups and rekey
}
