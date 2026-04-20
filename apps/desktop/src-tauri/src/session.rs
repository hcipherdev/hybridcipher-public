// Session persistence for desktop app - CLI compatible
// Stores session data in CLI's format and location so both tools share the same state
// Desktop can login independently and derive the same account key as CLI from user password

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use hybridcipher_crypto::account_protection::{
    decrypt_with_ad, encrypt_with_ad, ProtectedData, PROTECTED_DATA_MAGIC,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

// Constants matching CLI's session management
const USERS_DIR: &str = "users";
const GLOBAL_DIR: &str = "global";
const ACTIVE_USER_FILE: &str = "active_user.json";
const LAST_USER_FILE: &str = "last_user.json";
const SESSION_FILE: &str = "session.toml";
const SESSION_FILE_AAD: &[u8] = b"hybridcipher/session";
const ACCOUNT_KEY_CACHE_FILE: &str = ".account_key_cache";
const DEVICE_KEY_FILE: &str = "device_key.protected";
const DEVICE_KEY_FILE_AAD: &[u8] = b"hybridcipher/device_key_material";
const ACCOUNT_PROTECTION_FILE: &str = "account_protection.json";
const CANONICAL_PRODUCTION_SERVER: &str = "https://api.hybridcipher.com";

/// Account protection metadata - matches CLI's AccountProtectionMetadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProtectionMetadata {
    pub version: u32,
    pub kdf: String,
    pub salt: String,
    pub verifier: String,
}

impl AccountProtectionMetadata {
    /// Create new metadata with fresh salt
    pub fn new() -> Self {
        let mut salt_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);

        Self {
            version: 1,
            kdf: "argon2id".to_string(),
            salt: STANDARD.encode(salt_bytes),
            verifier: String::new(),
        }
    }
}

impl Default for AccountProtectionMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Session data that persists across app restarts - matches CLI's Session struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSession {
    pub user_id: String,
    pub username: String,
    pub device_id: String,
    #[serde(default)]
    pub device_status: Option<String>,
    pub server_url: String,
    pub token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub opaque_export_key: Option<String>,
    pub device_binding: String,
    pub device_keypair: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub migration_info: Option<MigrationInfo>,
    pub security_metadata: SessionSecurity,
    // Desktop-specific fields (compatible addition)
    #[serde(default)]
    pub email: String,
}

/// Session security metadata - matches CLI's SessionSecurity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSecurity {
    pub device_fingerprint: String,
    pub integrity_hash: String,
    pub version: u32,
    pub flags: SessionFlags,
}

/// Session security flags - matches CLI's SessionFlags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFlags {
    pub device_verified: bool,
    pub migration_recovered: bool,
    pub auto_renewal: bool,
    pub enhanced_security: bool,
}

/// Migration state information - matches CLI's MigrationInfo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationInfo {
    pub current_epoch: u64,
    pub target_epoch: Option<u64>,
    pub migration_start: Option<DateTime<Utc>>,
    pub phase: MigrationPhase,
    pub pending_files: Vec<String>,
    pub progress: f64,
    #[serde(default)]
    pub total_files: u64,
}

/// Migration phases - matches CLI's MigrationPhase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationPhase {
    Idle,
    Started,
    InProgress,
    ReadyForCutover,
    Completed,
    Failed,
}

impl Default for MigrationPhase {
    fn default() -> Self {
        MigrationPhase::Idle
    }
}

/// Active user record - matches CLI's ActiveUserRecord
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveUserRecord {
    username: String,
    server_url: String,
    user_id: String,
}

impl PersistedSession {
    /// Check if session is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    /// Check if session needs refresh (expires within 5 minutes)
    pub fn needs_refresh(&self) -> bool {
        let now = Utc::now();
        let threshold = self.expires_at - chrono::Duration::minutes(5);
        now >= threshold
    }
}

impl Default for SessionFlags {
    fn default() -> Self {
        Self {
            device_verified: true,
            migration_recovered: false,
            auto_renewal: true,
            enhanced_security: false,
        }
    }
}

impl Default for SessionSecurity {
    fn default() -> Self {
        Self {
            device_fingerprint: String::new(),
            integrity_hash: String::new(),
            version: 1,
            flags: SessionFlags::default(),
        }
    }
}

/// Session storage manager that uses CLI's format and location
pub struct SessionStore {
    base_dir: PathBuf,
    global_dir: PathBuf,
}

impl SessionStore {
    /// Create a new session store using CLI's directory structure
    pub fn new() -> Result<Self, String> {
        let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        let base_dir = PathBuf::from(home).join(".hybridcipher");
        let global_dir = base_dir.join(GLOBAL_DIR);

        // Create directories if they don't exist
        fs::create_dir_all(&base_dir)
            .map_err(|e| format!("Failed to create base directory: {}", e))?;
        fs::create_dir_all(&global_dir)
            .map_err(|e| format!("Failed to create global directory: {}", e))?;
        fs::create_dir_all(base_dir.join(USERS_DIR))
            .map_err(|e| format!("Failed to create users directory: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&global_dir, fs::Permissions::from_mode(0o700));
        }

        Ok(Self {
            base_dir,
            global_dir,
        })
    }

    /// Get user storage ID matching CLI's format (hash of email + server_url)
    fn get_user_storage_id(&self, email: &str, server_url: &str) -> String {
        let canonical_url = canonicalize_server_url(server_url);
        let mut hasher = Sha256::new();
        hasher.update(email.to_lowercase().as_bytes());
        hasher.update(canonical_url.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..8])
    }

    /// Get the user's config directory
    fn user_dir(&self, email: &str, server_url: &str) -> PathBuf {
        let user_id = self.get_user_storage_id(email, server_url);
        self.base_dir.join(USERS_DIR).join(&user_id)
    }

    /// Get session file path for a user (CLI compatible location)
    fn session_file_path(&self, email: &str, server_url: &str) -> PathBuf {
        self.user_dir(email, server_url).join(SESSION_FILE)
    }

    /// Load the state encryption key for a user
    fn load_state_key(&self, email: &str, server_url: &str) -> Result<[u8; 32], String> {
        let user_dir = self.user_dir(email, server_url);

        // First load the account key from cache
        let account_key = self.load_account_key(&user_dir)?;

        // Then try to load the device state key
        let device_key_path = user_dir.join(DEVICE_KEY_FILE);
        if !device_key_path.exists() {
            // Fallback to account key for legacy compatibility
            return Ok(account_key);
        }

        // Try to decrypt device key, but fall back to account key if it fails
        match (|| -> Result<[u8; 32], String> {
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
            Ok(key)
        })() {
            Ok(device_key) => Ok(device_key),
            Err(e) => {
                // Log the error but fall back to account key
                tracing::warn!(
                    "Could not load device key ({}), using account key fallback",
                    e
                );
                Ok(account_key)
            }
        }
    }

    /// Load account key from cache
    fn load_account_key(&self, user_dir: &PathBuf) -> Result<[u8; 32], String> {
        let cache_path = user_dir.join(ACCOUNT_KEY_CACHE_FILE);
        let encoded = fs::read_to_string(&cache_path)
            .map_err(|e| format!("Failed to read account key cache: {}", e))?;

        let decoded = STANDARD
            .decode(encoded.trim())
            .map_err(|e| format!("Failed to decode account key: {}", e))?;

        if decoded.len() != 32 {
            return Err("Account key has invalid length".to_string());
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }

    /// Check if account key is cached for a user
    pub fn has_account_key_cached(&self, email: &str, server_url: &str) -> bool {
        let user_dir = self.user_dir(email, server_url);
        user_dir.join(ACCOUNT_KEY_CACHE_FILE).exists()
    }

    /// Derive account key from password using Argon2id (CLI compatible)
    pub fn derive_account_key(
        &self,
        password: &str,
        metadata: &AccountProtectionMetadata,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        if metadata.kdf.to_lowercase() != "argon2id" {
            return Err(format!("Unsupported KDF algorithm: {}", metadata.kdf));
        }

        let salt_bytes = STANDARD
            .decode(&metadata.salt)
            .map_err(|e| format!("Invalid salt encoding: {}", e))?;

        // CLI uses: memory=64KB, iterations=3, parallelism=1, output=32 bytes
        let params = Params::new(64 * 1024, 3, 1, Some(32))
            .map_err(|e| format!("Failed to configure Argon2 params: {}", e))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password.as_bytes(), &salt_bytes, key.as_mut())
            .map_err(|e| format!("Failed to derive account key: {}", e))?;

        Ok(key)
    }

    /// Cache account key to disk (CLI compatible format)
    pub fn cache_account_key(
        &self,
        email: &str,
        server_url: &str,
        key: &[u8; 32],
    ) -> Result<(), String> {
        let user_dir = self.user_dir(email, server_url);
        fs::create_dir_all(&user_dir)
            .map_err(|e| format!("Failed to create user directory: {}", e))?;

        let cache_path = user_dir.join(ACCOUNT_KEY_CACHE_FILE);
        let encoded = STANDARD.encode(key);

        fs::write(&cache_path, encoded)
            .map_err(|e| format!("Failed to write account key cache: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&cache_path, fs::Permissions::from_mode(0o600));
        }

        tracing::info!("Cached account key for user: {}", email);
        Ok(())
    }

    /// Load or create account protection metadata
    pub fn load_or_create_account_metadata(
        &self,
        email: &str,
        server_url: &str,
    ) -> Result<AccountProtectionMetadata, String> {
        let user_dir = self.user_dir(email, server_url);
        let metadata_path = user_dir.join(ACCOUNT_PROTECTION_FILE);

        if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)
                .map_err(|e| format!("Failed to read account protection: {}", e))?;
            let metadata: AccountProtectionMetadata = serde_json::from_str(&content)
                .map_err(|e| format!("Invalid account protection format: {}", e))?;
            return Ok(metadata);
        }

        // Create new metadata if none exists
        Ok(AccountProtectionMetadata::new())
    }

    /// Save account protection metadata
    pub fn save_account_metadata(
        &self,
        email: &str,
        server_url: &str,
        metadata: &AccountProtectionMetadata,
    ) -> Result<(), String> {
        let user_dir = self.user_dir(email, server_url);
        fs::create_dir_all(&user_dir)
            .map_err(|e| format!("Failed to create user directory: {}", e))?;

        let metadata_path = user_dir.join(ACCOUNT_PROTECTION_FILE);
        let content = serde_json::to_string_pretty(metadata)
            .map_err(|e| format!("Failed to serialize account protection: {}", e))?;

        fs::write(&metadata_path, content)
            .map_err(|e| format!("Failed to write account protection: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Compute verifier hash for password validation (must match CLI)
    fn compute_verifier(key: &[u8; 32]) -> String {
        // CLI uses this exact label
        let mut hasher = Sha256::new();
        hasher.update(b"hybridcipher-account-verifier");
        hasher.update(key);
        let hash = hasher.finalize();
        STANDARD.encode(hash)
    }

    /// Legacy verifier used in early desktop builds (wrong label); kept for migration
    fn compute_legacy_verifier(key: &[u8; 32]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"hybridcipher/account_verifier");
        hasher.update(key);
        let hash = hasher.finalize();
        STANDARD.encode(hash)
    }

    /// Initialize account protection for a user (called on first login)
    /// Returns the derived account key
    pub fn initialize_account_protection(
        &self,
        email: &str,
        server_url: &str,
        password: &str,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        let user_dir = self.user_dir(email, server_url);
        fs::create_dir_all(&user_dir)
            .map_err(|e| format!("Failed to create user directory: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&user_dir, fs::Permissions::from_mode(0o700));
        }

        // Load existing metadata or create new
        let mut metadata = self.load_or_create_account_metadata(email, server_url)?;

        // Derive account key
        let key = self.derive_account_key(password, &metadata)?;

        // If no verifier set, this is first-time setup
        if metadata.verifier.is_empty() {
            metadata.verifier = Self::compute_verifier(&key);
            self.save_account_metadata(email, server_url, &metadata)?;
        } else {
            // Verify password matches; support legacy verifier label migration
            let expected_verifier = Self::compute_verifier(&key);
            if expected_verifier != metadata.verifier {
                let legacy_verifier = Self::compute_legacy_verifier(&key);
                if legacy_verifier == metadata.verifier {
                    // Migrate to correct label
                    let mut updated = metadata.clone();
                    updated.verifier = expected_verifier;
                    self.save_account_metadata(email, server_url, &updated)?;
                } else {
                    // Password changed externally (e.g. via CLI). Try to recover
                    // by re-wrapping local state if the raw key is in the keybundle.
                    let storage_id = self.get_user_storage_id(email, server_url);
                    if let Ok(Some(_raw_key)) = crate::key_bundle::load_state_key(&storage_id) {
                        tracing::warn!(
                            "Verifier mismatch for {}; re-wrapping desktop state with current password",
                            email
                        );
                        self.rewrap_after_password_change(email, server_url, password)?;
                        // Re-derive key against the freshly written metadata.
                        let fresh_metadata =
                            self.load_or_create_account_metadata(email, server_url)?;
                        let fresh_key = self.derive_account_key(password, &fresh_metadata)?;
                        return Ok(fresh_key);
                    }
                    return Err("Password does not match existing account".to_string());
                }
            }
        }

        // Cache the account key
        self.cache_account_key(email, server_url, &key)?;

        // Ensure device/state key exists
        self.ensure_device_key_exists(email, server_url, &key)?;

        tracing::info!("Account protection initialized for: {}", email);
        Ok(key)
    }

    /// Ensure device state key exists, create if needed
    fn ensure_device_key_exists(
        &self,
        email: &str,
        server_url: &str,
        account_key: &[u8; 32],
    ) -> Result<(), String> {
        let user_dir = self.user_dir(email, server_url);
        let device_key_path = user_dir.join(DEVICE_KEY_FILE);

        if device_key_path.exists() {
            return Ok(()); // Already exists
        }

        // Generate new device/state key
        let mut state_key = [0u8; 32];
        OsRng.fill_bytes(&mut state_key);

        // Encrypt with account key
        let protected = encrypt_with_ad(&state_key, *account_key, DEVICE_KEY_FILE_AAD)
            .map_err(|e| format!("Failed to encrypt device key: {}", e))?;

        let serialized = serde_json::to_string_pretty(&protected)
            .map_err(|e| format!("Failed to serialize device key: {}", e))?;

        fs::write(&device_key_path, serialized)
            .map_err(|e| format!("Failed to write device key: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&device_key_path, fs::Permissions::from_mode(0o600));
        }

        tracing::info!("Created device key for: {}", email);
        Ok(())
    }

    /// Verify password against stored account protection
    pub fn verify_password(
        &self,
        email: &str,
        server_url: &str,
        password: &str,
    ) -> Result<bool, String> {
        let metadata = self.load_or_create_account_metadata(email, server_url)?;

        if metadata.verifier.is_empty() {
            // No verifier = first time login, password is valid
            return Ok(true);
        }

        let key = self.derive_account_key(password, &metadata)?;
        let expected_verifier = Self::compute_verifier(&key);
        if expected_verifier == metadata.verifier {
            return Ok(true);
        }

        // Accept legacy verifier and migrate on next save
        let legacy_verifier = Self::compute_legacy_verifier(&key);
        Ok(legacy_verifier == metadata.verifier)
    }

    /// Re-wrap local desktop state after a password change or reset.
    ///
    /// Reads the raw device/state key from the desktop key bundle (which is not
    /// password-derived and therefore survives password rotation), then re-encrypts
    /// `device_key.protected` and updates `account_protection.json` + account key
    /// cache under the **new** password.
    pub fn rewrap_after_password_change(
        &self,
        email: &str,
        server_url: &str,
        new_password: &str,
    ) -> Result<(), String> {
        let storage_id = self.get_user_storage_id(email, server_url);
        let user_dir = self.user_dir(email, server_url);
        if !user_dir.exists() {
            // No local state for this user; nothing to re-wrap.
            return Ok(());
        }

        // Load the raw state key from the desktop key bundle (keychain).
        let state_key = crate::key_bundle::load_state_key(&storage_id)?.ok_or_else(|| {
            "Cannot re-wrap: device state key is not present in the desktop key bundle. \
                 Local encrypted state may become inaccessible until next full login."
                .to_string()
        })?;

        // Create fresh account protection metadata with new salt.
        let mut metadata = AccountProtectionMetadata::new();

        // Derive new account key from the new password.
        let new_account_key = self.derive_account_key(new_password, &metadata)?;
        metadata.verifier = Self::compute_verifier(&new_account_key);

        // Re-encrypt device_key.protected with the new account key.
        let protected = encrypt_with_ad(&state_key, *new_account_key, DEVICE_KEY_FILE_AAD)
            .map_err(|e| format!("Failed to re-encrypt device key: {}", e))?;
        let serialized = serde_json::to_string_pretty(&protected)
            .map_err(|e| format!("Failed to serialize device key: {}", e))?;
        let device_key_path = user_dir.join(DEVICE_KEY_FILE);
        fs::write(&device_key_path, serialized)
            .map_err(|e| format!("Failed to write re-wrapped device key: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&device_key_path, fs::Permissions::from_mode(0o600));
        }

        // Persist updated metadata and account key cache.
        self.save_account_metadata(email, server_url, &metadata)?;
        self.cache_account_key(email, server_url, &new_account_key)?;

        tracing::info!(
            "Re-wrapped desktop state after password change for: {}",
            email
        );
        Ok(())
    }

    /// Save session to disk in CLI's format and location
    /// Requires encryption keys to already be set up (call initialize_account_protection first)
    pub fn save_session(&self, session: &PersistedSession) -> Result<(), String> {
        let email = &session.email;
        let server_url = &session.server_url;
        let user_dir = self.user_dir(email, server_url);

        // Ensure user directory exists
        fs::create_dir_all(&user_dir)
            .map_err(|e| format!("Failed to create user directory: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&user_dir, fs::Permissions::from_mode(0o700));
        }

        // Load state key for encryption
        let state_key = self.load_state_key(email, server_url)?;

        // Serialize session to TOML (CLI format)
        let content = toml::to_string_pretty(session)
            .map_err(|e| format!("Failed to serialize session: {}", e))?;

        // Encrypt the session data
        let protected = encrypt_with_ad(content.as_bytes(), state_key, SESSION_FILE_AAD)
            .map_err(|e| format!("Failed to encrypt session: {}", e))?;

        let serialized = serde_json::to_string_pretty(&protected)
            .map_err(|e| format!("Failed to serialize encrypted session: {}", e))?;

        // Write to session file
        let session_path = self.session_file_path(email, server_url);
        let temp_path = session_path.with_extension("tmp");

        fs::write(&temp_path, &serialized)
            .map_err(|e| format!("Failed to write session file: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600));
        }

        fs::rename(&temp_path, &session_path)
            .map_err(|e| format!("Failed to finalize session file: {}", e))?;

        // Update active user file
        self.persist_active_user(email, server_url)?;

        tracing::info!(
            "Session saved (CLI compatible) for user: {}",
            session.username
        );
        Ok(())
    }

    /// Save session with password-based encryption (for first-time login)
    /// This initializes account protection and then saves the session
    pub fn save_session_with_password(
        &self,
        session: &PersistedSession,
        password: &str,
    ) -> Result<(), String> {
        let email = &session.email;
        let server_url = &session.server_url;

        // Initialize account protection (derives and caches key, creates device key if needed)
        self.initialize_account_protection(email, server_url, password)?;

        // Now save the session using the initialized keys
        self.save_session(session)
    }

    /// Load session from disk (CLI compatible format)
    pub fn load_session(
        &self,
        email: &str,
        server_url: &str,
    ) -> Result<Option<PersistedSession>, String> {
        let session_path = self.session_file_path(email, server_url);

        if !session_path.exists() {
            return Ok(None);
        }

        // Load state key for decryption
        let state_key = self.load_state_key(email, server_url)?;

        // Read and parse encrypted session
        let raw = fs::read_to_string(&session_path)
            .map_err(|e| format!("Failed to read session file: {}", e))?;

        // Try to parse as encrypted ProtectedData first
        let content = match serde_json::from_str::<ProtectedData>(&raw) {
            Ok(protected) if protected.magic == PROTECTED_DATA_MAGIC => {
                let decrypted = decrypt_with_ad(&protected, state_key, SESSION_FILE_AAD)
                    .map_err(|e| format!("Failed to decrypt session: {}", e))?;
                String::from_utf8(decrypted)
                    .map_err(|e| format!("Session is not valid UTF-8: {}", e))?
            }
            _ => {
                // Might be plaintext TOML (legacy)
                raw
            }
        };

        // Parse TOML content
        let mut session: PersistedSession =
            toml::from_str(&content).map_err(|e| format!("Failed to parse session: {}", e))?;

        // Ensure email is set (might be missing in CLI sessions)
        if session.email.is_empty() {
            session.email = session.username.clone();
        }

        // Check if session is still valid
        if !session.is_valid() {
            tracing::info!("Session expired for user: {}", email);
            return Ok(None);
        }

        tracing::info!(
            "Session loaded (CLI compatible) for user: {}",
            session.username
        );
        Ok(Some(session))
    }

    /// Delete session from disk
    pub fn delete_session(&self, email: &str, server_url: &str) -> Result<(), String> {
        let session_path = self.session_file_path(email, server_url);

        if session_path.exists() {
            // Securely overwrite file before deletion
            if let Ok(metadata) = fs::metadata(&session_path) {
                let file_size = metadata.len() as usize;
                let zeros = Zeroizing::new(vec![0u8; file_size]);
                let _ = fs::write(&session_path, zeros.as_slice());
            }

            fs::remove_file(&session_path)
                .map_err(|e| format!("Failed to delete session file: {}", e))?;

            tracing::info!("Session deleted for user: {}", email);
        }

        // Clear active user if it matches
        self.clear_active_user_if_matches(email)?;

        Ok(())
    }

    /// Persist active user to global file (CLI compatible)
    fn persist_active_user(&self, email: &str, server_url: &str) -> Result<(), String> {
        let user_id = self.get_user_storage_id(email, server_url);
        let canonical_url = canonicalize_server_url(server_url);

        let record = ActiveUserRecord {
            username: email.to_string(),
            server_url: canonical_url,
            user_id,
        };

        let content = serde_json::to_string_pretty(&record)
            .map_err(|e| format!("Failed to serialize active user: {}", e))?;

        let active_file = self.global_dir.join(ACTIVE_USER_FILE);
        fs::write(&active_file, content)
            .map_err(|e| format!("Failed to write active user file: {}", e))?;

        // Also update last_user.json for CLI compatibility
        let last_user_file = self.global_dir.join(LAST_USER_FILE);
        let last_record = serde_json::to_string_pretty(&record)
            .map_err(|e| format!("Failed to serialize last user: {}", e))?;
        let _ = fs::write(&last_user_file, last_record);

        Ok(())
    }

    /// Clear active user file on logout
    pub fn clear_active_user(&self) -> Result<(), String> {
        let active_file = self.global_dir.join(ACTIVE_USER_FILE);
        if active_file.exists() {
            fs::remove_file(&active_file)
                .map_err(|e| format!("Failed to remove active user file: {}", e))?;
        }
        Ok(())
    }

    /// Clear active user if it matches the given email
    fn clear_active_user_if_matches(&self, email: &str) -> Result<(), String> {
        let active_file = self.global_dir.join(ACTIVE_USER_FILE);
        if active_file.exists() {
            if let Ok(content) = fs::read_to_string(&active_file) {
                if let Ok(record) = serde_json::from_str::<ActiveUserRecord>(&content) {
                    if record.username.eq_ignore_ascii_case(email) {
                        let _ = fs::remove_file(&active_file);
                    }
                }
            }
        }
        Ok(())
    }

    /// List all stored sessions by reading active_user.json and checking user directories
    pub fn list_sessions(&self) -> Result<Vec<(String, String)>, String> {
        let mut sessions = Vec::new();

        // Check active user first
        let active_file = self.global_dir.join(ACTIVE_USER_FILE);
        if active_file.exists() {
            if let Ok(content) = fs::read_to_string(&active_file) {
                if let Ok(record) = serde_json::from_str::<ActiveUserRecord>(&content) {
                    // Verify session file exists
                    let session_path = self.session_file_path(&record.username, &record.server_url);
                    if session_path.exists() {
                        sessions.push((record.username, record.server_url));
                    }
                }
            }
        }

        // Also check last_user.json as fallback
        let last_user_file = self.global_dir.join(LAST_USER_FILE);
        if last_user_file.exists() {
            if let Ok(content) = fs::read_to_string(&last_user_file) {
                if let Ok(record) = serde_json::from_str::<ActiveUserRecord>(&content) {
                    let session_path = self.session_file_path(&record.username, &record.server_url);
                    if session_path.exists() {
                        let entry = (record.username.clone(), record.server_url.clone());
                        if !sessions.contains(&entry) {
                            sessions.push(entry);
                        }
                    }
                }
            }
        }

        Ok(sessions)
    }

    /// Get server URL for session lookup - defaults to production
    pub fn default_server_url() -> String {
        CANONICAL_PRODUCTION_SERVER.to_string()
    }
}

/// Canonicalize server URL to match CLI behavior
fn canonicalize_server_url(server_url: &str) -> String {
    let trimmed = server_url.trim();
    if trimmed.is_empty() {
        return CANONICAL_PRODUCTION_SERVER.to_string();
    }

    let lower = trimmed.to_ascii_lowercase();

    // Check legacy IP-based aliases
    const LEGACY_SERVER_ALIASES: &[&str] = &[
        "http://108.175.8.121:8080",
        "https://108.175.8.121:8080",
        "http://108.175.8.121",
        "https://108.175.8.121",
    ];

    for alias in LEGACY_SERVER_ALIASES {
        let alias_lower = alias.to_ascii_lowercase();
        if lower == alias_lower || lower.starts_with(&(alias_lower.clone() + "/")) {
            return CANONICAL_PRODUCTION_SERVER.to_string();
        }
    }

    // Check legacy HTTP aliases
    const LEGACY_HTTP_ALIASES: &[&str] = &[
        "http://api.hybridcipher.com",
        "http://api.hybridcipher.com:8080",
    ];

    for alias in LEGACY_HTTP_ALIASES {
        let alias_lower = alias.to_ascii_lowercase();
        if lower == alias_lower || lower.starts_with(&(alias_lower.clone() + "/")) {
            return CANONICAL_PRODUCTION_SERVER.to_string();
        }
    }

    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_validity() {
        let session = PersistedSession {
            user_id: "test-user".to_string(),
            username: "test".to_string(),
            device_id: "device1".to_string(),
            device_status: None,
            server_url: CANONICAL_PRODUCTION_SERVER.to_string(),
            token: "token".to_string(),
            refresh_token: String::new(),
            opaque_export_key: None,
            device_binding: String::new(),
            device_keypair: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            last_activity: Utc::now(),
            migration_info: None,
            security_metadata: SessionSecurity::default(),
            email: "test@example.com".to_string(),
        };

        assert!(session.is_valid());
        assert!(!session.needs_refresh());
    }

    #[test]
    fn test_expired_session() {
        let session = PersistedSession {
            user_id: "test-user".to_string(),
            username: "test".to_string(),
            device_id: "device1".to_string(),
            device_status: None,
            server_url: CANONICAL_PRODUCTION_SERVER.to_string(),
            token: "token".to_string(),
            refresh_token: String::new(),
            opaque_export_key: None,
            device_binding: String::new(),
            device_keypair: None,
            created_at: Utc::now() - chrono::Duration::hours(25),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            last_activity: Utc::now() - chrono::Duration::hours(2),
            migration_info: None,
            security_metadata: SessionSecurity::default(),
            email: "test@example.com".to_string(),
        };

        assert!(!session.is_valid());
    }

    #[test]
    fn test_canonicalize_server_url() {
        assert_eq!(
            canonicalize_server_url("http://108.175.8.121:8080"),
            CANONICAL_PRODUCTION_SERVER
        );
        assert_eq!(
            canonicalize_server_url("http://api.hybridcipher.com"),
            CANONICAL_PRODUCTION_SERVER
        );
        assert_eq!(
            canonicalize_server_url("https://api.hybridcipher.com"),
            "https://api.hybridcipher.com"
        );
        assert_eq!(canonicalize_server_url(""), CANONICAL_PRODUCTION_SERVER);
    }
}
