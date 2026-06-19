use crate::{
    error::CliError,
    security::{
        server_identity::{ServerIdentityManager, TrustDecision, TrustLevel, VerificationMethod},
        unlock::UnlockConfig,
    },
    ui,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, Utc};
use hex;
use hybridcipher_client::invitation::JoinCard as ClientJoinCard;
use hybridcipher_client::{
    auth::opaque::{DeviceLoginMetadata, OpaqueServerLogin},
    pinning::{generate_fingerprint, PinningConfig, PinningError, PinningMethod, PinningStore},
    storage::Storage,
    Client, ClientConfig,
};
use hybridcipher_crypto::account_protection::{
    decrypt_with_ad, encrypt_with_ad, ProtectedData, PROTECTED_DATA_MAGIC,
};
use hybridcipher_crypto::signatures::VerifyingKey;
use hybridcipher_messages::join_card::JoinCard as MessagesJoinCard;
use keyring::{Entry, Error as KeyringError};
use rand::{rngs::OsRng, Rng, RngCore};
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString, Zeroize};
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use uuid;
use zeroize::Zeroizing;

#[cfg(test)]
use hybridcipher_messages::transparency::TransparencyCheckpointEntry as ServerCheckpointEntry;
use hybridcipher_messages::transparency::{
    TransparencyCheckpoint as ServerCheckpointDocument, TransparencyConfig,
};

pub mod migration;
pub mod persistence;

/// Migration progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationProgress {
    pub phase: MigrationPhase,
    pub files_processed: u64,
    pub total_files: u64,
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub estimated_time_remaining: Option<u64>,
}

/// Server-provided summary of all devices registered for the active account.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisteredDeviceList {
    pub devices: Vec<RegisteredDevice>,
    pub total_devices: usize,
    pub max_devices: usize,
    pub remaining_slots: usize,
}

/// Metadata for an individual registered device.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisteredDevice {
    pub device_id: String,
    pub device_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub is_current_device: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine};
    use hybridcipher_crypto::signatures::SigningKey;
    use tempfile::TempDir;

    #[test]
    fn creates_isolated_user_contexts() {
        let temp_dir = TempDir::new().expect("temp dir");
        let manager = SessionManager::new(Some(temp_dir.path())).expect("session manager");

        manager
            .set_user_context("alice@example.com", "https://server-one")
            .expect("set alice context");
        let base_dir = manager
            .config_dir()
            .canonicalize()
            .expect("canonical base dir");
        let alice_dir = manager
            .user_config_dir()
            .expect("alice dir")
            .canonicalize()
            .expect("canonical alice dir");

        manager
            .set_user_context("bob@example.com", "https://server-two")
            .expect("set bob context");
        let bob_dir = manager
            .user_config_dir()
            .expect("bob dir")
            .canonicalize()
            .expect("canonical bob dir");

        assert_ne!(
            alice_dir, bob_dir,
            "each user should receive a unique config directory"
        );
        assert!(alice_dir.starts_with(&base_dir), "alice dir within base");
        assert!(bob_dir.starts_with(&base_dir), "bob dir within base");
    }

    #[test]
    fn reports_last_active_user_summary() {
        let temp_dir = TempDir::new().expect("temp dir");
        let manager = SessionManager::new(Some(temp_dir.path())).expect("session manager");

        assert!(
            manager.active_user_summary().is_none(),
            "no user expected initially"
        );

        manager
            .set_user_context("carol@example.com", "https://server-three")
            .expect("set carol context");

        let summary = manager
            .active_user_summary()
            .expect("summary should be available");
        assert_eq!(summary.username, "carol@example.com");
        assert_eq!(summary.server_url, "https://server-three");
        assert_eq!(
            summary.user_id.len(),
            16,
            "derived user id should match expected hash length"
        );
    }

    #[test]
    fn last_user_summary_persists_after_logout() {
        let temp_dir = TempDir::new().expect("temp dir");
        let manager = SessionManager::new(Some(temp_dir.path())).expect("session manager");

        let now = chrono::Utc::now();
        let session = Session {
            user_id: "user-123".to_string(),
            username: "dave@example.com".to_string(),
            device_id: "device-1".to_string(),
            device_status: None,
            server_url: "https://server-four".to_string(),
            token: "token".to_string(),
            refresh_token: String::new(),
            opaque_export_key: None,
            device_binding: String::new(),
            device_keypair: None,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            last_activity: now,
            migration_info: None,
            security_metadata: SessionSecurity {
                device_fingerprint: String::new(),
                integrity_hash: String::new(),
                version: 1,
                flags: SessionFlags {
                    device_verified: true,
                    migration_recovered: false,
                    auto_renewal: false,
                    enhanced_security: false,
                },
            },
        };

        manager
            .remember_last_user(&session)
            .expect("remember last user");
        manager.clear_user_context().expect("clear context");

        let summary = manager
            .active_user_summary()
            .expect("summary should be available after logout");
        assert_eq!(summary.username, session.username);
        assert_eq!(summary.server_url, session.server_url);
        assert_eq!(summary.user_id, session.user_id);
    }

    #[test]
    fn transparency_checkpoint_verification_persists_state() {
        let temp_dir = TempDir::new().expect("temp dir");
        let manager = SessionManager::new(Some(temp_dir.path())).expect("session manager");

        manager
            .set_user_context("eve@example.com", "https://example.test")
            .expect("set context");

        let mut prefs = TransparencyPreferences::default();
        prefs.enabled = true;
        manager
            .set_transparency_preferences(prefs)
            .expect("set prefs");

        let server_public_key_bytes = b"example-opaque-server-key-material";
        let server_public_key_b64 = general_purpose::STANDARD.encode(server_public_key_bytes);
        let fingerprint_bytes = Sha256::digest(server_public_key_bytes);
        let fingerprint_vec = fingerprint_bytes.to_vec();
        let fingerprint_hex = hex::encode_upper(&fingerprint_vec);
        let fingerprint_b64 = general_purpose::STANDARD.encode(&fingerprint_vec);
        let short_hex = fingerprint_hex.chars().take(16).collect::<String>();

        let entry = ServerCheckpointEntry {
            entry_type: "server_fingerprint".to_string(),
            sha256_hex: fingerprint_hex.clone(),
            sha256_base64: fingerprint_b64.clone(),
            short_hex: short_hex.clone(),
            public_key_base64: server_public_key_b64.clone(),
            server: None,
        };

        let signing_key_id = "transparency-log-dev-key";
        let root_hash = hex::encode_upper(Sha256::digest(b"checkpoint-root"));
        let log_url = Some("https://trust.example/checkpoints/latest.json".to_string());

        let generated_at = chrono::Utc::now().to_rfc3339();

        let mut checkpoint = ServerCheckpointDocument {
            version: 1,
            generated_at: generated_at.clone(),
            log_url: log_url.clone(),
            signing_key_id: Some(signing_key_id.to_string()),
            tree_size: 1,
            root_hash: root_hash.clone(),
            entries: vec![entry],
            signature: None,
        };

        let payload = CheckpointSigningPayload {
            version: checkpoint.version,
            generated_at: &checkpoint.generated_at,
            log_url: &checkpoint.log_url,
            signing_key_id: &checkpoint.signing_key_id,
            tree_size: checkpoint.tree_size,
            root_hash: &checkpoint.root_hash,
            entries: &checkpoint.entries,
        };

        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let signing_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let signing_key_bytes = hex::decode(signing_key_hex).expect("decode signing key");
        let signing_key =
            SigningKey::from_bytes(&signing_key_bytes).expect("construct signing key");
        let signature = signing_key.sign(&payload_bytes).expect("sign payload");
        let signature_b64 = general_purpose::STANDARD.encode(signature.as_bytes());
        checkpoint.signature = Some(signature_b64);

        let state = manager
            .verify_transparency_checkpoint(
                &checkpoint,
                signing_key_id,
                &server_public_key_b64,
                server_public_key_bytes,
                log_url.clone(),
                86_400,
            )
            .expect("checkpoint verifies");

        assert_eq!(state.root_hash_hex, root_hash);
        assert_eq!(state.tree_size, 1);
        assert_eq!(state.signing_key_id.as_deref(), Some(signing_key_id));

        manager
            .persist_transparency_state(&state)
            .expect("persist state");

        let cached = manager
            .load_transparency_state()
            .expect("load state")
            .expect("state exists");

        assert_eq!(cached.root_hash_hex, root_hash);
        assert_eq!(cached.signing_key_id.as_deref(), Some(signing_key_id));
        assert_eq!(cached.log_url, log_url);
        assert_eq!(cached.server_public_key_base64, server_public_key_b64);

        let summary = manager
            .transparency_cache_summary()
            .expect("summary query")
            .expect("summary populated");
        assert_eq!(summary.root_hash_hex, root_hash);
        assert_eq!(summary.tree_size, 1);
        assert_eq!(summary.signing_key_id.as_deref(), Some(signing_key_id));
    }
}

/// Group information for CLI display
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub role: String,
    pub current_epoch: Option<String>,
    pub member_count: usize,
    pub created_at: String,
}

/// Member information for CLI display
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub joined_at: String,
}

/// User-configurable transparency log preferences for verification flows.
#[derive(Debug, Clone)]
pub struct TransparencyPreferences {
    pub enabled: bool,
    pub require_transparency: bool,
    pub fallback_to_pinning: bool,
    pub log_url_override: Option<String>,
    pub verification_timeout_seconds: u64,
    pub max_checkpoint_age_seconds: u64,
}

impl Default for TransparencyPreferences {
    fn default() -> Self {
        Self {
            enabled: true,
            require_transparency: true,
            fallback_to_pinning: false,
            log_url_override: None,
            verification_timeout_seconds: 30,
            max_checkpoint_age_seconds: 86_400,
        }
    }
}

/// Cached state for the last successfully verified transparency checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransparencyVerificationState {
    log_url: Option<String>,
    signing_key_id: Option<String>,
    root_hash_hex: String,
    tree_size: u64,
    server_public_key_base64: String,
    checkpoint_fingerprint: String,
    checkpoint_generated_at: String,
    verified_at: String,
}

const TRANSPARENCY_STATE_FILE: &str = "transparency_state.json";

#[derive(Debug, Clone)]
struct TransparencyVerificationError {
    message: String,
}

impl TransparencyVerificationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TransparencyVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TransparencyVerificationError {}

/// Human-readable snapshot of a verified transparency checkpoint.
#[derive(Debug, Clone)]
pub struct TransparencyCacheSummary {
    pub log_url: Option<String>,
    pub signing_key_id: Option<String>,
    pub root_hash_hex: String,
    pub tree_size: u64,
    pub checkpoint_fingerprint: String,
    pub checkpoint_generated_at: String,
    pub verified_at: String,
}

impl From<TransparencyVerificationState> for TransparencyCacheSummary {
    fn from(state: TransparencyVerificationState) -> Self {
        Self {
            log_url: state.log_url,
            signing_key_id: state.signing_key_id,
            root_hash_hex: state.root_hash_hex,
            tree_size: state.tree_size,
            checkpoint_fingerprint: state.checkpoint_fingerprint,
            checkpoint_generated_at: state.checkpoint_generated_at,
            verified_at: state.verified_at,
        }
    }
}

#[derive(Default)]
struct CoverageConfigOverrides {
    batch_size: Option<usize>,
    parallel_uploads: Option<usize>,
    upload_min_interval_ms: Option<u64>,
    upload_backoff_base_ms: Option<u64>,
    upload_backoff_max_ms: Option<u64>,
    baseline_threshold: Option<usize>,
    compaction_min_entries: Option<u64>,
    compaction_idle_quiet_secs: Option<u64>,
    compaction_min_interval_secs: Option<u64>,
    compaction_max_interval_secs: Option<u64>,
    compaction_max_journal_bytes: Option<u64>,
    compaction_bulk_force_journal_bytes: Option<u64>,
    compaction_error_backoff_secs: Option<u64>,
    compaction_bulk_mode_enabled: Option<bool>,
}

/// Session management for CLI with secure persistence and migration state tracking
pub struct SessionManager {
    base_config_dir: PathBuf,
    global_dir: PathBuf,
    current_session: Arc<Mutex<Option<Session>>>,
    /// Tracks the active user context (config dir, storage, metadata)
    current_user_context: Arc<Mutex<Option<UserContext>>>,
    account_key: Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>,
    state_key: Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>,
    state_key_owner: Arc<Mutex<Option<String>>>,
    keystore_warning_emitted: Arc<Mutex<bool>>,
    transparency_prefs: Arc<Mutex<TransparencyPreferences>>,
    transparency_config: Arc<Mutex<TransparencyConfig>>,
}

/// Active user context holding per-user configuration paths and storage
#[derive(Clone)]
struct UserContext {
    username: String,
    server_url: String,
    user_id: String,
    config_dir: PathBuf,
    session_file: PathBuf,
    storage: Arc<hybridcipher_client::storage::LocalFsStorage>,
    account_metadata: Option<AccountProtectionMetadata>,
}

/// Represents the state of key pinning for a join card after consistency checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinCardPinState {
    /// The pin already exists and matches the join card identity key.
    AlreadyPinned,
    /// The pin was missing but successfully restored from the verified join card cache.
    RestoredFromCache,
    /// A pin exists but is not verified yet.
    Unverified { auto_pinned: bool },
    /// No pin exists and no cached verification was available to restore it.
    Missing,
    /// A pin exists but has expired based on the configured max age.
    Expired(DateTime<Utc>),
}

/// Result of ensuring a join card is published for the current device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinCardPublishState {
    /// Join card already exists on the server for this device.
    AlreadyPresent,
    /// Join card was published (or re-published) to the server.
    Published,
}

/// Result of ensuring the current device is pinned and verified locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentDevicePinState {
    /// The current device already has a verified pin.
    AlreadyVerified,
    /// An existing unverified pin was promoted to verified.
    PromotedUnverified,
    /// A new verified pin was created for the current device.
    PinnedVerified,
}

/// Unverified device report entry submitted by an admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnverifiedDeviceReport {
    pub user_id: uuid::Uuid,
    pub device_id: String,
    pub reasons: Vec<String>,
}

/// Unverified device record returned by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnverifiedDeviceInfo {
    pub user_id: uuid::Uuid,
    pub device_id: String,
    pub reasons: Vec<String>,
    pub reported_by: uuid::Uuid,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub first_seen_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub last_seen_at: DateTime<Utc>,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub resolved_by: Option<uuid::Uuid>,
    #[serde(default)]
    pub resolved_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolveUnverifiedResult {
    pub groups: Vec<uuid::Uuid>,
}

const USERS_DIR: &str = "users";
const GLOBAL_DIR_NAME: &str = "global";
const ACTIVE_USER_FILE: &str = "active_user.json";
const LAST_USER_FILE: &str = "last_user.json";
const ACCOUNT_PROTECTION_FILE: &str = "account_protection.json";
const ACCOUNT_KEY_CACHE_FILE: &str = ".account_key_cache";
const DEVICE_KEY_FILE: &str = "device_key.protected";
const KEYSTORE_SERVICE_NAME: &str = "hybridcipher";
const SESSION_FILE_AAD: &[u8] = b"hybridcipher/session";
const DEVICE_KEYPAIR_FILE_AAD: &[u8] = b"hybridcipher/device_keypair";
const INVITATION_KEYPAIR_FILE_AAD: &[u8] = b"hybridcipher/localfs/invitation_keypair";
const LEGACY_INVITATION_KEYPAIR_FILE_AAD: &[u8] = b"hybridcipher/invitation_keypair";
const JOIN_CARD_CACHE_FILE_AAD: &[u8] = b"hybridcipher/join_card_cache";
const DEVICE_KEY_FILE_AAD: &[u8] = b"hybridcipher/device_key_material";
const PINNING_CONFIG_KEY: &str = "pinning_config";
const USER_ID_CACHE_KEY: &str = "user_id_cache";
const GROUP_METADATA_CACHE_KEY: &str = "group_metadata_cache";
const GROUP_MEMBERS_CACHE_PREFIX: &str = "group_members_cache:";

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

fn compute_account_verifier(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"hybridcipher-account-verifier");
    hasher.update(key);
    general_purpose::STANDARD.encode(hasher.finalize())
}

fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveUserRecord {
    username: String,
    server_url: String,
    user_id: String,
}

/// Lightweight summary of the last active user, exposed for CLI status queries.
#[derive(Debug, Clone)]
pub struct ActiveUserSummary {
    pub username: String,
    pub server_url: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UserIdentityCache {
    #[serde(default)]
    by_email: HashMap<String, String>,
    #[serde(default)]
    by_user_id: HashMap<String, String>,
}

impl UserIdentityCache {
    fn insert(&mut self, email: &str, user_id: &str) -> bool {
        let email_key = normalize_email_key(email);
        let user_key = normalize_user_id_key(user_id);
        let email_value = email.trim().to_string();
        let user_value = user_id.trim().to_string();
        let mut changed = false;

        if self.by_email.get(&email_key) != Some(&user_value) {
            self.by_email.insert(email_key, user_value.clone());
            changed = true;
        }

        if self.by_user_id.get(&user_key) != Some(&email_value) {
            self.by_user_id.insert(user_key, email_value);
            changed = true;
        }

        changed
    }

    fn user_id_for_email(&self, email: &str) -> Option<String> {
        let key = normalize_email_key(email);
        self.by_email.get(&key).cloned()
    }

    fn email_for_user_id(&self, user_id: &str) -> Option<String> {
        let key = normalize_user_id_key(user_id);
        self.by_user_id.get(&key).cloned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GroupMetadataCache {
    #[serde(default)]
    by_id: HashMap<String, CachedGroupMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedGroupMetadata {
    name: String,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupMembersCacheEntry {
    cached_at: DateTime<Utc>,
    members: Vec<CachedMemberInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedMemberInfo {
    user_id: String,
    email: String,
    role: String,
    status: String,
    joined_at: String,
}

impl CachedMemberInfo {
    fn from_member(member: &MemberInfo) -> Self {
        Self {
            user_id: member.user_id.clone(),
            email: member.email.clone(),
            role: member.role.clone(),
            status: member.status.clone(),
            joined_at: member.joined_at.clone(),
        }
    }

    fn into_member(self) -> MemberInfo {
        MemberInfo {
            user_id: self.user_id,
            email: self.email,
            role: self.role,
            status: self.status,
            joined_at: self.joined_at,
        }
    }
}

impl GroupMetadataCache {
    fn insert(&mut self, group_id: &str, name: &str, role: Option<&str>) -> bool {
        let key = normalize_group_id_key(group_id);
        let name_value = name.trim().to_string();
        let role_value = role.map(|value| value.trim().to_string());
        let mut changed = false;

        match self.by_id.get(&key) {
            Some(existing)
                if existing.name == name_value
                    && existing.role.as_deref() == role_value.as_deref() => {}
            _ => {
                self.by_id.insert(
                    key,
                    CachedGroupMetadata {
                        name: name_value,
                        role: role_value,
                    },
                );
                changed = true;
            }
        }

        changed
    }

    fn name_for_id(&self, group_id: &str) -> Option<&str> {
        let key = normalize_group_id_key(group_id);
        self.by_id.get(&key).map(|entry| entry.name.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountProtectionMetadata {
    version: u32,
    kdf: String,
    salt: String,
    #[serde(default)]
    verifier: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CanonicalServerUrl {
    pub canonical: String,
    pub replaced_alias: Option<String>,
    pub upgraded_scheme: bool,
}

#[derive(Debug, Deserialize)]
struct ServerInfoResponse {
    public_keys: ServerInfoPublicKeys,
    #[serde(default)]
    transparency: Option<ServerTransparencyMetadata>,
    #[serde(default)]
    capabilities: Option<ServerInfoCapabilities>,
    #[serde(default)]
    recovery: Option<ServerRecoveryMetadata>,
}

#[derive(Debug, Deserialize)]
struct ServerInfoPublicKeys {
    opaque_login: ServerInfoOpaqueLogin,
    #[serde(default)]
    welcome_signing: Option<ServerInfoSigningKey>,
}

#[derive(Debug, Deserialize)]
struct ServerInfoOpaqueLogin {
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct ServerInfoSigningKey {
    public_key: String,
    #[serde(default)]
    key_id: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ServerInfoCapabilities {
    #[serde(default)]
    transparency_log: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct ServerRecoveryMetadata {
    #[serde(default)]
    recovery_public_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct ServerTransparencyMetadata {
    enabled: bool,
    log_url: Option<String>,
    signing_key_id: Option<String>,
    latest_checkpoint: Option<Box<RawValue>>,
}

#[derive(Debug, Clone)]
struct ServerTransparencyInfo {
    enabled: bool,
    log_url: Option<String>,
    signing_key_id: Option<String>,
    latest_checkpoint: Option<ServerCheckpointDocument>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ServerTransparencySummary {
    pub enabled: bool,
    pub log_url: Option<String>,
    pub signing_key_id: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Serialize)]
struct CheckpointSigningPayload<'a> {
    version: u32,
    generated_at: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_url: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_key_id: &'a Option<String>,
    tree_size: u64,
    root_hash: &'a str,
    entries: &'a [ServerCheckpointEntry],
}

#[derive(Debug)]
struct FetchedServerInfo {
    public_key_b64: String,
    public_key_bytes: Vec<u8>,
    welcome_signing: Option<FetchedSigningKey>,
    transparency: ServerTransparencyInfo,
    recovery: Option<FetchedRecoveryUnlockConfig>,
}

#[derive(Debug)]
struct FetchedSigningKey {
    public_key_b64: String,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FetchedRecoveryUnlockConfig {
    pub public_key_b64: String,
    pub validity_hours: u64,
}

#[derive(Debug, Deserialize, Default)]
struct BundledUnlockKeys {
    #[serde(default)]
    recovery_public_keys: Vec<String>,
}

const BUNDLED_SOS_UNLOCK_KEYS_JSON: &str = include_str!("../security/sos_decrypt_unlock_keys.json");

pub(crate) fn canonicalize_server_url(server_url: &str) -> CanonicalServerUrl {
    let trimmed = server_url.trim();

    if trimmed.is_empty() {
        return CanonicalServerUrl {
            canonical: CANONICAL_PRODUCTION_SERVER.to_string(),
            replaced_alias: None,
            upgraded_scheme: false,
        };
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

            return CanonicalServerUrl {
                canonical,
                replaced_alias: Some(alias.to_string()),
                upgraded_scheme: alias.starts_with("http://"),
            };
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

            return CanonicalServerUrl {
                canonical,
                replaced_alias: Some(alias.to_string()),
                upgraded_scheme: true,
            };
        }
    }

    CanonicalServerUrl {
        canonical: trimmed.to_string(),
        replaced_alias: None,
        upgraded_scheme: false,
    }
}

fn get_user_storage_id(username: &str, server_url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(username.to_lowercase().as_bytes());
    hasher.update(server_url.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn normalize_email_key(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn normalize_user_id_key(user_id: &str) -> String {
    user_id.trim().to_ascii_lowercase()
}

fn normalize_group_id_key(group_id: &str) -> String {
    group_id.trim().to_ascii_lowercase()
}

fn group_members_cache_key(group_id: &str) -> String {
    format!(
        "{}{}",
        GROUP_MEMBERS_CACHE_PREFIX,
        normalize_group_id_key(group_id)
    )
}

fn format_group_label(name: &str, group_id: &uuid::Uuid) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return group_id.to_string();
    }
    format!("{} ({})", trimmed, group_id)
}

fn ensure_clean_multi_user_structure(base_dir: &Path) -> Result<(), CliError> {
    if base_dir.exists() && !base_dir.join(USERS_DIR).exists() {
        println!("Converting to secure multi-user configuration...");
        println!("Note: All existing legacy data will be cleared for security.");

        std::fs::remove_dir_all(base_dir).map_err(|e| {
            CliError::configuration(format!("Failed to clear legacy config: {}", e))
        })?;

        println!("Legacy configuration cleared. Please re-register users.");
    }

    std::fs::create_dir_all(base_dir.join(USERS_DIR))
        .map_err(|e| CliError::configuration(format!("Failed to create user directory: {}", e)))?;
    std::fs::create_dir_all(base_dir.join(GLOBAL_DIR_NAME)).map_err(|e| {
        CliError::configuration(format!("Failed to create global directory: {}", e))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(base_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| CliError::configuration(format!("Failed to secure base config directory: {}", e)),
        )?;
        std::fs::set_permissions(
            base_dir.join(USERS_DIR),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(|e| CliError::configuration(format!("Failed to secure users directory: {}", e)))?;
        std::fs::set_permissions(
            base_dir.join(GLOBAL_DIR_NAME),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(|e| {
            CliError::configuration(format!("Failed to secure global directory: {}", e))
        })?;
    }

    Ok(())
}

impl SessionManager {
    fn account_metadata_path(&self, user_dir: &Path) -> PathBuf {
        user_dir.join(ACCOUNT_PROTECTION_FILE)
    }

    fn load_account_metadata_from_dir(
        &self,
        user_dir: &Path,
    ) -> Result<Option<AccountProtectionMetadata>, CliError> {
        let metadata_path = self.account_metadata_path(user_dir);
        if !metadata_path.exists() {
            return Ok(None);
        }

        let raw = std::fs::read_to_string(&metadata_path).map_err(|e| {
            CliError::session(format!("Failed to read account protection metadata: {}", e))
        })?;

        let metadata = serde_json::from_str::<AccountProtectionMetadata>(&raw).map_err(|e| {
            CliError::format(format!("Invalid account protection metadata format: {}", e))
        })?;

        Ok(Some(metadata))
    }

    fn persist_account_metadata(
        &self,
        user_dir: &Path,
        metadata: &AccountProtectionMetadata,
    ) -> Result<(), CliError> {
        let metadata_path = self.account_metadata_path(user_dir);
        let serialized = serde_json::to_string_pretty(metadata).map_err(|e| {
            CliError::format(format!(
                "Failed to serialize account protection metadata: {}",
                e
            ))
        })?;

        std::fs::write(&metadata_path, serialized).map_err(|e| {
            CliError::session(format!(
                "Failed to persist account protection metadata: {}",
                e
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&metadata_path)
                .map_err(|e| {
                    CliError::session(format!(
                        "Failed to inspect protection metadata permissions: {}",
                        e
                    ))
                })?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&metadata_path, perms).map_err(|e| {
                CliError::session(format!(
                    "Failed to harden protection metadata permissions: {}",
                    e
                ))
            })?;
        }

        Ok(())
    }

    fn account_key_locked(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.account_key.lock().ok().and_then(|guard| guard.clone())
    }

    fn set_account_key(&self, key: Zeroizing<[u8; 32]>) {
        if let Ok(mut guard) = self.account_key.lock() {
            *guard = Some(key);
        }
    }

    fn drop_account_key_memory(&self) {
        if let Ok(mut guard) = self.account_key.lock() {
            *guard = None;
        }
    }

    fn state_key_locked(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.state_key.lock().ok().and_then(|guard| guard.clone())
    }

    fn set_state_key(&self, key: Zeroizing<[u8; 32]>) {
        if let Ok(mut guard) = self.state_key.lock() {
            *guard = Some(key);
        }
        if let Ok(mut owner_guard) = self.state_key_owner.lock() {
            *owner_guard = self.current_user_context().map(|ctx| ctx.user_id.clone());
        }
    }

    fn drop_state_key_memory(&self) {
        if let Ok(mut guard) = self.state_key.lock() {
            *guard = None;
        }
        if let Ok(mut owner_guard) = self.state_key_owner.lock() {
            *owner_guard = None;
        }
    }

    fn clear_account_key(&self) {
        if let Some(context) = self.current_user_context() {
            let _ = self.clear_account_key_cache_path(&context.config_dir);
            context.storage.clear_account_encryption();
        }

        self.drop_account_key_memory();
        self.drop_state_key_memory();
    }

    fn create_account_metadata(&self) -> AccountProtectionMetadata {
        let mut salt_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);

        AccountProtectionMetadata {
            version: 1,
            kdf: "argon2id".to_string(),
            salt: general_purpose::STANDARD.encode(salt_bytes),
            verifier: String::new(),
        }
    }

    fn derive_account_key(
        &self,
        metadata: &AccountProtectionMetadata,
        password: &str,
    ) -> Result<Zeroizing<[u8; 32]>, CliError> {
        if metadata.kdf.to_lowercase() != "argon2id" {
            return Err(CliError::encryption(format!(
                "Unsupported key derivation algorithm '{}'",
                metadata.kdf
            )));
        }

        let salt_bytes = general_purpose::STANDARD
            .decode(&metadata.salt)
            .map_err(|e| CliError::encryption(format!("Invalid protection salt: {}", e)))?;

        let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| {
            CliError::encryption(format!("Failed to configure Argon2 parameters: {}", e))
        })?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password.as_bytes(), &salt_bytes, key.as_mut())
            .map_err(|e| CliError::encryption(format!("Failed to derive account key: {}", e)))?;

        Ok(key)
    }

    fn device_key_path(&self, user_dir: &Path) -> PathBuf {
        user_dir.join(DEVICE_KEY_FILE)
    }

    fn require_keystore(&self) -> bool {
        std::env::var("HYBRIDCIPHER_REQUIRE_KEYSTORE")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    }

    fn debug_keystore(&self) -> bool {
        std::env::var("HYBRIDCIPHER_DEBUG_KEYSTORE")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    }

    fn warn_keystore_downgrade(&self, message: &str) {
        if let Ok(mut guard) = self.keystore_warning_emitted.lock() {
            if *guard {
                return;
            }
            *guard = true;
        }
        ui::warning(message);
    }

    fn load_device_key_from_keystore(&self, user_id: &str) -> Result<Option<[u8; 32]>, CliError> {
        // On Linux, Entry::new() returns NoEntry when the entry doesn't exist yet.
        // This is expected during first registration/login, so treat it as "not cached".
        let entry = match Entry::new(KEYSTORE_SERVICE_NAME, user_id) {
            Ok(e) => e,
            Err(KeyringError::NoEntry) => {
                // Entry doesn't exist yet - not an error, just not cached
                if self.debug_keystore() {
                    ui::info(&format!(
                        "OS keystore: no cached device key for {} (will be created on first store)",
                        user_id
                    ));
                }
                return Ok(None);
            }
            Err(e) => {
                return Err(CliError::session(format!(
                    "Failed to access OS keystore for {}: {}",
                    user_id, e
                )));
            }
        };

        match entry.get_password() {
            Ok(value) => {
                let decoded = general_purpose::STANDARD
                    .decode(value.trim())
                    .map_err(|e| {
                        CliError::session(format!(
                            "Failed to decode device key from keystore: {}",
                            e
                        ))
                    })?;
                if decoded.len() != 32 {
                    return Ok(None);
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                if self.debug_keystore() {
                    ui::info(&format!(
                        "OS keystore: loaded device key (service={}, account={})",
                        KEYSTORE_SERVICE_NAME, user_id
                    ));
                }
                Ok(Some(key))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(CliError::session(format!(
                "Unable to read device key from keystore: {}",
                e
            ))),
        }
    }

    fn store_device_key_in_keystore(
        &self,
        user_id: &str,
        key: &[u8; 32],
    ) -> Result<bool, CliError> {
        // On Linux with the keyring crate, Entry::new() may return NoEntry
        // if the entry doesn't exist yet. Since this is a store operation
        // and we can't create entries on Linux before first write, treat this
        // as "keystore unavailable for now" and fall back to file storage.
        let entry = match Entry::new(KEYSTORE_SERVICE_NAME, user_id) {
            Ok(e) => e,
            Err(KeyringError::NoEntry) => {
                // Entry doesn't exist yet - on Linux this means we can't use keystore yet
                if self.debug_keystore() {
                    ui::info(&format!(
                        "OS keystore: entry for {} doesn't exist yet, skipping (will be available after manual creation)",
                        user_id
                    ));
                }
                if self.require_keystore() {
                    return Err(CliError::session(
                        "OS keystore is required but entry doesn't exist yet".to_string(),
                    ));
                }
                return Ok(false); // Keystore not available, use fallback
            }
            Err(e) => {
                if self.require_keystore() {
                    return Err(CliError::session(format!(
                        "OS keystore is required but unavailable: {}",
                        e
                    )));
                }
                self.warn_keystore_downgrade(&format!("OS keystore unavailable: {}", e));
                return Ok(false); // Keystore not available, use fallback
            }
        };

        let encoded = general_purpose::STANDARD.encode(key);
        match entry.set_password(&encoded) {
            Ok(_) => {
                // Verify the write by reading it back; if this fails, treat as keystore unavailable.
                match entry.get_password() {
                    Ok(read_back) => {
                        if read_back.trim() != encoded {
                            let msg = "OS keystore did not persist the device key correctly";
                            if self.require_keystore() {
                                return Err(CliError::session(msg.to_string()));
                            }
                            self.warn_keystore_downgrade(msg);
                            return Ok(false);
                        }
                    }
                    Err(err) => {
                        let msg = format!("OS keystore write verification failed: {}", err);
                        if self.require_keystore() {
                            return Err(CliError::session(msg));
                        }
                        self.warn_keystore_downgrade(&msg);
                        return Ok(false);
                    }
                }

                if self.require_keystore() || self.debug_keystore() {
                    ui::info(&format!(
                        "OS keystore: stored device key (service={}, account={})",
                        KEYSTORE_SERVICE_NAME, user_id
                    ));
                }
                Ok(true)
            }
            Err(e) => {
                if self.require_keystore() {
                    return Err(CliError::session(format!(
                        "OS keystore is required but unavailable: {}",
                        e
                    )));
                }
                self.warn_keystore_downgrade(&format!(
                    "OS keystore is unavailable; falling back to password-wrapped device key only ({})",
                    e
                ));
                Ok(false)
            }
        }
    }

    fn persist_device_key_fallback(
        &self,
        user_dir: &Path,
        account_key: &[u8; 32],
        device_key: &[u8; 32],
    ) -> Result<(), CliError> {
        let protected =
            encrypt_with_ad(device_key, *account_key, DEVICE_KEY_FILE_AAD).map_err(|e| {
                CliError::encryption(format!("Failed to encrypt device key fallback: {}", e))
            })?;
        let serialized = serde_json::to_string_pretty(&protected).map_err(|e| {
            CliError::format(format!("Failed to serialize device key fallback: {}", e))
        })?;
        let path = self.device_key_path(user_dir);
        std::fs::write(&path, serialized).map_err(|e| {
            CliError::session(format!("Failed to persist device key fallback: {}", e))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)
                .map_err(|e| CliError::session(format!("Failed to inspect permissions: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).map_err(|e| {
                CliError::session(format!("Failed to set device key permissions: {}", e))
            })?;
        }

        Ok(())
    }

    fn load_device_key_from_fallback(
        &self,
        user_dir: &Path,
        account_key: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, CliError> {
        let path = self.device_key_path(user_dir);
        if !path.exists() {
            return Ok(None);
        }

        let raw = std::fs::read_to_string(&path)
            .map_err(|e| CliError::session(format!("Failed to read device key fallback: {}", e)))?;
        let protected: ProtectedData = serde_json::from_str(&raw)
            .map_err(|e| CliError::format(format!("Invalid device key fallback format: {}", e)))?;

        let key = decrypt_with_ad(&protected, *account_key, DEVICE_KEY_FILE_AAD).map_err(|e| {
            CliError::decryption(format!("Failed to decrypt device key fallback: {}", e))
        })?;

        if key.len() != 32 {
            return Ok(None);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
        Ok(Some(key_bytes))
    }

    fn keystore_has_device_key(&self, user_id: &str) -> Result<bool, CliError> {
        // On Linux, Entry::new() returns NoEntry when the entry doesn't exist yet.
        let entry = match Entry::new(KEYSTORE_SERVICE_NAME, user_id) {
            Ok(e) => e,
            Err(KeyringError::NoEntry) => return Ok(false), // Entry doesn't exist = no key
            Err(e) => {
                return Err(CliError::session(format!(
                    "Failed to access OS keystore for {}: {}",
                    user_id, e
                )));
            }
        };

        match entry.get_password() {
            Ok(_) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(e) => Err(CliError::session(format!(
                "Unable to check device key in keystore: {}",
                e
            ))),
        }
    }

    /// Check whether the active user's device key exists in the OS keystore.
    pub fn has_keystore_device_key(&self) -> Result<bool, CliError> {
        let context = self
            .current_user_context()
            .ok_or_else(|| CliError::session("No active user context configured"))?;
        self.keystore_has_device_key(&context.user_id)
    }

    /// Check whether the device key for the provided account/server is stored in the OS keystore.
    pub fn keystore_status_for(&self, email: &str, server_url: &str) -> Result<bool, CliError> {
        let canonical = canonicalize_server_url(server_url);
        let user_id = get_user_storage_id(email, &canonical.canonical);
        self.keystore_has_device_key(&user_id)
    }

    /// Remove protected files that won't be decryptable after device key regeneration.
    /// This is called when the device key fallback cannot be decrypted (e.g., after password
    /// reset without keystore backup) and we're forced to generate a new device key.
    fn cleanup_stale_protected_files(&self, user_dir: &Path) {
        let stale_files = [
            "device_keypair",
            "invitation_keypair.json",
            "session.toml",
            "client_state.json",
            "group_id.json",
            "transparency_state.json",
        ];

        for filename in &stale_files {
            let path = user_dir.join(filename);
            if path.exists() {
                if let Err(e) = std::fs::remove_file(&path) {
                    ui::dim(&format!("Could not remove stale file {}: {}", filename, e));
                } else {
                    ui::dim(&format!("Removed stale encrypted file: {}", filename));
                }
            }
        }

        // Also clean up join_cards directory if present
        let join_cards_dir = user_dir.join("join_cards");
        if join_cards_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&join_cards_dir) {
                ui::dim(&format!("Could not remove join_cards directory: {}", e));
            } else {
                ui::dim("Removed stale join_cards directory");
            }
        }
    }

    fn prompt_for_account_password(&self, username: &str) -> Result<String, CliError> {
        ui::prompts::password(&format!("Enter password to unlock account {}", username))
    }

    fn account_key_cache_path(&self, user_dir: &Path) -> PathBuf {
        user_dir.join(ACCOUNT_KEY_CACHE_FILE)
    }

    fn cache_account_key(&self, user_dir: &Path, key_bytes: &[u8; 32]) -> Result<(), CliError> {
        let cache_path = self.account_key_cache_path(user_dir);
        let encoded = general_purpose::STANDARD.encode(key_bytes);
        std::fs::write(&cache_path, encoded)
            .map_err(|e| CliError::session(format!("Failed to cache account key: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&cache_path)
                .map_err(|e| CliError::session(format!("Failed to inspect cache file: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&cache_path, perms)
                .map_err(|e| CliError::session(format!("Failed to secure cache file: {}", e)))?;
        }

        Ok(())
    }

    fn load_cached_account_key(&self, user_dir: &Path) -> Result<Option<[u8; 32]>, CliError> {
        let cache_path = self.account_key_cache_path(user_dir);
        if !cache_path.exists() {
            return Ok(None);
        }

        let encoded = std::fs::read_to_string(&cache_path)
            .map_err(|e| CliError::session(format!("Failed to read account key cache: {}", e)))?;

        match general_purpose::STANDARD.decode(encoded.trim()) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Some(key))
            }
            Ok(_) | Err(_) => {
                let _ = std::fs::remove_file(&cache_path);
                Ok(None)
            }
        }
    }

    fn clear_account_key_cache_path(&self, user_dir: &Path) -> Result<(), CliError> {
        let cache_path = self.account_key_cache_path(user_dir);
        if cache_path.exists() {
            std::fs::remove_file(&cache_path).map_err(|e| {
                CliError::session(format!("Failed to remove account key cache: {}", e))
            })?;
        }
        Ok(())
    }

    fn update_context_metadata(&self, metadata: AccountProtectionMetadata) -> Result<(), CliError> {
        let mut guard = self
            .current_user_context
            .lock()
            .map_err(|_| CliError::session("Failed to lock user context"))?;
        if let Some(context) = guard.as_mut() {
            context.account_metadata = Some(metadata);
        }
        Ok(())
    }

    pub fn ensure_account_key_initialized(&self) -> Result<Zeroizing<[u8; 32]>, CliError> {
        if let Some(existing) = self.account_key_locked() {
            return Ok(existing);
        }

        let context = self
            .current_user_context()
            .ok_or_else(|| CliError::session("No active user context configured"))?;

        let mut metadata = context
            .account_metadata
            .clone()
            .unwrap_or_else(|| self.create_account_metadata());

        let username = context.username.clone();
        let config_dir = context.config_dir.clone();

        if let Some(cached_key) = self.load_cached_account_key(&config_dir)? {
            let key = Zeroizing::new(cached_key);
            self.set_account_key(key.clone());
            return Ok(key);
        }

        drop(context);

        let key = loop {
            let password = self.prompt_for_account_password(&username)?;
            let key = self.derive_account_key(&metadata, &password);
            match key {
                Ok(derived) => {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(derived.as_ref());

                    if metadata.verifier.is_empty() {
                        metadata.verifier = compute_account_verifier(&key_bytes);
                        self.persist_account_metadata(&config_dir, &metadata)?;
                        self.update_context_metadata(metadata.clone())?;
                        self.cache_account_key(&config_dir, &key_bytes)?;
                        break derived;
                    }

                    let expected = compute_account_verifier(&key_bytes);
                    if constant_time_equal(expected.as_bytes(), metadata.verifier.as_bytes()) {
                        self.cache_account_key(&config_dir, &key_bytes)?;
                        break derived;
                    }

                    ui::warning("⚠️  Password did not match encrypted account data");
                }
                Err(err) => {
                    ui::warning(&format!("⚠️  {}", err));
                }
            }
        };

        self.set_account_key(key.clone());
        Ok(key)
    }

    /// Return the OPAQUE export key derived during login/registration.
    pub async fn opaque_export_key(&self) -> Result<Zeroizing<[u8; 64]>, CliError> {
        let session = self.require_auth_with_server_check().await?;
        let b64 = session
            .opaque_export_key
            .as_ref()
            .ok_or_else(|| {
                CliError::authentication(
                    "OPAQUE export key is unavailable; log out and log back in to refresh session."
                        .to_string(),
                )
            })?
            .trim()
            .to_string();

        let bytes = general_purpose::STANDARD.decode(&b64).map_err(|e| {
            CliError::format(format!("OPAQUE export key is malformed base64: {}", e))
        })?;

        if bytes.len() != 64 {
            return Err(CliError::format(
                "OPAQUE export key has unexpected length; log in again to refresh it.".to_string(),
            ));
        }

        let mut key = [0u8; 64];
        key.copy_from_slice(&bytes);
        Ok(Zeroizing::new(key))
    }

    fn ensure_state_key_internal(
        &self,
        allow_generate: bool,
    ) -> Result<Zeroizing<[u8; 32]>, CliError> {
        if let Some(existing) = self.state_key_locked() {
            return Ok(existing);
        }

        let context = self
            .current_user_context()
            .ok_or_else(|| CliError::session("No active user context configured"))?;

        let user_dir = context.config_dir.clone();
        let user_id = context.user_id.clone();
        let storage = Arc::clone(&context.storage);

        // Avoid reusing a state key from a different user context.
        if let Ok(owner_guard) = self.state_key_owner.lock() {
            if let Some(owner) = owner_guard.as_ref() {
                if owner != &user_id {
                    self.drop_state_key_memory();
                }
            }
        }

        // 1) OS keystore (does not require password)
        if let Some(key_bytes) = self.load_device_key_from_keystore(&user_id)? {
            storage.enable_account_encryption(key_bytes);
            let key = Zeroizing::new(key_bytes);
            self.set_state_key(key.clone());
            return Ok(key);
        }

        // 2) Fallback wrapped by the account key (requires password)
        let account_key = self.ensure_account_key_initialized()?;
        let mut account_key_bytes = [0u8; 32];
        account_key_bytes.copy_from_slice(account_key.as_ref());

        match self.load_device_key_from_fallback(&user_dir, &account_key_bytes) {
            Ok(Some(key_bytes)) => {
                storage.enable_account_encryption(key_bytes);
                // Repopulate keystore best-effort
                let _ = self.store_device_key_in_keystore(&user_id, &key_bytes)?;
                let key = Zeroizing::new(key_bytes);
                self.set_state_key(key.clone());
                return Ok(key);
            }
            Ok(None) => { /* continue */ }
            Err(e) => {
                if allow_generate {
                    ui::warning(&format!(
                        "Device key fallback could not be decrypted ({e}); generating a new device key. Local state previously encrypted with the old key may be inaccessible."
                    ));
                    let _ = std::fs::remove_file(self.device_key_path(&user_dir));
                    // Clean up other protected files that won't be decryptable with the new key
                    self.cleanup_stale_protected_files(&user_dir);
                } else {
                    return Err(e);
                }
            }
        }

        if !allow_generate {
            return Err(CliError::decryption(
                "Device key is unavailable (missing keystore entry and fallback). \
                 Cannot decrypt local state; ensure this device has a keystore entry or re-login with a valid fallback."
                    .to_string(),
            ));
        }

        // 3) Generate a new device key and store it (used during fresh login/registration).
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        self.persist_device_key_fallback(&user_dir, &account_key_bytes, &key_bytes)?;
        let _ = self.store_device_key_in_keystore(&user_id, &key_bytes)?;
        storage.enable_account_encryption(key_bytes);
        let key = Zeroizing::new(key_bytes);
        self.set_state_key(key.clone());
        Ok(key)
    }

    fn ensure_state_key_initialized(&self) -> Result<Zeroizing<[u8; 32]>, CliError> {
        self.ensure_state_key_internal(true)
    }

    pub fn enforce_password_reset_prerequisites(
        &self,
        email: &str,
        server_url: &str,
    ) -> Result<(), CliError> {
        let user_id = get_user_storage_id(email, server_url);
        if self.keystore_has_device_key(&user_id)? {
            return Ok(());
        }

        ui::warning(
            "Password reset will continue without a keystore-backed device secret; this device may lose access to encrypted state.",
        );
        if !ui::prompts::confirm_with_default(
            "Proceed and accept potential data loss on this device?",
            false,
        )? {
            return Err(CliError::authentication(
                "Password reset aborted to avoid local data loss".to_string(),
            ));
        }
        Ok(())
    }

    pub fn rewrap_device_key_after_password_rotation(
        &self,
        email: &str,
        server_url: &str,
        new_password: &str,
    ) -> Result<(), CliError> {
        let user_id = get_user_storage_id(email, server_url);
        let user_dir = self.base_config_dir.join(USERS_DIR).join(&user_id);
        if !user_dir.exists() {
            return Ok(());
        }

        let device_key = match self.load_device_key_from_keystore(&user_id)? {
            Some(key) => key,
            None => {
                return Err(CliError::session(
                    "Device key is unavailable locally; cannot rewrap after password reset.",
                ))
            }
        };

        // Refresh account protection metadata with the new password so the fallback copy can be used.
        let metadata_path = user_dir.join(ACCOUNT_PROTECTION_FILE);
        let mut metadata = if metadata_path.exists() {
            let raw = std::fs::read_to_string(&metadata_path).map_err(|e| {
                CliError::session(format!(
                    "Failed to read account protection metadata for reset: {}",
                    e
                ))
            })?;
            serde_json::from_str(&raw).unwrap_or_else(|_| self.create_account_metadata())
        } else {
            self.create_account_metadata()
        };

        let mut salt_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);
        metadata.salt = general_purpose::STANDARD.encode(salt_bytes);
        metadata.verifier.clear();

        let derived = self.derive_account_key(&metadata, new_password)?;
        let mut derived_bytes = [0u8; 32];
        derived_bytes.copy_from_slice(derived.as_ref());
        metadata.verifier = compute_account_verifier(&derived_bytes);
        self.persist_account_metadata(&user_dir, &metadata)?;
        self.cache_account_key(&user_dir, &derived_bytes)?;
        self.persist_device_key_fallback(&user_dir, &derived_bytes, &device_key)?;

        Ok(())
    }

    pub fn initialize_account_protection(&self, password: &str) -> Result<(), CliError> {
        let context = self
            .current_user_context()
            .ok_or_else(|| CliError::session("No active user context configured"))?;

        let mut metadata = context
            .account_metadata
            .clone()
            .unwrap_or_else(|| self.create_account_metadata());

        let needs_verifier = metadata.verifier.is_empty();

        let key = self.derive_account_key(&metadata, password)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(key.as_ref());

        if needs_verifier {
            metadata.verifier = compute_account_verifier(&key_bytes);
            self.persist_account_metadata(&context.config_dir, &metadata)?;
            self.update_context_metadata(metadata.clone())?;
        }

        self.cache_account_key(&context.config_dir, &key_bytes)?;
        self.set_account_key(key);
        // Ensure the device/state key is initialized and bound to storage encryption.
        let _ = self.ensure_state_key_initialized()?;
        Ok(())
    }

    /// Verify the provided password matches the active account protection verifier.
    pub fn verify_account_password(&self, password: &SecretString) -> Result<(), CliError> {
        let context = self
            .current_user_context()
            .ok_or_else(|| CliError::session("No active user context configured"))?;

        let metadata = context.account_metadata.clone().ok_or_else(|| {
            CliError::authentication(
                "Account protection metadata is unavailable; please log out and log back in to refresh local state."
                    .to_string(),
            )
        })?;

        if metadata.verifier.is_empty() {
            return Err(CliError::authentication(
                "Account protection verifier missing; log out and log back in before changing your password."
                    .to_string(),
            ));
        }

        let derived = self.derive_account_key(&metadata, password.expose_secret())?;
        let mut derived_bytes = [0u8; 32];
        derived_bytes.copy_from_slice(derived.as_ref());

        let expected = compute_account_verifier(&derived_bytes);
        derived_bytes.zeroize();

        if !constant_time_equal(expected.as_bytes(), metadata.verifier.as_bytes()) {
            return Err(CliError::authentication(
                "Current password is incorrect".to_string(),
            ));
        }

        Ok(())
    }

    fn read_protected_file(
        &self,
        path: &Path,
        aad: &[u8],
    ) -> Result<Option<(String, bool)>, CliError> {
        if !path.exists() {
            return Ok(None);
        }

        let raw = std::fs::read_to_string(path)
            .map_err(|e| CliError::session(format!("Failed to read protected file: {}", e)))?;

        match serde_json::from_str::<ProtectedData>(&raw) {
            Ok(protected) if protected.magic == PROTECTED_DATA_MAGIC => {
                // Prefer the state/device key; fall back to the account key for legacy data and migrate.
                let state_key = self.ensure_state_key_initialized()?;
                let mut state_key_bytes = [0u8; 32];
                state_key_bytes.copy_from_slice(state_key.as_ref());

                let decrypted = decrypt_with_ad(&protected, state_key_bytes, aad).or_else(|_| {
                    let account_key = self.ensure_account_key_initialized()?;
                    let mut account_key_bytes = [0u8; 32];
                    account_key_bytes.copy_from_slice(account_key.as_ref());
                    decrypt_with_ad(&protected, account_key_bytes, aad).map_err(|e| {
                        CliError::decryption(format!(
                            "Failed to decrypt protected file: {}. \
                             Login failed, username or password may be incorrect, please try again.",
                            e
                        ))
                    })
                })?;
                let value = String::from_utf8(decrypted).map_err(|e| {
                    CliError::format(format!("Protected file is not valid UTF-8: {}", e))
                })?;

                // If the file was encrypted with the account key, rewrap with the state key.
                if let Err(err) = decrypt_with_ad(&protected, state_key_bytes, aad) {
                    let _ = err;
                    let _ = self.write_protected_file(path, &value, aad);
                }
                Ok(Some((value, true)))
            }
            _ => Ok(Some((raw, false))),
        }
    }

    fn write_protected_file(&self, path: &Path, data: &str, aad: &[u8]) -> Result<(), CliError> {
        let key = self.ensure_state_key_initialized()?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(key.as_ref());

        let protected = encrypt_with_ad(data.as_bytes(), key_bytes, aad).map_err(|e| {
            CliError::encryption(format!("Failed to encrypt protected file: {}", e))
        })?;

        let serialized = serde_json::to_string_pretty(&protected)
            .map_err(|e| CliError::format(format!("Failed to serialize protected file: {}", e)))?;

        std::fs::write(path, serialized)
            .map_err(|e| CliError::session(format!("Failed to persist protected file: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)
                .map_err(|e| CliError::session(format!("Failed to inspect permissions: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(|e| {
                CliError::session(format!("Failed to set protected file permissions: {}", e))
            })?;
        }

        Ok(())
    }
}

/// User session with authentication state and migration tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// User identifier
    pub user_id: String,
    /// Username for legacy compatibility
    pub username: String,
    /// Device identifier  
    pub device_id: String,
    /// Current device provisioning status as reported by the server
    #[serde(default)]
    pub device_status: Option<String>,
    /// Server URL
    pub server_url: String,
    /// Session token for authentication (encrypted)
    pub token: String,
    /// Refresh token issued by the server
    #[serde(default)]
    pub refresh_token: String,
    /// OPAQUE export key (base64) for password-derived wrapping (e.g., coverage registry)
    #[serde(default)]
    pub opaque_export_key: Option<String>,
    /// Device binding token for tamper detection
    pub device_binding: String,
    /// Device keypair for encryption/decryption (base64 encoded private key)
    pub device_keypair: Option<String>,
    /// Session creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Session expiration timestamp
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Last activity timestamp for automatic renewal
    pub last_activity: chrono::DateTime<chrono::Utc>,
    /// Current migration state
    pub migration_info: Option<MigrationInfo>,
    /// Session security metadata
    pub security_metadata: SessionSecurity,
}

/// Session security metadata for tamper detection and audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSecurity {
    /// Device fingerprint for binding verification
    pub device_fingerprint: String,
    /// Session integrity hash
    pub integrity_hash: String,
    /// Session version for compatibility
    pub version: u32,
    /// Security flags
    pub flags: SessionFlags,
}

/// Session security flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFlags {
    /// Whether device verification was completed
    pub device_verified: bool,
    /// Whether migration recovery was performed
    pub migration_recovered: bool,
    /// Whether session renewal is enabled
    pub auto_renewal: bool,
    /// Whether enhanced security mode is active
    pub enhanced_security: bool,
}

struct DeviceLoginContext {
    device_id: String,
    device_metadata: DeviceLoginMetadata,
    identity_keypair: hybridcipher_crypto::signatures::Ed25519KeyPair,
}

/// Migration state information for persistence across CLI sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationInfo {
    /// Current epoch ID
    pub current_epoch: u64,
    /// Target epoch ID (if migration in progress)
    pub target_epoch: Option<u64>,
    /// Migration start time
    pub migration_start: Option<chrono::DateTime<chrono::Utc>>,
    /// Migration phase
    pub phase: MigrationPhase,
    /// Files pending migration
    pub pending_files: Vec<String>,
    /// Migration progress percentage
    pub progress: f64,
    /// Total files to migrate (captured at rekey start)
    #[serde(default)]
    pub total_files: u64,
}

/// Migration phases for tracking progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationPhase {
    /// No migration in progress
    Idle,
    /// Migration has been initiated
    Started,
    /// Files are being migrated
    InProgress,
    /// Ready for cutover
    ReadyForCutover,
    /// Cutover in progress
    CutoverInProgress,
    /// Migration completed
    Completed,
    /// Migration failed
    Failed { error: String },
}

impl MigrationPhase {
    /// Get a human-readable description of the migration phase
    pub fn description(&self) -> &str {
        match self {
            MigrationPhase::Idle => "No migration in progress",
            MigrationPhase::Started => "Migration initiated",
            MigrationPhase::InProgress => "Migration in progress",
            MigrationPhase::ReadyForCutover => "Ready for cutover",
            MigrationPhase::CutoverInProgress => "Cutover in progress",
            MigrationPhase::Completed => "Migration completed",
            MigrationPhase::Failed { .. } => "Migration failed",
        }
    }

    /// Check if migration is currently active
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            MigrationPhase::Started
                | MigrationPhase::InProgress
                | MigrationPhase::ReadyForCutover
                | MigrationPhase::CutoverInProgress
        )
    }
}

impl SessionManager {
    /// Create a new session manager with enhanced security features
    pub fn new(config_path: Option<&Path>) -> Result<Self, CliError> {
        let base_config_dir = if let Some(path) = config_path {
            if path.is_dir() {
                path.to_path_buf()
            } else {
                path.parent()
                    .ok_or_else(|| CliError::configuration("Invalid config path"))?
                    .to_path_buf()
            }
        } else {
            dirs::home_dir()
                .ok_or_else(|| CliError::configuration("Could not determine home directory"))?
                .join(".hybridcipher")
        };

        ensure_clean_multi_user_structure(&base_config_dir)?;

        let global_dir = base_config_dir.join(GLOBAL_DIR_NAME);
        std::fs::create_dir_all(&global_dir).map_err(|e| {
            CliError::configuration(format!("Failed to create global config directory: {}", e))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&base_config_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| {
                    CliError::configuration(format!("Failed to set secure permissions: {}", e))
                })?;
            std::fs::set_permissions(&global_dir, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| {
                    CliError::configuration(format!(
                        "Failed to set global directory permissions: {}",
                        e
                    ))
                },
            )?;
        }

        let manager = Self {
            base_config_dir: base_config_dir.clone(),
            global_dir,
            current_session: Arc::new(Mutex::new(None)),
            current_user_context: Arc::new(Mutex::new(None)),
            account_key: Arc::new(Mutex::new(None)),
            state_key: Arc::new(Mutex::new(None)),
            state_key_owner: Arc::new(Mutex::new(None)),
            keystore_warning_emitted: Arc::new(Mutex::new(false)),
            transparency_prefs: Arc::new(Mutex::new(TransparencyPreferences::default())),
            transparency_config: Arc::new(Mutex::new(TransparencyConfig::default())),
        };

        manager.load_active_user_context()?;
        // Note: Session validation is deferred until explicitly needed by commands.
        // This avoids triggering keystore/password operations for unrelated users
        // when running commands like `register` that don't need the previous session.

        Ok(manager)
    }

    fn active_user_file(&self) -> PathBuf {
        self.global_dir.join(ACTIVE_USER_FILE)
    }

    fn last_user_file(&self) -> PathBuf {
        self.global_dir.join(LAST_USER_FILE)
    }

    fn load_active_user_context(&self) -> Result<(), CliError> {
        let active_file = self.active_user_file();
        if !active_file.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&active_file).map_err(|e| {
            CliError::configuration(format!("Failed to read active user file: {}", e))
        })?;

        let record: ActiveUserRecord = serde_json::from_str(&content).map_err(|e| {
            CliError::configuration(format!("Failed to parse active user file: {}", e))
        })?;

        // Use the internal method that skips session validation during construction.
        self.set_user_context_internal(&record.username, &record.server_url, false)?;
        Ok(())
    }

    fn persist_active_user(&self, context: &UserContext) -> Result<(), CliError> {
        let record = ActiveUserRecord {
            username: context.username.clone(),
            server_url: context.server_url.clone(),
            user_id: context.user_id.clone(),
        };

        let content = serde_json::to_string_pretty(&record).map_err(|e| {
            CliError::configuration(format!("Failed to serialize active user: {}", e))
        })?;

        let active_file = self.active_user_file();
        std::fs::create_dir_all(&self.global_dir)
            .map_err(|e| CliError::configuration(format!("Failed to prepare global dir: {}", e)))?;
        std::fs::write(&active_file, content).map_err(|e| {
            CliError::configuration(format!("Failed to persist active user: {}", e))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&active_file, permissions).map_err(|e| {
                CliError::configuration(format!("Failed to secure active user file: {}", e))
            })?;
        }

        Ok(())
    }

    fn persist_last_user_record(&self, record: &ActiveUserRecord) -> Result<(), CliError> {
        let content = serde_json::to_string_pretty(record).map_err(|e| {
            CliError::configuration(format!("Failed to serialize last user: {}", e))
        })?;

        let last_file = self.last_user_file();
        std::fs::create_dir_all(&self.global_dir)
            .map_err(|e| CliError::configuration(format!("Failed to prepare global dir: {}", e)))?;
        std::fs::write(&last_file, content)
            .map_err(|e| CliError::configuration(format!("Failed to persist last user: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&last_file, permissions).map_err(|e| {
                CliError::configuration(format!("Failed to secure last user file: {}", e))
            })?;
        }

        Ok(())
    }

    fn load_last_user_record(&self) -> Result<Option<ActiveUserRecord>, CliError> {
        let last_file = self.last_user_file();
        if !last_file.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&last_file).map_err(|e| {
            CliError::configuration(format!("Failed to read last user file: {}", e))
        })?;

        let record: ActiveUserRecord = serde_json::from_str(&content).map_err(|e| {
            CliError::configuration(format!("Failed to parse last user file: {}", e))
        })?;

        Ok(Some(record))
    }

    fn clear_active_user(&self) -> Result<(), CliError> {
        let active_file = self.active_user_file();
        if active_file.exists() {
            std::fs::remove_file(&active_file).map_err(|e| {
                CliError::configuration(format!("Failed to clear active user file: {}", e))
            })?;
        }
        Ok(())
    }

    fn current_user_context(&self) -> Option<UserContext> {
        match self.current_user_context.lock() {
            Ok(ctx) => ctx.clone(),
            Err(_) => None,
        }
    }

    /// Update transparency preferences based on CLI configuration or tests.
    pub fn set_transparency_preferences(
        &self,
        prefs: TransparencyPreferences,
    ) -> Result<(), CliError> {
        let mut guard = self
            .transparency_prefs
            .lock()
            .map_err(|_| CliError::internal("Failed to lock transparency preferences"))?;
        *guard = prefs;
        Ok(())
    }

    /// Store the transparency configuration for downstream client construction.
    pub fn set_transparency_config(&self, config: TransparencyConfig) -> Result<(), CliError> {
        let mut guard = self
            .transparency_config
            .lock()
            .map_err(|_| CliError::internal("Failed to lock transparency configuration"))?;
        *guard = config;
        Ok(())
    }

    fn transparency_preferences(&self) -> TransparencyPreferences {
        self.transparency_prefs
            .lock()
            .expect("transparency preferences lock poisoned")
            .clone()
    }

    pub fn transparency_config(&self) -> TransparencyConfig {
        self.transparency_config
            .lock()
            .expect("transparency configuration lock poisoned")
            .clone()
    }

    /// Max age (hours) for membership proofs (0 disables enforcement).
    pub fn membership_proof_max_age_hours(&self) -> u64 {
        self.current_client_config().membership_proof_max_age_hours
    }

    /// Env var name used to opt out of coverage IPC auto-detection.
    pub fn coverage_ipc_opt_out_env(&self) -> String {
        self.current_client_config().coverage_ipc_opt_out_env
    }

    fn current_client_config(&self) -> ClientConfig {
        let mut config = hybridcipher_client::config_loader::load_client_config_from_files();
        config.transparency_config = self.transparency_config();
        if let Some(patterns) = self.load_exclude_file_patterns() {
            config.excluded_file_patterns = patterns;
        }
        if let Some(coverage_config) = self.load_coverage_config() {
            if let Some(batch_size) = coverage_config.batch_size {
                config.coverage_batch_size = batch_size;
            }
            if let Some(parallel_uploads) = coverage_config.parallel_uploads {
                config.coverage_parallel_uploads = parallel_uploads;
            }
            if let Some(min_interval_ms) = coverage_config.upload_min_interval_ms {
                config.coverage_upload_min_interval_ms = min_interval_ms;
            }
            if let Some(backoff_base_ms) = coverage_config.upload_backoff_base_ms {
                config.coverage_upload_backoff_base_ms = backoff_base_ms;
            }
            if let Some(backoff_max_ms) = coverage_config.upload_backoff_max_ms {
                config.coverage_upload_backoff_max_ms = backoff_max_ms;
            }
            if let Some(baseline_threshold) = coverage_config.baseline_threshold {
                config.coverage_baseline_threshold = baseline_threshold;
            }

            if let Some(min_entries) = coverage_config.compaction_min_entries {
                config.coverage_compaction.min_entries = min_entries;
            }
            if let Some(idle_quiet_secs) = coverage_config.compaction_idle_quiet_secs {
                config.coverage_compaction.idle_quiet_secs = idle_quiet_secs;
            }
            if let Some(min_interval_secs) = coverage_config.compaction_min_interval_secs {
                config.coverage_compaction.min_interval_secs = min_interval_secs;
            }
            if let Some(max_interval_secs) = coverage_config.compaction_max_interval_secs {
                config.coverage_compaction.max_interval_secs = max_interval_secs;
            }
            if let Some(max_journal_bytes) = coverage_config.compaction_max_journal_bytes {
                config.coverage_compaction.max_journal_bytes = max_journal_bytes;
            }
            if let Some(force_bytes) = coverage_config.compaction_bulk_force_journal_bytes {
                config.coverage_compaction.bulk_force_journal_bytes = force_bytes;
            }
            if let Some(backoff_secs) = coverage_config.compaction_error_backoff_secs {
                config.coverage_compaction.error_backoff_secs = backoff_secs;
            }
            if let Some(bulk_enabled) = coverage_config.compaction_bulk_mode_enabled {
                config.coverage_compaction.bulk_mode_enabled = bulk_enabled;
            }
        }
        config
    }

    fn load_exclude_file_patterns(&self) -> Option<Vec<String>> {
        let candidates = hybridcipher_client::config_loader::config_file_candidates();

        for path in candidates {
            let contents = match fs::read_to_string(&path) {
                Ok(contents) => contents,
                Err(err) => {
                    tracing::warn!(
                        "Failed to read config file {} for exclude patterns: {}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };
            let parsed: toml::Value = match toml::from_str(&contents) {
                Ok(val) => val,
                Err(err) => {
                    tracing::warn!(
                        "Failed to parse {} for exclude patterns: {}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };
            if let Some(patterns) = parsed
                .get("coverage")
                .and_then(|section| section.get("exclude_files"))
                .and_then(|val| val.as_array())
            {
                let list: Vec<String> = patterns
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !list.is_empty() {
                    return Some(list);
                }
            }
        }

        None
    }

    fn load_coverage_config(&self) -> Option<CoverageConfigOverrides> {
        let candidates = hybridcipher_client::config_loader::config_file_candidates();

        for path in candidates {
            let contents = match fs::read_to_string(&path) {
                Ok(contents) => contents,
                Err(err) => {
                    tracing::warn!(
                        "Failed to read config file {} for coverage config: {}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };
            let parsed: toml::Value = match toml::from_str(&contents) {
                Ok(val) => val,
                Err(err) => {
                    tracing::warn!(
                        "Failed to parse {} for coverage config: {}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };
            if let Some(coverage_section) = parsed.get("coverage") {
                let mut overrides = CoverageConfigOverrides::default();

                if let Some(batch_val) = coverage_section.get("batch_size") {
                    if let Some(batch_int) = batch_val.as_integer() {
                        overrides.batch_size = Some(batch_int as usize);
                    }
                }

                if let Some(parallel_val) = coverage_section.get("parallel_uploads") {
                    if let Some(parallel_int) = parallel_val.as_integer() {
                        overrides.parallel_uploads = Some(parallel_int as usize);
                    }
                }

                if let Some(value) = coverage_section.get("upload_min_interval_ms") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.upload_min_interval_ms = Some(int_val.max(0) as u64);
                    }
                }

                if let Some(value) = coverage_section.get("upload_backoff_base_ms") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.upload_backoff_base_ms = Some(int_val.max(0) as u64);
                    }
                }

                if let Some(value) = coverage_section.get("upload_backoff_max_ms") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.upload_backoff_max_ms = Some(int_val.max(0) as u64);
                    }
                }

                if let Some(value) = coverage_section.get("baseline_threshold") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.baseline_threshold = Some(int_val.max(0) as usize);
                    }
                }

                if let Some(value) = coverage_section.get("compaction_min_entries") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.compaction_min_entries = Some(int_val.max(0) as u64);
                    }
                }
                if let Some(value) = coverage_section.get("compaction_idle_quiet_secs") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.compaction_idle_quiet_secs = Some(int_val.max(0) as u64);
                    }
                }
                if let Some(value) = coverage_section.get("compaction_min_interval_secs") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.compaction_min_interval_secs = Some(int_val.max(0) as u64);
                    }
                }
                if let Some(value) = coverage_section.get("compaction_max_interval_secs") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.compaction_max_interval_secs = Some(int_val.max(0) as u64);
                    }
                }
                if let Some(value) = coverage_section.get("compaction_max_journal_bytes") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.compaction_max_journal_bytes = Some(int_val.max(0) as u64);
                    }
                }
                if let Some(value) = coverage_section.get("compaction_bulk_force_journal_bytes") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.compaction_bulk_force_journal_bytes = Some(int_val.max(0) as u64);
                    }
                }
                if let Some(value) = coverage_section.get("compaction_error_backoff_secs") {
                    if let Some(int_val) = value.as_integer() {
                        overrides.compaction_error_backoff_secs = Some(int_val.max(0) as u64);
                    }
                }
                if let Some(value) = coverage_section.get("compaction_bulk_mode_enabled") {
                    if let Some(bool_val) = value.as_bool() {
                        overrides.compaction_bulk_mode_enabled = Some(bool_val);
                    }
                }

                if overrides.batch_size.is_some()
                    || overrides.parallel_uploads.is_some()
                    || overrides.upload_min_interval_ms.is_some()
                    || overrides.upload_backoff_base_ms.is_some()
                    || overrides.upload_backoff_max_ms.is_some()
                    || overrides.baseline_threshold.is_some()
                    || overrides.compaction_min_entries.is_some()
                    || overrides.compaction_idle_quiet_secs.is_some()
                    || overrides.compaction_min_interval_secs.is_some()
                    || overrides.compaction_max_interval_secs.is_some()
                    || overrides.compaction_max_journal_bytes.is_some()
                    || overrides.compaction_bulk_force_journal_bytes.is_some()
                    || overrides.compaction_error_backoff_secs.is_some()
                    || overrides.compaction_bulk_mode_enabled.is_some()
                {
                    return Some(overrides);
                }
            }
        }

        None
    }

    fn transparency_state_path(&self) -> Result<PathBuf, CliError> {
        let context = self
            .current_user_context()
            .ok_or_else(|| CliError::session("No active user context configured"))?;
        Ok(context.config_dir.join(TRANSPARENCY_STATE_FILE))
    }

    fn load_transparency_state(&self) -> Result<Option<TransparencyVerificationState>, CliError> {
        let path = self.transparency_state_path()?;

        if !path.exists() {
            return Ok(None);
        }

        let contents = fs::read_to_string(&path).map_err(|e| {
            CliError::configuration(format!(
                "Failed to read transparency cache at {}: {}",
                path.display(),
                e
            ))
        })?;

        let state: TransparencyVerificationState =
            serde_json::from_str(&contents).map_err(|e| {
                CliError::configuration(format!(
                    "Failed to parse transparency cache {}: {}",
                    path.display(),
                    e
                ))
            })?;

        Ok(Some(state))
    }

    fn persist_transparency_state(
        &self,
        state: &TransparencyVerificationState,
    ) -> Result<(), CliError> {
        let path = self.transparency_state_path()?;
        let contents = serde_json::to_string_pretty(state).map_err(|e| {
            CliError::configuration(format!("Failed to serialize transparency cache: {}", e))
        })?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                CliError::configuration(format!(
                    "Failed to prepare transparency cache directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        fs::write(&path, contents).map_err(|e| {
            CliError::configuration(format!(
                "Failed to persist transparency cache at {}: {}",
                path.display(),
                e
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, permissions).map_err(|e| {
                CliError::configuration(format!(
                    "Failed to secure transparency cache {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        Ok(())
    }

    pub fn transparency_cache_summary(&self) -> Result<Option<TransparencyCacheSummary>, CliError> {
        Ok(self
            .load_transparency_state()?
            .map(TransparencyCacheSummary::from))
    }

    pub async fn refresh_transparency_cache(
        &self,
        server_url: &str,
    ) -> Result<Option<TransparencyCacheSummary>, CliError> {
        self.preflight_server_identity(server_url).await?;
        self.transparency_cache_summary()
    }

    fn verify_transparency_checkpoint(
        &self,
        checkpoint: &ServerCheckpointDocument,
        signing_key_id: &str,
        server_public_key_b64: &str,
        server_public_key_bytes: &[u8],
        log_url: Option<String>,
        max_checkpoint_age_seconds: u64,
    ) -> Result<TransparencyVerificationState, TransparencyVerificationError> {
        use crate::security::transparency::{signature_from_base64, verifying_key_for};

        let verifying_key = verifying_key_for(signing_key_id).ok_or_else(|| {
            TransparencyVerificationError::new(format!(
                "Unknown transparency signing key '{}'; please update the CLI",
                signing_key_id
            ))
        })?;

        let signature_b64 = checkpoint.signature.as_deref().ok_or_else(|| {
            TransparencyVerificationError::new("Transparency checkpoint missing signature")
        })?;

        let signature = signature_from_base64(signature_b64)
            .map_err(|e| TransparencyVerificationError::new(e.to_string()))?;

        let payload_json = checkpoint.signing_payload().map_err(|e| {
            TransparencyVerificationError::new(format!(
                "Failed to serialize checkpoint payload for verification: {}",
                e
            ))
        })?;

        let verified =
            hybridcipher_crypto::signatures::verify(&verifying_key, &payload_json, &signature)
                .is_ok()
                || {
                    let root_bytes = checkpoint
                        .root_hash_bytes()
                        .map_err(|e| TransparencyVerificationError::new(e.to_string()))?;
                    hybridcipher_crypto::signatures::verify(&verifying_key, &root_bytes, &signature)
                        .is_ok()
                };

        if !verified {
            return Err(TransparencyVerificationError::new(
                "Transparency checkpoint signature verification failed",
            ));
        }

        let generated_at = chrono::DateTime::parse_from_rfc3339(&checkpoint.generated_at)
            .map_err(|e| {
                TransparencyVerificationError::new(format!(
                    "Transparency checkpoint timestamp invalid: {}",
                    e
                ))
            })?
            .with_timezone(&chrono::Utc);

        if max_checkpoint_age_seconds > 0 {
            let now = chrono::Utc::now();
            let age_seconds = now.signed_duration_since(generated_at).num_seconds();
            if age_seconds.is_positive() && age_seconds as u64 > max_checkpoint_age_seconds {
                return Err(TransparencyVerificationError::new(format!(
                    "Transparency checkpoint too old ({}s > {}s)",
                    age_seconds, max_checkpoint_age_seconds
                )));
            }
        }

        let entry = checkpoint
            .entries
            .iter()
            .find(|entry| entry.entry_type == "server_fingerprint")
            .ok_or_else(|| {
                TransparencyVerificationError::new(
                    "Transparency checkpoint missing server fingerprint entry",
                )
            })?;

        if entry.public_key_base64.trim() != server_public_key_b64.trim() {
            return Err(TransparencyVerificationError::new(
                "Transparency checkpoint fingerprint does not match server public key",
            ));
        }

        let fingerprint_bytes = Sha256::digest(server_public_key_bytes);
        let fingerprint_vec = fingerprint_bytes.to_vec();
        let fingerprint_hex = hex::encode_upper(&fingerprint_vec);
        let fingerprint_b64 = general_purpose::STANDARD.encode(&fingerprint_vec);

        if !fingerprint_hex.eq_ignore_ascii_case(entry.sha256_hex.trim()) {
            return Err(TransparencyVerificationError::new(
                "Transparency checkpoint SHA-256 fingerprint mismatch",
            ));
        }

        let expected_short = fingerprint_hex
            .chars()
            .take(entry.short_hex.len())
            .collect::<String>();
        if !expected_short.eq_ignore_ascii_case(entry.short_hex.trim()) {
            return Err(TransparencyVerificationError::new(
                "Transparency checkpoint short fingerprint mismatch",
            ));
        }

        if fingerprint_b64.trim() != entry.sha256_base64.trim() {
            return Err(TransparencyVerificationError::new(
                "Transparency checkpoint base64 fingerprint mismatch",
            ));
        }

        let checkpoint_fingerprint = hex::encode_upper(Sha256::digest(&payload_json));

        Ok(TransparencyVerificationState {
            log_url,
            signing_key_id: Some(signing_key_id.to_string()),
            root_hash_hex: checkpoint.root_hash.to_uppercase(),
            tree_size: checkpoint.tree_size,
            server_public_key_base64: server_public_key_b64.to_string(),
            checkpoint_fingerprint,
            checkpoint_generated_at: checkpoint.generated_at.clone(),
            verified_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        })
    }

    /// Return basic information about the last active user if one is recorded.
    pub fn active_user_summary(&self) -> Option<ActiveUserSummary> {
        if let Some(ctx) = self.current_user_context() {
            return Some(ActiveUserSummary {
                username: ctx.username,
                server_url: ctx.server_url,
                user_id: ctx.user_id,
            });
        }

        match self.load_last_user_record() {
            Ok(Some(record)) => Some(ActiveUserSummary {
                username: record.username,
                server_url: record.server_url,
                user_id: record.user_id,
            }),
            Ok(None) | Err(_) => None,
        }
    }

    /// Persist the provided session as the last user for display after logout.
    pub fn remember_last_user(&self, session: &Session) -> Result<(), CliError> {
        let record = ActiveUserRecord {
            username: session.username.clone(),
            server_url: session.server_url.clone(),
            user_id: session.user_id.clone(),
        };
        self.persist_last_user_record(&record)
    }

    pub fn user_storage_id_for(&self, username: &str, server_url: &str) -> String {
        let canonical = canonicalize_server_url(server_url);
        get_user_storage_id(username, &canonical.canonical)
    }

    pub async fn cache_user_identity(&self, email: &str, user_id: &str) -> Result<(), CliError> {
        self.cache_user_identities(vec![(email.to_string(), user_id.to_string())])
            .await
    }

    pub async fn cache_user_identities(
        &self,
        identities: Vec<(String, String)>,
    ) -> Result<(), CliError> {
        if identities.is_empty() {
            return Ok(());
        }

        let mut cache = self.load_user_identity_cache().await?;
        let mut changed = false;

        for (email, user_id) in identities {
            if email.trim().is_empty() || user_id.trim().is_empty() {
                continue;
            }
            if cache.insert(&email, &user_id) {
                changed = true;
            }
        }

        if changed {
            self.persist_user_identity_cache(&cache).await?;
        }

        Ok(())
    }

    pub async fn resolve_user_identifier(&self, identifier: &str) -> Result<String, CliError> {
        let trimmed = identifier.trim();
        if trimmed.is_empty() {
            return Err(CliError::invalid_input(
                "User identifier is required.".to_string(),
            ));
        }

        if !trimmed.contains('@') {
            return Ok(trimmed.to_string());
        }

        if let Ok(cache) = self.load_user_identity_cache().await {
            if let Some(user_id) = cache.user_id_for_email(trimmed) {
                return Ok(user_id);
            }
        }

        let mut lookup_errors: Vec<String> = Vec::new();

        match self.fetch_join_cards_for_email(trimmed).await {
            Ok(cards) => {
                if let Some(card) = cards.into_iter().next() {
                    let user_id = card.user_id.to_string();
                    let _ = self.cache_user_identity(trimmed, &user_id).await;
                    return Ok(user_id);
                }
            }
            Err(err) => lookup_errors.push(format!("join card lookup failed: {}", err)),
        }

        match self.ensure_active_group().await {
            Ok(group_id) => match self.list_group_members_http(&group_id.to_string()).await {
                Ok(members) => {
                    if let Some(member) = members
                        .iter()
                        .find(|member| member.email.eq_ignore_ascii_case(trimmed))
                    {
                        let user_id = member.user_id.clone();
                        let _ = self.cache_user_identity(&member.email, &user_id).await;
                        return Ok(user_id);
                    }
                }
                Err(err) => lookup_errors.push(format!("group member lookup failed: {}", err)),
            },
            Err(err) => lookup_errors.push(format!("active group lookup failed: {}", err)),
        }

        let mut message = format!(
            "No user ID found for email '{}'. Run 'hybridcipher list-members' to refresh the cache or use the UUID.",
            trimmed
        );
        if !lookup_errors.is_empty() {
            message.push_str(&format!(" Details: {}", lookup_errors.join("; ")));
        }

        Err(CliError::not_found(message))
    }

    pub async fn cached_email_for_user_id(&self, user_id: &str) -> Option<String> {
        let trimmed = user_id.trim();
        if trimmed.is_empty() {
            return None;
        }
        let cache = self.load_user_identity_cache().await.ok()?;
        cache.email_for_user_id(trimmed)
    }

    pub async fn cache_group_metadata(&self, groups: &[GroupInfo]) -> Result<(), CliError> {
        if groups.is_empty() {
            return Ok(());
        }

        let mut cache = self.load_group_metadata_cache().await?;
        let mut changed = false;

        for group in groups {
            if cache.insert(&group.id, &group.name, Some(&group.role)) {
                changed = true;
            }
        }

        if changed {
            self.persist_group_metadata_cache(&cache).await?;
        }

        Ok(())
    }

    pub async fn group_label_for_id(&self, group_id: &str) -> String {
        let trimmed = group_id.trim();
        if trimmed.is_empty() {
            return String::new();
        }

        match uuid::Uuid::parse_str(trimmed) {
            Ok(group_uuid) => self.group_label(&group_uuid).await,
            Err(_) => trimmed.to_string(),
        }
    }

    pub async fn group_label(&self, group_id: &uuid::Uuid) -> String {
        if let Some((name, _)) = self.group_membership_from_state(group_id) {
            if !name.trim().is_empty() {
                return format_group_label(&name, group_id);
            }
        }

        if let Ok(cache) = self.load_group_metadata_cache().await {
            if let Some(name) = cache.name_for_id(&group_id.to_string()) {
                if !name.trim().is_empty() {
                    return format_group_label(name, group_id);
                }
            }
        }

        if let Ok(groups) = self.list_groups_http().await {
            if let Some(group) = groups
                .iter()
                .find(|entry| entry.id.eq_ignore_ascii_case(&group_id.to_string()))
            {
                return format_group_label(&group.name, group_id);
            }
        }

        group_id.to_string()
    }

    async fn load_user_identity_cache(&self) -> Result<UserIdentityCache, CliError> {
        let storage = self.current_storage()?;
        let raw = storage
            .load_config(USER_ID_CACHE_KEY)
            .await
            .map_err(|e| CliError::storage(format!("Failed to load user cache: {}", e)))?;

        let Some(raw) = raw else {
            return Ok(UserIdentityCache::default());
        };

        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(UserIdentityCache::default());
        }

        match serde_json::from_str::<UserIdentityCache>(trimmed) {
            Ok(cache) => Ok(cache),
            Err(err) => {
                ui::warning(&format!(
                    "User identity cache is corrupted; rebuilding cache ({})",
                    err
                ));
                Ok(UserIdentityCache::default())
            }
        }
    }

    async fn persist_user_identity_cache(&self, cache: &UserIdentityCache) -> Result<(), CliError> {
        let storage = self.current_storage()?;
        let serialized = serde_json::to_string(cache).map_err(|e| {
            CliError::configuration(format!("Failed to serialize user cache: {}", e))
        })?;
        storage
            .store_config(USER_ID_CACHE_KEY, &serialized)
            .await
            .map_err(|e| CliError::storage(format!("Failed to persist user cache: {}", e)))
    }

    async fn load_group_metadata_cache(&self) -> Result<GroupMetadataCache, CliError> {
        let storage = self.current_storage()?;
        let raw = storage
            .load_config(GROUP_METADATA_CACHE_KEY)
            .await
            .map_err(|e| CliError::storage(format!("Failed to load group cache: {}", e)))?;

        let Some(raw) = raw else {
            return Ok(GroupMetadataCache::default());
        };

        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(GroupMetadataCache::default());
        }

        match serde_json::from_str::<GroupMetadataCache>(trimmed) {
            Ok(cache) => Ok(cache),
            Err(err) => {
                ui::warning(&format!(
                    "Group metadata cache is corrupted; rebuilding cache ({})",
                    err
                ));
                Ok(GroupMetadataCache::default())
            }
        }
    }

    async fn persist_group_metadata_cache(
        &self,
        cache: &GroupMetadataCache,
    ) -> Result<(), CliError> {
        let storage = self.current_storage()?;
        let serialized = serde_json::to_string(cache).map_err(|e| {
            CliError::configuration(format!("Failed to serialize group cache: {}", e))
        })?;
        storage
            .store_config(GROUP_METADATA_CACHE_KEY, &serialized)
            .await
            .map_err(|e| CliError::storage(format!("Failed to persist group cache: {}", e)))
    }

    async fn load_group_members_cache(
        &self,
        group_id: &str,
    ) -> Result<GroupMembersCacheEntry, CliError> {
        let storage = self.current_storage()?;
        let key = group_members_cache_key(group_id);
        let raw = storage
            .load_config(&key)
            .await
            .map_err(|e| CliError::storage(format!("Failed to load group members cache: {}", e)))?;

        let Some(raw) = raw else {
            return Ok(GroupMembersCacheEntry {
                cached_at: Utc::now(),
                members: Vec::new(),
            });
        };

        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(GroupMembersCacheEntry {
                cached_at: Utc::now(),
                members: Vec::new(),
            });
        }

        match serde_json::from_str::<GroupMembersCacheEntry>(trimmed) {
            Ok(cache) => Ok(cache),
            Err(err) => {
                ui::warning(&format!(
                    "Group members cache is corrupted; rebuilding cache ({})",
                    err
                ));
                Ok(GroupMembersCacheEntry {
                    cached_at: Utc::now(),
                    members: Vec::new(),
                })
            }
        }
    }

    async fn persist_group_members_cache(
        &self,
        group_id: &str,
        members: &[MemberInfo],
    ) -> Result<(), CliError> {
        let storage = self.current_storage()?;
        let key = group_members_cache_key(group_id);
        let cache = GroupMembersCacheEntry {
            cached_at: Utc::now(),
            members: members.iter().map(CachedMemberInfo::from_member).collect(),
        };
        let serialized = serde_json::to_string(&cache).map_err(|e| {
            CliError::configuration(format!("Failed to serialize group members cache: {}", e))
        })?;
        storage
            .store_config(&key, &serialized)
            .await
            .map_err(|e| CliError::storage(format!("Failed to persist group members cache: {}", e)))
    }

    pub async fn list_group_members_with_cache(
        &self,
        group_id: &str,
    ) -> Result<Vec<MemberInfo>, CliError> {
        match self.list_group_members_http(group_id).await {
            Ok(members) => {
                if let Err(err) = self.persist_group_members_cache(group_id, &members).await {
                    ui::warning(&format!("Failed to update group members cache: {}", err));
                }
                Ok(members)
            }
            Err(err) => {
                let cache = self.load_group_members_cache(group_id).await?;
                if !cache.members.is_empty() {
                    ui::warning(&format!(
                        "Failed to fetch group members from server; using cached members from {}.",
                        cache.cached_at.to_rfc3339()
                    ));
                    return Ok(cache
                        .members
                        .into_iter()
                        .map(CachedMemberInfo::into_member)
                        .collect());
                }
                Err(err)
            }
        }
    }

    pub async fn list_admin_group_ids_with_cache(&self) -> Result<Vec<String>, CliError> {
        match self.list_groups_http().await {
            Ok(groups) => Ok(groups
                .into_iter()
                .filter(|group| Self::role_allows_admin(&group.role))
                .map(|group| group.id)
                .collect()),
            Err(err) => {
                let cache = self.load_group_metadata_cache().await?;
                let mut ids = Vec::new();
                for (group_id, meta) in cache.by_id.iter() {
                    if let Some(role) = meta.role.as_deref() {
                        if Self::role_allows_admin(role) {
                            ids.push(group_id.clone());
                        }
                    }
                }
                if !ids.is_empty() {
                    ui::warning("Failed to fetch groups from server; using cached group metadata.");
                    return Ok(ids);
                }
                Err(err)
            }
        }
    }

    pub fn current_storage(
        &self,
    ) -> Result<Arc<hybridcipher_client::storage::LocalFsStorage>, CliError> {
        self.current_user_context()
            .map(|ctx| Arc::clone(&ctx.storage))
            .ok_or_else(|| CliError::session("No active user context configured"))
    }

    /// Load persisted pinning configuration for the active user context.
    pub async fn load_pinning_config(&self) -> Result<PinningConfig, CliError> {
        let storage = self.current_storage()?;
        load_pinning_config_for_storage(storage.as_ref()).await
    }

    /// Load the server identity manager for the active user context
    pub fn server_identity_manager(&self) -> Result<ServerIdentityManager, CliError> {
        let context = self
            .current_user_context()
            .ok_or_else(|| CliError::session("No active user context configured"))?;
        let path = context.config_dir.join("server_identities.json");
        ServerIdentityManager::load(path).map_err(Into::into)
    }

    pub fn pinned_welcome_signing_key(&self) -> Result<Option<Vec<u8>>, CliError> {
        let session = self.require_auth()?;
        let manager = self.server_identity_manager()?;
        Ok(manager.welcome_signing_key_bytes(&session.server_url))
    }

    /// Set the active user context, creating required directories with secure permissions.
    pub fn set_user_context(&self, username: &str, server_url: &str) -> Result<(), CliError> {
        self.set_user_context_internal(username, server_url, true)
    }

    /// Internal method to set user context with optional session loading.
    fn set_user_context_internal(
        &self,
        username: &str,
        server_url: &str,
        load_session: bool,
    ) -> Result<(), CliError> {
        // Drop any in-memory account key before switching contexts (cache persists until logout).
        self.drop_account_key_memory();
        // Drop any in-memory state key so it cannot leak across users.
        self.drop_state_key_memory();

        let trimmed_server = server_url.trim();
        let canonicalization = canonicalize_server_url(trimmed_server);
        let canonical_server_url = canonicalization.canonical.clone();

        if let Some(alias) = canonicalization.replaced_alias.as_ref() {
            if canonicalization.upgraded_scheme {
                ui::info(&format!(
                    "📡 Detected legacy HybridCipher endpoint '{}'; upgrading to secure '{}'.",
                    alias, canonical_server_url
                ));
            } else {
                ui::info(&format!(
                    "📡 Detected legacy HybridCipher endpoint '{}'; normalizing to '{}'.",
                    alias, canonical_server_url
                ));
            }
        }

        let user_id = get_user_storage_id(username, &canonical_server_url);
        let user_dir = self.base_config_dir.join(USERS_DIR).join(&user_id);

        let canonicalized = canonical_server_url != trimmed_server;
        if canonicalized {
            let legacy_id = get_user_storage_id(username, trimmed_server);
            if legacy_id != user_id {
                let legacy_dir = self.base_config_dir.join(USERS_DIR).join(&legacy_id);
                if legacy_dir.exists() {
                    if user_dir.exists() {
                        ui::warning(&format!(
                            "⚠️  Both legacy ({}) and canonical ({}) session directories exist. Using canonical directory.",
                            legacy_id, user_id
                        ));
                    } else {
                        std::fs::rename(&legacy_dir, &user_dir).map_err(|e| {
                            CliError::configuration(format!(
                                "Failed to migrate session directory from legacy server reference: {}",
                                e
                            ))
                        })?;
                        ui::info(&format!(
                            "💾 Migrated stored session data to '{}'.",
                            canonical_server_url
                        ));
                    }
                }
            }
        }

        std::fs::create_dir_all(&user_dir).map_err(|e| {
            CliError::configuration(format!("Failed to create user directory: {}", e))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&user_dir, permissions).map_err(|e| {
                CliError::configuration(format!("Failed to secure user directory: {}", e))
            })?;
        }

        let session_file = user_dir.join("session.toml");
        let storage = Arc::new(hybridcipher_client::storage::LocalFsStorage::new_for_user(
            &self.base_config_dir,
            &user_id,
        ));

        let account_metadata = self.load_account_metadata_from_dir(&user_dir)?;

        // new_for_user already ensures directories exist, but we still want
        // secured permissions on the user directory we computed above.

        let context = UserContext {
            username: username.to_string(),
            server_url: canonical_server_url.clone(),
            user_id,
            config_dir: user_dir,
            session_file,
            storage,
            account_metadata,
        };

        let mut guard = self
            .current_user_context
            .lock()
            .map_err(|_| CliError::session("Failed to lock user context"))?;
        *guard = Some(context.clone());
        drop(guard);

        self.persist_active_user(&context)?;
        if load_session {
            self.load_session_with_validation()?;
        }

        Ok(())
    }

    /// Clear any active user context and remove persisted pointers.
    pub fn clear_user_context(&self) -> Result<(), CliError> {
        self.clear_account_key();
        let mut guard = self
            .current_user_context
            .lock()
            .map_err(|_| CliError::session("Failed to lock user context"))?;
        *guard = None;
        drop(guard);

        self.clear_active_user()?;
        Ok(())
    }

    /// Zeroize sensitive in-memory session data before logout or context switch.
    pub fn clear_sensitive_memory(&self) -> Result<(), CliError> {
        let mut guard = self
            .current_session
            .lock()
            .map_err(|_| CliError::session("Failed to lock session state"))?;

        if let Some(session) = guard.as_mut() {
            session.token.zeroize();
            session.refresh_token.zeroize();
            session.device_binding.zeroize();
            if let Some(export_key) = session.opaque_export_key.as_mut() {
                export_key.zeroize();
            }
            if let Some(keypair) = session.device_keypair.as_mut() {
                keypair.zeroize();
            }
            session.device_keypair = None;
        }

        self.drop_state_key_memory();
        self.drop_account_key_memory();

        Ok(())
    }

    /// Remove temporary files created during the session lifecycle.
    pub fn cleanup_temporary_files(&self) -> Result<(), CliError> {
        if let Some(context) = self.current_user_context() {
            let temp_dir = context.config_dir.join("temp");
            if temp_dir.exists() {
                std::fs::remove_dir_all(&temp_dir).map_err(|e| {
                    CliError::session(format!("Failed to remove temporary directory: {}", e))
                })?;
            }

            for entry in std::fs::read_dir(&context.config_dir).map_err(|e| {
                CliError::session(format!("Failed to inspect user config directory: {}", e))
            })? {
                let entry = entry.map_err(|e| {
                    CliError::session(format!("Failed to read directory entry: {}", e))
                })?;
                let file_name = entry.file_name();
                if file_name.to_string_lossy().ends_with(".tmp") {
                    std::fs::remove_file(entry.path()).map_err(|e| {
                        CliError::session(format!("Failed to remove temporary file: {}", e))
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Lock the user's session directory to prevent concurrent access.
    pub fn lock_user_session(&self) -> Result<(), CliError> {
        if let Some(context) = self.current_user_context() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &context.config_dir,
                    std::fs::Permissions::from_mode(0o700),
                )
                .map_err(|e| {
                    CliError::session(format!("Failed to secure user directory: {}", e))
                })?;
            }

            let lock_file = context.config_dir.join(".session_lock");
            let timestamp = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            std::fs::write(&lock_file, format!("locked_at_{}", timestamp)).map_err(|e| {
                CliError::session(format!("Failed to write session lock file: {}", e))
            })?;
        }

        Ok(())
    }

    /// Get the current session
    pub fn current_session(&self) -> Option<Session> {
        self.current_session.lock().unwrap().clone()
    }

    /// Check if user is authenticated with comprehensive validation
    pub fn is_authenticated(&self) -> bool {
        // Try to load session from disk if not already in memory
        if self.current_session.lock().unwrap().is_none() {
            let _ = self.load_session_with_validation();
        }

        if let Some(session) = &*self.current_session.lock().unwrap() {
            // Check session expiration
            if chrono::Utc::now() >= session.expires_at {
                return false;
            }

            // Validate device binding
            if !self.validate_device_binding(session) {
                return false;
            }

            // Check session integrity
            if !self.validate_session_integrity(session) {
                return false;
            }

            true
        } else {
            false
        }
    }

    /// Require authentication with automatic renewal if needed
    pub fn require_auth(&self) -> Result<Session, CliError> {
        if !self.is_authenticated() {
            return Err(CliError::NotAuthenticated(
                "Not authenticated. Please login first with 'hybridcipher login <username>'".into(),
            ));
        }

        let mut session_guard = self.current_session.lock().unwrap();
        let session = session_guard.as_mut().unwrap();

        let now = chrono::Utc::now();
        session.last_activity = now;
        drop(session_guard);
        self.save_session_securely()?;

        Ok(self
            .current_session
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone())
    }

    /// Require authentication and validate the session against the server.
    pub async fn require_auth_with_server_check(&self) -> Result<Session, CliError> {
        let session = self.require_auth()?;
        if !self.verify_session_with_server(&session).await? {
            return Err(CliError::NotAuthenticated(
                "Session expired. Please login again with 'hybridcipher login <username>'".into(),
            ));
        }
        Ok(session)
    }

    /// Validate the current session with the server, invalidating local state on 401.
    pub async fn verify_session_with_server(&self, session: &Session) -> Result<bool, CliError> {
        let base_url = session.server_url.trim_end_matches('/');
        let endpoint = if base_url.ends_with("/api/v1") {
            format!("{}/groups", base_url)
        } else {
            format!("{}/api/v1/groups", base_url)
        };

        let response = reqwest::Client::new()
            .get(&endpoint)
            .bearer_auth(&session.token)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| {
                CliError::network(format!("Failed to verify session with server: {}", e))
            })?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("verify_session_with_server")?;
            return Ok(false);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(CliError::network(format!(
                "Session verification failed ({}): {}",
                status, body
            )));
        }

        Ok(true)
    }

    /// Store a new session with enhanced security
    pub fn store_session(&self, mut session: Session) -> Result<(), CliError> {
        let canonicalization = canonicalize_server_url(&session.server_url);
        if canonicalization.canonical != session.server_url {
            session.server_url = canonicalization.canonical;
        }

        // Generate device binding and integrity hash
        session.device_binding = self.generate_device_binding()?;
        session.security_metadata.integrity_hash = self.compute_session_integrity(&session)?;
        session.last_activity = chrono::Utc::now();

        *self.current_session.lock().unwrap() = Some(session.clone());
        self.save_session_securely()?;

        // Log session creation for audit
        self.log_session_event("session_created", &session)?;

        Ok(())
    }

    /// Clear the current session with secure cleanup
    pub fn clear_session(&self) -> Result<(), CliError> {
        // Log session termination for audit
        if let Some(session) = &*self.current_session.lock().unwrap() {
            self.log_session_event("session_terminated", session)?;
        }

        *self.current_session.lock().unwrap() = None;

        if let Some(context) = self.current_user_context() {
            if context.session_file.exists() {
                self.secure_file_deletion(&context.session_file)?;
            }
        }

        Ok(())
    }

    /// Invalidate the current session when the server rejects stored credentials.
    pub fn invalidate_session(&self, source: &str) -> Result<(), CliError> {
        if let Some(mut session) = self.current_session() {
            let event_type = format!("session_invalidated:{}", source);
            let _ = self.log_session_event(&event_type, &session);

            session.token.zeroize();
            session.refresh_token.zeroize();
            session.device_binding.zeroize();
            if let Some(export_key) = session.opaque_export_key.as_mut() {
                export_key.zeroize();
            }
            if let Some(keypair) = session.device_keypair.as_mut() {
                keypair.zeroize();
            }
        }

        self.clear_sensitive_memory()?;
        self.clear_session()?;
        Ok(())
    }

    /// Update migration information with state synchronization
    pub fn update_migration_info(&self, migration_info: MigrationInfo) -> Result<(), CliError> {
        let mut session_guard = self.current_session.lock().unwrap();
        if let Some(session) = session_guard.as_mut() {
            session.migration_info = Some(migration_info.clone());
            session.last_activity = chrono::Utc::now();
            session.security_metadata.flags.migration_recovered = true;
            session.security_metadata.integrity_hash = self.compute_session_integrity(session)?;

            drop(session_guard);
            self.save_session_securely()?;

            // Log migration state update
            self.log_migration_event("migration_state_updated", &migration_info)?;
        } else {
            return Err(CliError::session("No active session to update"));
        }
        Ok(())
    }

    /// Mark the current device as approved after recovery.
    pub fn mark_device_recovered(&self) -> Result<(), CliError> {
        let mut session_guard = self.current_session.lock().unwrap();
        let session = session_guard
            .as_mut()
            .ok_or_else(|| CliError::session("No active session to update"))?;

        session.device_status = None;
        session.last_activity = chrono::Utc::now();
        session.security_metadata.flags.device_verified = true;
        session.security_metadata.flags.migration_recovered = true;
        session.security_metadata.integrity_hash = self.compute_session_integrity(session)?;

        let session_snapshot = session.clone();
        drop(session_guard);

        self.save_session_securely()?;
        self.log_session_event("device_recovered", &session_snapshot)?;
        Ok(())
    }

    /// Synchronize migration state with automatic recovery
    pub async fn synchronize_migration_state(&self) -> Result<(), CliError> {
        if let Some(session) = &*self.current_session.lock().unwrap() {
            if let Some(migration_info) = &session.migration_info {
                if migration_info.phase.is_active() {
                    // Perform migration state recovery
                    self.recover_migration_state(migration_info).await?;
                }
            }
        }
        Ok(())
    }

    /// Get migration information from current session
    pub fn migration_info(&self) -> Option<MigrationInfo> {
        self.current_session
            .lock()
            .unwrap()
            .as_ref()?
            .migration_info
            .clone()
    }

    /// Explicitly load and validate the current user's session.
    /// Call this when a command needs access to an existing session.
    /// This triggers keystore access and may prompt for password if needed.
    #[allow(dead_code)]
    pub fn ensure_session_loaded(&self) -> Result<(), CliError> {
        self.load_session_with_validation()
    }

    /// Load session from disk with comprehensive validation
    fn load_session_with_validation(&self) -> Result<(), CliError> {
        let Some(context) = self.current_user_context() else {
            *self.current_session.lock().unwrap() = None;
            return Ok(());
        };

        if !context.session_file.exists() {
            *self.current_session.lock().unwrap() = None;
            return Ok(());
        }

        let needs_protection = context
            .account_metadata
            .as_ref()
            .map(|metadata| metadata.verifier.is_empty())
            .unwrap_or(true);

        // Ensure the state/device key is available before attempting to decrypt the session file.
        let state_key = match self.ensure_state_key_internal(false) {
            Ok(key) => key,
            Err(err) => {
                ui::warning(&format!(
                    "Local session file was unreadable; it has been cleared. Please log in again. ({})",
                    err
                ));
                self.secure_file_deletion(&context.session_file)?;
                *self.current_session.lock().unwrap() = None;
                self.drop_state_key_memory();
                return Ok(());
            }
        };
        let mut state_key_bytes = [0u8; 32];
        state_key_bytes.copy_from_slice(state_key.as_ref());

        let raw = std::fs::read_to_string(&context.session_file)
            .map_err(|e| CliError::session(format!("Failed to read session file: {}", e)))?;

        let (content, encrypted) = match serde_json::from_str::<ProtectedData>(&raw) {
            Ok(protected) if protected.magic == PROTECTED_DATA_MAGIC => {
                // Try the state/device key first; fall back to account key for legacy data.
                match decrypt_with_ad(&protected, state_key_bytes, SESSION_FILE_AAD) {
                    Ok(decrypted) => {
                        let decoded = String::from_utf8(decrypted).map_err(|e| {
                            CliError::decryption(format!("Session file is not valid UTF-8: {}", e))
                        })?;
                        // If decrypted with the state key, ensure storage is bound to it for downstream operations.
                        context.storage.enable_account_encryption(state_key_bytes);
                        (decoded, true)
                    }
                    Err(_) => {
                        let account_key = self.ensure_account_key_initialized()?;
                        let mut account_bytes = [0u8; 32];
                        account_bytes.copy_from_slice(account_key.as_ref());
                        match decrypt_with_ad(&protected, account_bytes, SESSION_FILE_AAD) {
                            Ok(decrypted) => {
                                let decoded = String::from_utf8(decrypted).map_err(|e| {
                                    CliError::decryption(format!(
                                        "Session file is not valid UTF-8: {}",
                                        e
                                    ))
                                })?;
                                (decoded, true)
                            }
                            Err(_) => {
                                // Unable to decrypt with either key; clear the corrupted session so the user can log in again.
                                self.secure_file_deletion(&context.session_file)?;
                                *self.current_session.lock().unwrap() = None;
                                ui::warning(
                                    "Local session file was unreadable; it has been cleared. Please log in again.",
                                );
                                return Ok(());
                            }
                        }
                    }
                }
            }
            Ok(_) => (raw.clone(), false),
            Err(_) => (raw.clone(), false),
        };

        if !encrypted && needs_protection {
            self.ensure_account_key_initialized()?;
        }

        let mut session: Session = toml::from_str(&content)
            .map_err(|e| CliError::session(format!("Failed to parse session file: {}", e)))?;

        let canonicalization = canonicalize_server_url(&session.server_url);
        let server_changed = canonicalization.canonical != session.server_url;

        if server_changed {
            if let Some(alias) = canonicalization.replaced_alias.as_ref() {
                if canonicalization.upgraded_scheme {
                    ui::info(&format!(
                        "📡 Refreshing session registration: '{}' is now associated with secure '{}'.",
                        alias, canonicalization.canonical
                    ));
                } else {
                    ui::info(&format!(
                        "📡 Refreshing session registration: '{}' is now normalized to '{}'.",
                        alias, canonicalization.canonical
                    ));
                }
            } else {
                ui::info(&format!(
                    "📡 Harmonizing saved server reference to '{}'.",
                    canonicalization.canonical
                ));
            }

            session.server_url = canonicalization.canonical.clone();
        }

        if chrono::Utc::now() >= session.expires_at {
            self.secure_file_deletion(&context.session_file)?;
            *self.current_session.lock().unwrap() = None;
            self.drop_state_key_memory();
            return Ok(());
        }

        if !self.validate_device_binding(&session) {
            self.secure_file_deletion(&context.session_file)?;
            *self.current_session.lock().unwrap() = None;
            return Err(CliError::session(
                "Session device binding validation failed",
            ));
        }

        if !self.validate_session_integrity(&session) {
            self.secure_file_deletion(&context.session_file)?;
            *self.current_session.lock().unwrap() = None;
            return Err(CliError::session("Session integrity validation failed"));
        }

        *self.current_session.lock().unwrap() = Some(session.clone());

        if server_changed {
            self.log_session_event("session_server_canonicalized", &session)?;
            ui::info(&format!(
                "✅ Confirmed session '{}' is registered with {}",
                session.username, session.server_url
            ));
        }

        if server_changed || (!encrypted && self.account_key_locked().is_some()) {
            // Session file was plaintext or encrypted with the legacy password key; migrate.
            let _ = self.ensure_state_key_initialized()?;
            self.save_session_securely()?;
        }

        Ok(())
    }

    /// Save session to disk with encryption and secure permissions
    fn save_session_securely(&self) -> Result<(), CliError> {
        let Some(context) = self.current_user_context() else {
            return Err(CliError::session(
                "Cannot persist session without an active user context",
            ));
        };

        if let Some(session) = &*self.current_session.lock().unwrap() {
            let content = toml::to_string_pretty(session)
                .map_err(|e| CliError::session(format!("Failed to serialize session: {}", e)))?;

            let key = self.ensure_state_key_initialized()?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(key.as_ref());

            let protected = encrypt_with_ad(content.as_bytes(), key_bytes, SESSION_FILE_AAD)
                .map_err(|e| CliError::encryption(format!("Failed to encrypt session: {}", e)))?;

            let serialized = serde_json::to_string_pretty(&protected).map_err(|e| {
                CliError::format(format!("Failed to serialize encrypted session: {}", e))
            })?;

            let temp_file = context.session_file.with_extension("tmp");
            std::fs::write(&temp_file, serialized)
                .map_err(|e| CliError::session(format!("Failed to write session file: {}", e)))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let permissions = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&temp_file, permissions).map_err(|e| {
                    CliError::session(format!("Failed to set secure permissions: {}", e))
                })?;
            }

            std::fs::rename(&temp_file, &context.session_file).map_err(|e| {
                CliError::session(format!("Failed to finalize session file: {}", e))
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let permissions = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&context.session_file, permissions).map_err(|e| {
                    CliError::session(format!("Failed to secure session file: {}", e))
                })?;
            }
        }
        Ok(())
    }

    /// Validate device binding for tamper detection
    fn validate_device_binding(&self, session: &Session) -> bool {
        // In a real implementation, this would check hardware-specific identifiers
        // For now, we'll simulate device binding validation
        let expected_binding = match self.generate_device_binding() {
            Ok(binding) => binding,
            Err(_) => return false,
        };

        // Simple validation - in reality this would be more sophisticated
        session.device_binding.len() == expected_binding.len()
    }

    /// Validate session integrity
    fn validate_session_integrity(&self, session: &Session) -> bool {
        match self.compute_session_integrity(session) {
            Ok(expected_hash) => session.security_metadata.integrity_hash == expected_hash,
            Err(_) => false,
        }
    }

    /// Generate device binding for session security
    fn generate_device_binding(&self) -> Result<String, CliError> {
        // Generate a device-specific binding token
        // In a real implementation, this would incorporate hardware identifiers
        let mut rng = rand::thread_rng();
        let binding_data: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
        Ok(hex::encode(binding_data))
    }

    /// Compute session integrity hash
    fn compute_session_integrity(&self, session: &Session) -> Result<String, CliError> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(session.user_id.as_bytes());
        hasher.update(session.device_id.as_bytes());
        hasher.update(session.token.as_bytes());
        hasher.update(session.created_at.to_rfc3339().as_bytes());

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// Secure file deletion with overwriting
    fn secure_file_deletion(&self, file_path: &Path) -> Result<(), CliError> {
        if file_path.exists() {
            // Overwrite file content before deletion
            let file_size = std::fs::metadata(file_path)
                .map_err(|e| CliError::session(format!("Failed to get file metadata: {}", e)))?
                .len();

            let random_data: Vec<u8> = (0..file_size).map(|_| rand::random::<u8>()).collect();
            std::fs::write(file_path, random_data)
                .map_err(|e| CliError::session(format!("Failed to overwrite file: {}", e)))?;

            // Remove the file
            std::fs::remove_file(file_path)
                .map_err(|e| CliError::session(format!("Failed to remove file: {}", e)))?;
        }
        Ok(())
    }

    /// Log session events for audit trail
    fn log_session_event(&self, event_type: &str, session: &Session) -> Result<(), CliError> {
        // In a real implementation, this would log to a secure audit system
        let _log_entry = format!(
            "[{}] {} - User: {}, Device: {}, Server: {}",
            crate::ui::formatting::format_local_and_utc(&chrono::Utc::now()),
            event_type,
            session.user_id,
            session.device_id,
            session.server_url
        );

        // For now, we'll use debug logging (silent in production)
        Ok(())
    }

    /// Log migration events for audit trail
    fn log_migration_event(
        &self,
        event_type: &str,
        migration_info: &MigrationInfo,
    ) -> Result<(), CliError> {
        let log_entry = format!(
            "[{}] {} - Epoch: {} -> {:?}, Phase: {:?}, Progress: {:.1}%",
            crate::ui::formatting::format_local_and_utc(&chrono::Utc::now()),
            event_type,
            migration_info.current_epoch,
            migration_info.target_epoch,
            migration_info.phase,
            migration_info.progress
        );

        if std::env::var("HYBRIDCIPHER_DEBUG_REKEY")
            .map(|v| !v.is_empty() && v != "0" && v.to_ascii_lowercase() != "false")
            .unwrap_or(false)
        {
            eprintln!("MIGRATION_AUDIT: {}", log_entry);
        }
        Ok(())
    }

    /// Recover migration state after session restoration
    async fn recover_migration_state(
        &self,
        migration_info: &MigrationInfo,
    ) -> Result<(), CliError> {
        // Simulate migration state recovery
        if std::env::var("HYBRIDCIPHER_DEBUG_REKEY")
            .map(|v| !v.is_empty() && v != "0" && v.to_ascii_lowercase() != "false")
            .unwrap_or(false)
        {
            eprintln!(
                "Recovering migration state: {:?} -> {:?} ({:.1}% complete)",
                migration_info.current_epoch, migration_info.target_epoch, migration_info.progress
            );
        }

        // In a real implementation, this would:
        // 1. Reconnect to the server
        // 2. Verify migration state consistency
        // 3. Resume interrupted operations
        // 4. Update local state

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        Ok(())
    }

    /// Get the base configuration directory path
    pub fn config_dir(&self) -> &Path {
        &self.base_config_dir
    }

    /// Get the active user's configuration directory if a user is selected.
    pub fn user_config_dir(&self) -> Option<PathBuf> {
        self.current_user_context()
            .map(|ctx| ctx.config_dir.clone())
    }

    /// Location for the unified recovery artifact for the active user.
    pub fn recovery_artifact_path(&self) -> Result<PathBuf, CliError> {
        let dir = self.user_config_dir().ok_or_else(|| {
            CliError::configuration(
                "No active user context; login is required before using recovery commands.",
            )
        })?;
        Ok(dir.join("recovery_backup.b64"))
    }

    /// Clean up a specific user's encrypted session directory after password reset.
    /// This removes all encrypted data that was protected with the old password.
    #[allow(dead_code)]
    pub async fn cleanup_user_directory(
        &self,
        email: &str,
        server_url: &str,
    ) -> Result<(), CliError> {
        let user_id = get_user_storage_id(email, server_url);
        let user_dir = self.base_config_dir.join(USERS_DIR).join(&user_id);

        if user_dir.exists() {
            tokio::fs::remove_dir_all(&user_dir)
                .await
                .map_err(|e| CliError::session(format!("Failed to clean user directory: {}", e)))?;
            tracing::info!(user_id = %user_id, "Cleaned encrypted session directory after password reset");
            Ok(())
        } else {
            // Directory doesn't exist, nothing to clean
            Ok(())
        }
    }

    fn normalized_join_card_identifier(identifier: &str) -> String {
        let mut slug = String::new();
        let mut prev_was_sep = false;

        for ch in identifier.trim().chars() {
            if ch.is_ascii_alphanumeric() {
                slug.push(ch.to_ascii_lowercase());
                prev_was_sep = false;
            } else if !prev_was_sep {
                slug.push('_');
                prev_was_sep = true;
            }
        }

        let slug = slug.trim_matches('_').to_string();
        if slug.is_empty() {
            "member".to_string()
        } else {
            slug
        }
    }

    fn join_card_storage_dir(&self) -> Result<PathBuf, CliError> {
        let Some(context) = self.current_user_context() else {
            return Err(CliError::session(
                "No active user context. Log in before managing join cards.",
            ));
        };

        let dir = context.config_dir.join("join_cards");
        fs::create_dir_all(&dir).map_err(|e| {
            CliError::session(format!(
                "Failed to prepare join card storage directory: {}",
                e
            ))
        })?;
        Ok(dir)
    }

    fn join_card_cache_path(&self, identifier: &str) -> Result<PathBuf, CliError> {
        let dir = self.join_card_storage_dir()?;
        let slug = Self::normalized_join_card_identifier(identifier);
        Ok(dir.join(format!("{}.json.enc", slug)))
    }

    pub fn suggested_join_card_path(&self, identifier: &str) -> Option<PathBuf> {
        self.current_user_context().map(|ctx| {
            let slug = Self::normalized_join_card_identifier(identifier);
            ctx.config_dir
                .join("join_cards")
                .join(format!("{}.json", slug))
        })
    }

    pub fn load_cached_join_card(&self, identifier: &str) -> Result<Option<String>, CliError> {
        if self.current_user_context().is_none() {
            return Ok(None);
        }

        let path = self.join_card_cache_path(identifier)?;

        if !path.exists() {
            return Ok(None);
        }

        match self.read_protected_file(&path, JOIN_CARD_CACHE_FILE_AAD)? {
            Some((data, _)) => Ok(Some(data)),
            None => Ok(None),
        }
    }

    pub fn cache_join_card(
        &self,
        identifier: &str,
        join_card_json: &str,
    ) -> Result<PathBuf, CliError> {
        let path = self.join_card_cache_path(identifier)?;
        self.write_protected_file(&path, join_card_json, JOIN_CARD_CACHE_FILE_AAD)?;
        Ok(path)
    }

    /// Load all cached join cards from the secure store for the active user context.
    pub fn load_cached_join_cards(&self) -> Result<Vec<ClientJoinCard>, CliError> {
        let mut cards = Vec::new();
        let dir = match self.join_card_storage_dir() {
            Ok(path) => path,
            Err(err) => return Err(err),
        };

        if !dir.exists() {
            return Ok(cards);
        }

        for entry in fs::read_dir(&dir)
            .map_err(|e| CliError::io(format!("Failed to list cached join cards: {}", e)))?
        {
            let entry = entry
                .map_err(|e| CliError::io(format!("Failed to read join card entry: {}", e)))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let Some((data, _was_encrypted)) =
                self.read_protected_file(&path, JOIN_CARD_CACHE_FILE_AAD)?
            else {
                continue;
            };

            if data.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<ClientJoinCard>(&data) {
                Ok(card) => cards.push(card),
                Err(err) => {
                    tracing::warn!(
                        "Cached join card at {} failed to parse: {}",
                        path.display(),
                        err
                    );
                }
            }
        }

        Ok(cards)
    }

    /// Find a cached join card matching the specified user and device identifiers.
    pub fn find_cached_join_card_for_device(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<ClientJoinCard>, CliError> {
        let cached = self.load_cached_join_cards()?;
        for card in cached {
            if card.user_id.to_string() == user_id && card.device_id == device_id {
                return Ok(Some(card));
            }
        }
        Ok(None)
    }

    /// Ensure that a join card has a corresponding pinned key entry.
    ///
    /// This method is non-interactive: it verifies existing pins and attempts to
    /// restore missing entries from the encrypted join card cache. Callers can
    /// use the returned state to decide whether to prompt the operator.
    pub async fn check_or_restore_join_card_pin(
        &self,
        join_card: &ClientJoinCard,
    ) -> Result<JoinCardPinState, CliError> {
        join_card.verify_signature().map_err(|e| {
            CliError::PinningFailed(format!("Join card signature verification failed: {}", e))
        })?;
        if !join_card.is_valid() {
            return Err(CliError::PinningFailed(
                "Join card has expired; request a fresh join card before proceeding.".to_string(),
            ));
        }

        let storage = self.current_storage()?;
        let pinning_config = load_pinning_config_for_storage(storage.as_ref()).await?;
        let pinning_store = PinningStore::new(storage, pinning_config.clone());

        let user_id = join_card.user_id.to_string();
        let device_id = join_card.device_id.clone();
        let identity_key_bytes: [u8; 32] = join_card
            .identity_public
            .as_slice()
            .try_into()
            .map_err(|_| {
                CliError::invalid_input(
                    "Join card identity key must be exactly 32 bytes (Ed25519)".to_string(),
                )
            })?;

        let existing_pin = match pinning_store.get_pinned_key(&user_id, &device_id).await {
            Ok(pin) => pin,
            Err(PinningError::ExpiredPin { pinned_at }) => {
                return Ok(JoinCardPinState::Expired(pinned_at));
            }
            Err(e) => {
                return Err(CliError::PinningFailed(format!(
                    "Failed to load pinned key: {}",
                    e
                )))
            }
        };

        match existing_pin {
            Some(existing_pin) => {
                if existing_pin.identity_public_key != identity_key_bytes {
                    return Err(CliError::PinningFailed(format!(
                        "Pinned fingerprint {} does not match join card fingerprint {} for {}:{}",
                        existing_pin.fingerprint,
                        generate_fingerprint(&identity_key_bytes),
                        user_id,
                        device_id
                    )));
                }
                if existing_pin.verified {
                    return Ok(JoinCardPinState::AlreadyPinned);
                }
                return Ok(JoinCardPinState::Unverified { auto_pinned: false });
            }
            None => {}
        }

        if let Some(cached_card) = self.find_cached_join_card_for_device(&user_id, &device_id)? {
            if cached_card.identity_public == join_card.identity_public {
                let verifying_key = VerifyingKey::from_bytes(&identity_key_bytes).map_err(|e| {
                    CliError::invalid_input(format!("Join card identity key is invalid: {}", e))
                })?;

                let note = Some(format!(
                    "Restored automatically from cached verification on {}",
                    Utc::now().to_rfc3339()
                ));

                pinning_store
                    .pin_key(
                        &user_id,
                        &device_id,
                        &verifying_key,
                        PinningMethod::Manual,
                        note,
                    )
                    .await
                    .map_err(|e| {
                        CliError::PinningFailed(format!(
                            "Failed to restore pin from cache for {}:{}: {}",
                            user_id, device_id, e
                        ))
                    })?;

                return Ok(JoinCardPinState::RestoredFromCache);
            }
        }

        Ok(JoinCardPinState::Missing)
    }

    /// Optionally auto-pin a join card without verification when missing.
    pub async fn check_or_restore_join_card_pin_with_auto_pin(
        &self,
        join_card: &ClientJoinCard,
        auto_pin: bool,
    ) -> Result<JoinCardPinState, CliError> {
        let state = self.check_or_restore_join_card_pin(join_card).await?;
        if !auto_pin {
            return Ok(state);
        }

        match state {
            JoinCardPinState::Missing => {
                self.auto_pin_join_card_unverified(join_card).await?;
                Ok(JoinCardPinState::Unverified { auto_pinned: true })
            }
            other => Ok(other),
        }
    }

    async fn auto_pin_join_card_unverified(
        &self,
        join_card: &ClientJoinCard,
    ) -> Result<(), CliError> {
        let storage = self.current_storage()?;
        let pinning_config = load_pinning_config_for_storage(storage.as_ref()).await?;
        let pinning_store = PinningStore::new(storage, pinning_config.clone());

        let identity_key_bytes: [u8; 32] = join_card
            .identity_public
            .as_slice()
            .try_into()
            .map_err(|_| {
                CliError::invalid_input(
                    "Join card identity key must be exactly 32 bytes (Ed25519)".to_string(),
                )
            })?;

        let verifying_key = VerifyingKey::from_bytes(&identity_key_bytes).map_err(|e| {
            CliError::invalid_input(format!("Join card identity key is invalid: {}", e))
        })?;

        let note = Some(format!(
            "Auto-pinned from join card (unverified) on {}",
            Utc::now().to_rfc3339()
        ));

        pinning_store
            .pin_key_unverified(
                &join_card.user_id.to_string(),
                &join_card.device_id,
                &verifying_key,
                note,
            )
            .await
            .map_err(|e| {
                CliError::PinningFailed(format!(
                    "Failed to auto-pin join card for {}:{}: {}",
                    join_card.user_id, join_card.device_id, e
                ))
            })?;

        Ok(())
    }

    /// Ensure the current device is pinned and marked verified using local keys.
    pub async fn ensure_current_device_pin_verified(
        &self,
        trigger: &str,
    ) -> Result<CurrentDevicePinState, CliError> {
        let session = self.require_auth()?;
        let user_id = session.user_id.clone();
        let device_id = session.device_id.clone();
        let user_uuid = uuid::Uuid::parse_str(&user_id).map_err(|e| {
            CliError::configuration(format!(
                "Active session contains invalid user identifier '{}': {}",
                user_id, e
            ))
        })?;

        let invitation_keypair = self.get_or_create_invitation_keypair().await?;
        if invitation_keypair.device_id != device_id {
            return Err(CliError::PinningFailed(format!(
                "Local invitation keypair device ID '{}' does not match session device ID '{}'",
                invitation_keypair.device_id, device_id
            )));
        }

        if !invitation_keypair.is_valid() {
            return Err(CliError::PinningFailed(
                "Local invitation keypair has expired; refresh the join card before continuing."
                    .to_string(),
            ));
        }

        let join_card = invitation_keypair
            .create_join_card(user_uuid)
            .map_err(|e| {
                CliError::PinningFailed(format!("Failed to create local join card: {}", e))
            })?;
        join_card.verify_signature().map_err(|e| {
            CliError::PinningFailed(format!(
                "Local join card signature verification failed: {}",
                e
            ))
        })?;
        if !join_card.is_valid() {
            return Err(CliError::PinningFailed(
                "Local join card has expired; refresh the join card before continuing.".to_string(),
            ));
        }

        let identity_key_bytes: [u8; 32] = join_card
            .identity_public
            .as_slice()
            .try_into()
            .map_err(|_| {
                CliError::invalid_input(
                    "Join card identity key must be exactly 32 bytes (Ed25519)".to_string(),
                )
            })?;
        let verifying_key = VerifyingKey::from_bytes(&identity_key_bytes).map_err(|e| {
            CliError::invalid_input(format!("Join card identity key is invalid: {}", e))
        })?;

        let storage = self.current_storage()?;
        let pinning_config = load_pinning_config_for_storage(storage.as_ref()).await?;
        let pinning_store = PinningStore::new(storage, pinning_config.clone());

        let mut expired_pin = None;
        let existing_pin = match pinning_store.get_pinned_key(&user_id, &device_id).await {
            Ok(pin) => pin,
            Err(PinningError::ExpiredPin { pinned_at }) => {
                expired_pin = Some(pinned_at);
                None
            }
            Err(e) => {
                return Err(CliError::PinningFailed(format!(
                    "Failed to load pinned key: {}",
                    e
                )))
            }
        };

        let mut note = format!(
            "Auto-verified local device during {} on {}",
            trigger,
            Utc::now().to_rfc3339()
        );
        if expired_pin.is_some() {
            note = format!("Re-pinned local device after expiry. {}", note);
        }

        let merge_notes = |existing: Option<String>, extra: &str| -> Option<String> {
            let mut combined = existing.unwrap_or_default();
            if combined.trim().is_empty() {
                combined = extra.to_string();
            } else if !combined.contains(extra) {
                combined.push_str(" | ");
                combined.push_str(extra);
            }
            if combined.trim().is_empty() {
                None
            } else {
                Some(combined)
            }
        };

        match existing_pin {
            Some(existing_pin) => {
                if existing_pin.identity_public_key != identity_key_bytes {
                    return Err(CliError::PinningFailed(format!(
                        "Pinned fingerprint {} does not match local join card fingerprint {} for {}:{}",
                        existing_pin.fingerprint,
                        generate_fingerprint(&identity_key_bytes),
                        user_id,
                        device_id
                    )));
                }
                if existing_pin.verified {
                    return Ok(CurrentDevicePinState::AlreadyVerified);
                }

                let updated = pinning_store
                    .mark_pin_verified(&user_id, &device_id, PinningMethod::Manual)
                    .await
                    .map_err(|e| {
                        CliError::PinningFailed(format!(
                            "Failed to verify local pin for {}:{}: {}",
                            user_id, device_id, e
                        ))
                    })?;

                let existing_notes = updated.notes.clone();
                let merged_notes = merge_notes(existing_notes.clone(), &note);
                if merged_notes != existing_notes {
                    pinning_store
                        .update_pin_notes(&user_id, &device_id, merged_notes)
                        .await
                        .map_err(|e| {
                            CliError::PinningFailed(format!(
                                "Failed to update local pin notes for {}:{}: {}",
                                user_id, device_id, e
                            ))
                        })?;
                }

                Ok(CurrentDevicePinState::PromotedUnverified)
            }
            None => {
                pinning_store
                    .pin_key(
                        &user_id,
                        &device_id,
                        &verifying_key,
                        PinningMethod::Manual,
                        Some(note),
                    )
                    .await
                    .map_err(|e| {
                        CliError::PinningFailed(format!(
                            "Failed to pin local device for {}:{}: {}",
                            user_id, device_id, e
                        ))
                    })?;
                Ok(CurrentDevicePinState::PinnedVerified)
            }
        }
    }

    /// Create an authenticated client from current session
    pub async fn create_client(
        &self,
    ) -> Result<
        Client<
            hybridcipher_client::storage::LocalFsStorage,
            hybridcipher_client::network::MockNetwork,
        >,
        CliError,
    > {
        self.create_client_with_config_overrides(|_| {}).await
    }

    /// Create an authenticated client with config overrides.
    pub async fn create_client_with_config_overrides<F>(
        &self,
        apply_overrides: F,
    ) -> Result<
        Client<
            hybridcipher_client::storage::LocalFsStorage,
            hybridcipher_client::network::MockNetwork,
        >,
        CliError,
    >
    where
        F: FnOnce(&mut ClientConfig),
    {
        let session = self.require_auth()?;

        // Use persistent on-disk storage so client state survives across CLI runs
        let storage = self.current_storage()?;
        let network = hybridcipher_client::network::MockNetwork::new();

        // Get or create device identity for the client
        let device_identity = if let Some(keypair_data) = &session.device_keypair {
            // Deserialize existing keypair from session
            let private_key_bytes =
                general_purpose::STANDARD
                    .decode(keypair_data)
                    .map_err(|e| {
                        CliError::authentication(format!("Failed to decode device keypair: {}", e))
                    })?;

            hybridcipher_crypto::signatures::Ed25519KeyPair::from_bytes(&private_key_bytes)
                .map_err(|e| {
                    CliError::authentication(format!("Failed to restore device keypair: {}", e))
                })?
        } else {
            // Check if device_keypair file exists on disk first
            let context = self
                .current_user_context()
                .ok_or_else(|| CliError::session("No authenticated user context"))?;
            let keypair_file = context.config_dir.join("device_keypair");

            if keypair_file.exists() {
                // Load existing keypair from file (encrypted or legacy plaintext)
                let (keypair_data_raw, was_encrypted) = self
                    .read_protected_file(&keypair_file, DEVICE_KEYPAIR_FILE_AAD)?
                    .ok_or_else(|| {
                        CliError::session("Device keypair file missing despite existence check")
                    })?;

                let keypair_data = keypair_data_raw.trim().to_string();

                let private_key_bytes =
                    general_purpose::STANDARD
                        .decode(&keypair_data)
                        .map_err(|e| {
                            CliError::authentication(format!(
                                "Failed to decode device keypair from file: {}",
                                e
                            ))
                        })?;

                // Migrate legacy plaintext into encrypted form immediately.
                if !was_encrypted {
                    self.write_protected_file(
                        &keypair_file,
                        &keypair_data,
                        DEVICE_KEYPAIR_FILE_AAD,
                    )?;
                }

                // Update session with the keypair from file
                self.update_device_keypair(keypair_data)?;

                hybridcipher_crypto::signatures::Ed25519KeyPair::from_bytes(&private_key_bytes)
                    .map_err(|e| {
                        CliError::authentication(format!(
                            "Failed to restore device keypair from file: {}",
                            e
                        ))
                    })?
            } else {
                // Generate new keypair and store it both in session and file
                let new_keypair = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
                let private_key_bytes = new_keypair.private_key_bytes();
                let keypair_data = general_purpose::STANDARD.encode(&private_key_bytes);

                // Save to file using account protection
                self.write_protected_file(&keypair_file, &keypair_data, DEVICE_KEYPAIR_FILE_AAD)?;

                // Update session with new keypair
                self.update_device_keypair(keypair_data)?;
                new_keypair
            }
        };

        // Create client honoring active transparency configuration
        let mut client_config = self.current_client_config();
        apply_overrides(&mut client_config);
        let automation_enabled = client_config.migration_automation_enabled;
        let client = Client::with_client_config(
            device_identity,
            storage,
            std::sync::Arc::new(network),
            client_config,
        );

        if automation_enabled {
            if let Err(err) = client.auto_sync_welcome_messages("startup").await {
                tracing::warn!(
                    "Automatic Welcome sync on client startup failed: {}. Local cache may be stale.",
                    err
                );
            }
        }

        if let Ok(Some(active_group)) = self.current_group_id().await {
            if let Err(err) = client.use_group(active_group).await {
                tracing::warn!(
                    "Failed to apply cached group context {} during client initialization: {}",
                    active_group,
                    err
                );
            }
        }

        if automation_enabled && client.is_migrating().await {
            if let Err(err) = client.rekey_status().await {
                tracing::warn!(
                    "Unable to refresh rekey status during client initialization: {}",
                    err
                );
            }
        }

        Ok(client)
    }

    /// Create a client for local operations (doesn't require authentication)
    pub async fn create_local_client(
        &self,
    ) -> Result<
        Client<
            hybridcipher_client::storage::LocalFsStorage,
            hybridcipher_client::network::MockNetwork,
        >,
        CliError,
    > {
        // Use persistent storage and create network implementation
        let storage = self.current_storage()?;
        let network = hybridcipher_client::network::MockNetwork::new();

        // Get or create persistent device identity
        let device_identity = self.get_or_create_device_keypair().await?;

        // Create client with persistent storage
        let client_config = self.current_client_config();
        let client = Client::with_client_config(
            device_identity,
            storage,
            std::sync::Arc::new(network),
            client_config,
        );

        if let Ok(Some(active_group)) = self.current_group_id().await {
            if let Err(err) = client.use_group(active_group).await {
                tracing::warn!(
                    "Failed to apply cached group context {}: {}",
                    active_group,
                    err
                );
            }
        }

        Ok(client)
    }

    /// Get or create a persistent device keypair (for local operations)
    pub async fn get_or_create_device_keypair(
        &self,
    ) -> Result<hybridcipher_crypto::signatures::Ed25519KeyPair, CliError> {
        let context = self.current_user_context().ok_or_else(|| {
            CliError::session("No active user context configured for device keypair access")
        })?;

        // Try to load from persistent storage first
        let keypair_file = context.config_dir.join("device_keypair");

        if keypair_file.exists() {
            let (keypair_data_raw, was_encrypted) = self
                .read_protected_file(&keypair_file, DEVICE_KEYPAIR_FILE_AAD)?
                .ok_or_else(|| {
                    CliError::session("Device keypair file missing despite existence check")
                })?;

            let keypair_data = keypair_data_raw.trim().to_string();

            if !was_encrypted {
                self.write_protected_file(&keypair_file, &keypair_data, DEVICE_KEYPAIR_FILE_AAD)?;
            }

            let private_key_bytes =
                general_purpose::STANDARD
                    .decode(&keypair_data)
                    .map_err(|e| {
                        CliError::session(format!("Failed to decode device keypair: {}", e))
                    })?;

            hybridcipher_crypto::signatures::Ed25519KeyPair::from_bytes(&private_key_bytes)
                .map_err(|e| CliError::session(format!("Failed to restore device keypair: {}", e)))
        } else {
            // Generate new keypair and save it
            let new_keypair = hybridcipher_crypto::signatures::Ed25519KeyPair::generate();
            let private_key_bytes = new_keypair.private_key_bytes();
            let keypair_data = general_purpose::STANDARD.encode(&private_key_bytes);

            // Ensure config directory exists
            std::fs::create_dir_all(&context.config_dir).map_err(|e| {
                CliError::session(format!("Failed to create config directory: {}", e))
            })?;

            self.write_protected_file(&keypair_file, &keypair_data, DEVICE_KEYPAIR_FILE_AAD)?;

            Ok(new_keypair)
        }
    }

    /// Get or create a persistent invitation keypair (for receiving Welcome messages)
    pub async fn get_or_create_invitation_keypair(
        &self,
    ) -> Result<hybridcipher_client::invitation::InvitationKeyPair, CliError> {
        use hybridcipher_client::invitation::InvitationKeyPair;

        let context = self.current_user_context().ok_or_else(|| {
            CliError::session("No active user context configured for invitation keypair access")
        })?;

        // Try to load from persistent storage first
        let keypair_file = context.config_dir.join("invitation_keypair.json");

        if keypair_file.exists() {
            let primary = self.read_protected_file(&keypair_file, INVITATION_KEYPAIR_FILE_AAD);

            let (keypair_data_raw, was_encrypted, used_legacy) = match primary {
                Ok(Some(data)) => (data.0, data.1, false),
                Ok(None) => {
                    return Err(CliError::session(
                        "Invitation keypair file missing despite existence check",
                    ))
                }
                Err(CliError::Decryption { .. }) => {
                    let legacy = self
                        .read_protected_file(&keypair_file, LEGACY_INVITATION_KEYPAIR_FILE_AAD)?
                        .ok_or_else(|| {
                            CliError::session(
                                "Invitation keypair file missing despite existence check",
                            )
                        })?;
                    (legacy.0, legacy.1, true)
                }
                Err(err) => return Err(err),
            };

            if !was_encrypted || used_legacy {
                self.write_protected_file(
                    &keypair_file,
                    &keypair_data_raw,
                    INVITATION_KEYPAIR_FILE_AAD,
                )?;
            }

            serde_json::from_str::<InvitationKeyPair>(&keypair_data_raw).map_err(|e| {
                CliError::session(format!("Failed to deserialize invitation keypair: {}", e))
            })
        } else {
            // Use device_id from current session if available, otherwise generate from device keypair
            let device_id = if let Some(session) = &*self.current_session.lock().unwrap() {
                session.device_id.clone()
            } else {
                // Fallback: Generate device ID from device identity public key
                let device_identity = self.get_or_create_device_keypair().await?;
                let device_public_key = device_identity.public_key_bytes();
                format!("device_{}", hex::encode(&device_public_key[..8]))
            };

            // Generate new invitation keypair and save it
            let new_keypair = InvitationKeyPair::generate(device_id).map_err(|e| {
                CliError::session(format!("Failed to generate invitation keypair: {}", e))
            })?;

            let keypair_data = serde_json::to_string_pretty(&new_keypair).map_err(|e| {
                CliError::session(format!("Failed to serialize invitation keypair: {}", e))
            })?;

            // Ensure config directory exists
            std::fs::create_dir_all(&context.config_dir).map_err(|e| {
                CliError::session(format!("Failed to create config directory: {}", e))
            })?;

            self.write_protected_file(&keypair_file, &keypair_data, INVITATION_KEYPAIR_FILE_AAD)?;

            Ok(new_keypair)
        }
    }

    /// Update the device keypair in the current session
    fn update_device_keypair(&self, keypair_data: String) -> Result<(), CliError> {
        let mut session_guard = self
            .current_session
            .lock()
            .map_err(|_| CliError::session("Failed to acquire session lock"))?;

        if let Some(session) = session_guard.as_mut() {
            session.device_keypair = Some(keypair_data);
            // Save the updated session
            drop(session_guard);
            self.save_session_securely()?;
        }

        Ok(())
    }

    /// Fetch second-party verification status for a specific device/user, if present.
    pub async fn get_second_party_status(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<(String, Option<String>)>, CliError> {
        let session = self.require_auth()?;
        let client = reqwest::Client::new();
        let url = format!(
            "{}/api/v1/pin/second-party/status?user_id={}&device_id={}",
            session.server_url.trim_end_matches('/'),
            user_id,
            device_id
        );

        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to fetch verifier status: {}", e)))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("second_party_status")?;
            return Err(CliError::NotAuthenticated(
                "Session expired. Please login again.".into(),
            ));
        }
        if resp.status() == StatusCode::FORBIDDEN {
            return Ok(None);
        }
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::network(format!(
                "Verifier status request failed ({}): {}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct StatusResp {
            status: String,
            #[allow(dead_code)]
            next_verifier_index: Option<i32>,
            #[serde(default)]
            last_error: Option<String>,
        }

        let parsed: Option<StatusResp> = resp
            .json()
            .await
            .map_err(|e| CliError::network(format!("Invalid verifier status response: {}", e)))?;

        Ok(parsed.map(|s| (s.status, s.last_error)))
    }

    pub async fn list_second_party_statuses(
        &self,
        group_id: Option<&str>,
    ) -> Result<Vec<SecondPartyStatusEntry>, CliError> {
        let session = self.require_auth()?;
        let client = reqwest::Client::new();
        let mut url = format!(
            "{}/api/v1/pin/second-party/statuses",
            session.server_url.trim_end_matches('/')
        );
        if let Some(group_id) = group_id {
            url.push_str("?group_id=");
            url.push_str(&urlencoding::encode(group_id));
        }

        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to fetch verifier statuses: {}", e)))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("second_party_statuses")?;
            return Err(CliError::NotAuthenticated(
                "Session expired. Please login again.".into(),
            ));
        }
        if resp.status() == StatusCode::FORBIDDEN {
            return Err(CliError::permission(
                "Not authorized to view second-party statuses.".to_string(),
            ));
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::network(format!(
                "Verifier statuses request failed ({}): {}",
                status, body
            )));
        }

        let parsed: Vec<SecondPartyStatusEntry> = resp
            .json()
            .await
            .map_err(|e| CliError::network(format!("Invalid verifier status response: {}", e)))?;

        Ok(parsed)
    }

    /// Add a member using direct HTTP API call to HybridCipher server
    pub async fn add_member_http(
        &self,
        member_name: &str,
        welcome_messages: Vec<serde_json::Value>,
    ) -> Result<(), CliError> {
        let session = self.require_auth()?;

        // Use the production HybridCipher server
        let server_url = "https://api.hybridcipher.com";

        // Create HTTP client
        let client = reqwest::Client::new();

        // Get the current active group from client state instead of default group
        let group_id = match self.ensure_active_group().await {
            Ok(id) => id,
            Err(_) => {
                // Fallback to get_or_create_default_group if no active group is set
                match self
                    .get_or_create_default_group(&client, &session.token, server_url)
                    .await
                {
                    Ok(id) => id,
                    Err(e) => return Err(e),
                }
            }
        };

        // Step 2: Add member to the group using the proper API endpoint
        // Based on the server integration guide, the endpoint is /api/v1/groups/:id/members

        // Determine if the member_name is a UUID or an email/username
        // Prioritize email format - if it contains @ it's an email, regardless of whether it could be parsed as UUID
        if welcome_messages.is_empty() {
            return Err(CliError::invalid_input(
                "Welcome payload required. Use 'hybridcipher welcome generate' to create one",
            ));
        }

        let mut add_member_request = serde_json::Map::new();

        if member_name.contains('@') {
            add_member_request.insert(
                "email".into(),
                serde_json::Value::String(member_name.to_string()),
            );
            add_member_request.insert(
                "invitation_message".into(),
                serde_json::Value::String(format!("Welcome to the group, {}!", member_name)),
            );
        } else if let Ok(user_id) = uuid::Uuid::parse_str(member_name) {
            add_member_request.insert("user_id".into(), serde_json::json!(user_id));
            add_member_request.insert(
                "invitation_message".into(),
                serde_json::Value::String("Welcome to the group!".into()),
            );
        } else {
            let email = format!("{}@example.com", member_name);
            add_member_request.insert("email".into(), serde_json::json!(email));
            add_member_request.insert(
                "invitation_message".into(),
                serde_json::Value::String(format!("Welcome to the group, {}!", member_name)),
            );
        }

        add_member_request.insert("role".into(), serde_json::Value::String("member".into()));
        add_member_request.insert(
            "welcome_messages".into(),
            serde_json::Value::Array(welcome_messages),
        );

        let add_member_request = serde_json::Value::Object(add_member_request);

        let response = client
            .post(&format!(
                "{}/api/v1/groups/{}/members",
                server_url, group_id
            ))
            .header("Authorization", &format!("Bearer {}", session.token))
            .header("Content-Type", "application/json")
            .json(&add_member_request)
            .send()
            .await
            .map_err(|e| CliError::network(format!("HTTP request failed: {}", e)))?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("add_member_http")?;
            return Err(CliError::authentication(
                "Authentication token rejected by the server. Please login again with 'hybridcipher login <username>'.",
            ));
        }

        if response.status().is_success() {
            let response_body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| CliError::network(format!("Invalid server response: {}", e)))?;

            println!("✓ Successfully added member '{}' to group", member_name);
            if let Some(member_info) = response_body.get("member") {
                if let Some(user_id) = member_info.get("user_id") {
                    println!("ℹ Member ID: {}", user_id);
                }
                if let Some(invitation_status) = member_info.get("invitation_status") {
                    println!("ℹ Invitation status: {}", invitation_status);
                }
            }
            Ok(())
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(CliError::network(format!(
                "Failed to add member '{}': {} - {}",
                member_name, status, error_text
            )))
        }
    }

    /// Report unverified devices for a group to the server.
    pub async fn report_unverified_devices(
        &self,
        group_id: uuid::Uuid,
        devices: &[UnverifiedDeviceReport],
    ) -> Result<usize, CliError> {
        if devices.is_empty() {
            return Ok(0);
        }

        let session = self.require_auth()?;
        let client = reqwest::Client::new();

        let base_url = session.server_url.trim_end_matches('/');
        let endpoint = if base_url.ends_with("/api/v1") {
            format!("{}/groups/{}/unverified-devices", base_url, group_id)
        } else {
            format!("{}/api/v1/groups/{}/unverified-devices", base_url, group_id)
        };

        #[derive(Serialize)]
        struct UnverifiedDeviceReportRequest {
            devices: Vec<UnverifiedDeviceReport>,
        }

        let request = UnverifiedDeviceReportRequest {
            devices: devices.to_vec(),
        };

        let response = client
            .post(&endpoint)
            .bearer_auth(&session.token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                CliError::network(format!("Failed to report unverified devices: {}", e))
            })?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("report_unverified_devices")?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(CliError::network(format!(
                "Failed to report unverified devices (status {}): {}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct UnverifiedDeviceReportResponse {
            recorded: usize,
        }

        let parsed: UnverifiedDeviceReportResponse = response
            .json()
            .await
            .map_err(|e| CliError::network(format!("Invalid report response: {}", e)))?;

        Ok(parsed.recorded)
    }

    /// List unverified devices for a group from the server.
    pub async fn list_unverified_devices(
        &self,
        group_id: uuid::Uuid,
        include_resolved: bool,
    ) -> Result<Vec<UnverifiedDeviceInfo>, CliError> {
        let session = self.require_auth()?;
        let client = reqwest::Client::new();

        let base_url = session.server_url.trim_end_matches('/');
        let mut endpoint = if base_url.ends_with("/api/v1") {
            format!("{}/groups/{}/unverified-devices", base_url, group_id)
        } else {
            format!("{}/api/v1/groups/{}/unverified-devices", base_url, group_id)
        };
        if include_resolved {
            endpoint.push_str("?include_resolved=true");
        }

        let response = client
            .get(&endpoint)
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to fetch unverified devices: {}", e)))?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("list_unverified_devices")?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(CliError::network(format!(
                "Failed to fetch unverified devices (status {}): {}",
                status, body
            )));
        }

        let parsed: Vec<UnverifiedDeviceInfo> = response
            .json()
            .await
            .map_err(|e| CliError::network(format!("Invalid list response: {}", e)))?;

        Ok(parsed)
    }

    /// Resolve an unverified device entry across admin groups (or a specific group if provided).
    pub async fn resolve_unverified_device(
        &self,
        user_id: &str,
        device_id: &str,
        group_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<ResolveUnverifiedResult, CliError> {
        let session = self.require_auth()?;
        let client = reqwest::Client::new();

        let base_url = session.server_url.trim_end_matches('/');
        let endpoint = if base_url.ends_with("/api/v1") {
            format!("{}/unverified-devices/resolve", base_url)
        } else {
            format!("{}/api/v1/unverified-devices/resolve", base_url)
        };

        #[derive(Serialize)]
        struct ResolveRequest<'a> {
            user_id: &'a str,
            device_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            group_id: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: Option<&'a str>,
        }

        #[derive(Deserialize)]
        struct ResolveResponse {
            #[serde(default)]
            groups: Vec<uuid::Uuid>,
        }

        let request = ResolveRequest {
            user_id,
            device_id,
            group_id,
            reason,
        };

        let response = client
            .post(&endpoint)
            .bearer_auth(&session.token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                CliError::network(format!("Failed to resolve unverified device: {}", e))
            })?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("resolve_unverified_device")?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if response.status() == StatusCode::FORBIDDEN {
            return Ok(ResolveUnverifiedResult { groups: Vec::new() });
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(CliError::network(format!(
                "Failed to resolve unverified device (status {}): {}",
                status, body
            )));
        }

        let parsed: ResolveResponse = response
            .json()
            .await
            .map_err(|e| CliError::network(format!("Invalid resolve response: {}", e)))?;

        Ok(ResolveUnverifiedResult {
            groups: parsed.groups,
        })
    }

    /// Remove a member using direct HTTP API call to HybridCipher server
    pub async fn remove_member_http(
        &self,
        group_id: uuid::Uuid,
        member_id: uuid::Uuid,
    ) -> Result<(), CliError> {
        let session = self.require_auth()?;
        let base_url = session.server_url.trim_end_matches('/');
        let api_base = if base_url.ends_with("/api/v1") {
            base_url.to_string()
        } else {
            format!("{}/api/v1", base_url)
        };
        let client = reqwest::Client::new();
        let response = client
            .delete(&format!(
                "{}/groups/{}/members/{}",
                api_base, group_id, member_id
            ))
            .header("Authorization", &format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| CliError::network(format!("HTTP request failed: {}", e)))?;

        match response.status() {
            StatusCode::UNAUTHORIZED => {
                self.invalidate_session("remove_member_http")?;
                Err(CliError::authentication(
                    "Authentication token rejected by the server. Please login again with 'hybridcipher login <username>'.",
                ))
            }
            StatusCode::FORBIDDEN => {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                Err(CliError::permission(format!(
                    "Server rejected member removal request: {}",
                    body.trim()
                )))
            }
            StatusCode::NOT_FOUND => Err(CliError::not_found(
                "Member or group not found. Verify the group context and member identifier.",
            )),
            status if status.is_success() => Ok(()),
            status => {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                Err(CliError::network(format!(
                    "Failed to remove member (status {}): {}",
                    status, body
                )))
            }
        }
    }

    pub async fn publish_join_card(&self, join_card: &MessagesJoinCard) -> Result<(), CliError> {
        let session = self.require_auth()?;
        let client = reqwest::Client::new();

        let base_url = session.server_url.trim_end_matches('/');
        let endpoint = if base_url.ends_with("/api/v1") {
            format!("{}/directory/join-cards", base_url)
        } else {
            format!("{}/api/v1/directory/join-cards", base_url)
        };

        let request = DirectoryUploadJoinCardRequest {
            join_card: join_card.clone(),
        };

        let response = client
            .post(&endpoint)
            .bearer_auth(&session.token)
            .json(&request)
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to publish join card: {}", e)))?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("publish_join_card")?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(CliError::network(format!(
                "Server rejected join card upload: {} - {}",
                status, error_text
            )));
        }

        Ok(())
    }

    /// Ensure the current device has a join card published to the server directory.
    pub async fn ensure_join_card_published_for_current_device(
        &self,
    ) -> Result<JoinCardPublishState, CliError> {
        let session = self.require_auth()?;
        let user_id = uuid::Uuid::parse_str(&session.user_id).map_err(|e| {
            CliError::configuration(format!(
                "Active session contains invalid user identifier '{}': {}",
                session.user_id, e
            ))
        })?;

        let device_id = session.device_id.clone();

        if let Ok(server_cards) = self.fetch_join_cards_for_user_id(&user_id).await {
            if server_cards.iter().any(|card| card.device_id == device_id) {
                return Ok(JoinCardPublishState::AlreadyPresent);
            }
        }

        let mut join_card = None;
        if let Some(cached_card) =
            self.find_cached_join_card_for_device(&session.user_id, &device_id)?
        {
            if cached_card.verify_signature().is_ok() && cached_card.is_valid() {
                join_card = Some(cached_card);
            }
        }

        let join_card = if let Some(card) = join_card {
            card
        } else {
            let invitation_keypair = self.get_or_create_invitation_keypair().await?;
            let created = invitation_keypair.create_join_card(user_id)?;

            if let Ok(canonical_json) = serde_json::to_string_pretty(&created) {
                let _ = self.cache_join_card(&session.username, &canonical_json);
            }

            created
        };

        let payload = client_join_card_to_messages(&join_card)?;
        self.publish_join_card(&payload).await?;

        Ok(JoinCardPublishState::Published)
    }

    pub async fn fetch_join_cards_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<MessagesJoinCard>, CliError> {
        let cards = self.fetch_join_cards_from_directory("email", email).await?;
        Ok(cards
            .into_iter()
            .map(|card| client_join_card_to_messages(&card))
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub async fn fetch_join_cards_for_user_id(
        &self,
        user_id: &uuid::Uuid,
    ) -> Result<Vec<ClientJoinCard>, CliError> {
        self.fetch_join_cards_from_directory("user_id", &user_id.to_string())
            .await
    }

    /// Get the currently selected group, falling back to server discovery when cache is absent
    pub async fn ensure_active_group(&self) -> Result<uuid::Uuid, CliError> {
        if let Some(group_id) = self.load_cached_group_uuid().await? {
            println!("ℹ Using current active group: {}", group_id);
            return Ok(group_id);
        }

        // Fallback: discover groups from server and persist the primary one locally
        let discovered_group = self.discover_and_cache_primary_group().await?;
        println!(
            "ℹ Using current active group discovered from server: {}",
            discovered_group
        );
        Ok(discovered_group)
    }

    async fn fetch_join_cards_from_directory(
        &self,
        param_key: &str,
        param_value: &str,
    ) -> Result<Vec<ClientJoinCard>, CliError> {
        let session = self.require_auth()?;
        let client = reqwest::Client::new();

        let base_url = session.server_url.trim_end_matches('/');
        let mut endpoint = if base_url.ends_with("/api/v1") {
            format!("{}/directory/join-cards", base_url)
        } else {
            format!("{}/api/v1/directory/join-cards", base_url)
        };
        endpoint.push('?');
        endpoint.push_str(param_key);
        endpoint.push('=');
        endpoint.push_str(&urlencoding::encode(param_value));

        let response = client
            .get(&endpoint)
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|e| {
                CliError::network(format!("Failed to fetch join card directory: {}", e))
            })?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("fetch_join_cards_directory")?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(CliError::network(format!(
                "Failed to fetch join cards: {} - {}",
                status, error_text
            )));
        }

        let payload: DirectoryJoinCardResponse = response.json().await.map_err(|e| {
            CliError::network(format!("Invalid join card directory response: {}", e))
        })?;

        payload
            .join_cards
            .into_iter()
            .map(|entry| messages_join_card_to_client(&entry.join_card))
            .collect()
    }

    pub async fn current_group_id(&self) -> Result<Option<uuid::Uuid>, CliError> {
        self.load_cached_group_uuid().await
    }

    pub async fn set_current_group_id(&self, group_id: uuid::Uuid) -> Result<(), CliError> {
        self.persist_active_group_uuid(group_id).await?;
        self.apply_group_selection(group_id).await
    }

    pub async fn clear_current_group_id(&self) -> Result<(), CliError> {
        let storage = self.current_storage()?;
        storage
            .store_config("group_id", "")
            .await
            .map_err(|e| CliError::session(format!("Failed to clear active group ID: {}", e)))?;
        Ok(())
    }

    pub async fn ensure_current_group(&self) -> Result<uuid::Uuid, CliError> {
        self.ensure_active_group().await
    }

    pub async fn sync_current_group_into_state(
        &self,
        group_id: uuid::Uuid,
    ) -> Result<(), CliError> {
        self.apply_group_selection(group_id).await
    }

    async fn apply_group_selection(&self, group_id: uuid::Uuid) -> Result<(), CliError> {
        let client = self.create_local_client().await?;
        client
            .use_group(group_id)
            .await
            .map_err(|e| CliError::session(format!("Failed to apply group context: {}", e)))?;
        Ok(())
    }

    pub fn group_membership_from_state(
        &self,
        group_id: &uuid::Uuid,
    ) -> Option<(String, Option<String>)> {
        let context = self.current_user_context()?;
        let state_path = context.config_dir.join("client_state.json");

        let content = std::fs::read_to_string(&state_path).ok()?;
        let value: serde_json::Value = serde_json::from_str(&content).ok()?;
        let memberships = value.get("group_memberships")?.as_object()?;
        let entry = memberships.get(&group_id.to_string())?.as_object()?;

        let name = entry.get("group_name")?.as_str()?.to_string();
        let role = entry
            .get("user_role")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Some((name, role))
    }

    fn role_allows_admin(role: &str) -> bool {
        matches!(role.to_ascii_lowercase().as_str(), "admin" | "owner")
    }

    pub(crate) fn admin_only_message(command: &str, role: Option<&str>) -> String {
        let mut message = format!(
            "Command '{}' is available to group administrators only.",
            command
        );
        if let Some(role) = role {
            message.push_str(&format!(" Your role in this group is {}.", role));
        }
        message.push_str(" Contact your group admin to run this command or request an admin role.");
        message
    }

    pub async fn require_group_admin(
        &self,
        group_id: uuid::Uuid,
        command: &str,
    ) -> Result<(), CliError> {
        if let Some((_, role)) = self.group_membership_from_state(&group_id) {
            if let Some(role) = role {
                if Self::role_allows_admin(&role) {
                    return Ok(());
                }
                return Err(CliError::permission(Self::admin_only_message(
                    command,
                    Some(&role),
                )));
            }
        }

        let groups = self.list_groups_http().await?;
        if let Some(group) = groups
            .iter()
            .find(|group| group.id.eq_ignore_ascii_case(&group_id.to_string()))
        {
            if Self::role_allows_admin(&group.role) {
                return Ok(());
            }
            return Err(CliError::permission(Self::admin_only_message(
                command,
                Some(&group.role),
            )));
        }

        Err(CliError::session(format!(
            "Group {} is not in your memberships. Use 'hybridcipher list-groups' to verify access.",
            group_id
        )))
    }

    async fn load_cached_group_uuid(&self) -> Result<Option<uuid::Uuid>, CliError> {
        let storage = self.current_storage()?;

        // Ensure the device/state key is available before attempting to read
        // encrypted configuration values like the cached group ID.
        let mut key_error: Option<CliError> = None;
        if let Err(err) = self.ensure_state_key_internal(false) {
            key_error = Some(err);
        }

        let cached_value = storage
            .load_config("group_id")
            .await
            .map_err(|e| CliError::session(format!("Failed to load cached group ID: {}", e)))?;

        let Some(raw_id) = cached_value else {
            return Ok(None);
        };

        let trimmed = raw_id.trim().trim_matches('"');
        if trimmed.is_empty() {
            return Ok(None);
        }

        let parsed = match uuid::Uuid::parse_str(trimmed) {
            Ok(group_id) => group_id,
            Err(err) => {
                if let Some(key_err) = key_error {
                    ui::warning(&format!(
                        "Unable to unlock device key; cached group ID may be unreadable ({}).",
                        key_err
                    ));
                }
                ui::warning(&format!(
                    "Cached group ID is invalid or unreadable; falling back to server discovery ({}).",
                    err
                ));
                return Ok(None);
            }
        };

        Ok(Some(parsed))
    }

    async fn persist_active_group_uuid(&self, group_id: uuid::Uuid) -> Result<(), CliError> {
        let storage = self.current_storage()?;

        storage
            .store_config("group_id", &group_id.to_string())
            .await
            .map_err(|e| CliError::session(format!("Failed to persist active group ID: {}", e)))?;

        Ok(())
    }

    async fn discover_and_cache_primary_group(&self) -> Result<uuid::Uuid, CliError> {
        let groups = self.list_groups_http().await?;

        let first_group = groups.into_iter().next().ok_or_else(|| {
            CliError::session(
                "No groups found for the current user. Use 'hybridcipher create-group' or ask an admin to invite you.",
            )
        })?;

        let group_uuid = uuid::Uuid::parse_str(&first_group.id).map_err(|e| {
            CliError::session(format!(
                "Server returned invalid group ID '{}': {}",
                first_group.id, e
            ))
        })?;

        self.persist_active_group_uuid(group_uuid).await?;
        Ok(group_uuid)
    }

    async fn fetch_server_info(&self, server_url: &str) -> Result<FetchedServerInfo, CliError> {
        let canonical = canonicalize_server_url(server_url);
        let base = canonical.canonical.trim_end_matches('/');
        let info_url = format!("{}/api/v1/server/info", base);

        let client = reqwest::Client::new();
        let response = client.get(&info_url).send().await.map_err(|e| {
            CliError::network(format!(
                "Failed to query server info endpoint at {}: {}",
                info_url, e
            ))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            return Err(CliError::network(format!(
                "Server info endpoint {} returned {}: {}",
                info_url,
                status,
                body.trim()
            )));
        }

        let info: ServerInfoResponse = response.json().await.map_err(|e| {
            CliError::network(format!(
                "Failed to parse server info response from {}: {}",
                info_url, e
            ))
        })?;

        let key_b64 = info.public_keys.opaque_login.public_key.trim();
        let key_bytes = general_purpose::STANDARD.decode(key_b64).map_err(|e| {
            CliError::PinningFailed(format!(
                "Server provided invalid public key encoding at {}: {}",
                info_url, e
            ))
        })?;

        if key_bytes.is_empty() {
            return Err(CliError::PinningFailed(format!(
                "Server info endpoint {} returned an empty public key",
                info_url
            )));
        }
        let transparency_meta = info.transparency.unwrap_or_default();
        let capabilities = info.capabilities.unwrap_or_default();

        let latest_checkpoint = match transparency_meta.latest_checkpoint {
            Some(raw) => Some(
                serde_json::from_str::<ServerCheckpointDocument>(raw.get()).map_err(|e| {
                    CliError::network(format!(
                        "Server returned invalid transparency checkpoint JSON: {}",
                        e
                    ))
                })?,
            ),
            None => None,
        };

        let transparency = ServerTransparencyInfo {
            enabled: transparency_meta.enabled || capabilities.transparency_log,
            log_url: transparency_meta.log_url.clone(),
            signing_key_id: transparency_meta.signing_key_id.clone(),
            latest_checkpoint,
        };

        let recovery = info.recovery.and_then(|meta| {
            meta.recovery_public_key
                .as_ref()
                .map(|key| FetchedRecoveryUnlockConfig {
                    public_key_b64: key.trim().to_string(),
                    validity_hours: 24,
                })
        });

        let welcome_signing =
            info.public_keys
                .welcome_signing
                .map(|descriptor| FetchedSigningKey {
                    public_key_b64: descriptor.public_key.trim().to_string(),
                    key_id: descriptor.key_id,
                });

        Ok(FetchedServerInfo {
            public_key_b64: key_b64.to_string(),
            public_key_bytes: key_bytes,
            welcome_signing,
            transparency,
            recovery,
        })
    }

    /// Fetch the server public key from `/api/v1/server/info` for TOFU pinning.
    pub async fn fetch_server_public_key(&self, server_url: &str) -> Result<Vec<u8>, CliError> {
        let info = self.fetch_server_info(server_url).await?;
        Ok(info.public_key_bytes)
    }

    /// Fetch transparency metadata from `/api/v1/server/info` for audit/logging purposes.
    pub async fn fetch_server_transparency_info(
        &self,
        server_url: &str,
    ) -> Result<ServerTransparencySummary, CliError> {
        let info = self.fetch_server_info(server_url).await?;
        Ok(ServerTransparencySummary {
            enabled: info.transparency.enabled,
            log_url: info.transparency.log_url,
            signing_key_id: info.transparency.signing_key_id,
        })
    }

    /// Fetch unlock-code verification config (public key and validity) from the server.
    pub async fn fetch_unlock_config(
        &self,
        server_url: &str,
    ) -> Result<Option<UnlockConfig>, CliError> {
        // Prefer explicit operator-provided overrides.
        let env_validity_hours = std::env::var("HYBRIDCIPHER_UNLOCK_CODE_VALIDITY_HOURS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());

        if let Ok(env_key) = std::env::var("HYBRIDCIPHER_UNLOCK_PUBLIC_KEY") {
            let trimmed = env_key.trim();
            if !trimmed.is_empty() {
                let key_bytes = general_purpose::STANDARD.decode(trimmed).map_err(|e| {
                    CliError::configuration(format!(
                        "HYBRIDCIPHER_UNLOCK_PUBLIC_KEY is not valid base64: {}",
                        e
                    ))
                })?;
                let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                    CliError::configuration(format!(
                        "HYBRIDCIPHER_UNLOCK_PUBLIC_KEY is not a valid Ed25519 key: {}",
                        e
                    ))
                })?;
                let validity_hours = env_validity_hours.unwrap_or(24);

                return Ok(Some(UnlockConfig {
                    verifying_key,
                    validity_hours,
                }));
            }
        }

        // Use built-in defaults baked at build time (optional).
        let bundled_keys: BundledUnlockKeys =
            serde_json::from_str(BUNDLED_SOS_UNLOCK_KEYS_JSON).unwrap_or_default();
        for key_b64 in bundled_keys.recovery_public_keys.iter() {
            let trimmed = key_b64.trim();
            if trimmed.is_empty() {
                continue;
            }
            let key_bytes = match general_purpose::STANDARD.decode(trimmed) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            if let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) {
                let validity_hours = env_validity_hours.unwrap_or(24);
                return Ok(Some(UnlockConfig {
                    verifying_key,
                    validity_hours,
                }));
            }
        }

        // As a last resort, look at server info if it advertises the public key.
        let info = self.fetch_server_info(server_url).await?;
        let Some(recovery) = info.recovery else {
            return Ok(None);
        };

        if recovery.public_key_b64.trim().is_empty() {
            return Ok(None);
        }

        let key_bytes = general_purpose::STANDARD
            .decode(recovery.public_key_b64.trim())
            .map_err(|e| {
                CliError::configuration(format!(
                    "Server advertised an invalid recovery public key encoding: {}",
                    e
                ))
            })?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            CliError::configuration(format!(
                "Server provided recovery public key is invalid: {}",
                e
            ))
        })?;

        Ok(Some(UnlockConfig {
            verifying_key,
            validity_hours: env_validity_hours.unwrap_or(recovery.validity_hours),
        }))
    }

    /// Perform a Trust-on-First-Use preflight by querying the server info endpoint and
    /// updating the stored fingerprint before any sensitive protocol messages are sent.
    pub async fn preflight_server_identity(
        &self,
        server_url: &str,
    ) -> Result<TrustDecision, CliError> {
        let fetched_info = self.fetch_server_info(server_url).await?;
        let mut identity_manager = self.server_identity_manager()?;
        let mut trust_decision = identity_manager
            .verify_server_identity(server_url, &fetched_info.public_key_bytes)
            .map_err(CliError::from)?;

        if let Some(signing_info) = fetched_info.welcome_signing.as_ref() {
            identity_manager
                .update_welcome_signing_key(
                    server_url,
                    &signing_info.public_key_b64,
                    signing_info.key_id.as_deref(),
                )
                .map_err(CliError::from)?;
        }

        let prefs = self.transparency_preferences();
        if !prefs.enabled {
            return Ok(trust_decision);
        }

        let transparency = fetched_info.transparency;

        if !transparency.enabled {
            if prefs.require_transparency {
                return Err(CliError::PinningFailed(
                    "Server transparency verification required but server did not advertise support"
                        .to_string(),
                ));
            }
            ui::warning(
                "Transparency log disabled on server; falling back to pinned fingerprint verification",
            );
            return Ok(trust_decision);
        }

        let Some(checkpoint) = transparency.latest_checkpoint else {
            if prefs.require_transparency {
                return Err(CliError::PinningFailed(
                    "Server did not provide a transparency checkpoint".to_string(),
                ));
            }
            ui::warning("Server transparency checkpoint unavailable; continuing with TOFU pinning");
            return Ok(trust_decision);
        };

        let signing_key_id = checkpoint
            .signing_key_id
            .as_deref()
            .or_else(|| transparency.signing_key_id.as_deref());

        let Some(signing_key_id) = signing_key_id else {
            if prefs.require_transparency {
                return Err(CliError::PinningFailed(
                    "Transparency checkpoint missing signing key identifier".to_string(),
                ));
            }
            ui::warning(
                "Transparency checkpoint missing signing key identifier; continuing with TOFU",
            );
            return Ok(trust_decision);
        };

        let resolved_log_url = checkpoint
            .log_url
            .clone()
            .or(transparency.log_url.clone())
            .or(prefs.log_url_override.clone());

        match self.load_transparency_state() {
            Ok(Some(cached)) => {
                let cache_stale = if prefs.max_checkpoint_age_seconds > 0 {
                    match chrono::DateTime::parse_from_rfc3339(&cached.checkpoint_generated_at) {
                        Ok(parsed) => {
                            let ts = parsed.with_timezone(&chrono::Utc);
                            let age = chrono::Utc::now().signed_duration_since(ts).num_seconds();
                            age.is_positive() && age as u64 > prefs.max_checkpoint_age_seconds
                        }
                        Err(err) => {
                            ui::warning(&format!(
                                "Stored transparency checkpoint timestamp invalid ({}); revalidating",
                                err
                            ));
                            true
                        }
                    }
                } else {
                    false
                };

                let same_checkpoint = cached
                    .root_hash_hex
                    .eq_ignore_ascii_case(&checkpoint.root_hash)
                    && cached.server_public_key_base64.trim() == fetched_info.public_key_b64.trim()
                    && cached
                        .signing_key_id
                        .as_deref()
                        .map(|id| id == signing_key_id)
                        .unwrap_or(false);

                if same_checkpoint && !cache_stale {
                    identity_manager.set_trust_level(
                        server_url,
                        TrustLevel::TransparencyLog,
                        VerificationMethod::TransparencyProof,
                    )?;
                    return Ok(TrustDecision::Trusted(TrustLevel::TransparencyLog));
                } else if same_checkpoint {
                    ui::warning(
                        "Cached transparency checkpoint expired; performing fresh verification",
                    );
                }
            }
            Ok(None) => {}
            Err(err) => {
                ui::warning(&format!(
                    "Unable to read cached transparency state; continuing with live verification: {}",
                    err
                ));
            }
        }

        match self.verify_transparency_checkpoint(
            &checkpoint,
            signing_key_id,
            &fetched_info.public_key_b64,
            &fetched_info.public_key_bytes,
            resolved_log_url.clone(),
            prefs.max_checkpoint_age_seconds,
        ) {
            Ok(state) => {
                self.persist_transparency_state(&state)?;
                identity_manager.set_trust_level(
                    server_url,
                    TrustLevel::TransparencyLog,
                    VerificationMethod::TransparencyProof,
                )?;
                trust_decision = TrustDecision::Trusted(TrustLevel::TransparencyLog);
                if let Some(log_url) = resolved_log_url {
                    ui::info(&format!(
                        "Transparency checkpoint verified against {} (tree size {}, root {})",
                        log_url,
                        state.tree_size,
                        &state.root_hash_hex[..state.root_hash_hex.len().min(16)]
                    ));
                } else {
                    ui::info(&format!(
                        "Transparency checkpoint verified (tree size {}, root {})",
                        state.tree_size,
                        &state.root_hash_hex[..state.root_hash_hex.len().min(16)]
                    ));
                }
            }
            Err(err) => {
                if prefs.require_transparency {
                    return Err(CliError::PinningFailed(format!(
                        "Transparency verification failed: {}",
                        err
                    )));
                }
                ui::warning(&format!(
                    "Transparency verification failed ({}); falling back to pinned fingerprint",
                    err
                ));
            }
        }

        Ok(trust_decision)
    }

    /// Get or create a default group for the user
    async fn get_or_create_default_group(
        &self,
        client: &reqwest::Client,
        token: &str,
        server_url: &str,
    ) -> Result<uuid::Uuid, CliError> {
        // First, try to list existing groups
        let response = client
            .get(&format!("{}/api/v1/groups", server_url))
            .header("Authorization", &format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to list groups: {}", e)))?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("get_or_create_default_group_list")?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if response.status().is_success() {
            let groups: serde_json::Value = response
                .json()
                .await
                .map_err(|e| CliError::network(format!("Invalid groups response: {}", e)))?;

            // Look for an existing group
            if let Some(groups_array) = groups.get("groups").and_then(|g| g.as_array()) {
                if let Some(first_group) = groups_array.first() {
                    if let Some(group_id_str) = first_group.get("id").and_then(|id| id.as_str()) {
                        if let Ok(group_id) = uuid::Uuid::parse_str(group_id_str) {
                            println!("ℹ Using existing group: {}", group_id);
                            return Ok(group_id);
                        }
                    }
                }
            }
        }

        // No existing group found, create a new one
        println!("ℹ Creating default group...");
        let create_group_request = serde_json::json!({
            "name": "Default Group",
            "description": "Default group for file sharing",
            "settings": {
                "auto_rekey_enabled": false,
                "max_members": 100,
                "require_admin_approval": false,
                "allow_member_invite": true
            }
        });

        let response = client
            .post(&format!("{}/api/v1/groups", server_url))
            .header("Authorization", &format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&create_group_request)
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to create group: {}", e)))?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.invalidate_session("get_or_create_default_group_create")?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if response.status().is_success() {
            let group_response: serde_json::Value = response
                .json()
                .await
                .map_err(|e| CliError::network(format!("Invalid create group response: {}", e)))?;

            if let Some(group_id_str) = group_response.get("id").and_then(|id| id.as_str()) {
                if let Ok(group_id) = uuid::Uuid::parse_str(group_id_str) {
                    println!("✓ Created default group: {}", group_id);
                    return Ok(group_id);
                }
            }
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(CliError::network(format!(
                "Failed to create default group: {} - {}",
                status, error_text
            )));
        }

        Err(CliError::network(
            "Failed to parse group ID from server response".to_string(),
        ))
    }

    /// Create a real authenticated session by running the OPAQUE login flow
    /// against the HybridCipher server.
    pub async fn login_to_server(
        &self,
        username: &str,
        password: &str,
        server_url: &str,
        mfa_code: Option<String>,
        backup_code: Option<String>,
    ) -> Result<TrustDecision, CliError> {
        use hybridcipher_client::auth::opaque::{OpaqueAuth, OpaqueError, OpaqueServerLogin};

        let mut context = self.build_device_login_context().await?;
        context.device_metadata.mfa_code = mfa_code;
        context.device_metadata.backup_code = backup_code;
        let opaque_auth = OpaqueAuth::new(context.device_id.clone());

        let login_result: OpaqueServerLogin = match opaque_auth
            .login_with_server(username, password, server_url, context.device_metadata)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                return Err(match err {
                    OpaqueError::DeviceLimitReached(message) => {
                        CliError::authentication(format!("Device limit reached: {}", message))
                    }
                    OpaqueError::EmailConfirmationRequired(message) => CliError::authentication(
                        format!("Email confirmation required: {}", message),
                    ),
                    OpaqueError::MfaRequired(message) => {
                        CliError::authentication(format!("MFA required: {}", message))
                    }
                    OpaqueError::MfaEnrollmentRequired(message) => {
                        CliError::authentication(format!("MFA enrollment required: {}", message))
                    }
                    OpaqueError::RateLimited(message) => {
                        CliError::authentication(format!("Rate limited: {}", message))
                    }
                    _ => CliError::authentication(format!("OPAQUE login failed: {err}")),
                })
            }
        };

        self.apply_login_result(login_result, server_url, password, context.identity_keypair)
    }

    pub fn apply_login_result(
        &self,
        login_result: OpaqueServerLogin,
        server_url: &str,
        password: &str,
        identity_keypair: hybridcipher_crypto::signatures::Ed25519KeyPair,
    ) -> Result<TrustDecision, CliError> {
        let mut identity_manager = self.server_identity_manager()?;
        let trust_decision = identity_manager
            .verify_server_identity(server_url, &login_result.server_public_key)
            .map_err(CliError::from)?;

        // Initialize per-account protection before persisting any credentials.
        self.initialize_account_protection(password)?;

        if let Some(last_login) = login_result.last_login.as_ref() {
            ui::info(&format!(
                "Server recorded login at {}",
                last_login.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ));
        } else if login_result.is_new_device {
            ui::info("No previous login timestamp returned; treating this as a first-time device.");
        }

        if matches!(
            login_result.device_status.as_deref(),
            Some(status) if status == "pending-welcome"
        ) {
            ui::warning(&format!(
                "⚠️  This device is pending approval. Sign in on an existing trusted device and run `hybridcipher issue-welcome --device {}` to authorize it.",
                login_result.device_id
            ));
        }

        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(login_result.expires_in);

        // Store the device keypair used for login to maintain consistency
        let private_key_bytes = identity_keypair.private_key_bytes();
        let keypair_data = general_purpose::STANDARD.encode(&private_key_bytes);

        let session = Session {
            user_id: login_result.user_id.to_string(),
            username: login_result.username.clone(),
            device_id: login_result.device_id.clone(),
            device_status: login_result.device_status.clone(),
            server_url: server_url.to_string(),
            token: login_result.access_token.clone(),
            refresh_token: login_result.refresh_token.clone(),
            opaque_export_key: Some(general_purpose::STANDARD.encode(login_result.export_key)),
            device_binding: String::new(), // populated in store_session
            device_keypair: Some(keypair_data),
            created_at: now,
            expires_at,
            last_activity: now,
            migration_info: None,
            security_metadata: SessionSecurity {
                device_fingerprint: format!("cli_fingerprint_{}", login_result.device_id),
                integrity_hash: String::new(),
                version: 1,
                flags: SessionFlags {
                    device_verified: !login_result.is_new_device,
                    migration_recovered: false,
                    auto_renewal: true,
                    enhanced_security: true,
                },
            },
        };

        self.store_session(session)?;

        Ok(trust_decision)
    }

    async fn build_device_login_context(&self) -> Result<DeviceLoginContext, CliError> {
        let identity_keypair = self.get_or_create_device_keypair().await?;
        let identity_public_key = identity_keypair.public_key_bytes().to_vec();
        let invitation_keypair = self.get_or_create_invitation_keypair().await?;
        let invitation_public_key = invitation_keypair
            .invitation_public_key()
            .map_err(|e| {
                CliError::session(format!(
                    "Failed to load invitation public key for login: {}",
                    e
                ))
            })?
            .to_bytes()
            .to_vec();

        let device_id = format!("device_{}", hex::encode(&identity_public_key[..8]));
        let device_metadata = DeviceLoginMetadata {
            identity_public_key_hex: hex::encode(&identity_public_key),
            invitation_public_key_hex: hex::encode(&invitation_public_key),
            device_display_name: Some(format!(
                "CLI-{}-{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            )),
            mfa_code: None,
            backup_code: None,
        };

        Ok(DeviceLoginContext {
            device_id,
            device_metadata,
            identity_keypair,
        })
    }

    /// Request the server to resend an email confirmation link.
    pub async fn resend_confirmation_email(
        &self,
        email: &str,
        server_url: &str,
    ) -> Result<(), CliError> {
        let trimmed = server_url.trim_end_matches('/');
        let endpoint = if trimmed.ends_with("/api/v1") {
            format!("{}/auth/resend-confirmation", trimmed)
        } else {
            format!("{}/api/v1/auth/resend-confirmation", trimmed)
        };

        let client = reqwest::Client::new();
        let response = client
            .post(&endpoint)
            .json(&serde_json::json!({ "email": email }))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| {
                CliError::network(format!(
                    "Failed to contact the server to resend confirmation email: {}",
                    e
                ))
            })?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());

        Err(CliError::authentication(format!(
            "Server rejected confirmation resend request: {} {}",
            status,
            body.trim()
        )))
    }

    /// List groups that the user belongs to
    pub async fn list_groups_http(&self) -> Result<Vec<GroupInfo>, CliError> {
        let session = self.require_auth()?;
        let server_url = session.server_url.clone();

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/api/v1/groups", server_url))
            .header("Authorization", &format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| CliError::network(format!("HTTP request failed: {}", e)))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.invalidate_session("list_groups_http")?;
            return Err(CliError::authentication(
                "Authentication token rejected by the server. Please login again with 'hybridcipher login <username>'.",
            ));
        }

        if response.status().is_success() {
            let response_body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| CliError::network(format!("Invalid server response: {}", e)))?;

            let empty_vec = vec![];
            let groups = response_body
                .get("groups")
                .and_then(|g| g.as_array())
                .unwrap_or(&empty_vec);

            let mut group_infos = Vec::new();
            for group in groups {
                if let Some(group_info) = self.parse_group_info(group) {
                    group_infos.push(group_info);
                }
            }

            if let Err(err) = self.cache_group_metadata(&group_infos).await {
                ui::warning(&format!(
                    "Failed to update local group metadata cache: {}",
                    err
                ));
            }

            Ok(group_infos)
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(CliError::network(format!(
                "Failed to list groups: {} - {}",
                status, error_text
            )))
        }
    }

    /// Rename a group using the server API
    pub async fn rename_group_http(
        &self,
        group_id: uuid::Uuid,
        new_name: &str,
    ) -> Result<GroupInfo, CliError> {
        let session = self.require_auth()?;
        let server_url = session.server_url.trim_end_matches('/');

        let client = reqwest::Client::new();
        let response = client
            .put(&format!("{}/api/v1/groups/{}", server_url, group_id))
            .header("Authorization", &format!("Bearer {}", session.token))
            .json(&serde_json::json!({ "name": new_name }))
            .send()
            .await
            .map_err(|e| CliError::network(format!("HTTP request failed: {}", e)))?;

        match response.status() {
            StatusCode::OK => {
                let response_body: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| CliError::network(format!("Invalid server response: {}", e)))?;

                self.parse_group_info(&response_body).ok_or_else(|| {
                    CliError::network(
                        "Server returned an unexpected group payload while renaming.".to_string(),
                    )
                })
            }
            StatusCode::UNAUTHORIZED => {
                self.invalidate_session("rename_group_http")?;
                Err(CliError::authentication(
                    "Authentication token rejected by the server. Please login again.".to_string(),
                ))
            }
            StatusCode::FORBIDDEN => Err(CliError::session(
                "You do not have permission to rename this group.".to_string(),
            )),
            StatusCode::NOT_FOUND => Err(CliError::not_found("Group not found")),
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(CliError::network(format!(
                    "Failed to rename group: {} - {}",
                    status, error_text
                )))
            }
        }
    }

    /// Fetch the list of registered devices for the authenticated user
    pub async fn fetch_registered_devices(&self) -> Result<RegisteredDeviceList, CliError> {
        let session = self.require_auth()?;
        let server_url = session.server_url.trim_end_matches('/');

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/api/v1/auth/devices", server_url))
            .header("Authorization", format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to fetch devices: {}", e)))?;

        match response.status() {
            StatusCode::OK => response
                .json::<RegisteredDeviceList>()
                .await
                .map_err(|e| CliError::network(format!("Failed to parse device list: {}", e))),
            StatusCode::UNAUTHORIZED => {
                self.invalidate_session("fetch_registered_devices")?;
                Err(CliError::authentication(
                    "Session expired. Please login again with 'hybridcipher login <email>'.",
                ))
            }
            StatusCode::FORBIDDEN => {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                Err(CliError::session(format!(
                    "Server rejected device listing request: {}",
                    body.trim()
                )))
            }
            status => {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                Err(CliError::network(format!(
                    "Failed to fetch devices (status {}): {}",
                    status, body
                )))
            }
        }
    }

    /// List members of a specific group
    pub async fn list_group_members_http(
        &self,
        group_id: &str,
    ) -> Result<Vec<MemberInfo>, CliError> {
        let session = self.require_auth()?;
        let base_url = session.server_url.trim_end_matches('/');
        let api_base = if base_url.ends_with("/api/v1") {
            base_url.to_string()
        } else {
            format!("{}/api/v1", base_url)
        };

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/groups/{}/members", api_base, group_id))
            .header("Authorization", &format!("Bearer {}", session.token))
            .send()
            .await
            .map_err(|e| CliError::network(format!("HTTP request failed: {}", e)))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.invalidate_session("list_group_members_http")?;
            return Err(CliError::authentication(
                "Authentication token rejected by the server. Please login again with 'hybridcipher login <username>'.",
            ));
        }

        if response.status().is_success() {
            let response_body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| CliError::network(format!("Invalid server response: {}", e)))?;

            let empty_vec = vec![];
            let members = response_body
                .get("members")
                .and_then(|m| m.as_array())
                .unwrap_or(&empty_vec);

            let mut member_infos = Vec::new();
            for member in members {
                if let Some(member_info) = self.parse_member_info(member) {
                    member_infos.push(member_info);
                }
            }

            Ok(member_infos)
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(CliError::network(format!(
                "Failed to list group members: {} - {}",
                status, error_text
            )))
        }
    }

    /// Parse group information from JSON response
    fn parse_group_info(&self, group: &serde_json::Value) -> Option<GroupInfo> {
        Some(GroupInfo {
            id: group.get("id")?.as_str()?.to_string(),
            name: group.get("name")?.as_str()?.to_string(),
            description: group
                .get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string()),
            role: group.get("user_role")?.as_str()?.to_string(),
            current_epoch: group
                .get("current_epoch")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string()),
            member_count: group.get("member_count")?.as_u64()? as usize,
            created_at: group.get("created_at")?.as_str()?.to_string(),
        })
    }

    /// Parse member information from JSON response
    fn parse_member_info(&self, member: &serde_json::Value) -> Option<MemberInfo> {
        Some(MemberInfo {
            user_id: member.get("user_id")?.as_str()?.to_string(),
            email: member.get("email")?.as_str()?.to_string(),
            role: member.get("role")?.as_str()?.to_string(),
            status: member
                .get("status")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    // Fallback to invitation_status if status is not available
                    member
                        .get("invitation_status")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "active".to_string())
                }),
            joined_at: member.get("joined_at")?.as_str()?.to_string(),
        })
    }
}

#[derive(Clone, Serialize)]
struct DirectoryUploadJoinCardRequest {
    join_card: MessagesJoinCard,
}

#[derive(Debug, Deserialize)]
struct DirectoryJoinCardResponse {
    join_cards: Vec<DirectoryJoinCardEntry>,
}

#[derive(Debug, Deserialize)]
pub struct SecondPartyStatusEntry {
    pub target_user_id: String,
    pub target_device_id: String,
    #[serde(default)]
    pub group_id: Option<String>,
    pub status: String,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DirectoryJoinCardEntry {
    join_card: MessagesJoinCard,
}

pub fn client_join_card_to_messages(
    join_card: &ClientJoinCard,
) -> Result<MessagesJoinCard, CliError> {
    let expires: u64 = join_card
        .expires_at
        .timestamp()
        .try_into()
        .map_err(|_| CliError::format("Join card expiration timestamp is out of range"))?;

    Ok(MessagesJoinCard {
        user_id: join_card.user_id.to_string(),
        device_id: join_card.device_id.clone(),
        identity_public: join_card.identity_public.clone(),
        invitation_public: join_card.invitation_public.clone(),
        expires,
        signature: join_card.signature.clone(),
    })
}

pub fn messages_join_card_to_client(
    join_card: &MessagesJoinCard,
) -> Result<ClientJoinCard, CliError> {
    let user_id = uuid::Uuid::parse_str(&join_card.user_id).map_err(|e| {
        CliError::invalid_input(format!("Join card user identifier is invalid: {}", e))
    })?;

    let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(join_card.expires as i64, 0)
        .ok_or_else(|| {
        CliError::invalid_input("Join card expires_at is invalid".to_string())
    })?;

    Ok(ClientJoinCard {
        user_id,
        device_id: join_card.device_id.clone(),
        identity_public: join_card.identity_public.clone(),
        invitation_public: join_card.invitation_public.clone(),
        expires_at,
        signature: join_card.signature.clone(),
    })
}

async fn load_pinning_config_for_storage(
    storage: &hybridcipher_client::storage::LocalFsStorage,
) -> Result<PinningConfig, CliError> {
    match storage
        .load_config(PINNING_CONFIG_KEY)
        .await
        .map_err(|e| CliError::storage(format!("Failed to load pinning configuration: {}", e)))?
    {
        Some(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw).map_err(|e| {
            CliError::configuration(format!("Corrupted pinning configuration: {}", e))
        }),
        _ => Ok(hybridcipher_client::config_loader::load_client_config_from_files().pinning_config),
    }
}
