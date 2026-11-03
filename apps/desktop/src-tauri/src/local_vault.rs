//! Accountless "On this device" vault: its record, storage identity and keys.
//!
//! A vault lives in `users/local-<random>` with the same files an account uses:
//! a cached account key, a state key in the system keychain with a fallback
//! wrapped by the account key, and the device identity. Upgrading to an account
//! renames that directory to the account's storage identity, so encrypted files
//! and keys move without being rewritten.

use crate::key_bundle;
use chrono::{DateTime, Utc};
use hybridcipher_crypto::account_protection::{decrypt_with_ad, encrypt_with_ad, ProtectedData};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const RECORD_FILE: &str = "local_vault.json";
const GLOBAL_DIR: &str = "global";
const USERS_DIR: &str = "users";
const STORAGE_PREFIX: &str = "local-";
const ACCOUNT_KEY_CACHE_FILE: &str = ".account_key_cache";
const DEVICE_KEY_FILE: &str = "device_key.protected";
const DEVICE_KEY_FILE_AAD: &[u8] = b"hybridcipher/device_key_material";
/// Written when an upgrade re-protects the vault under the account password.
const ACCOUNT_PROTECTION_FILE: &str = "account_protection.json";
/// Written by account sign-in (`session.rs`); either one means an account used this device.
const ACTIVE_USER_FILE: &str = "active_user.json";
const LAST_USER_FILE: &str = "last_user.json";
pub const STORAGE_MISSING_MESSAGE: &str =
    "This device's vault files are missing. Restore the vault from your recovery kit, or start a new one.";
/// A copy of the recovery kit, sealed by the recovery code, kept to check a
/// typed code at upgrade. It is no more sensitive than the kit the user saved.
pub const KIT_COPY_FILE: &str = "local_recovery_kit.hcrk";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum UpgradePhase {
    /// The account exists on the server; the vault is still local.
    Registered,
    /// Vault storage now lives under the account's storage identity.
    StorageMoved,
    /// An account session is open on the moved storage.
    SignedIn,
    /// The server's Personal default is the vault's group.
    Adopted,
    /// The vault key is the account's committed genesis epoch.
    KeysCommitted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeProgress {
    pub email: String,
    pub server_url: String,
    pub account_storage_id: String,
    pub phase: UpgradePhase,
}

/// Where one vault folder is in a move into an existing account.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MergeStep {
    /// Some files may still belong to the vault.
    Pending,
    /// Every file belongs to the account's Personal group.
    Moved,
    /// Protected by the account (or left unprotected, as it was in the vault).
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MergeFolder {
    pub path: PathBuf,
    /// Protected in the vault, so the account protects it too.
    pub protected: bool,
    pub step: MergeStep,
}

/// A move of the vault's files into an account that already existed. The folder
/// list is fixed when the move starts, so a resumed move works on the same set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeProgress {
    pub user_id: String,
    pub email: String,
    pub server_url: String,
    pub target_group_id: Uuid,
    pub folders: Vec<MergeFolder>,
}

impl MergeProgress {
    /// The first folder still to finish.
    pub fn next_folder(&self) -> Option<usize> {
        self.folders
            .iter()
            .position(|folder| folder.step < MergeStep::Done)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVaultRecord {
    pub storage_id: String,
    pub group_id: Uuid,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub kit_saved: bool,
    #[serde(default)]
    pub upgrade: Option<UpgradeProgress>,
    /// Set once the vault's files start moving into an existing account. From
    /// then on the vault never opens on its own again: some files already belong
    /// to the account.
    #[serde(default)]
    pub merge: Option<MergeProgress>,
}

/// The open vault while the app runs without an account session.
pub struct LocalVaultContext {
    pub record: LocalVaultRecord,
    /// Last characters of the code shown for the current kit, held only in
    /// memory until the user confirms they saved it.
    pub pending_kit_check: Option<String>,
}

pub fn user_dir(config_dir: &Path, storage_id: &str) -> PathBuf {
    config_dir.join(USERS_DIR).join(storage_id)
}

pub fn new_storage_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    format!("{STORAGE_PREFIX}{}", hex::encode(bytes))
}

fn record_path(config_dir: &Path) -> PathBuf {
    config_dir.join(GLOBAL_DIR).join(RECORD_FILE)
}

pub fn load_record(config_dir: &Path) -> Result<Option<LocalVaultRecord>, String> {
    let path = record_path(config_dir);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read local vault details: {e}"))?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| format!("Local vault details are unreadable: {e}"))
}

pub fn save_record(config_dir: &Path, record: &LocalVaultRecord) -> Result<(), String> {
    let path = record_path(config_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to prepare local vault details: {e}"))?;
    }
    let serialized = serde_json::to_string_pretty(record)
        .map_err(|e| format!("Failed to encode local vault details: {e}"))?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serialized)
        .map_err(|e| format!("Failed to save local vault details: {e}"))?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&temporary, &path).map_err(|e| format!("Failed to save local vault details: {e}"))
}

pub fn delete_record(config_dir: &Path) -> Result<(), String> {
    match fs::remove_file(record_path(config_dir)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Failed to remove local vault details: {error}")),
    }
}

/// Keep a record whose storage is gone, so a new or restored vault can take its
/// place without destroying the only trace of the old one.
pub fn set_aside_record(config_dir: &Path) -> Result<PathBuf, String> {
    let path = record_path(config_dir);
    let aside = path.with_extension(format!(
        "json.missing-{}",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));
    fs::rename(&path, &aside).map_err(|e| format!("Failed to set aside local vault details: {e}"))?;
    Ok(aside)
}

/// Whether a storage directory holds a vault, not merely exists: a failed open
/// or a stale background writer can leave an empty directory behind.
pub fn storage_present(config_dir: &Path, storage_id: &str) -> bool {
    user_dir(config_dir, storage_id)
        .join(ACCOUNT_KEY_CACHE_FILE)
        .is_file()
}

/// The storage identity that holds the vault, if any does. An interrupted
/// upgrade may already have moved it before the record was updated.
pub fn find_storage(config_dir: &Path, record: &LocalVaultRecord) -> Option<String> {
    if storage_present(config_dir, &record.storage_id) {
        return Some(record.storage_id.clone());
    }
    record
        .upgrade
        .as_ref()
        .map(|progress| progress.account_storage_id.clone())
        .filter(|account| storage_present(config_dir, account))
}

pub fn current_storage_id(config_dir: &Path, record: &LocalVaultRecord) -> String {
    find_storage(config_dir, record).unwrap_or_else(|| record.storage_id.clone())
}

/// Fresh account and state keys for a new vault, kept the way a remembered
/// account login keeps them: the account key cached for this OS user and the
/// state key in the system keychain, with a fallback wrapped by the account key.
pub fn create_storage_keys(
    config_dir: &Path,
    storage_id: &str,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    let dir = user_dir(config_dir, storage_id);
    if dir.exists() {
        return Err("Local vault storage already exists".into());
    }
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create local vault storage: {e}"))?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let mut state_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(state_key.as_mut());
    let account_key = write_local_keys(&dir, storage_id, &state_key)?;
    Ok((account_key, state_key))
}

/// Protect a state key the accountless way under a fresh random account key.
/// The keychain entry is written first, so a vault interrupted between the two
/// files still opens from the keychain and a repeat call finishes the job.
fn write_local_keys(
    dir: &Path,
    storage_id: &str,
    state_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut account_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(account_key.as_mut());
    key_bundle::store_state_key(storage_id, state_key)?;
    let protected = encrypt_with_ad(state_key, *account_key, DEVICE_KEY_FILE_AAD)
        .map_err(|e| format!("Failed to protect local vault key: {e}"))?;
    let serialized = serde_json::to_string_pretty(&protected)
        .map_err(|e| format!("Failed to encode local vault key: {e}"))?;
    let fallback = dir.join(DEVICE_KEY_FILE);
    let temporary = fallback.with_extension("protected.tmp");
    fs::write(&temporary, serialized).map_err(|e| format!("Failed to save local vault key: {e}"))?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&temporary, &fallback).map_err(|e| format!("Failed to save local vault key: {e}"))?;
    hybridcipher_crypto::local_key_cache::save(&dir.join(ACCOUNT_KEY_CACHE_FILE), &account_key)
        .map_err(|e| format!("Failed to save local vault key: {e}"))?;
    Ok(account_key)
}

/// Undo an account creation that has not signed in yet: bring the vault back to
/// an accountless storage identity and protect its keys without the password the
/// upgrade wrapped them with. Safe to repeat after an interruption at any point.
pub fn return_to_local(
    config_dir: &Path,
    record: &LocalVaultRecord,
) -> Result<LocalVaultRecord, String> {
    let progress = record
        .upgrade
        .as_ref()
        .ok_or("No account creation is in progress")?;
    if progress.phase >= UpgradePhase::SignedIn {
        return Err("This account is already in use and can't be undone here".into());
    }
    let current = find_storage(config_dir, record).ok_or(STORAGE_MISSING_MESSAGE)?;
    let mut record = record.clone();
    if current.starts_with(STORAGE_PREFIX) {
        record.storage_id = current;
    } else {
        // Name the destination first: until the move lands, `find_storage`
        // still finds the vault under the account identity.
        record.storage_id = new_storage_id();
        save_record(config_dir, &record)?;
        move_storage(config_dir, &current, &record.storage_id)?;
    }
    let (_, state_key) = load_storage_keys(config_dir, &record.storage_id)?;
    let dir = user_dir(config_dir, &record.storage_id);
    write_local_keys(&dir, &record.storage_id, &state_key)?;
    match fs::remove_file(dir.join(ACCOUNT_PROTECTION_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Failed to remove account protection details: {error}")),
    }
    record.upgrade = None;
    save_record(config_dir, &record)?;
    Ok(record)
}

/// Load the keys of an existing vault without any password.
///
/// The folder's own copy of the state key (wrapped by the cached account key)
/// decides: a keychain entry under the same name can be left over from deleted
/// data, so one that disagrees is replaced instead of trusted.
pub fn load_storage_keys(
    config_dir: &Path,
    storage_id: &str,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    let dir = user_dir(config_dir, storage_id);
    let account_key = Zeroizing::new(
        hybridcipher_crypto::local_key_cache::load(&dir.join(ACCOUNT_KEY_CACHE_FILE))
            .map_err(|e| format!("Failed to unlock local vault: {e}"))?,
    );
    let from_folder = folder_state_key(&dir, &account_key);
    match (key_bundle::load_state_key(storage_id)?, from_folder) {
        (Some(keychain), Some(folder)) if keychain != *folder => {
            tracing::warn!(
                "Keychain entry for {} did not match the vault's own key; replacing it",
                storage_id
            );
            key_bundle::store_state_key(storage_id, &folder)?;
            Ok((account_key, folder))
        }
        (Some(keychain), _) => Ok((account_key, Zeroizing::new(keychain))),
        (None, Some(folder)) => Ok((account_key, folder)),
        (None, None) => Err("The local vault key is missing from the system keychain".into()),
    }
}

/// The state key wrapped in the vault folder itself. `None` when the copy is
/// absent or doesn't open with the cached account key, as after an interruption
/// between rewriting the copy and the cache; the keychain, written first, holds
/// the key then.
fn folder_state_key(dir: &Path, account_key: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    let raw = fs::read_to_string(dir.join(DEVICE_KEY_FILE)).ok()?;
    let protected: ProtectedData = serde_json::from_str(&raw).ok()?;
    let bytes = Zeroizing::new(decrypt_with_ad(&protected, *account_key, DEVICE_KEY_FILE_AAD).ok()?);
    let key: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(Zeroizing::new(key))
}

/// Move vault storage and its keychain entry to the account's storage
/// identity. Safe to repeat after an interruption at any point, and the keychain
/// is settled before the folder moves, so a failure leaves nothing half-done.
pub fn move_storage(config_dir: &Path, from_id: &str, to_id: &str) -> Result<(), String> {
    let from_dir = user_dir(config_dir, from_id);
    let to_dir = user_dir(config_dir, to_id);
    // An empty directory left at the source after a finished move is not a vault.
    if storage_present(config_dir, from_id) {
        if to_dir.exists() {
            return Err(
                "This device already has data for that account. Use a different email, or remove that account's data first."
                    .into(),
            );
        }
        let (_, state_key) = load_storage_keys(config_dir, from_id)?;
        // No folder exists under the destination, so an entry there protects
        // nothing; this vault's entry replaces it.
        key_bundle::copy_bundle_for_key(from_id, to_id, &state_key)?;
        fs::rename(&from_dir, &to_dir)
            .map_err(|e| format!("Failed to move local vault storage: {e}"))?;
    } else if storage_present(config_dir, to_id) {
        // Interrupted after the rename: the moved folder settles the destination entry.
        let (_, state_key) = load_storage_keys(config_dir, to_id).or_else(|error| {
            let fallback = key_bundle::load_state_key(from_id)?.ok_or(error)?;
            let account_key = Zeroizing::new(
                hybridcipher_crypto::local_key_cache::load(&to_dir.join(ACCOUNT_KEY_CACHE_FILE))
                    .map_err(|e| format!("Failed to unlock local vault: {e}"))?,
            );
            Ok::<_, String>((account_key, Zeroizing::new(fallback)))
        })?;
        key_bundle::copy_bundle_for_key(from_id, to_id, &state_key)?;
    } else {
        return Err(STORAGE_MISSING_MESSAGE.into());
    }
    key_bundle::delete_bundle(from_id)
}

/// Remove keychain entries a missing vault left behind. Only names with no
/// folder are touched, and an account name only while that account was never
/// signed in from this vault.
pub fn forget_missing_keys(config_dir: &Path, record: &LocalVaultRecord) -> Result<(), String> {
    let mut names = vec![record.storage_id.clone()];
    if let Some(progress) = &record.upgrade {
        if progress.phase < UpgradePhase::SignedIn {
            names.push(progress.account_storage_id.clone());
        }
    }
    for name in names {
        if !user_dir(config_dir, &name).exists() {
            key_bundle::delete_bundle(&name)?;
        }
    }
    Ok(())
}

/// Nothing on this device has used HybridCipher yet: no vault, and no account
/// ever signed in here (no active or last user, no account storage folder).
/// Only then does the app open a vault on its own at first launch.
pub fn is_fresh_device(config_dir: &Path) -> bool {
    let global = config_dir.join(GLOBAL_DIR);
    if [RECORD_FILE, ACTIVE_USER_FILE, LAST_USER_FILE]
        .iter()
        .any(|name| global.join(name).exists())
    {
        return false;
    }
    let Ok(entries) = fs::read_dir(config_dir.join(USERS_DIR)) else {
        return true;
    };
    !entries.flatten().any(|entry| {
        entry.path().is_dir() && !entry.file_name().to_string_lossy().starts_with(STORAGE_PREFIX)
    })
}

/// A vault that never protected anything: folders can't be protected until its
/// recovery kit is saved, and it isn't becoming part of an account.
pub fn is_pristine(record: &LocalVaultRecord) -> bool {
    !record.kit_saved && record.upgrade.is_none() && record.merge.is_none()
}

/// Remove a vault that was never upgraded: its storage, keychain entry and record.
pub fn remove_storage(config_dir: &Path, storage_id: &str) -> Result<(), String> {
    if !storage_id.starts_with(STORAGE_PREFIX) {
        return Err("Only an accountless vault can be removed here".into());
    }
    let dir = user_dir(config_dir, storage_id);
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("Failed to remove local vault: {e}"))?;
    }
    key_bundle::delete_bundle(storage_id)?;
    delete_record(config_dir)
}

#[cfg(test)]
#[path = "../tests/local/test_local_vault_storage.rs"]
mod tests;
