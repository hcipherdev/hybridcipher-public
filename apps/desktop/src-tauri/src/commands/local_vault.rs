//! Accountless "On this device" vault: create, recovery kit, restore, the
//! resumable upgrade that turns the vault into a new account's Personal data, and
//! the resumable move of its files into an account that already exists.
use super::*;
use crate::local_vault::{
    self as vault, LocalVaultContext, LocalVaultRecord, MergeFolder, MergeProgress, MergeStep,
    UpgradePhase, UpgradeProgress, KIT_COPY_FILE,
};
use hybridcipher_client::local_recovery_kit::{generate_recovery_code, LocalRecoveryKit};
use hybridcipher_client::saved_code_recovery::{format_recovery_code, parse_recovery_code};

/// Serializes vault creation, opening and upgrade.
static LOCAL_VAULT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const KIT_CHECK_CHARACTERS: usize = 4;

#[derive(Debug, Serialize)]
pub struct LocalVaultStatus {
    /// A vault exists on this device.
    pub available: bool,
    /// The app is running in local mode (no account session is open).
    pub active: bool,
    pub group_id: Option<String>,
    pub created_at: Option<String>,
    pub kit_saved: bool,
    /// Email of an account creation that has started but not finished.
    pub upgrade_email: Option<String>,
    pub upgrade_phase: Option<UpgradePhase>,
    /// The record exists but its files are gone; the user can restore from the
    /// recovery kit or start a new vault.
    pub storage_missing: bool,
    /// Email of the account this vault's files are moving into, until the move
    /// finishes. Meanwhile the vault never opens on its own.
    pub merge_email: Option<String>,
    /// An account is signed in and the vault's files can move into it.
    pub can_merge: bool,
    /// No vault and no account has used this device, so the app may start a
    /// vault on its own once the terms are accepted.
    pub fresh_device: bool,
}

const STORAGE_MISSING_CODE: &str = "LOCAL_VAULT_STORAGE_MISSING";
const VAULT_EXISTS_CODE: &str = "LOCAL_VAULT_EXISTS";
const VAULT_NOT_EMPTY_CODE: &str = "LOCAL_VAULT_NOT_EMPTY";

#[derive(Debug, Serialize)]
pub struct LocalRecoveryKitResult {
    /// Shown once; the app never stores it.
    pub recovery_code: String,
}

#[derive(Debug, Serialize)]
pub struct LocalVaultUpgradeResult {
    /// "confirm_email" while the new account waits for its link, then "complete".
    pub status: &'static str,
    pub email: String,
    /// Present only when the user had no recovery code; shown once.
    pub new_recovery_code: Option<String>,
}

fn status_of(record: Option<&LocalVaultRecord>, active: bool) -> LocalVaultStatus {
    LocalVaultStatus {
        available: record.is_some(),
        active: active && record.is_some(),
        group_id: record.map(|record| record.group_id.to_string()),
        created_at: record.map(|record| record.created_at.to_rfc3339()),
        kit_saved: record.is_some_and(|record| record.kit_saved),
        upgrade_email: record
            .and_then(|record| record.upgrade.as_ref())
            .map(|progress| progress.email.clone()),
        upgrade_phase: record
            .and_then(|record| record.upgrade.as_ref())
            .map(|progress| progress.phase),
        storage_missing: false,
        merge_email: record
            .and_then(|record| record.merge.as_ref())
            .map(|progress| progress.email.clone()),
        can_merge: false,
        fresh_device: false,
    }
}

fn missing_status(record: &LocalVaultRecord) -> LocalVaultStatus {
    LocalVaultStatus {
        storage_missing: true,
        ..status_of(Some(record), false)
    }
}

/// Make room for a new or restored vault. Only a record whose files are gone may
/// be replaced; it is kept aside, never deleted.
fn replace_missing_record(config: &Path, record: &LocalVaultRecord) -> Result<(), String> {
    if vault::find_storage(config, record).is_some() {
        return Err("This device already has a local vault.".into());
    }
    let aside = vault::set_aside_record(config)?;
    if let Err(error) = vault::forget_missing_keys(config, record) {
        tracing::warn!("Keychain entries of a missing vault were not removed: {}", error);
    }
    tracing::warn!(
        "Local vault {} had no files; its details were kept at {}",
        record.group_id,
        aside.display()
    );
    Ok(())
}

fn config_dir(state: &AppState) -> PathBuf {
    state.local_client.config_dir().to_path_buf()
}

/// An account being created from this device's vault, until the vault key is its
/// committed genesis. Meanwhile no other Personal genesis may run (it would make
/// adoption impossible) and an ordinary login must not create fresh keys.
pub(crate) fn pending_vault_upgrade(state: &AppState) -> Option<(Uuid, String)> {
    let record = vault::load_record(&config_dir(state)).ok().flatten()?;
    let progress = record.upgrade?;
    (progress.phase < UpgradePhase::KeysCommitted).then_some((record.group_id, progress.email))
}

/// Whether a sign-in check for `email` must wait for the vault upgrade. Until the
/// vault's storage has moved under the account, a sign-in would create fresh keys
/// there; afterwards it is the same check the upgrade itself makes.
pub(crate) fn vault_upgrade_blocks_login(state: &AppState, email: &str) -> bool {
    vault::load_record(&config_dir(state))
        .ok()
        .flatten()
        .is_some_and(|record| upgrade_blocks_login(&record, email))
}

fn upgrade_blocks_login(record: &LocalVaultRecord, email: &str) -> bool {
    record.upgrade.as_ref().is_some_and(|progress| {
        progress.email.eq_ignore_ascii_case(email.trim())
            && progress.phase < UpgradePhase::StorageMoved
    })
}

pub(crate) const LOCAL_VAULT_UPGRADE_PENDING: &str =
    "Finish creating your account from this device's vault first.";

/// Open the vault's storage with a local-only client and enter local mode.
async fn open_vault(state: &AppState, mut record: LocalVaultRecord) -> Result<(), String> {
    if let Some(progress) = &record.merge {
        return Err(merge_pending_message(progress));
    }
    let config = config_dir(state);
    record.storage_id = vault::current_storage_id(&config, &record);
    let client = state
        .local_client
        .initialize_for_local_vault(&record.storage_id)
        .await?;
    let info = client
        .local_vault_info()
        .await
        .map_err(|error| error.to_string())?;
    if info.map(|info| info.group_id) != Some(record.group_id) {
        state.local_client.clear().await;
        return Err("Local vault storage does not match its saved details".into());
    }
    *state.local_vault.lock().await = Some(LocalVaultContext {
        record,
        pending_kit_check: None,
    });
    Ok(())
}

/// Report the vault, opening it when no account session is active.
#[tauri::command]
pub async fn local_vault_status(
    state: State<'_, AppState>,
) -> Result<CommandResponse<LocalVaultStatus>, String> {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    let record = match vault::load_record(&config_dir(&state)) {
        Ok(record) => record,
        Err(error) => return Ok(CommandResponse::err(error)),
    };
    if state.session.lock().await.is_some() {
        let can_merge = record.as_ref().is_some_and(|record| {
            merge_allowed(
                record,
                vault::find_storage(&config_dir(&state), record).is_some(),
            )
        });
        return Ok(CommandResponse::ok(LocalVaultStatus {
            can_merge,
            ..status_of(record.as_ref(), false)
        }));
    }
    let Some(record) = record else {
        return Ok(CommandResponse::ok(LocalVaultStatus {
            fresh_device: vault::is_fresh_device(&config_dir(&state)),
            ..status_of(None, false)
        }));
    };
    // Some files already belong to the account; only signing in finishes the move.
    if record.merge.is_some() {
        return Ok(CommandResponse::ok(status_of(Some(&record), false)));
    }
    if state.local_vault.lock().await.is_none() {
        if vault::find_storage(&config_dir(&state), &record).is_none() {
            return Ok(CommandResponse::ok(missing_status(&record)));
        }
        if let Err(error) = open_vault(&state, record.clone()).await {
            return Ok(CommandResponse::err(error));
        }
        if let Some(user_dir) = local_vault_storage_dir(&state).await {
            state.reconnect_left_mounts(user_dir).await;
        }
    }
    let context = state.local_vault.lock().await;
    let record = context.as_ref().map(|context| &context.record);
    Ok(CommandResponse::ok(status_of(record, true)))
}

/// Start using the app on this device without an account. A vault whose files
/// are gone is replaced only when `replace_missing` confirms the user chose to.
#[tauri::command]
pub async fn create_local_vault(
    replace_missing: Option<bool>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<LocalVaultStatus>, String> {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    let _gate = UPDATE_OPERATION_GATE.read().await;
    if state.session.lock().await.is_some() {
        return Ok(CommandResponse::err(
            "Sign out of your account before starting a vault on this device.",
        ));
    }
    let config = config_dir(&state);
    match vault::load_record(&config) {
        Ok(Some(record)) if vault::find_storage(&config, &record).is_none() => {
            if !replace_missing.unwrap_or(false) {
                return Ok(CommandResponse::err_with_code(
                    STORAGE_MISSING_CODE,
                    vault::STORAGE_MISSING_MESSAGE,
                ));
            }
            if let Err(error) = replace_missing_record(&config, &record) {
                return Ok(CommandResponse::err(error));
            }
        }
        Ok(Some(record)) => {
            if state.local_vault.lock().await.is_none() {
                if let Err(error) = open_vault(&state, record.clone()).await {
                    return Ok(CommandResponse::err(error));
                }
            }
            return Ok(CommandResponse::ok(status_of(Some(&record), true)));
        }
        Ok(None) => {}
        Err(error) => return Ok(CommandResponse::err(error)),
    }
    let storage_id = vault::new_storage_id();
    let created = async {
        let (_, state_key) = vault::create_storage_keys(&config, &storage_id)?;
        state
            .client
            .create_local_vault_device_keys(&vault::user_dir(&config, &storage_id), &state_key)?;
        let client = state
            .local_client
            .initialize_for_local_vault(&storage_id)
            .await?;
        let info = client
            .create_local_vault()
            .await
            .map_err(|error| error.to_string())?;
        let record = LocalVaultRecord {
            storage_id: storage_id.clone(),
            group_id: info.group_id,
            created_at: info.created_at,
            kit_saved: false,
            upgrade: None,
            merge: None,
        };
        vault::save_record(&config, &record)?;
        Ok::<_, String>(record)
    }
    .await;
    match created {
        Ok(record) => {
            let status = status_of(Some(&record), true);
            *state.local_vault.lock().await = Some(LocalVaultContext {
                record,
                pending_kit_check: None,
            });
            Ok(CommandResponse::ok(status))
        }
        Err(error) => {
            state.local_client.clear().await;
            if let Err(cleanup) = vault::remove_storage(&config, &storage_id) {
                tracing::warn!("Failed to clean up an unfinished local vault: {}", cleanup);
            }
            Ok(CommandResponse::err(error))
        }
    }
}

/// Seal the vault's keys under a new recovery code and save the kit file.
#[tauri::command]
pub async fn create_local_recovery_kit(
    save_path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<LocalRecoveryKitResult>, String> {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    let Some(group_id) = state.local_vault_group().await else {
        return Ok(CommandResponse::err("No local vault is open"));
    };
    let client = state.local_client.client().await?;
    let entries = match client.export_local_vault_entries(group_id).await {
        Ok(entries) => entries,
        Err(error) => return Ok(CommandResponse::err(error.to_string())),
    };
    let code = generate_recovery_code();
    let kit = match LocalRecoveryKit::create(code.as_ref(), &entries) {
        Ok(kit) => kit,
        Err(error) => return Ok(CommandResponse::err(error)),
    };
    if let Err(error) = kit.save_to_path(Path::new(&save_path)) {
        return Ok(CommandResponse::err(error));
    }
    let storage_id = {
        let context = state.local_vault.lock().await;
        let Some(context) = context.as_ref() else {
            return Ok(CommandResponse::err("No local vault is open"));
        };
        vault::current_storage_id(&config_dir(&state), &context.record)
    };
    // A sealed copy lets the upgrade check a typed code without storing it.
    let copy = vault::user_dir(&config_dir(&state), &storage_id).join(KIT_COPY_FILE);
    if let Err(error) = kit.save_to_path(&copy) {
        return Ok(CommandResponse::err(error));
    }
    let formatted = format_recovery_code(code.as_ref());
    let check = formatted[formatted.len() - KIT_CHECK_CHARACTERS..].to_string();
    if let Some(context) = state.local_vault.lock().await.as_mut() {
        context.pending_kit_check = Some(check);
    }
    Ok(CommandResponse::ok(LocalRecoveryKitResult {
        recovery_code: formatted,
    }))
}

/// Confirm the user kept the code by retyping its last characters.
#[tauri::command]
pub async fn confirm_local_recovery_kit(
    last_characters: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<LocalVaultStatus>, String> {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    let record = {
        let mut context = state.local_vault.lock().await;
        let Some(context) = context.as_mut() else {
            return Ok(CommandResponse::err("No local vault is open"));
        };
        let typed = last_characters.trim().to_ascii_uppercase();
        match context.pending_kit_check.as_deref() {
            Some(expected) if expected == typed => {}
            Some(_) => {
                return Ok(CommandResponse::err_with_code(
                    "RECOVERY_CODE_MISMATCH",
                    "Those characters don't match the end of your recovery key.",
                ))
            }
            None => {
                return Ok(CommandResponse::err(
                    "Create a recovery kit before confirming it.",
                ))
            }
        }
        context.pending_kit_check = None;
        context.record.kit_saved = true;
        context.record.clone()
    };
    if let Err(error) = vault::save_record(&config_dir(&state), &record) {
        return Ok(CommandResponse::err(error));
    }
    Ok(CommandResponse::ok(status_of(Some(&record), true)))
}

/// Recreate a vault on a new device from its recovery kit file and code. A vault
/// already on this device is replaced only when `replace_empty` confirms the user
/// chose to, and only while none of its files depend on its key.
#[tauri::command]
pub async fn restore_local_vault_from_kit(
    kit_path: String,
    recovery_code: String,
    replace_empty: Option<bool>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<LocalVaultStatus>, String> {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    if state.session.lock().await.is_some() {
        return Ok(CommandResponse::err(
            "Sign out of your account before restoring a vault on this device.",
        ));
    }
    let config = config_dir(&state);
    // Restoring is how a vault whose files are gone comes back.
    let (missing, present) = match vault::load_record(&config) {
        Ok(None) => (None, None),
        Ok(Some(record)) => match vault::find_storage(&config, &record) {
            None => (Some(record), None),
            Some(storage_id) => (None, Some((record, storage_id))),
        },
        Err(error) => return Ok(CommandResponse::err(error)),
    };
    if present.is_some() && !replace_empty.unwrap_or(false) {
        return Ok(CommandResponse::err_with_code(
            VAULT_EXISTS_CODE,
            "This device already has a local vault.",
        ));
    }
    let contents = match parse_recovery_code(&recovery_code).and_then(|code| {
        LocalRecoveryKit::load_from_path(Path::new(&kit_path))
            .and_then(|kit| kit.open(&code).map(|contents| (kit, contents)))
    }) {
        Ok(opened) => opened,
        Err(error) => {
            return Ok(CommandResponse::err_with_code(
                "RECOVERY_KIT_INVALID",
                error,
            ))
        }
    };
    let (kit, contents) = contents;
    if let Some(record) = missing {
        if let Err(error) = replace_missing_record(&config, &record) {
            return Ok(CommandResponse::err(error));
        }
    }
    // The vault being replaced is closed now and removed only once the restore
    // has worked, so a failed restore leaves it as it was.
    let replaced = match present {
        Some((record, storage_id)) => {
            match close_empty_vault(&state, &record, &storage_id, contents.group_id).await {
                Ok(()) => Some(storage_id),
                Err(response) => return Ok(response),
            }
        }
        None => None,
    };
    let _gate = UPDATE_OPERATION_GATE.read().await;
    let storage_id = vault::new_storage_id();
    let restored = async {
        let (_, state_key) = vault::create_storage_keys(&config, &storage_id)?;
        state
            .client
            .create_local_vault_device_keys(&vault::user_dir(&config, &storage_id), &state_key)?;
        let client = state
            .local_client
            .initialize_for_local_vault(&storage_id)
            .await?;
        let info = client
            .import_local_recovery_kit(&contents)
            .await
            .map_err(|error| error.to_string())?;
        kit.save_to_path(&vault::user_dir(&config, &storage_id).join(KIT_COPY_FILE))?;
        if let Some(replaced) = &replaced {
            vault::remove_storage(&config, replaced)?;
        }
        let record = LocalVaultRecord {
            storage_id: storage_id.clone(),
            group_id: info.group_id,
            created_at: info.created_at,
            kit_saved: true,
            upgrade: None,
            merge: None,
        };
        vault::save_record(&config, &record)?;
        Ok::<_, String>(record)
    }
    .await;
    match restored {
        Ok(record) => {
            let status = status_of(Some(&record), true);
            *state.local_vault.lock().await = Some(LocalVaultContext {
                record,
                pending_kit_check: None,
            });
            Ok(CommandResponse::ok(status))
        }
        Err(error) => {
            state.local_client.clear().await;
            if let Err(cleanup) = vault::remove_storage(&config, &storage_id) {
                tracing::warn!("Failed to clean up an unfinished restore: {}", cleanup);
            }
            Ok(CommandResponse::err(error))
        }
    }
}

/// Close the vault on this device so a restored one can take its place, after
/// checking that nothing would be lost: no folder may still need its key.
async fn close_empty_vault(
    state: &AppState,
    record: &LocalVaultRecord,
    storage_id: &str,
    restoring_group: Uuid,
) -> Result<(), CommandResponse<LocalVaultStatus>> {
    if record.upgrade.is_some() || record.merge.is_some() {
        return Err(CommandResponse::err(
            "This vault is becoming part of an account. Finish that first, then restore.",
        ));
    }
    if restoring_group == record.group_id {
        return Err(CommandResponse::err(
            "This recovery kit is for the vault already on this device.",
        ));
    }
    let in_use = async {
        let client = state.local_client.open_local_vault_detached(storage_id).await?;
        client.stop_coverage_watchers().await;
        client
            .local_vault_folders_in_use(record.group_id)
            .await
            .map_err(desktop_safe_client_error)
    }
    .await
    .map_err(CommandResponse::err)?;
    if !in_use.is_empty() {
        let folders = in_use
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CommandResponse::err_with_code(
            VAULT_NOT_EMPTY_CODE,
            format!(
                "The vault on this device still protects files in: {folders}. Unprotect these \
                 folders and decrypt their files first, then restore."
            ),
        ));
    }
    operations::cancel_all_desktop_operations(state).await;
    let _exclusive = UPDATE_OPERATION_GATE.write().await;
    stop_all_mounts_including(state, &vault::user_dir(&config_dir(state), storage_id))
        .await
        .map_err(|error| {
            CommandResponse::err(format!("Close your protected folders first: {error}"))
        })?;
    state.local_client.clear().await;
    *state.local_vault.lock().await = None;
    Ok(())
}

/// Close an open vault, and stop its mounts, before an account signs in: an account
/// and a vault never run at once. The vault opens again once no account is signed in.
pub(crate) async fn close_open_vault(state: &AppState) -> Result<(), String> {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    if state.local_vault.lock().await.is_none() {
        return Ok(());
    }
    operations::cancel_all_desktop_operations(state).await;
    let _exclusive = UPDATE_OPERATION_GATE.write().await;
    stop_all_mounts_safely(state, false)
        .await
        .map_err(|error| format!("Close your protected folders before signing in: {error}"))?;
    state.local_client.clear().await;
    *state.local_vault.lock().await = None;
    Ok(())
}

/// After an account signs in, remove a vault the app started on its own that was
/// never used. Otherwise it would reopen whenever no account is signed in.
/// Failures are logged only: they must never fail the sign-in.
pub(crate) async fn discard_pristine_vault(state: &AppState) {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    if state.local_vault.lock().await.is_some() {
        return;
    }
    let config = config_dir(state);
    let record = match vault::load_record(&config) {
        Ok(Some(record)) if vault::is_pristine(&record) => record,
        Ok(_) => return,
        Err(error) => {
            tracing::warn!("Could not read the local vault record after sign-in: {}", error);
            return;
        }
    };
    match vault::remove_storage(&config, &record.storage_id) {
        Ok(()) => tracing::info!("Removed an unused local vault after sign-in"),
        Err(error) => tracing::warn!("Could not remove an unused local vault: {}", error),
    }
}

/// Leave the vault to sign in to an existing account.
#[tauri::command]
pub async fn close_local_vault(
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    match close_open_vault(&state).await {
        Ok(()) => Ok(CommandResponse::ok(true)),
        Err(error) => Ok(CommandResponse::err(error)),
    }
}

/// Create an account from the vault, or resume one that was interrupted.
#[tauri::command]
pub async fn upgrade_local_vault_to_account(
    email: String,
    password: String,
    recovery_code: Option<String>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<LocalVaultUpgradeResult>, String> {
    let password = Zeroizing::new(password);
    let email = email.trim().to_string();
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    let _login_guard = LOGIN_OPERATION_LOCK.lock().await;
    match run_upgrade(&state, &email, &password, recovery_code.as_deref()).await {
        Ok(result) => Ok(CommandResponse::ok(result)),
        Err((code, message)) => Ok(CommandResponse::err_with_code(code, message)),
    }
}

/// Undo an account creation that hasn't signed in yet, for example after a
/// mistyped email, so the vault is local again and any email can be used.
/// The account already registered on the server stays unconfirmed and unused.
#[tauri::command]
pub async fn cancel_local_vault_upgrade(
    state: State<'_, AppState>,
) -> Result<CommandResponse<LocalVaultStatus>, String> {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    let _login_guard = LOGIN_OPERATION_LOCK.lock().await;
    if state.session.lock().await.is_some() {
        return Ok(CommandResponse::err(
            "This account is already signed in, so creating it can't be undone.",
        ));
    }
    let config = config_dir(&state);
    let record = match vault::load_record(&config) {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(CommandResponse::err("There is no local vault on this device")),
        Err(error) => return Ok(CommandResponse::err(error)),
    };
    if phase(&record).is_none() {
        let active = state.local_vault.lock().await.is_some();
        return Ok(CommandResponse::ok(status_of(Some(&record), active)));
    }
    if phase(&record) >= Some(UpgradePhase::SignedIn) {
        return Ok(CommandResponse::err(
            "This account is already in use, so creating it can't be undone.",
        ));
    }

    // Mounts keep their state in the vault's storage, so they stop before it moves.
    operations::cancel_all_desktop_operations(&state).await;
    let _exclusive = UPDATE_OPERATION_GATE.write().await;
    if let Err(error) = stop_all_mounts_safely(&state, false).await {
        return Ok(CommandResponse::err(format!(
            "Close your protected folders first: {error}"
        )));
    }
    state.local_client.clear().await;
    *state.local_vault.lock().await = None;
    state.client.clear_auth_cache();

    let restored = match vault::return_to_local(&config, &record) {
        Ok(restored) => restored,
        Err(error) => {
            let reloaded = vault::load_record(&config).ok().flatten().unwrap_or(record);
            if let Err(reopen) = open_vault(&state, reloaded).await {
                tracing::warn!("Vault did not reopen after a failed undo: {}", reopen);
            }
            return Ok(CommandResponse::err(error));
        }
    };
    if let Err(error) = open_vault(&state, restored.clone()).await {
        return Ok(CommandResponse::err(error));
    }
    Ok(CommandResponse::ok(status_of(Some(&restored), true)))
}

type UpgradeError = (String, String);

fn failed(message: impl Into<String>) -> UpgradeError {
    ("LOCAL_VAULT_UPGRADE_FAILED".into(), message.into())
}

fn phase(record: &LocalVaultRecord) -> Option<UpgradePhase> {
    record.upgrade.as_ref().map(|progress| progress.phase)
}

async fn advance(
    state: &AppState,
    record: &mut LocalVaultRecord,
    next: UpgradePhase,
) -> Result<(), UpgradeError> {
    if let Some(progress) = record.upgrade.as_mut() {
        progress.phase = next;
    }
    vault::save_record(&config_dir(state), record).map_err(failed)?;
    if let Some(context) = state.local_vault.lock().await.as_mut() {
        context.record = record.clone();
    }
    Ok(())
}

/// Check a typed recovery code against the vault's sealed kit copy.
fn verify_recovery_code(
    config: &Path,
    record: &LocalVaultRecord,
    typed: &str,
) -> Result<Zeroizing<Vec<u8>>, UpgradeError> {
    let code = parse_recovery_code(typed)
        .map_err(|error| ("RECOVERY_CODE_MISMATCH".to_string(), error))?;
    let copy =
        vault::user_dir(config, &vault::current_storage_id(config, record)).join(KIT_COPY_FILE);
    let contents = LocalRecoveryKit::load_from_path(&copy)
        .map_err(|_| failed("This vault has no saved recovery kit. Continue without a recovery key to get a new one."))?
        .open(&code)
        .map_err(|_| ("RECOVERY_CODE_MISMATCH".to_string(), "That recovery key doesn't belong to this vault.".to_string()))?;
    if contents.group_id != record.group_id {
        return Err((
            "RECOVERY_CODE_MISMATCH".into(),
            "That recovery key doesn't belong to this vault.".into(),
        ));
    }
    Ok(code)
}

fn map_register_error(error: String) -> UpgradeError {
    let lower = error.to_ascii_lowercase();
    if lower.contains("409") || lower.contains("already") || lower.contains("exists") {
        return (
            "ACCOUNT_EXISTS".into(),
            "This email already has an account. Sign in to it, and this vault's files can move into it."
                .into(),
        );
    }
    failed(error)
}

async fn run_upgrade(
    state: &AppState,
    email: &str,
    password: &str,
    typed_code: Option<&str>,
) -> Result<LocalVaultUpgradeResult, UpgradeError> {
    // Shared while talking to the server; exclusive only while storage moves.
    let mut gate = Some(UPDATE_OPERATION_GATE.read().await);
    let config = config_dir(state);
    let mut record = vault::load_record(&config)
        .map_err(failed)?
        .ok_or_else(|| failed("There is no local vault on this device"))?;
    let server_url = state.client.server_url().to_string();
    if email.is_empty() || password.is_empty() {
        return Err(failed("Enter an email and password"));
    }
    if let Some(progress) = &record.merge {
        return Err(failed(merge_pending_message(progress)));
    }
    if let Some(progress) = &record.upgrade {
        if !progress.email.eq_ignore_ascii_case(email) {
            return Err(failed(format!(
                "Finish creating the account for {} first.",
                progress.email
            )));
        }
        if progress.server_url != server_url {
            return Err(failed("Account creation started on a different server"));
        }
    }
    // Check the code before anything changes, so a typo can't strand the upgrade.
    let code = match typed_code.map(str::trim).filter(|code| !code.is_empty()) {
        Some(typed) => Some(verify_recovery_code(&config, &record, typed)?),
        None => None,
    };

    if phase(&record).is_none() {
        if state.session.lock().await.is_some() {
            return Err(failed(
                "Sign out before creating an account from this vault",
            ));
        }
        let account_storage_id = state
            .local_client
            .user_storage_id_for_session(email, &server_url);
        if vault::user_dir(&config, &account_storage_id).exists() {
            return Err(failed(
                "This device already has data for that email. Use a different email.",
            ));
        }
        let (account_key, state_key) =
            vault::load_storage_keys(&config, &record.storage_id).map_err(failed)?;
        state
            .client
            .register_with_local_vault_keys(
                email.to_string(),
                password.to_string(),
                &vault::user_dir(&config, &record.storage_id),
                &account_key,
                &state_key,
            )
            .await
            .map_err(map_register_error)?;
        record.upgrade = Some(UpgradeProgress {
            email: email.to_string(),
            server_url: server_url.clone(),
            account_storage_id,
            phase: UpgradePhase::Registered,
        });
        advance(state, &mut record, UpgradePhase::Registered).await?;
    }
    let account_storage_id = record
        .upgrade
        .as_ref()
        .map(|progress| progress.account_storage_id.clone())
        .ok_or_else(|| failed("Account creation details are missing"))?;

    if phase(&record) < Some(UpgradePhase::StorageMoved) {
        // Login creates fresh keys for an email's storage if none exist, so the
        // vault's storage must be in place before the first sign-in. Mounts keep
        // their state in that storage, so they stop before it moves, and the
        // exclusive gate keeps a new mount from starting until it has moved.
        drop(gate.take());
        operations::cancel_all_desktop_operations(state).await;
        let exclusive = UPDATE_OPERATION_GATE.write().await;
        stop_all_mounts_safely(state, false).await.map_err(|err| {
            failed(format!(
                "Close your protected folders before creating an account: {err}"
            ))
        })?;
        state.local_client.clear().await;
        // The record keeps the vault's own name until the move is saved; a move
        // interrupted after the rename resumes from there.
        let moved = vault::move_storage(&config, &record.storage_id, &account_storage_id).and_then(|_| {
            crate::session::SessionStore::new_without_key_cache_migration()?
                .rewrap_after_password_change(email, &server_url, password)
        });
        if let Err(error) = moved {
            let _ = open_vault(state, record.clone()).await;
            return Err(failed(error));
        }
        record.storage_id = account_storage_id.clone();
        advance(state, &mut record, UpgradePhase::StorageMoved).await?;
        // The vault keeps working from its new place while email is confirmed.
        open_vault(state, record.clone()).await.map_err(failed)?;
        drop(exclusive);
        gate = Some(UPDATE_OPERATION_GATE.read().await);
    }
    let _gate = gate;

    if phase(&record) < Some(UpgradePhase::SignedIn) {
        if state.session.lock().await.is_none() {
            match state
                .client
                .login(email.to_string(), password, None, None)
                .await
            {
                Ok(result) => {
                    let session = crate::state::UserSession {
                        email: result.email.clone(),
                        device_id: result.device_id.clone(),
                        token: result.token.clone(),
                        refresh_token: result.refresh_token.clone().unwrap_or_default(),
                        team_entitlement: None,
                        team_revoked: false,
                        pending_team_requests: Vec::new(),
                        expires_at: chrono::Utc::now().timestamp() + result.expires_in,
                        user_id: result.user_id.clone(),
                        server_url: Some(server_url.clone()),
                        opaque_export_key: result.opaque_export_key.clone(),
                        persistent: true,
                    };
                    state.local_client.clear().await;
                    *state.local_vault.lock().await = None;
                    if let Err(error) = state.save_session_with_password(session, password).await {
                        state.client.clear_auth_cache();
                        let _ = open_vault(state, record.clone()).await;
                        return Err(failed(format!(
                            "Signed in, but the account could not open on this device: {error}"
                        )));
                    }
                }
                Err(error)
                    if error.code == "EMAIL_CONFIRMATION_REQUIRED"
                        || is_confirmation_required_error(&error.message) =>
                {
                    state.client.clear_auth_cache();
                    return Ok(LocalVaultUpgradeResult {
                        status: "confirm_email",
                        email: email.to_string(),
                        new_recovery_code: None,
                    });
                }
                Err(error) => {
                    state.client.clear_auth_cache();
                    return Err((error.code, error.message));
                }
            }
        }
        advance(state, &mut record, UpgradePhase::SignedIn).await?;
    }

    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or_else(|| failed("Sign in to finish creating your account"))?;
    if !session.email.eq_ignore_ascii_case(email) {
        return Err(failed("A different account is signed in"));
    }
    let group_id = record.group_id;

    if phase(&record) < Some(UpgradePhase::Adopted) {
        personal_workspace::adopt_local_personal_group(state, &session, group_id)
            .await
            .map_err(failed)?;
        advance(state, &mut record, UpgradePhase::Adopted).await?;
    }

    let client = state.local_client.client().await.map_err(failed)?;
    if phase(&record) < Some(UpgradePhase::KeysCommitted) {
        let key = client
            .local_vault_genesis_key(group_id)
            .await
            .map_err(|error| failed(error.to_string()))?;
        client
            .initialize_group_epoch_with_key(group_id, &key)
            .await
            .map_err(|error| {
                failed(format!(
                    "Could not link this vault's key to the account: {error}"
                ))
            })?;
        advance(state, &mut record, UpgradePhase::KeysCommitted).await?;
    }

    let snapshot = personal_workspace::personal_workspace_snapshot(state, &session, true)
        .await
        .map_err(failed)?;
    let group =
        personal_workspace::available_personal_group(&snapshot, Some(group_id)).map_err(failed)?;
    let epoch = operations::group_epoch_uuid(&group)
        .map_err(failed)?
        .ok_or_else(|| failed("The account's encryption key could not be confirmed"))?;
    client
        .use_group_at_epoch(group_id, epoch)
        .await
        .map_err(|error| failed(error.to_string()))?;

    let mut new_recovery_code = None;
    if !recovery_backup_exists(&server_url, &session.token, &session.email, state)
        .await
        .map_err(failed)?
    {
        let formatted = bootstrap_recovery_backup(
            &server_url,
            &session.token,
            &session.email,
            password,
            client.clone(),
            group_id,
            state,
            code.as_ref().map(|code| code.as_slice()),
        )
        .await
        .map_err(failed)?;
        if code.is_none() {
            new_recovery_code = Some(formatted);
        }
    }

    client
        .clear_local_vault_marker()
        .await
        .map_err(|error| failed(error.to_string()))?;
    let _ = std::fs::remove_file(vault::user_dir(&config, &record.storage_id).join(KIT_COPY_FILE));
    vault::delete_record(&config).map_err(failed)?;
    *state.local_vault.lock().await = None;
    Ok(LocalVaultUpgradeResult {
        status: "complete",
        email: session.email.clone(),
        new_recovery_code,
    })
}

// ------------------------------------------------- move into an existing account

const MERGE_FAILED: &str = "LOCAL_VAULT_MERGE_FAILED";
const MERGE_OTHER_ACCOUNT: &str = "LOCAL_VAULT_MERGE_OTHER_ACCOUNT";
const ACCOUNT_KEYS_NOT_READY: &str = "ACCOUNT_KEYS_NOT_READY";
const MERGE_PROGRESS_EVENT: &str = "local_vault_merge_progress";

#[derive(Debug, Serialize)]
pub struct LocalVaultMergeResult {
    /// Folders the account protects now.
    pub protected_folders: usize,
    /// Files whose keys moved to the account in this run.
    pub moved_files: usize,
}

#[derive(Debug, Clone, Serialize)]
struct MergeProgressEvent {
    folder: String,
    folder_index: usize,
    folder_count: usize,
    /// "moving" while file keys move, "protecting" while the account takes the folder.
    phase: &'static str,
    total_files: usize,
    processed_files: usize,
}

fn merge_failed(message: impl Into<String>) -> UpgradeError {
    (MERGE_FAILED.into(), message.into())
}

fn keys_not_ready() -> UpgradeError {
    (
        ACCOUNT_KEYS_NOT_READY.into(),
        "Finish setting up your account on this device first: enter your recovery key, or approve this device from one you already use. Then move the files."
            .into(),
    )
}

fn merge_pending_message(progress: &MergeProgress) -> String {
    format!(
        "This vault's files are moving into {}. Sign in as {} to finish.",
        progress.email, progress.email
    )
}

/// A vault can move into an account when its files are here and no new account
/// is being created from it.
fn merge_allowed(record: &LocalVaultRecord, storage_present: bool) -> bool {
    // Without a saved kit the vault never protected a folder, so there is nothing to move.
    storage_present && record.kit_saved && record.upgrade.is_none()
}

/// A move that started under one account only continues under that account.
fn merge_belongs_to(progress: &MergeProgress, user_id: &str, server_url: &str) -> bool {
    progress.user_id == user_id && progress.server_url == server_url
}

/// The vault's folders to move, one entry per path. Protected folders become the
/// account's; folders removed from the vault but left encrypted still move, or
/// their files would be lost with the vault key. Folders that are gone are skipped.
fn merge_folder_list(roots: impl IntoIterator<Item = (PathBuf, bool)>) -> Vec<MergeFolder> {
    let mut folders: Vec<MergeFolder> = Vec::new();
    for (path, protected) in roots {
        match folders.iter_mut().find(|folder| folder.path == path) {
            Some(folder) => folder.protected |= protected,
            None => folders.push(MergeFolder {
                path,
                protected,
                step: MergeStep::Pending,
            }),
        }
    }
    folders
}

/// Move this device's vault into the signed-in account, which already existed.
/// Each vault file's key is rewrapped for the account's Personal workspace (the
/// contents stay as they are), the account protects the vault's folders, and the
/// vault is removed. An interrupted move resumes where it stopped.
#[tauri::command]
pub async fn merge_local_vault_into_account(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CommandResponse<LocalVaultMergeResult>, String> {
    let _lock = LOCAL_VAULT_LOCK.lock().await;
    match run_merge(&state, &app).await {
        Ok(result) => Ok(CommandResponse::ok(result)),
        Err((code, message)) => Ok(CommandResponse::err_with_code(code, message)),
    }
}

async fn run_merge(
    state: &AppState,
    app: &AppHandle,
) -> Result<LocalVaultMergeResult, UpgradeError> {
    let mut gate = Some(ensure_authenticated(state).await.map_err(merge_failed)?);
    let session = current_authenticated_session(state)
        .await
        .map_err(merge_failed)?;
    let server_url = current_server_url(state, &session);
    let config = config_dir(state);
    let mut record = vault::load_record(&config)
        .map_err(merge_failed)?
        .ok_or_else(|| merge_failed("There is no local vault on this device"))?;
    if let Some(progress) = &record.upgrade {
        return Err(merge_failed(format!(
            "Finish creating the account for {} first.",
            progress.email
        )));
    }
    if let Some(progress) = &record.merge {
        if !merge_belongs_to(progress, &session.user_id, &server_url) {
            return Err((MERGE_OTHER_ACCOUNT.into(), merge_pending_message(progress)));
        }
    }
    let storage_id = vault::find_storage(&config, &record)
        .ok_or_else(|| merge_failed(vault::STORAGE_MISSING_MESSAGE))?;

    // The target is the account's Personal workspace key on this device.
    let snapshot = personal_workspace::personal_workspace_snapshot(state, &session, true)
        .await
        .map_err(merge_failed)?;
    let group =
        personal_workspace::available_personal_group(&snapshot, None).map_err(merge_failed)?;
    let personal = Uuid::parse_str(group["id"].as_str().unwrap_or_default())
        .map_err(|_| merge_failed("Your Personal workspace couldn't be identified"))?;
    if record
        .merge
        .as_ref()
        .is_some_and(|progress| progress.target_group_id != personal)
    {
        return Err(merge_failed(
            "Your Personal workspace changed while this vault's files were moving.",
        ));
    }
    let epoch = operations::group_epoch_uuid(&group)
        .map_err(merge_failed)?
        .ok_or_else(keys_not_ready)?;
    let account = state.local_client.client().await.map_err(merge_failed)?;
    if !account
        .has_cached_group_epoch_key(personal, epoch)
        .await
        .unwrap_or(false)
    {
        let _ = account.refresh_committed_group_epoch(personal).await;
    }
    account
        .use_group_at_epoch(personal, epoch)
        .await
        .map_err(|_| keys_not_ready())?;
    let to = account
        .current_group_transfer_key(personal)
        .await
        .map_err(|_| keys_not_ready())?;

    let vault_client = state
        .local_client
        .open_local_vault_detached(&storage_id)
        .await
        .map_err(merge_failed)?;
    // Its watcher would encrypt and index files in folders that are mid-move.
    vault_client.stop_coverage_watchers().await;
    let vault_client = vault_client.for_local_group(record.group_id);
    let from = vault_client
        .local_vault_transfer_key(record.group_id)
        .await
        .map_err(|error| merge_failed(desktop_safe_client_error(error)))?;
    let vault_roots = vault_client
        .coverage_roots()
        .await
        .map_err(|error| merge_failed(desktop_safe_client_error(error)))?;

    if record.merge.is_none() {
        let folders = merge_folder_list(
            vault_roots
                .iter()
                .filter(|root| root.group_id.map_or(true, |group| group == record.group_id))
                .filter(|root| root.path.exists())
                .map(|root| {
                    (
                        root.path.clone(),
                        root.state == hybridcipher_client::coverage::CoverageRootState::Active,
                    )
                }),
        );
        // The vault's folders may still be mounted from before the sign-in.
        drop(gate.take());
        operations::cancel_all_desktop_operations(state).await;
        let exclusive = UPDATE_OPERATION_GATE.write().await;
        stop_all_mounts_including(state, &vault::user_dir(&config, &storage_id))
            .await
            .map_err(|error| {
                merge_failed(format!("Close your protected folders first: {error}"))
            })?;
        record.merge = Some(MergeProgress {
            user_id: session.user_id.clone(),
            email: session.email.clone(),
            server_url: server_url.clone(),
            target_group_id: personal,
            folders,
        });
        vault::save_record(&config, &record).map_err(merge_failed)?;
        drop(exclusive);
        gate = Some(UPDATE_OPERATION_GATE.read().await);
    }
    let _gate = gate;

    let account_scoped = account.for_local_group(personal);
    let folder_count = record
        .merge
        .as_ref()
        .map_or(0, |progress| progress.folders.len());
    let mut moved_files = 0;
    let mut protected_folders = 0;
    while let Some(index) = record.merge.as_ref().and_then(MergeProgress::next_folder) {
        let folder = record.merge.as_ref().expect("merge in progress").folders[index].clone();
        let label = folder.path.display().to_string();
        let emit = {
            let app = app.clone();
            let label = label.clone();
            move |phase: &'static str, total_files: usize, processed_files: usize| {
                let _ = app.emit(
                    MERGE_PROGRESS_EVENT,
                    MergeProgressEvent {
                        folder: label.clone(),
                        folder_index: index,
                        folder_count,
                        phase,
                        total_files,
                        processed_files,
                    },
                );
            }
        };

        if folder.step == MergeStep::Pending {
            if folder.path.exists() {
                let report = emit.clone();
                let progress = account
                    .transfer_folder_to_group(
                        &folder.path,
                        from.clone(),
                        to.clone(),
                        move |progress| {
                            report("moving", progress.total_files, progress.processed_files)
                        },
                    )
                    .await
                    .map_err(|error| merge_failed(desktop_safe_client_error(error)))?;
                moved_files += progress.moved_files;
            }
            set_merge_step(&config, &mut record, index, MergeStep::Moved).map_err(merge_failed)?;
        }

        emit("protecting", 0, 0);
        if folder.protected && folder.path.exists() {
            account
                .coverage_assert_folder_owned_by(&folder.path, personal)
                .await
                .map_err(|error| merge_failed(desktop_safe_client_error(error)))?;
            // The registry of protected folders is shared by every storage on this
            // device, so the vault gives the folder up before the account takes it.
            // `vault_roots` is read at the start of each run, so a folder given up
            // before an interruption is not given up twice.
            let held_by_vault = vault_roots.iter().any(|root| {
                root.path == folder.path
                    && root.state == hybridcipher_client::coverage::CoverageRootState::Active
            });
            if held_by_vault {
                vault_client
                    .coverage_unenroll_root(&folder.path)
                    .await
                    .map_err(|error| merge_failed(desktop_safe_client_error(error)))?;
            }
            let already_protected = account_scoped
                .coverage_roots()
                .await
                .map_err(|error| merge_failed(desktop_safe_client_error(error)))?
                .iter()
                .any(|root| {
                    root.path == folder.path
                        && root.group_id == Some(personal)
                        && root.state == hybridcipher_client::coverage::CoverageRootState::Active
                });
            if !already_protected {
                hybridcipher_client::ipc::coverage_workflows::enroll_and_hydrate(
                    &account_scoped,
                    folder.path.clone(),
                )
                .await
                .map_err(|error| merge_failed(desktop_safe_client_error(error)))?;
            }
            protected_folders += 1;
        }
        set_merge_step(&config, &mut record, index, MergeStep::Done).map_err(merge_failed)?;
    }

    // Nothing may stay readable only by the vault key, which is deleted next.
    let folders = record
        .merge
        .as_ref()
        .map(|progress| progress.folders.clone())
        .unwrap_or_default();
    for folder in folders.iter().filter(|folder| folder.path.exists()) {
        account
            .coverage_assert_folder_owned_by(&folder.path, personal)
            .await
            .map_err(|error| merge_failed(desktop_safe_client_error(error)))?;
    }
    drop(vault_client);
    vault::remove_storage(&config, &storage_id).map_err(merge_failed)?;
    *state.local_vault.lock().await = None;
    Ok(LocalVaultMergeResult {
        protected_folders,
        moved_files,
    })
}

fn set_merge_step(
    config: &Path,
    record: &mut LocalVaultRecord,
    index: usize,
    step: MergeStep,
) -> Result<(), String> {
    if let Some(folder) = record
        .merge
        .as_mut()
        .and_then(|progress| progress.folders.get_mut(index))
    {
        folder.step = step;
    }
    vault::save_record(config, record)
}

#[cfg(test)]
#[path = "../../tests/local/test_local_vault_commands.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/local/test_local_vault_merge.rs"]
mod merge_tests;
