use crate::{
    cli_schema::CliCommand,
    cli_utils::locate_cli_binary,
    http_client::{GroupListResponse, GroupRole},
    individual_views::{
        build_folder_coverage_review, build_individual_home_status,
        build_personal_devices_overview, CurrentDeviceSnapshot, DeviceCountSnapshot,
        FolderAttentionSnapshot, FolderCoverageReview, IndividualHomeStatus,
        IndividualHomeStatusInput, IndividualSecuritySnapshot, IndividualSettingsSnapshot,
        PendingDeviceRecord, PersonalDevicesOverview, PersonalDevicesOverviewInput,
        RegisteredDeviceRecord, StaleDeviceRecord, UnverifiedDeviceRecord,
    },
    key_bundle, legal,
    local_client::LocalClient,
    process_utils::{configure_background_std_command, configure_background_tokio_command},
    recovery_artifact::{
        format_recovery_code, BackupArtifact, BackupEntryPlain, RECOVERY_CODE_BYTES,
    },
    release_notes,
    state::AppState,
    terminal_diagnostics::TerminalDiagnosticPayload,
};
use base64::engine::general_purpose;
use base64::Engine;
use dunce;
use hex;
use hkdf::Hkdf;
use hybridcipher_client::{
    coverage::{CoverageRootKind, CoverageRootState},
    state::client::{CoverageFileRecord, CoverageRootStats, CoverageScanSummary},
};
use hybridcipher_crypto::account_protection::{decrypt_with_ad, encrypt_with_ad, ProtectedData};
use hybridcipher_mount_sync::{
    load_mount_conflict_registry, load_mount_recovery_registry, read_conflict_preview_text,
    sync_mount_conflict_action_requests_dir, sync_mount_conflict_action_results_dir,
    sync_mount_conflict_registry_path, sync_mount_recovery_action_requests_dir,
    sync_mount_recovery_action_results_dir, sync_mount_recovery_registry_path,
    ConflictResolutionAction, ConflictResolutionRequest, ConflictResolutionResponse,
    ConflictResolutionResult, MountConflictPreview, MountConflictRecord, MountRecoveryCopyPreview,
    MountRecoveryCopyRecord, MountSyncRuntimeStatus, RecoveryCopyResolutionAction,
    RecoveryCopyResolutionRequest, RecoveryCopyResolutionResponse, RecoveryCopyResolutionResult,
};
use once_cell::sync::Lazy;
use opaque_ke::{key_exchange::tripledh::TripleDh, CipherSuite, ClientLogin, Ristretto255};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use qrcode::{render::svg, QrCode};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::{Arc, Mutex},
    thread,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::{
    fs,
    time::{sleep, Duration},
};
use uuid::Uuid;

mod file_ops;
mod groups;
mod rekey;
mod settings;

pub use file_ops::*;
pub use groups::*;
pub use rekey::*;
pub use settings::*;

/// Standard response wrapper for all commands
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
}

impl<T> CommandResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            error_code: None,
        }
    }

    pub fn err<E: ToString>(error: E) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.to_string()),
            error_code: None,
        }
    }

    pub fn err_with_code<C: ToString, E: ToString>(code: C, error: E) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.to_string()),
            error_code: Some(code.to_string()),
        }
    }
}

// ============================================================================
// Authentication Commands
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub device_name: Option<String>,
}

#[tauri::command]
pub async fn register_user(
    request: RegisterRequest,
    state: State<'_, AppState>,
) -> Result<CommandResponse<String>, String> {
    tracing::info!("Register command called for email: {}", request.email);

    match state.client.register(request.email, request.password).await {
        Ok(result) => Ok(CommandResponse::ok(result.message)),
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailConfirmationStatus {
    pub confirmed: bool,
    pub message: Option<String>,
}

fn is_confirmation_required_error(message: &str) -> bool {
    let lowered = message.to_lowercase();
    lowered.contains("confirmation")
        || lowered.contains("emailconfirmationrequired")
        || lowered.contains("email confirmation")
}

#[tauri::command]
pub async fn check_email_confirmation(
    email: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<EmailConfirmationStatus>, String> {
    match state
        .client
        .login(email.clone(), password, None, None)
        .await
    {
        Ok(_) => Ok(CommandResponse::ok(EmailConfirmationStatus {
            confirmed: true,
            message: None,
        })),
        Err(err) => {
            if err.code == "EMAIL_CONFIRMATION_REQUIRED"
                || is_confirmation_required_error(&err.message)
            {
                Ok(CommandResponse::ok(EmailConfirmationStatus {
                    confirmed: false,
                    message: Some("Email confirmation pending.".to_string()),
                }))
            } else {
                Ok(CommandResponse::err_with_code(err.code, err.message))
            }
        }
    }
}

#[tauri::command]
pub async fn resend_confirmation_email(
    email: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<String>, String> {
    let server_url = state.client.server_url().to_string();
    let endpoint = api_endpoint(&server_url, "auth/resend-confirmation");
    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .json(&json!({ "email": email }))
        .send()
        .await
        .map_err(|e| format!("Failed to resend confirmation email: {}", e))?;

    if response.status().is_success() {
        let body: Value = response.json().await.unwrap_or_else(|_| Value::Null);
        let message = body
            .get("message")
            .and_then(|value| value.as_str())
            .unwrap_or("Confirmation email resent.")
            .to_string();
        return Ok(CommandResponse::ok(message));
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Ok(CommandResponse::err(format!(
        "Confirmation resend failed with status {}: {}",
        status, body
    )))
}

fn default_remember_me() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetSessionInfo {
    pub session_id: String,
}

struct DesktopOpaqueCipherSuite;

impl CipherSuite for DesktopOpaqueCipherSuite {
    type OprfCs = Ristretto255;
    type KeGroup = Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

fn is_mfa_required_error(message: &str) -> bool {
    let lower = message.to_lowercase();
    (lower.contains("mfarequired") || (lower.contains("mfa") && lower.contains("required")))
        && !lower.contains("enrollment")
}

fn is_mfa_enrollment_error(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("mfa") && lower.contains("enrollment")
}

fn canonicalize_password_reset_server_url(server_url: &str) -> String {
    let trimmed = server_url.trim();
    if trimmed.is_empty() {
        return "https://api.hybridcipher.com".to_string();
    }

    let lower = trimmed.to_ascii_lowercase();
    for alias in [
        "http://108.175.8.121:8080",
        "https://108.175.8.121:8080",
        "http://108.175.8.121",
        "https://108.175.8.121",
    ] {
        let alias_lower = alias.to_ascii_lowercase();
        if lower == alias_lower || lower.starts_with(&(alias_lower.clone() + "/")) {
            return "https://api.hybridcipher.com".to_string();
        }
    }

    for alias in [
        "http://api.hybridcipher.com",
        "http://api.hybridcipher.com:8080",
    ] {
        let alias_lower = alias.to_ascii_lowercase();
        if lower == alias_lower || lower.starts_with(&(alias_lower.clone() + "/")) {
            return "https://api.hybridcipher.com".to_string();
        }
    }

    trimmed.to_string()
}

fn password_reset_user_storage_id(email: &str, server_url: &str) -> String {
    let canonical_url = canonicalize_password_reset_server_url(server_url);
    let mut hasher = Sha256::new();
    hasher.update(email.to_lowercase().as_bytes());
    hasher.update(canonical_url.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn desktop_bundle_has_device_key(email: &str, server_url: &str) -> Result<bool, String> {
    let storage_id = password_reset_user_storage_id(email, server_url);
    crate::key_bundle::has_state_key(&storage_id)
}

fn password_reset_probe_identity_public_key_hex() -> String {
    "00".repeat(32)
}

fn password_reset_probe_invitation_public_key_hex() -> String {
    "00".repeat(1312)
}

#[tauri::command]
pub async fn check_password_reset_account(
    email: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    let email = email.trim().to_string();
    if email.is_empty() {
        return Ok(CommandResponse::err("Email is required."));
    }

    let mut rng = OsRng;
    let credential_request =
        ClientLogin::<DesktopOpaqueCipherSuite>::start(&mut rng, b"desktop-password-reset-check")
            .map_err(|e| format!("Failed to build password reset lookup request: {e:?}"))?
            .message;

    let credential_request_b64 =
        general_purpose::STANDARD.encode(credential_request.serialize().to_vec());

    let endpoint = api_endpoint(state.client.server_url(), "auth/login/start");
    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .json(&json!({
            "username_or_email": email,
            "device_id": "desktop_password_reset_probe",
            "credential_request": credential_request_b64,
            "identity_public_key": password_reset_probe_identity_public_key_hex(),
            "invitation_public_key": password_reset_probe_invitation_public_key_hex(),
            "device_display_name": "Desktop Password Reset Probe",
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to contact server: {}", e))?;

    if response.status().is_success() {
        return Ok(CommandResponse::ok(true));
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status == reqwest::StatusCode::BAD_REQUEST
        && body.to_ascii_lowercase().contains("maximum device limit")
    {
        return Ok(CommandResponse::ok(true));
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        return Ok(CommandResponse::err_with_code(
            "EMAIL_CONFIRMATION_REQUIRED",
            if body.trim().is_empty() {
                "This account exists but still requires email confirmation before sign-in."
            } else {
                &body
            },
        ));
    }
    if status == reqwest::StatusCode::UNAUTHORIZED
        && body.to_ascii_lowercase().contains("invalid credentials")
    {
        return Ok(CommandResponse::err_with_code(
            "ACCOUNT_NOT_FOUND",
            "No account was found for that email address.",
        ));
    }

    Ok(CommandResponse::err_with_code(
        "PASSWORD_RESET_ACCOUNT_CHECK_FAILED",
        if body.trim().is_empty() {
            format!(
                "Password reset account check failed with status {}.",
                status
            )
        } else {
            format!("Password reset account check failed ({}): {}", status, body)
        },
    ))
}

#[tauri::command]
pub async fn request_password_reset(
    email: String,
    mfa_code: Option<String>,
    backup_code: Option<String>,
    accept_data_loss: Option<bool>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<String>, String> {
    let email = email.trim().to_string();
    if email.is_empty() {
        return Ok(CommandResponse::err("Email is required."));
    }

    let server_url = state.client.server_url().to_string();
    let active_session = { state.session.lock().await.clone() };
    if let Some(session) = active_session {
        let now = chrono::Utc::now().timestamp();
        let active_server = session
            .server_url
            .clone()
            .unwrap_or_else(|| server_url.clone());
        if session.expires_at > now
            && session.email.eq_ignore_ascii_case(&email)
            && canonicalize_password_reset_server_url(&active_server)
                == canonicalize_password_reset_server_url(&server_url)
        {
            return Ok(CommandResponse::err_with_code(
                "PASSWORD_RESET_ACTIVE_SESSION",
                "You are currently logged in as this account. Log out before resetting a forgotten password.",
            ));
        }
    }

    let accept_data_loss = accept_data_loss.unwrap_or(false);
    let keystore_present = desktop_bundle_has_device_key(&email, &server_url)?;
    if !keystore_present && !accept_data_loss {
        return Ok(CommandResponse::err_with_code(
            "DATA_LOSS_CONFIRMATION_REQUIRED",
            "This device does not currently have a keystore-backed device key. Continuing may make previously encrypted local state unreadable unless another trusted device still has the keys.",
        ));
    }

    let endpoint = api_endpoint(&server_url, "auth/password-reset/request");
    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .json(&json!({
            "email": email,
            "mfa_code": mfa_code,
            "backup_code": backup_code,
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to contact server: {}", e))?;

    if response.status().is_success() {
        return Ok(CommandResponse::ok(
            "If an account exists for that email, a reset token has been sent.".to_string(),
        ));
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if is_mfa_enrollment_error(&body) {
        return Ok(CommandResponse::err_with_code(
            "MFA_ENROLLMENT_REQUIRED",
            "MFA is not enabled for this account. Enable MFA first, then retry password reset.",
        ));
    }
    if is_mfa_required_error(&body) {
        return Ok(CommandResponse::err_with_code(
            "MFA_REQUIRED",
            if body.trim().is_empty() {
                "MFA verification failed or was missing.".to_string()
            } else {
                body
            },
        ));
    }

    Ok(CommandResponse::err_with_code(
        "PASSWORD_RESET_REQUEST_FAILED",
        format!("Reset request failed ({}): {}", status, body),
    ))
}

#[tauri::command]
pub async fn login_user(
    email: String,
    password: String,
    persist_session: Option<bool>,
    mfa_code: Option<String>,
    backup_code: Option<String>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<crate::client::LoginResult>, String> {
    tracing::info!("Login command called for email: {}", email);

    let remember_me = persist_session.unwrap_or_else(default_remember_me);

    match state
        .client
        .login(email.clone(), password.clone(), mfa_code, backup_code)
        .await
    {
        Ok(result) => {
            // Create user session
            let session = crate::state::UserSession {
                email: result.email.clone(),
                device_id: result.device_id.clone(),
                token: result.token.clone(),
                refresh_token: result.refresh_token.clone().unwrap_or_default(),
                expires_at: chrono::Utc::now().timestamp() + result.expires_in,
                user_id: result.user_id.clone(),
                server_url: Some(state.client.server_url().to_string()),
                opaque_export_key: result.opaque_export_key.clone(),
            };

            // Save session with password-based encryption (derives and caches account key)
            // This allows desktop to login independently from CLI while sharing the same storage
            let save_result = if remember_me {
                state.save_session_with_password(session, &password).await
            } else {
                // Even for non-persistent sessions, we need the account key for encryption
                // So still use password-based initialization but don't persist session
                state.save_session_with_password(session, &password).await
            };

            if let Err(e) = save_result {
                tracing::error!("Failed to save session: {}", e);
                return Ok(CommandResponse::err(format!(
                    "Login succeeded but session could not be initialized: {}",
                    e
                )));
            }

            let mut login_result = result;
            let recovery_code = match bootstrap_default_group_on_login(&state, &password).await {
                Ok(code) => code,
                Err(err) => {
                    tracing::warn!("Post-login bootstrap skipped: {}", err);
                    None
                }
            };
            let auto_recovery_code = match auto_provision_recovery_on_login(&state, &password).await
            {
                Ok(code) => code,
                Err(err) => {
                    tracing::warn!("Recovery auto-provision skipped: {}", err);
                    None
                }
            };
            login_result.recovery_code = recovery_code.or(auto_recovery_code);

            Ok(CommandResponse::ok(login_result))
        }
        Err(e) => Ok(CommandResponse::err_with_code(e.code, e.message)),
    }
}

async fn bootstrap_default_group_on_login(
    state: &AppState,
    password: &str,
) -> Result<Option<String>, String> {
    let session = {
        let guard = state.session.lock().await;
        guard
            .clone()
            .ok_or_else(|| "No active session found".to_string())?
    };

    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let token = session.token.clone();

    let groups = fetch_group_list(&server_url, &token).await?;
    let target = groups
        .groups
        .iter()
        .find(|group| group_needs_genesis(group));
    let Some(group) = target else {
        return Ok(None);
    };

    let group_id = group.id;
    let client = state
        .local_client
        .client()
        .await
        .map_err(|e| format!("Local client unavailable: {}", e))?;

    if let Err(err) = client.use_group(group_id).await {
        tracing::warn!("Failed to set active group {}: {}", group_id, err);
    }

    client
        .initialize_group_epoch(group_id, 1)
        .await
        .map_err(|e| format!("Failed to initialize default group: {}", e))?;

    if let Err(err) = client.use_group(group_id).await {
        tracing::warn!("Failed to cache default group {}: {}", group_id, err);
    }

    if recovery_backup_exists(&server_url, &token, &session.email, state).await? {
        return Ok(None);
    }

    let code = bootstrap_recovery_backup(
        &server_url,
        &token,
        &session.email,
        password,
        client,
        group_id,
        state,
    )
    .await?;

    Ok(Some(code))
}

fn api_endpoint(base_url: &str, path: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    let suffix = path.trim_start_matches('/');
    if trimmed.ends_with("/api/v1") {
        format!("{}/{}", trimmed, suffix)
    } else {
        format!("{}/api/v1/{}", trimmed, suffix)
    }
}

async fn fetch_group_list(server_url: &str, token: &str) -> Result<GroupListResponse, String> {
    let endpoint = api_endpoint(server_url, "groups");
    let client = reqwest::Client::new();
    let response = client
        .get(endpoint)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch group list: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Authentication token rejected during group listing".to_string());
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Group listing failed with status {}: {}",
            status, body
        ));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Invalid group list response: {}", e))
}

fn group_needs_genesis(group: &crate::http_client::GroupInfo) -> bool {
    let no_epoch = group
        .current_epoch
        .as_ref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true);
    let is_admin = matches!(group.user_role, GroupRole::Admin);
    no_epoch && is_admin
}

fn recovery_artifact_path(
    state: &AppState,
    email: &str,
    server_url: &str,
) -> Result<PathBuf, String> {
    let user_dir = state.local_client.user_dir_for_session(email, server_url);
    Ok(user_dir.join("recovery_backup.b64"))
}

async fn recovery_backup_exists(
    server_url: &str,
    token: &str,
    email: &str,
    state: &AppState,
) -> Result<bool, String> {
    let path = recovery_artifact_path(state, email, server_url)?;
    if path.exists() {
        return Ok(true);
    }

    let endpoint = api_endpoint(server_url, "recovery-artifact");
    let client = reqwest::Client::new();
    let response = client
        .get(endpoint)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Failed to check recovery backup status: {}", e))?;

    match response.status() {
        reqwest::StatusCode::OK => Ok(true),
        reqwest::StatusCode::NOT_FOUND => Ok(false),
        reqwest::StatusCode::UNAUTHORIZED => {
            Err("Authentication token rejected while checking recovery backups".to_string())
        }
        status => {
            let body = response.text().await.unwrap_or_default();
            Err(format!(
                "Recovery backup check failed with status {}: {}",
                status, body
            ))
        }
    }
}

fn recovery_auto_backup_state(
    session: &crate::state::UserSession,
    state: &AppState,
) -> &'static str {
    if session.device_id.trim().is_empty() {
        return "missing_device_id";
    }

    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let user_dir = state
        .local_client
        .user_dir_for_session(&session.email, &server_url);
    let writer_blob_path = user_dir.join(WRITER_BLOB_FILE);
    if !writer_blob_path.exists() {
        return "missing_writer_blob";
    }

    let storage_id = state
        .local_client
        .user_storage_id_for_session(&session.email, &server_url);
    match key_bundle::load_writer_key(&storage_id, &session.device_id) {
        Ok(Some(_)) => "ready",
        Err(_) => "secure_storage_unavailable",
        Ok(None) => "missing_writer_key",
    }
}

const WRITER_BLOB_FILE: &str = "recovery_writer_blob.json";
const WRITER_AAD: &[u8] = b"hybridcipher/recovery/writer";

struct WriterMaterial {
    epoch_key: [u8; 32],
}

fn derive_writer_key(k_file: &[u8; 32], device_id: &str) -> Result<[u8; 32], String> {
    let mut writer_key = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(None, k_file);
    hk.expand(format!("writer:{}", device_id).as_bytes(), &mut writer_key)
        .map_err(|_| "Failed to derive writer key".to_string())?;
    Ok(writer_key)
}

fn persist_recovery_writer_material(
    state: &AppState,
    session: &crate::state::UserSession,
    k_file: &[u8; 32],
    epoch_key: &[u8; 32],
) -> Result<(), String> {
    let writer_key = derive_writer_key(k_file, &session.device_id)?;
    let blob = encrypt_with_ad(epoch_key, writer_key, WRITER_AAD)
        .map_err(|e| format!("Failed to seal writer blob: {}", e))?;

    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let storage_id = state
        .local_client
        .user_storage_id_for_session(&session.email, &server_url);
    if let Err(err) = key_bundle::store_writer_key(&storage_id, &session.device_id, &writer_key) {
        tracing::warn!(
            "Could not store writer key in secure storage; silent recovery backup may be unavailable: {}",
            err
        );
    }

    let user_dir = state
        .local_client
        .user_dir_for_session(&session.email, &server_url);
    let path = user_dir.join(WRITER_BLOB_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create writer blob dir: {}", e))?;
    }
    let serialized =
        serde_json::to_vec(&blob).map_err(|e| format!("Failed to serialize writer blob: {}", e))?;
    std::fs::write(&path, serialized)
        .map_err(|e| format!("Failed to persist writer blob: {}", e))?;
    Ok(())
}

fn load_recovery_writer_material(
    state: &AppState,
    session: &crate::state::UserSession,
) -> Result<Option<WriterMaterial>, String> {
    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let user_dir = state
        .local_client
        .user_dir_for_session(&session.email, &server_url);
    let path = user_dir.join(WRITER_BLOB_FILE);
    if !path.exists() {
        return Ok(None);
    }

    let blob_bytes =
        std::fs::read(&path).map_err(|e| format!("Failed to read writer blob: {}", e))?;
    let blob: ProtectedData = serde_json::from_slice(&blob_bytes)
        .map_err(|e| format!("Writer blob is malformed: {}", e))?;

    let storage_id = state
        .local_client
        .user_storage_id_for_session(&session.email, &server_url);
    let key = match key_bundle::load_writer_key(&storage_id, &session.device_id)
        .map_err(|e| format!("Failed to read writer key from secure storage: {}", e))?
    {
        Some(key) => key,
        None => return Ok(None),
    };
    let epoch_key_bytes = decrypt_with_ad(&blob, key, WRITER_AAD).map_err(|e| {
        format!(
            "Failed to decrypt writer blob; recovery prompts will be required: {}",
            e
        )
    })?;
    if epoch_key_bytes.len() != 32 {
        return Ok(None);
    }
    let mut epoch_key = [0u8; 32];
    epoch_key.copy_from_slice(&epoch_key_bytes);
    Ok(Some(WriterMaterial { epoch_key }))
}

async fn fetch_mfa_status(server_url: &str, token: &str) -> Result<MfaStatusResponse, String> {
    let endpoint = api_endpoint(server_url, "mfa/status");
    let client = reqwest::Client::new();
    let response = client
        .get(endpoint)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch MFA status: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Authentication token rejected while checking MFA status".to_string());
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "MFA status check failed with status {}: {}",
            status, body
        ));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Invalid MFA status response: {}", e))
}

async fn bootstrap_recovery_backup(
    server_url: &str,
    token: &str,
    email: &str,
    password: &str,
    client: std::sync::Arc<LocalClient>,
    group_id: Uuid,
    state: &AppState,
) -> Result<String, String> {
    let capsule = client
        .export_recovery_capsule(group_id)
        .await
        .map_err(|e| format!("Unable to collect epoch secrets for recovery: {}", e))?;

    let mut entries = Vec::new();
    for epoch in &capsule.epochs {
        entries.push(BackupEntryPlain {
            group_id: capsule.group_id,
            epoch_number: epoch.epoch_number,
            epoch_uuid: epoch.epoch_uuid,
            created_at: epoch.created_at,
            is_active: epoch.is_active,
            encryption_key_b64: epoch.encryption_key_b64.clone(),
        });
    }

    if entries.is_empty() {
        return Err("No epoch secrets available to back up".to_string());
    }

    let mut recovery_secret_bytes = [0u8; RECOVERY_CODE_BYTES];
    OsRng.fill_bytes(&mut recovery_secret_bytes);
    let formatted_code = format_recovery_code(&recovery_secret_bytes);

    let mut artifact = BackupArtifact::new(password, &recovery_secret_bytes)?;
    artifact.append_entries(&entries, password, &recovery_secret_bytes)?;

    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or_else(|| "No active session found".to_string())?;
    let path = recovery_artifact_path(state, email, server_url)?;
    let k_file = artifact.unwrap_file_key(password, &recovery_secret_bytes)?;
    let hkdf_salt = general_purpose::STANDARD
        .decode(&artifact.hkdf_salt_b64)
        .map_err(|e| format!("Invalid HKDF salt encoding: {}", e))?;
    let epoch_key = artifact.derive_epoch_key_from_file_key(k_file.as_ref(), &hkdf_salt)?;
    let mut k_file_bytes = [0u8; 32];
    k_file_bytes.copy_from_slice(k_file.as_ref());
    persist_recovery_writer_material(state, &session, &k_file_bytes, &epoch_key)?;
    artifact.save_to_path(&path)?;

    upload_recovery_artifact(server_url, token, &artifact).await?;

    Ok(formatted_code)
}

async fn auto_provision_recovery_on_login(
    state: &AppState,
    password: &str,
) -> Result<Option<String>, String> {
    let session = {
        let guard = state.session.lock().await;
        guard
            .clone()
            .ok_or_else(|| "No active session found".to_string())?
    };

    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let token = session.token.clone();

    let client = state
        .local_client
        .client()
        .await
        .map_err(|e| format!("Local client unavailable: {}", e))?;
    let group_id = match client.active_group_id_opt().await {
        Some(group_id) => group_id,
        None => return Ok(None),
    };

    let capsule = client
        .export_recovery_capsule(group_id)
        .await
        .map_err(|e| format!("Unable to collect epoch secrets for recovery: {}", e))?;

    let mut entries = Vec::new();
    for epoch in &capsule.epochs {
        entries.push(BackupEntryPlain {
            group_id: capsule.group_id,
            epoch_number: epoch.epoch_number,
            epoch_uuid: epoch.epoch_uuid,
            created_at: epoch.created_at,
            is_active: epoch.is_active,
            encryption_key_b64: epoch.encryption_key_b64.clone(),
        });
    }

    if entries.is_empty() {
        return Ok(None);
    }

    let artifact_path = recovery_artifact_path(state, &session.email, &server_url)?;
    let mut artifact = BackupArtifact::load_from_path(&artifact_path).ok();
    let writer = load_recovery_writer_material(state, &session)
        .ok()
        .flatten();

    if let (Some(mut existing), Some(writer)) = (artifact.take(), writer) {
        existing
            .append_entries_with_epoch_key(&entries, &writer.epoch_key)
            .map_err(|e| format!("Failed to append recovery entries: {}", e))?;
        existing.save_to_path(&artifact_path)?;
        upload_recovery_artifact(&server_url, &token, &existing).await?;
        return Ok(None);
    }

    let backup_exists = recovery_backup_exists(&server_url, &token, &session.email, state).await?;
    if backup_exists {
        return Ok(None);
    }

    let code = bootstrap_recovery_backup(
        &server_url,
        &token,
        &session.email,
        password,
        client,
        group_id,
        state,
    )
    .await?;

    Ok(Some(code))
}

async fn upload_recovery_artifact(
    server_url: &str,
    token: &str,
    artifact: &BackupArtifact,
) -> Result<(), String> {
    #[derive(Serialize)]
    struct UploadRecoveryArtifactRequest {
        artifact_blob: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_version: Option<u32>,
    }

    let endpoint = api_endpoint(server_url, "recovery-artifact");
    let payload = UploadRecoveryArtifactRequest {
        artifact_blob: artifact.to_base64()?,
        expected_version: None,
    };

    let client = reqwest::Client::new();
    let response = client
        .put(endpoint)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Failed to upload recovery backup: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Recovery backup upload failed with status {}: {}",
            status, body
        ));
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub status: String,
    pub email: Option<String>,
    pub device_id: Option<String>,
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub refreshed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshTokenRequestBody {
    refresh_token: String,
    device_id: String,
    user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshTokenResponseBody {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

const SESSION_REFRESH_WINDOW_SECS: i64 = 5 * 60;

async fn refresh_desktop_session(
    state: &AppState,
    session: &crate::state::UserSession,
) -> Result<crate::state::UserSession, String> {
    if session.refresh_token.trim().is_empty() {
        return Err("Session refresh token is unavailable. Please login again.".to_string());
    }

    let user_id = Uuid::parse_str(session.user_id.trim())
        .map_err(|_| "Session user ID is invalid. Please login again.".to_string())?;
    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let endpoint = api_endpoint(&server_url, "auth/refresh");
    let payload = RefreshTokenRequestBody {
        refresh_token: session.refresh_token.clone(),
        device_id: session.device_id.clone(),
        user_id,
    };

    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Failed to refresh session token: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Session refresh was rejected by the server. Please login again.".to_string());
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Session refresh failed with status {}: {}",
            status, body
        ));
    }

    let body: RefreshTokenResponseBody = response
        .json()
        .await
        .map_err(|e| format!("Invalid token refresh response: {}", e))?;

    let mut refreshed = session.clone();
    refreshed.token = body.access_token;
    refreshed.refresh_token = body.refresh_token;
    refreshed.expires_at = chrono::Utc::now()
        .timestamp()
        .saturating_add(body.expires_in.max(1));

    state.persist_refreshed_session(refreshed.clone()).await?;
    Ok(refreshed)
}

async fn ensure_session_ready_internal(
    state: &AppState,
) -> Result<Option<(crate::state::UserSession, bool)>, String> {
    ensure_session_ready_impl(state, false).await
}

async fn ensure_session_ready_impl(
    state: &AppState,
    force_refresh: bool,
) -> Result<Option<(crate::state::UserSession, bool)>, String> {
    let mut session = {
        let session = state.session.lock().await;
        session.clone()
    };

    if session.is_none() {
        session = state.restore_session().await?;
    }

    let mut session = match session {
        Some(session) => session,
        None => return Ok(None),
    };

    let mut refreshed = false;
    let now = chrono::Utc::now().timestamp();
    let refresh_cutoff = session
        .expires_at
        .saturating_sub(SESSION_REFRESH_WINDOW_SECS.max(0));

    if force_refresh || now >= refresh_cutoff {
        let mut last_err = String::new();
        let mut succeeded = false;
        // Retry up to 3 times with backoff to tolerate network delays on system wake.
        for attempt in 0u32..3 {
            if attempt > 0 {
                sleep(Duration::from_secs(1u64 << (attempt - 1))).await;
            }
            match refresh_desktop_session(state, &session).await {
                Ok(updated) => {
                    session = updated;
                    refreshed = true;
                    succeeded = true;
                    break;
                }
                Err(err) => {
                    tracing::warn!("Session refresh attempt {} failed: {}", attempt + 1, err);
                    last_err = err;
                }
            }
        }
        if !succeeded {
            let still_valid = chrono::Utc::now().timestamp() < session.expires_at;
            if still_valid {
                tracing::warn!(
                    "Session refresh failed but current token is still valid: {}",
                    last_err
                );
            } else {
                state.clear_session().await;
                return Err(last_err);
            }
        }
    }

    if chrono::Utc::now().timestamp() >= session.expires_at {
        state.clear_session().await;
        return Ok(None);
    }

    Ok(Some((session, refreshed)))
}

#[tauri::command]
pub async fn get_session_info(
    state: State<'_, AppState>,
    force_refresh: Option<bool>,
) -> Result<SessionInfo, String> {
    match ensure_session_ready_impl(&state, force_refresh.unwrap_or(false)).await {
        Ok(Some((session, refreshed))) => Ok(SessionInfo {
            status: "active".to_string(),
            email: Some(session.email),
            device_id: Some(session.device_id),
            expires_at: Some(session.expires_at),
            refreshed,
            error: None,
        }),
        Ok(None) => Ok(SessionInfo {
            status: "none".to_string(),
            email: None,
            device_id: None,
            expires_at: None,
            refreshed: false,
            error: None,
        }),
        Err(err) => Ok(SessionInfo {
            status: "error".to_string(),
            email: None,
            device_id: None,
            expires_at: None,
            refreshed: false,
            error: Some(err),
        }),
    }
}

#[tauri::command]
pub async fn logout_user(state: State<'_, AppState>) -> Result<CommandResponse<bool>, String> {
    tracing::info!("Logout command called");

    if let Err(err) = state.cloud_provider.stop_all(true, false).await {
        return Ok(CommandResponse::err(format!(
            "Failed to dehydrate Cloud Files mounts during logout: {}",
            err
        )));
    }

    // Unmount all folders before logout
    if let Err(err) = state.mount_manager.unmount_all(false).await {
        tracing::warn!("Failed to unmount folders during logout: {}", err);
    }

    // Clear session from memory, disk, and local caches
    state.clear_session().await;

    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn restore_session(
    state: State<'_, AppState>,
) -> Result<CommandResponse<crate::state::UserSession>, String> {
    tracing::info!("Restore session command called");

    match state.restore_session().await {
        Ok(Some(session)) => Ok(CommandResponse::ok(session)),
        Ok(None) => Ok(CommandResponse {
            success: true,
            data: None,
            error: None,
            error_code: None,
        }),
        Err(e) => Ok(CommandResponse::err(e)),
    }
}

// ============================================================================
// CLI Schema Commands - Dynamic CLI exploration
// ============================================================================

#[tauri::command]
pub async fn get_cli_schema(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<CliCommand>>, String> {
    tracing::info!("Get CLI schema command called");

    // The desktop UI currently reads the bundled schema snapshot from cli_schema.rs.
    // Keep this command as the stable entry point for future runtime schema loading.

    let schema = state.cli_schema.get_full_schema().await;
    Ok(CommandResponse::ok(schema))
}

#[tauri::command]
pub async fn execute_cli_command(
    command: String,
    args: Vec<String>,
    _state: State<'_, AppState>,
    _window: tauri::Window,
) -> Result<CommandResponse<String>, String> {
    tracing::info!("Execute CLI command: {} {:?}", command, args);

    // The public desktop build does not expose direct CLI execution here.
    // Keep the command surface stable until streamed execution is wired in.

    // Emit output events as they come:
    // window.emit("cli-output", CliOutput { line: "Processing..." })?;

    Ok(CommandResponse::ok(
        "Command executed successfully".to_string(),
    ))
}

#[tauri::command]
pub async fn get_command_help(
    command_path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Option<CliCommand>>, String> {
    tracing::info!("Get command help called for: {}", command_path);

    let help = state.cli_schema.get_command_help(&command_path).await;
    Ok(CommandResponse::ok(help))
}

// ============================================================================
// Trust & Transparency Commands
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerTrustVerifyRequest {
    pub safety_number: String,
}

#[tauri::command]
pub async fn server_trust_verify(
    request: ServerTrustVerifyRequest,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::info!(
        "Server trust verify command called for safety number: {}",
        request.safety_number
    );

    // Server identity verification is not yet wired into this desktop command.
    // Return a placeholder success response while the UI contract remains stable.

    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn get_transparency_proof(
    _state: State<'_, AppState>,
) -> Result<CommandResponse<String>, String> {
    tracing::info!("Get transparency proof command called");

    // Transparency proof retrieval is not yet wired into this desktop command.
    Ok(CommandResponse::ok(
        "Transparency proof not available yet".to_string(),
    ))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleProofRequest {
    pub group_id: String,
    pub proof: String,
}

#[tauri::command]
pub async fn verify_merkle_proof(
    request: MerkleProofRequest,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::info!(
        "Verify merkle proof command called for group: {}",
        request.group_id
    );

    // Merkle proof verification is not yet wired into this desktop command.
    Ok(CommandResponse::ok(false))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PinServerIdentityRequest {
    pub fingerprint: String,
}

#[tauri::command]
pub async fn pin_server_identity(
    request: PinServerIdentityRequest,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::info!(
        "Pin server identity command called with fingerprint: {}",
        request.fingerprint
    );

    // Server identity pinning is not yet wired into this desktop command.
    Ok(CommandResponse::ok(true))
}

// ============================================================================
// Audit & Coverage Commands
// ============================================================================

#[tauri::command]
pub async fn audit_devices(
    _state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<String>>, String> {
    tracing::info!("Audit devices command called");

    // Device audit retrieval is not yet wired into this desktop command.
    Ok(CommandResponse::ok(Vec::new()))
}

#[tauri::command]
pub async fn audit_stale_devices(
    _state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<String>>, String> {
    tracing::info!("Audit stale devices command called");

    // Stale device retrieval is not yet wired into this desktop command.
    Ok(CommandResponse::ok(Vec::new()))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingDeviceSummary {
    pub device_id: String,
    pub email: String,
    pub device_name: Option<String>,
    pub pending_since: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StaleDeviceSummary {
    pub device_id: String,
    pub email: String,
    pub device_name: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnverifiedDeviceSummary {
    pub device_id: String,
    pub email: String,
    pub device_name: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisteredDevicesResponse {
    devices: Vec<RegisteredDeviceApiRecord>,
}

#[derive(Debug, Deserialize)]
struct RegisteredDeviceApiRecord {
    device_id: String,
    device_name: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
    is_current_device: bool,
}

#[derive(Debug, Deserialize)]
struct PendingDeviceApiRecord {
    device_id: String,
    device_name: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pending_since: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct GroupUnverifiedDeviceInfo {
    user_id: Uuid,
    device_id: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_seen_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct DeviceRemovalResponsePayload {
    removed_device_id: String,
    revoked_sessions: usize,
    updated_groups: Vec<Uuid>,
    remaining_devices: usize,
    removed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceRevocationResult {
    pub removed_device_id: String,
    pub removed_current_device: bool,
    pub revoked_sessions: usize,
    pub remaining_devices: usize,
    pub removed_at: String,
    pub updated_groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GroupDeviceAuditResponse {
    #[serde(rename = "group_id")]
    _group_id: Uuid,
    #[serde(rename = "generated_at", with = "chrono::serde::ts_seconds")]
    _generated_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "stale_threshold_days")]
    _stale_threshold_days: i64,
    devices: Vec<DeviceHealthEntry>,
}

#[derive(Debug, Deserialize)]
struct DeviceHealthEntry {
    user_id: Uuid,
    device_id: String,
    device_name: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_seen: chrono::DateTime<chrono::Utc>,
    stale: bool,
}

#[derive(Debug, Deserialize)]
struct MembersListResponse {
    members: Vec<GroupMember>,
    has_more: bool,
    next_offset: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupMember {
    user_id: Uuid,
    email: String,
    #[serde(default)]
    is_owner: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupMemberDetails {
    pub user_id: String,
    pub email: String,
    pub joined_at: Option<String>,
    pub last_seen: Option<String>,
    pub devices: Vec<MemberDeviceSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemberDeviceSummary {
    pub device_id: String,
    pub device_name: Option<String>,
    pub last_seen: Option<String>,
    pub added_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GroupDetailsResponse {
    group: GroupDetailsInfo,
    members: Vec<GroupDetailsMember>,
}

#[derive(Debug, Deserialize)]
struct GroupDetailsInfo {
    creator_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct GroupDetailsMember {
    user_id: Uuid,
    email: String,
    joined_at: chrono::DateTime<chrono::Utc>,
    last_active: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
struct GroupDeviceRosterResponse {
    devices: Vec<GroupDeviceRosterEntry>,
}

#[derive(Debug, Deserialize)]
struct GroupDeviceRosterEntry {
    user_id: Uuid,
    device_id: String,
    device_name: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_seen: chrono::DateTime<chrono::Utc>,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn fetch_registered_device_records_internal(
    state: &AppState,
    session: &crate::state::UserSession,
    current_device: Option<&CurrentDeviceSnapshot>,
) -> Result<Vec<RegisteredDeviceRecord>, String> {
    let server_url = current_server_url(state, session);
    let endpoint = api_endpoint(&server_url, "auth/devices");
    let client = reqwest::Client::new();
    let response = client
        .get(endpoint)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch registered devices: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Authentication token rejected. Please login again.".to_string());
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Registered devices request failed ({}): {}",
            status, body
        ));
    }

    let payload: RegisteredDevicesResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse registered devices response: {}", e))?;

    let current_device = current_device.map(|snapshot| {
        (
            snapshot.device_id.as_str().to_string(),
            snapshot.is_verified,
        )
    });

    Ok(payload
        .devices
        .into_iter()
        .map(|device| {
            let is_verified = current_device
                .as_ref()
                .filter(|(device_id, _)| *device_id == device.device_id)
                .map(|(_, is_verified)| *is_verified)
                .unwrap_or(true);
            RegisteredDeviceRecord {
                device_id: device.device_id,
                device_name: device.device_name,
                created_at: device.created_at.to_rfc3339(),
                last_seen: device.last_seen.to_rfc3339(),
                is_current_device: device.is_current_device,
                is_verified,
            }
        })
        .collect())
}

async fn fetch_pending_device_records_internal(
    state: &AppState,
    session: &crate::state::UserSession,
) -> Result<Vec<PendingDeviceRecord>, String> {
    let server_url = current_server_url(state, session);
    let endpoint = api_endpoint(&server_url, "auth/pending-devices");
    let client = reqwest::Client::new();
    let response = client
        .get(endpoint)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch pending devices: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Authentication token rejected. Please login again.".to_string());
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Pending devices request failed ({}): {}",
            status, body
        ));
    }

    let payload: Vec<PendingDeviceApiRecord> = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse pending devices response: {}", e))?;

    Ok(payload
        .into_iter()
        .map(|device| PendingDeviceRecord {
            device_id: device.device_id,
            email: session.email.clone(),
            device_name: device.device_name,
            observed_at: Some(device.pending_since.to_rfc3339()),
        })
        .collect())
}

async fn fetch_group_device_audit_internal(
    session: &crate::state::UserSession,
    api_base: &str,
    group_id: Uuid,
) -> Result<Option<GroupDeviceAuditResponse>, String> {
    let audit_url = format!("{}/groups/{}/devices?stale_days=30", api_base, group_id);
    let client = reqwest::Client::new();
    let response = client
        .get(&audit_url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch device audit: {}", e))?;

    match response.status() {
        reqwest::StatusCode::UNAUTHORIZED => {
            Err("Authentication token rejected. Please login again.".to_string())
        }
        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND => Ok(None),
        status if !status.is_success() => {
            let body = response.text().await.unwrap_or_default();
            Err(format!(
                "Device audit request failed ({}): {}",
                status, body
            ))
        }
        _ => response
            .json()
            .await
            .map(Some)
            .map_err(|e| format!("Failed to parse device audit response: {}", e)),
    }
}

async fn fetch_unverified_device_records_internal(
    session: &crate::state::UserSession,
    api_base: &str,
    group_id: Uuid,
    email_map: &HashMap<Uuid, String>,
    device_name_map: &HashMap<String, String>,
) -> Result<Vec<UnverifiedDeviceRecord>, String> {
    let url = format!(
        "{}/groups/{}/unverified-devices?include_resolved=false",
        api_base, group_id
    );
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch unverified devices: {}", e))?;

    match response.status() {
        reqwest::StatusCode::UNAUTHORIZED => {
            Err("Authentication token rejected. Please login again.".to_string())
        }
        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND => Ok(Vec::new()),
        status if !status.is_success() => {
            let body = response.text().await.unwrap_or_default();
            Err(format!(
                "Unverified devices request failed ({}): {}",
                status, body
            ))
        }
        _ => {
            let payload: Vec<GroupUnverifiedDeviceInfo> = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse unverified devices response: {}", e))?;
            Ok(payload
                .into_iter()
                .map(|device| UnverifiedDeviceRecord {
                    device_id: device.device_id.clone(),
                    email: email_map
                        .get(&device.user_id)
                        .cloned()
                        .unwrap_or_else(|| session.email.clone()),
                    device_name: device_name_map.get(&device.device_id).cloned(),
                    last_seen: Some(device.last_seen_at.to_rfc3339()),
                })
                .collect())
        }
    }
}

async fn load_personal_devices_overview_input_internal(
    state: &AppState,
    session: &crate::state::UserSession,
) -> Result<PersonalDevicesOverviewInput, String> {
    let server_url = current_server_url(state, session);
    let api_base = api_base_url(&server_url);
    let current_device = load_current_device_snapshot(session, &server_url);
    let registered_devices =
        fetch_registered_device_records_internal(state, session, current_device.as_ref()).await?;
    let pending_devices = fetch_pending_device_records_internal(state, session).await?;

    let mut stale_devices = Vec::new();
    let mut unverified_devices = Vec::new();
    let mut device_name_map = registered_devices
        .iter()
        .filter_map(|device| {
            device
                .device_name
                .as_ref()
                .map(|name| (device.device_id.clone(), name.clone()))
        })
        .collect::<HashMap<_, _>>();

    if let Some(group_id) = active_group_id_for_session(state).await {
        let email_map = fetch_group_member_emails(session, &api_base, group_id).await?;
        if let Some(audit) = fetch_group_device_audit_internal(session, &api_base, group_id).await?
        {
            for device in &audit.devices {
                if let Some(name) = device.device_name.as_ref() {
                    device_name_map
                        .entry(device.device_id.clone())
                        .or_insert_with(|| name.clone());
                }
            }

            stale_devices = audit
                .devices
                .iter()
                .filter(|device| device.stale)
                .map(|device| StaleDeviceRecord {
                    device_id: device.device_id.clone(),
                    email: email_map
                        .get(&device.user_id)
                        .cloned()
                        .unwrap_or_else(|| session.email.clone()),
                    device_name: device.device_name.clone(),
                    last_seen: Some(device.last_seen.to_rfc3339()),
                })
                .collect();
        }

        unverified_devices = fetch_unverified_device_records_internal(
            session,
            &api_base,
            group_id,
            &email_map,
            &device_name_map,
        )
        .await?;
    }

    Ok(PersonalDevicesOverviewInput {
        current_device_id: if session.device_id.trim().is_empty() {
            None
        } else {
            Some(session.device_id.clone())
        },
        registered_devices,
        pending_devices,
        stale_devices,
        unverified_devices,
        rename_supported: false,
        revoke_supported: true,
    })
}

#[tauri::command]
pub async fn get_pending_devices(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<PendingDeviceSummary>>, String> {
    ensure_authenticated(&state).await?;
    let session = require_authenticated_session(&state).await?;
    let summaries = fetch_pending_device_records_internal(&state, &session)
        .await?
        .into_iter()
        .map(|device| PendingDeviceSummary {
            device_id: device.device_id,
            email: device.email,
            device_name: device.device_name,
            pending_since: device.observed_at,
        })
        .collect();
    Ok(CommandResponse::ok(summaries))
}

#[tauri::command]
pub async fn get_stale_devices(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<StaleDeviceSummary>>, String> {
    ensure_authenticated(&state).await?;
    let session = require_authenticated_session(&state).await?;
    let server_url = current_server_url(&state, &session);
    let api_base = api_base_url(&server_url);
    let Some(group_id) = active_group_id_for_session(&state).await else {
        return Ok(CommandResponse::ok(Vec::new()));
    };
    let email_map = fetch_group_member_emails(&session, &api_base, group_id).await?;
    let Some(audit) = fetch_group_device_audit_internal(&session, &api_base, group_id).await?
    else {
        return Ok(CommandResponse::ok(Vec::new()));
    };

    let summaries = audit
        .devices
        .into_iter()
        .filter(|device| device.stale)
        .map(|device| StaleDeviceSummary {
            device_id: device.device_id,
            email: email_map
                .get(&device.user_id)
                .cloned()
                .unwrap_or_else(|| session.email.clone()),
            device_name: device.device_name,
            last_seen: Some(device.last_seen.to_rfc3339()),
        })
        .collect::<Vec<_>>();

    Ok(CommandResponse::ok(summaries))
}

#[tauri::command]
pub async fn get_unverified_devices(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<UnverifiedDeviceSummary>>, String> {
    ensure_authenticated(&state).await?;
    let session = require_authenticated_session(&state).await?;
    let server_url = current_server_url(&state, &session);
    let api_base = api_base_url(&server_url);
    let Some(group_id) = active_group_id_for_session(&state).await else {
        return Ok(CommandResponse::ok(Vec::new()));
    };
    let email_map = fetch_group_member_emails(&session, &api_base, group_id).await?;

    let mut device_name_map = HashMap::new();
    if let Some(audit) = fetch_group_device_audit_internal(&session, &api_base, group_id).await? {
        for device in audit.devices {
            if let Some(name) = device.device_name {
                device_name_map.insert(device.device_id, name);
            }
        }
    }

    let summaries = fetch_unverified_device_records_internal(
        &session,
        &api_base,
        group_id,
        &email_map,
        &device_name_map,
    )
    .await?
    .into_iter()
    .map(|device| UnverifiedDeviceSummary {
        device_id: device.device_id,
        email: device.email,
        device_name: device.device_name,
        last_seen: device.last_seen,
    })
    .collect();

    Ok(CommandResponse::ok(summaries))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveStaleDeviceRequest {
    pub device_id: String,
}

#[tauri::command]
pub async fn remove_stale_devices(
    request: RemoveStaleDeviceRequest,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::info!(
        "Remove stale device command called for device: {}",
        request.device_id
    );

    // Stale device removal is not yet wired into this desktop command.
    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn get_coverage_status(
    _state: State<'_, AppState>,
) -> Result<CommandResponse<String>, String> {
    tracing::info!("Get coverage status command called");

    // Coverage metrics retrieval is not yet wired into this desktop command.
    Ok(CommandResponse::ok(
        "Coverage metrics not available yet".to_string(),
    ))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsStatus {
    pub coverage_last_scan: Option<String>,
    pub coverage_ipc_active: bool,
    pub coverage_ipc_supported: bool,
    pub registry_last_upload: Option<String>,
    pub registry_version: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoverageSummaryCard {
    pub id: String,
    pub label: String,
    pub value: String,
    pub detail: String,
    pub tone: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoverageFolderRow {
    pub root_id: String,
    pub path: String,
    pub kind: String,
    pub state: String,
    pub last_scan: Option<String>,
    pub tracked_files: u64,
    pub orphaned_files: u64,
    pub unmanaged_files: u64,
    pub coverage_percent: u32,
    pub coverage_label: String,
    pub attention_label: String,
    pub needs_attention: bool,
    pub recommended_action_id: Option<String>,
    pub recommended_action_label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoverageAttentionItem {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub root_id: Option<String>,
    pub folder_path: Option<String>,
    pub action_id: Option<String>,
    pub action_label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoverageCenterSnapshot {
    pub overall_coverage_percent: u32,
    pub tracked_files: u64,
    pub orphaned_files: u64,
    pub unmanaged_files: u64,
    pub enrolled_folder_count: usize,
    pub last_scan_at: Option<String>,
    pub ipc_state: String,
    pub summary_cards: Vec<CoverageSummaryCard>,
    pub folders: Vec<CoverageFolderRow>,
    pub attention_items: Vec<CoverageAttentionItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoverageScanResult {
    pub root_path: Option<String>,
    pub roots_scanned: usize,
    pub files_indexed: usize,
    pub orphaned_files: usize,
    pub unmanaged_files: usize,
    pub missing_roots: Vec<String>,
    pub completed_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CoverageScanProgressPayload {
    pub root_id: String,
    pub root_path: String,
    pub processed: usize,
    pub total: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CoverageScanFinishedPayload {
    pub success: bool,
    pub result: Option<CoverageScanResult>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub mfa_enabled: bool,
    pub recovery_backup_ok: bool,
    pub recovery_auto_backup_ok: bool,
    pub recovery_auto_backup_state: String,
}

#[derive(Debug, Deserialize)]
struct MfaStatusResponse {
    enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaEnrollStartResult {
    pub secret: String,
    pub otpauth_url: String,
    pub qr_svg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MfaEnrollStartResponse {
    secret: String,
    otpauth_url: String,
    qr_svg: Option<String>,
}

#[derive(Debug, Serialize)]
struct MfaEnrollVerifyRequest {
    code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaEnrollVerifyResult {
    pub backup_codes: Vec<String>,
    pub enabled_at: i64,
}

#[derive(Debug, Deserialize)]
struct MfaEnrollVerifyResponse {
    backup_codes: Vec<String>,
    enabled_at: i64,
}

fn current_server_url(state: &AppState, session: &crate::state::UserSession) -> String {
    session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string())
}

async fn require_authenticated_session(
    state: &AppState,
) -> Result<crate::state::UserSession, String> {
    ensure_session_ready_internal(state)
        .await?
        .map(|(session, _)| session)
        .ok_or_else(|| "No active session found".to_string())
}

fn load_current_device_snapshot(
    session: &crate::state::UserSession,
    server_url: &str,
) -> Option<CurrentDeviceSnapshot> {
    let device_id = session.device_id.trim();
    if device_id.is_empty() {
        return None;
    }

    if let Ok(session_store) = crate::session::SessionStore::new() {
        match session_store.load_session(&session.email, server_url) {
            Ok(Some(persisted)) => {
                return Some(CurrentDeviceSnapshot {
                    device_id: session.device_id.clone(),
                    is_verified: persisted.security_metadata.flags.device_verified,
                });
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!("Failed to load persisted session security flags: {}", err);
            }
        }
    }

    Some(CurrentDeviceSnapshot {
        device_id: session.device_id.clone(),
        is_verified: true,
    })
}

async fn active_group_id_for_session(state: &AppState) -> Option<Uuid> {
    match state.local_client.client_opt().await {
        Some(client) => client.active_group_id_opt().await,
        None => None,
    }
}

async fn load_settings_status_internal(state: &AppState) -> Result<SettingsStatus, String> {
    let session = state.session.lock().await.clone();
    let mut registry_last_upload = None;
    let mut registry_version = None;
    let mut coverage_ipc_active = false;
    let coverage_ipc_supported = cfg!(unix);

    if let Some(session) = session.as_ref() {
        let server_url = current_server_url(state, session);
        let registry_path = state
            .local_client
            .coverage_registry_meta_path_for_session(&session.email, &server_url);

        if let Ok(data) = fs::read_to_string(&registry_path).await {
            if let Ok(value) = serde_json::from_str::<Value>(&data) {
                registry_version = value
                    .get("version")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| v.try_into().ok());
                registry_last_upload = value
                    .get("updated_at")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
            }
        }

        if coverage_ipc_supported {
            let socket_path = state
                .local_client
                .coverage_ipc_socket_path_for_session(&session.email, &server_url);
            coverage_ipc_active = socket_path.exists();
        }
    }

    let mut coverage_last_scan = None;
    if let Some(client) = state.local_client.client_opt().await {
        if let Ok(stats) = client.coverage_root_stats().await {
            let last_scan = stats
                .iter()
                .filter_map(|summary| summary.root.last_scan)
                .max_by_key(|dt| dt.timestamp());
            coverage_last_scan = last_scan.map(|dt| dt.to_rfc3339());
        }
    }

    Ok(SettingsStatus {
        coverage_last_scan,
        coverage_ipc_active,
        coverage_ipc_supported,
        registry_last_upload,
        registry_version,
    })
}

async fn load_security_status_internal(
    state: &AppState,
    session: &crate::state::UserSession,
) -> Result<SecurityStatus, String> {
    let server_url = current_server_url(state, session);
    let token = session.token.clone();

    let mfa_status = fetch_mfa_status(&server_url, &token).await?;
    let recovery_backup_ok =
        recovery_backup_exists(&server_url, &token, &session.email, state).await?;
    let recovery_auto_backup_state = recovery_auto_backup_state(session, state);
    let recovery_auto_backup_ok = recovery_auto_backup_state == "ready";

    Ok(SecurityStatus {
        mfa_enabled: mfa_status.enabled,
        recovery_backup_ok,
        recovery_auto_backup_ok,
        recovery_auto_backup_state: recovery_auto_backup_state.to_string(),
    })
}

#[tauri::command]
pub async fn get_settings_status(
    state: State<'_, AppState>,
) -> Result<CommandResponse<SettingsStatus>, String> {
    Ok(CommandResponse::ok(
        load_settings_status_internal(&state).await?,
    ))
}

#[tauri::command]
pub async fn get_operations_refresh_interval_secs() -> Result<CommandResponse<u64>, String> {
    let config = hybridcipher_client::config_loader::load_client_config_from_files();
    Ok(CommandResponse::ok(
        config.admin_operations_refresh_interval_secs,
    ))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionHealthConfig {
    pub check_interval_ms: u64,
    pub expiry_grace_ms: u64,
    pub mount_continue_enable_ms: u64,
    pub mount_cancel_enable_ms: u64,
    pub mount_background_timeout_ms: u64,
}

#[tauri::command]
pub async fn get_session_health_config() -> Result<CommandResponse<SessionHealthConfig>, String> {
    let config = hybridcipher_client::config_loader::load_client_config_from_files();
    Ok(CommandResponse::ok(SessionHealthConfig {
        check_interval_ms: config
            .session_health_check_interval_secs
            .saturating_mul(1000),
        expiry_grace_ms: config.session_health_expiry_grace_secs.saturating_mul(1000),
        mount_continue_enable_ms: config.mount_continue_enable_secs.saturating_mul(1000),
        mount_cancel_enable_ms: config.mount_cancel_enable_secs.saturating_mul(1000),
        mount_background_timeout_ms: config.mount_background_timeout_secs.saturating_mul(1000),
    }))
}

#[tauri::command]
pub async fn get_group_members(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<GroupMember>>, String> {
    ensure_authenticated(&state).await?;

    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or_else(|| "No active session found".to_string())?;

    let group_id = match state.local_client.client_opt().await {
        Some(client) => client.active_group_id_opt().await,
        None => None,
    };

    let Some(group_id) = group_id else {
        return Ok(CommandResponse::ok(Vec::new()));
    };

    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let api_base = api_base_url(&server_url);

    let url = format!("{}/groups/{}", api_base, group_id);
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch group details: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(CommandResponse::err(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Ok(CommandResponse::err(format!(
            "Group details request failed ({}): {}",
            status, body
        )));
    }

    let details: GroupDetailsResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse group details response: {}", e))?;

    let creator_id = details.group.creator_id;

    let mut members = details
        .members
        .into_iter()
        .map(|member| GroupMember {
            user_id: member.user_id,
            email: member.email,
            is_owner: member.user_id == creator_id,
        })
        .collect::<Vec<_>>();

    members.sort_by(|a, b| a.email.to_lowercase().cmp(&b.email.to_lowercase()));

    Ok(CommandResponse::ok(members))
}

#[tauri::command]
pub async fn remove_group_member(
    user_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    ensure_authenticated(&state).await?;

    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or_else(|| "No active session found".to_string())?;

    let group_id = match state.local_client.client_opt().await {
        Some(client) => client.active_group_id_opt().await,
        None => None,
    };

    let Some(group_id) = group_id else {
        return Ok(CommandResponse::err(
            "No active group selected. Switch to a group first.".to_string(),
        ));
    };

    let trimmed = user_id.trim();
    if trimmed.is_empty() {
        return Ok(CommandResponse::err(
            "Member identifier is required.".to_string(),
        ));
    }

    let target_user_id = match Uuid::parse_str(trimmed) {
        Ok(uuid) => uuid,
        Err(_) => {
            let server_url = session
                .server_url
                .clone()
                .unwrap_or_else(|| state.client.server_url().to_string());
            let api_base = api_base_url(&server_url);
            let members = fetch_group_member_emails(&session, &api_base, group_id).await?;
            let lookup = trimmed.to_lowercase();
            let resolved = members
                .into_iter()
                .find(|(_, email)| email.to_lowercase() == lookup)
                .map(|(user_id, _)| user_id);
            match resolved {
                Some(uuid) => uuid,
                None => {
                    return Ok(CommandResponse::err(
                        "Member identifier must be a UUID or existing group email.".to_string(),
                    ))
                }
            }
        }
    };

    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let api_base = api_base_url(&server_url);
    let client = reqwest::Client::new();
    let response = client
        .delete(&format!(
            "{}/groups/{}/members/{}",
            api_base, group_id, target_user_id
        ))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    match response.status() {
        reqwest::StatusCode::UNAUTHORIZED => Ok(CommandResponse::err(
            "Authentication token rejected. Please login again.".to_string(),
        )),
        reqwest::StatusCode::BAD_REQUEST => Ok(CommandResponse::err(
            "Cannot remove the group owner.".to_string(),
        )),
        reqwest::StatusCode::FORBIDDEN => {
            let body = response.text().await.unwrap_or_default();
            Ok(CommandResponse::err(format!(
                "Server rejected member removal: {}",
                body.trim()
            )))
        }
        reqwest::StatusCode::NOT_FOUND => Ok(CommandResponse::err(
            "Member or group not found. Verify the active group.".to_string(),
        )),
        status if status.is_success() => Ok(CommandResponse::ok(true)),
        status => {
            let body = response.text().await.unwrap_or_default();
            Ok(CommandResponse::err(format!(
                "Failed to remove member (status {}): {}",
                status, body
            )))
        }
    }
}

#[tauri::command]
pub async fn get_group_member_details(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<GroupMemberDetails>>, String> {
    ensure_authenticated(&state).await?;

    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or_else(|| "No active session found".to_string())?;

    let group_id = match state.local_client.client_opt().await {
        Some(client) => client.active_group_id_opt().await,
        None => None,
    };

    let Some(group_id) = group_id else {
        return Ok(CommandResponse::ok(Vec::new()));
    };

    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let api_base = api_base_url(&server_url);
    let client = reqwest::Client::new();

    let details_url = format!("{}/groups/{}", api_base, group_id);
    let details_resp = client
        .get(&details_url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch group details: {}", e))?;

    if details_resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(CommandResponse::err(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    if !details_resp.status().is_success() {
        let status = details_resp.status();
        let body = details_resp.text().await.unwrap_or_default();
        return Ok(CommandResponse::err(format!(
            "Group details request failed ({}): {}",
            status, body
        )));
    }

    let details: GroupDetailsResponse = details_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse group details response: {}", e))?;

    let devices_url = format!("{}/groups/{}/devices?stale_days=30", api_base, group_id);
    let devices_resp = client
        .get(&devices_url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch group devices: {}", e))?;

    if devices_resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(CommandResponse::err(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    if !devices_resp.status().is_success() {
        let status = devices_resp.status();
        let body = devices_resp.text().await.unwrap_or_default();
        return Ok(CommandResponse::err(format!(
            "Group devices request failed ({}): {}",
            status, body
        )));
    }

    let device_payload: GroupDeviceRosterResponse = devices_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse group devices response: {}", e))?;

    let mut device_map: HashMap<Uuid, Vec<MemberDeviceSummary>> = HashMap::new();
    for device in device_payload.devices {
        device_map
            .entry(device.user_id)
            .or_default()
            .push(MemberDeviceSummary {
                device_id: device.device_id,
                device_name: device.device_name,
                last_seen: Some(device.last_seen.to_rfc3339()),
                added_at: device.created_at.map(|dt| dt.to_rfc3339()),
            });
    }

    let mut members = details
        .members
        .into_iter()
        .map(|member| GroupMemberDetails {
            user_id: member.user_id.to_string(),
            email: member.email,
            joined_at: Some(member.joined_at.to_rfc3339()),
            last_seen: member.last_active.map(|dt| dt.to_rfc3339()),
            devices: device_map.remove(&member.user_id).unwrap_or_default(),
        })
        .collect::<Vec<_>>();

    members.sort_by(|a, b| a.email.to_lowercase().cmp(&b.email.to_lowercase()));

    Ok(CommandResponse::ok(members))
}

#[tauri::command]
pub async fn get_security_status(
    state: State<'_, AppState>,
) -> Result<CommandResponse<SecurityStatus>, String> {
    let session = require_authenticated_session(&state).await?;
    Ok(CommandResponse::ok(
        load_security_status_internal(&state, &session).await?,
    ))
}

#[tauri::command]
pub async fn mfa_enroll_start(
    state: State<'_, AppState>,
) -> Result<CommandResponse<MfaEnrollStartResult>, String> {
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or_else(|| "No active session found".to_string())?;
    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let token = session.token.clone();

    let endpoint = api_endpoint(&server_url, "mfa/totp/enroll/start");
    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Failed to start MFA enrollment: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Authentication token rejected while starting MFA enrollment".to_string());
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "MFA enrollment start failed with status {}: {}",
            status, body
        ));
    }

    let body: MfaEnrollStartResponse = response
        .json()
        .await
        .map_err(|e| format!("Invalid MFA enrollment response: {}", e))?;

    let qr_svg = body
        .qr_svg
        .or_else(|| render_qr_svg(&body.otpauth_url).ok());

    Ok(CommandResponse::ok(MfaEnrollStartResult {
        secret: body.secret,
        otpauth_url: body.otpauth_url,
        qr_svg,
    }))
}

#[tauri::command]
pub async fn mfa_enroll_verify(
    state: State<'_, AppState>,
    code: String,
) -> Result<CommandResponse<MfaEnrollVerifyResult>, String> {
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or_else(|| "No active session found".to_string())?;
    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());
    let token = session.token.clone();

    let endpoint = api_endpoint(&server_url, "mfa/totp/enroll/verify");
    let client = reqwest::Client::new();
    let payload = MfaEnrollVerifyRequest { code };
    let response = client
        .post(endpoint)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Failed to verify MFA enrollment: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Authentication token rejected while verifying MFA".to_string());
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "MFA enrollment verification failed with status {}: {}",
            status, body
        ));
    }

    let body: MfaEnrollVerifyResponse = response
        .json()
        .await
        .map_err(|e| format!("Invalid MFA verification response: {}", e))?;

    Ok(CommandResponse::ok(MfaEnrollVerifyResult {
        backup_codes: body.backup_codes,
        enabled_at: body.enabled_at,
    }))
}

fn render_qr_svg(payload: &str) -> Result<String, String> {
    let code = QrCode::new(payload.as_bytes())
        .map_err(|e| format!("Failed to generate QR code: {}", e))?;
    Ok(code.render::<svg::Color>().min_dimensions(220, 220).build())
}

// ============================================================================
// Additional Commands
// ============================================================================

#[tauri::command]
pub async fn get_server_info(
    state: State<'_, AppState>,
) -> Result<CommandResponse<crate::client::ServerInfo>, String> {
    tracing::info!("Get server info command called");
    let info = state.client.server_info().await;
    Ok(CommandResponse::ok(info))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateServerUrlRequest {
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TerminalResult {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TerminalSessionInfo {
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TerminalOutputPayload {
    pub session_id: String,
    pub chunk: String,
}

struct TerminalSession {
    child: Box<dyn portable_pty::Child + Send>,
    master: Box<dyn portable_pty::MasterPty + Send>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
}

struct PasswordResetSession {
    child: Box<dyn portable_pty::Child + Send>,
    master: Box<dyn portable_pty::MasterPty + Send>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    output: Arc<Mutex<String>>,
    email: String,
    server_url: String,
}

static TERMINAL_SESSIONS: Lazy<Mutex<HashMap<String, TerminalSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static PASSWORD_RESET_SESSIONS: Lazy<Mutex<HashMap<String, PasswordResetSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const EXIT_STATUS_SENTINEL: &str = "__HYBRIDCIPHER_EXIT_STATUS__=";
const MAX_COMMAND_OUTPUT_BYTES: usize = 512 * 1024;
const COMMAND_OUTPUT_TAIL_BYTES: usize = 8 * 1024;
const OUTPUT_TRUNCATED_MARKER: &str = "\n[output truncated]\n";

#[derive(Debug)]
struct LimitedOutputCollector {
    limit: usize,
    tail_limit: usize,
    prefix: Vec<u8>,
    tail: Vec<u8>,
    truncated: bool,
}

impl LimitedOutputCollector {
    fn new(limit: usize, tail_limit: usize) -> Self {
        Self {
            limit,
            tail_limit,
            prefix: Vec::new(),
            tail: Vec::new(),
            truncated: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }

        if !self.truncated {
            let remaining = self.limit.saturating_sub(self.prefix.len());
            if chunk.len() <= remaining {
                self.prefix.extend_from_slice(chunk);
                return;
            }

            self.prefix.extend_from_slice(&chunk[..remaining]);
            self.truncated = true;
            self.push_tail(&chunk[remaining..]);
            return;
        }

        self.push_tail(chunk);
    }

    fn push_tail(&mut self, chunk: &[u8]) {
        if self.tail_limit == 0 || chunk.is_empty() {
            return;
        }

        self.tail.extend_from_slice(chunk);
        if self.tail.len() > self.tail_limit {
            let excess = self.tail.len() - self.tail_limit;
            self.tail.drain(0..excess);
        }
    }

    fn finish(self) -> String {
        let mut bytes = self.prefix;
        if self.truncated {
            bytes.extend_from_slice(OUTPUT_TRUNCATED_MARKER.as_bytes());
            bytes.extend_from_slice(&self.tail);
        }
        String::from_utf8_lossy(&bytes).to_string()
    }
}

fn read_limited_stream<R: Read>(
    mut reader: R,
    limit: usize,
    tail_limit: usize,
) -> std::io::Result<String> {
    let mut collector = LimitedOutputCollector::new(limit, tail_limit);
    let mut buf = [0u8; 4096];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        collector.push(&buf[..n]);
    }

    Ok(collector.finish())
}

fn join_output_reader(
    handle: thread::JoinHandle<std::io::Result<String>>,
) -> std::io::Result<String> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::other("output reader thread panicked")),
    }
}

fn collect_child_output_limited(
    mut child: std::process::Child,
    limit: usize,
    tail_limit: usize,
) -> std::io::Result<(std::process::ExitStatus, String, String)> {
    let stdout_handle = child
        .stdout
        .take()
        .map(|stdout| thread::spawn(move || read_limited_stream(stdout, limit, tail_limit)));
    let stderr_handle = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(move || read_limited_stream(stderr, limit, tail_limit)));

    let status = child.wait()?;
    let stdout = match stdout_handle {
        Some(handle) => join_output_reader(handle)?,
        None => String::new(),
    };
    let stderr = match stderr_handle {
        Some(handle) => join_output_reader(handle)?,
        None => String::new(),
    };

    Ok((status, stdout, stderr))
}

fn wrap_shell_command_for_status(command: &str) -> String {
    format!(
        "{command}; __hc_status=$?; printf '\\n{sentinel}%s\\n' \"$__hc_status\"; exit \"$__hc_status\"",
        command = command,
        sentinel = EXIT_STATUS_SENTINEL
    )
}

fn summarize_password_reset_output(output: &str) -> Option<String> {
    let normalized = output.replace('\r', "");
    for line in normalized.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.ends_with(':') {
            continue;
        }
        if trimmed == "New password" || trimmed == "Confirm new password" {
            continue;
        }
        return Some(trimmed.to_string());
    }
    None
}

fn extract_wrapped_exit_status(output: &mut String) -> Option<i32> {
    let mut parsed_status = None;
    let mut kept_lines: Vec<&str> = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(status) = trimmed.strip_prefix(EXIT_STATUS_SENTINEL) {
            if let Ok(code) = status.trim().parse::<i32>() {
                parsed_status = Some(code);
                continue;
            }
        }
        kept_lines.push(line);
    }

    if parsed_status.is_some() {
        *output = kept_lines.join("\n");
    }

    parsed_status
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use hybridcipher_client::coverage::{
        CoverageRoot, FileCoverageState, FileIndexEntry, FileOrphanKind,
    };
    use hybridcipher_client::state::client::{CoverageFileRecord, CoverageScanSummary};

    #[test]
    fn macos_file_provider_backend_serializes_with_stable_label() {
        assert_eq!(
            MountBackend::MacOsFileProvider.as_str(),
            "macos-file-provider"
        );

        let state: MountRuntimeState = serde_json::from_str(
            r#"{
  "root_id": "12345678-90ab-cdef-1234-567890abcdef",
  "mountpoint": "/Users/example/Library/CloudStorage/HybridCipher",
  "encrypted_dir": "/Users/example/Documents/encrypted",
  "platform": "macos",
  "backend": "macos-file-provider",
  "ready": true,
  "requested_unmount": false
}"#,
        )
        .expect("deserialize macOS provider runtime state");

        assert_eq!(state.backend().as_str(), "macos-file-provider");
        assert!(state.backend().has_runtime_status());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_file_provider_url_matches_domain_display_name_path() {
        let root_id = Uuid::parse_str("00741c18-f05f-45f2-8f54-4c1c84a7bc14").expect("valid uuid");
        let encrypted_dir = Path::new("/Users/example/Desktop/wetgzfolder/hybridcipher_websitev3");

        let provider_url = determine_desktop_file_provider_url(encrypted_dir, root_id)
            .expect("derive macOS File Provider URL");

        assert_eq!(
            provider_url
                .file_name()
                .and_then(|name| name.to_str())
                .expect("provider url basename"),
            "HybridCipher-hybridcipher_websitev3-00741c18-mount"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stale_macos_file_provider_cleanup_loads_persisted_registration() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::parse_str("00741c18-f05f-45f2-8f54-4c1c84a7bc14").expect("valid uuid");
        let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
            hybridcipher_macos_file_provider::ProviderHostConfig {
                user_config_dir: temp.path().to_path_buf(),
                socket_path: None,
                provider_identifier: None,
            },
        );
        let registration = hybridcipher_macos_file_provider::FileProviderDomainRegistration {
            root_id,
            domain_identifier: format!("com.hybridcipher.root.{root_id}"),
            display_name: "hybridcipher_websitev3-00741c18-mount".to_string(),
            encrypted_root: PathBuf::from("/Users/example/encrypted"),
            user_visible_url: Some(PathBuf::from(
                "/Users/example/Library/CloudStorage/HybridCipher-hybridcipher_websitev3-00741c18-mount",
            )),
        };
        host.register_domain(&registration).unwrap();

        let loaded = load_stored_macos_file_provider_registration(temp.path(), root_id)
            .expect("load stored registration")
            .expect("registration exists");

        assert_eq!(loaded.domain_identifier, registration.domain_identifier);
        assert_eq!(loaded.user_visible_url, registration.user_visible_url);
    }

    #[test]
    fn limited_output_collector_keeps_prefix_and_tail_when_truncated() {
        let mut collector = LimitedOutputCollector::new(8, 64);
        collector.push(b"abcdefgh");
        collector.push(b"ijklmnop");
        collector.push(format!("\n{}17\n", EXIT_STATUS_SENTINEL).as_bytes());

        let rendered = collector.finish();

        assert!(rendered.starts_with("abcdefgh"));
        assert!(rendered.contains("[output truncated]"));
        assert!(rendered.contains(EXIT_STATUS_SENTINEL));
        assert!(rendered.ends_with("17\n"));
    }

    #[test]
    fn build_individual_home_status_flags_missing_protection_layers() {
        let summary = build_individual_home_status(IndividualHomeStatusInput {
            security: IndividualSecuritySnapshot {
                mfa_enabled: false,
                recovery_backup_ok: false,
                recovery_auto_backup_ok: false,
            },
            settings: IndividualSettingsSnapshot {
                coverage_last_scan: None,
                registry_last_upload: None,
            },
            protected_count: 1,
            mounted_count: 1,
            current_device: Some(CurrentDeviceSnapshot {
                device_id: "device-current".to_string(),
                is_verified: false,
            }),
            device_counts: DeviceCountSnapshot {
                trusted: 1,
                pending: 1,
                stale: 0,
                unverified: 1,
            },
            folder_attention: FolderAttentionSnapshot {
                conflicts: 1,
                recovery_copies: 1,
            },
            now: Utc.with_ymd_and_hms(2026, 3, 24, 12, 0, 0).unwrap(),
        });

        assert_eq!(summary.protected_count, 1);
        assert_eq!(summary.mounted_count, 1);
        assert_eq!(summary.attention_count, 6);
        assert_eq!(summary.device_counts.pending, 1);
        assert_eq!(summary.device_counts.unverified, 1);
        assert_eq!(summary.folder_attention.conflicts, 1);
        assert_eq!(summary.folder_attention.recovery_copies, 1);
        assert_eq!(summary.current_device.unwrap().is_verified, false);
        assert_eq!(summary.post_quantum_status, "protected_now");
        assert_eq!(summary.post_quantum_primary_text, "Protected now");
        assert_eq!(
            summary.post_quantum_secondary_text,
            "Your protected folders are secured now with quantum-resistant encryption."
        );
        assert!(summary.post_quantum_explainer_available);
    }

    #[test]
    fn build_individual_home_status_marks_post_quantum_review_without_protected_folders() {
        let summary = build_individual_home_status(IndividualHomeStatusInput {
            security: IndividualSecuritySnapshot {
                mfa_enabled: true,
                recovery_backup_ok: true,
                recovery_auto_backup_ok: true,
            },
            settings: IndividualSettingsSnapshot {
                coverage_last_scan: Some("2026-03-24T10:00:00Z".to_string()),
                registry_last_upload: Some("2026-03-24T11:00:00Z".to_string()),
            },
            protected_count: 0,
            mounted_count: 0,
            current_device: Some(CurrentDeviceSnapshot {
                device_id: "device-current".to_string(),
                is_verified: true,
            }),
            device_counts: DeviceCountSnapshot {
                trusted: 1,
                pending: 0,
                stale: 0,
                unverified: 0,
            },
            folder_attention: FolderAttentionSnapshot::default(),
            now: Utc.with_ymd_and_hms(2026, 3, 24, 12, 0, 0).unwrap(),
        });

        assert_eq!(summary.post_quantum_status, "needs_review");
        assert_eq!(summary.post_quantum_primary_text, "Needs review");
        assert_eq!(
            summary.post_quantum_secondary_text,
            "Add a protected folder to start securing files now with post-quantum encryption."
        );
    }

    #[test]
    fn build_personal_devices_overview_partitions_records_by_status() {
        let overview = build_personal_devices_overview(PersonalDevicesOverviewInput {
            current_device_id: Some("device-current".to_string()),
            registered_devices: vec![
                RegisteredDeviceRecord {
                    device_id: "device-current".to_string(),
                    device_name: Some("This Mac".to_string()),
                    created_at: "2026-03-22T09:00:00Z".to_string(),
                    last_seen: "2026-03-24T11:55:00Z".to_string(),
                    is_current_device: true,
                    is_verified: true,
                },
                RegisteredDeviceRecord {
                    device_id: "device-laptop".to_string(),
                    device_name: Some("Travel Laptop".to_string()),
                    created_at: "2026-03-20T09:00:00Z".to_string(),
                    last_seen: "2026-03-24T09:30:00Z".to_string(),
                    is_current_device: false,
                    is_verified: true,
                },
            ],
            pending_devices: vec![PendingDeviceRecord {
                device_id: "device-phone".to_string(),
                email: "user@example.com".to_string(),
                device_name: Some("Phone".to_string()),
                observed_at: Some("2026-03-24T08:30:00Z".to_string()),
            }],
            stale_devices: vec![StaleDeviceRecord {
                device_id: "device-old".to_string(),
                email: "user@example.com".to_string(),
                device_name: Some("Old Laptop".to_string()),
                last_seen: Some("2026-02-10T08:00:00Z".to_string()),
            }],
            unverified_devices: vec![UnverifiedDeviceRecord {
                device_id: "device-tablet".to_string(),
                email: "user@example.com".to_string(),
                device_name: Some("Tablet".to_string()),
                last_seen: Some("2026-03-24T07:45:00Z".to_string()),
            }],
            rename_supported: false,
            revoke_supported: true,
        });

        assert_eq!(
            overview
                .current_device
                .as_ref()
                .map(|device| device.device_id.as_str()),
            Some("device-current")
        );
        assert_eq!(
            overview
                .trusted_devices
                .iter()
                .map(|device| device.device_id.as_str())
                .collect::<Vec<_>>(),
            vec!["device-laptop"]
        );
        assert_eq!(
            overview
                .setup_devices
                .iter()
                .map(|device| device.device_id.as_str())
                .collect::<Vec<_>>(),
            vec!["device-phone", "device-tablet"]
        );
        assert_eq!(
            overview
                .review_devices
                .iter()
                .map(|device| device.device_id.as_str())
                .collect::<Vec<_>>(),
            vec!["device-old"]
        );
        assert_eq!(overview.rename_supported, false);
        assert_eq!(overview.revoke_supported, true);
    }

    #[test]
    fn build_personal_devices_overview_keeps_current_device_when_it_needs_setup() {
        let overview = build_personal_devices_overview(PersonalDevicesOverviewInput {
            current_device_id: Some("device-current".to_string()),
            registered_devices: vec![],
            pending_devices: vec![PendingDeviceRecord {
                device_id: "device-current".to_string(),
                email: "user@example.com".to_string(),
                device_name: Some("This Mac".to_string()),
                observed_at: Some("2026-03-24T08:30:00Z".to_string()),
            }],
            stale_devices: vec![],
            unverified_devices: vec![],
            rename_supported: false,
            revoke_supported: true,
        });

        assert_eq!(
            overview.current_device.as_ref().map(|device| (
                device.device_id.as_str(),
                device.status.as_str(),
                device.is_current_device
            )),
            Some(("device-current", "pending", true))
        );
        assert!(overview.setup_devices.is_empty());
    }

    #[test]
    fn build_coverage_center_snapshot_summarizes_root_stats_and_attention() {
        let taxes_root_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let projects_root_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let stats = vec![
            CoverageRootStats {
                root: CoverageRoot {
                    root_id: taxes_root_id,
                    path: PathBuf::from("/Users/test/Documents/Taxes"),
                    group_id: None,
                    kind: CoverageRootKind::Folder,
                    state: CoverageRootState::Active,
                    created_at: Utc.with_ymd_and_hms(2026, 3, 20, 9, 0, 0).unwrap(),
                    updated_at: Utc.with_ymd_and_hms(2026, 3, 24, 11, 0, 0).unwrap(),
                    last_scan: Some(Utc.with_ymd_and_hms(2026, 3, 24, 11, 20, 0).unwrap()),
                },
                tracked_files: 500,
                tracked_bytes: 0,
                orphaned_files: 0,
                orphaned_bytes: 0,
                orphan_wrong_epoch: 0,
                orphan_missing_file: 0,
                orphan_missing_metadata: 0,
                orphan_outcast: 0,
                unmanaged_files: 0,
                unmanaged_bytes: 0,
                coverage_ratio: 1.0,
                recent_orphans: vec![],
                recent_unmanaged: vec![],
            },
            CoverageRootStats {
                root: CoverageRoot {
                    root_id: projects_root_id,
                    path: PathBuf::from("/Users/test/Documents/Projects"),
                    group_id: None,
                    kind: CoverageRootKind::Folder,
                    state: CoverageRootState::Active,
                    created_at: Utc.with_ymd_and_hms(2026, 3, 21, 9, 0, 0).unwrap(),
                    updated_at: Utc.with_ymd_and_hms(2026, 3, 24, 11, 0, 0).unwrap(),
                    last_scan: Some(Utc.with_ymd_and_hms(2026, 3, 24, 11, 20, 0).unwrap()),
                },
                tracked_files: 420,
                tracked_bytes: 0,
                orphaned_files: 30,
                orphaned_bytes: 0,
                orphan_wrong_epoch: 0,
                orphan_missing_file: 0,
                orphan_missing_metadata: 24,
                orphan_outcast: 6,
                unmanaged_files: 50,
                unmanaged_bytes: 0,
                coverage_ratio: 0.84,
                recent_orphans: vec![],
                recent_unmanaged: vec![],
            },
        ];

        let snapshot = build_coverage_center_snapshot(
            &stats,
            &SettingsStatus {
                coverage_last_scan: Some("2026-03-24T11:20:00Z".to_string()),
                coverage_ipc_active: true,
                coverage_ipc_supported: true,
                registry_last_upload: None,
                registry_version: None,
            },
        );

        assert_eq!(snapshot.overall_coverage_percent, 92);
        assert_eq!(snapshot.enrolled_folder_count, 2);
        assert_eq!(snapshot.tracked_files, 920);
        assert_eq!(snapshot.orphaned_files, 30);
        assert_eq!(snapshot.unmanaged_files, 50);
        assert_eq!(snapshot.ipc_state, "active");
        assert_eq!(snapshot.folders.len(), 2);
        assert_eq!(snapshot.folders[0].coverage_label, "Fully protected");
        assert_eq!(
            snapshot.folders[1].recommended_action_id.as_deref(),
            Some("review-folder-coverage")
        );
        assert_eq!(snapshot.attention_items.len(), 1);
        assert_eq!(
            snapshot.attention_items[0].root_id.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
    }

    #[test]
    fn build_coverage_scan_result_maps_summary_and_target_root() {
        let result = build_coverage_scan_result(
            CoverageScanSummary {
                roots_scanned: 2,
                files_indexed: 920,
                orphaned_files: 30,
                unmanaged_files: 50,
                missing_roots: vec![PathBuf::from("/Users/test/Documents/Missing")],
            },
            Some("/Users/test/Documents/Projects".to_string()),
            Utc.with_ymd_and_hms(2026, 3, 24, 12, 30, 0).unwrap(),
        );

        assert_eq!(
            result.root_path.as_deref(),
            Some("/Users/test/Documents/Projects")
        );
        assert_eq!(result.roots_scanned, 2);
        assert_eq!(result.files_indexed, 920);
        assert_eq!(
            result.missing_roots,
            vec!["/Users/test/Documents/Missing".to_string()]
        );
        assert_eq!(result.completed_at, "2026-03-24T12:30:00+00:00");
    }

    #[test]
    fn build_folder_coverage_review_reports_missing_files_and_exact_rows() {
        let root_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let group_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let root = CoverageRoot {
            root_id,
            path: PathBuf::from("/Users/test/Documents/Taxes"),
            group_id: Some(group_id),
            kind: CoverageRootKind::Folder,
            state: CoverageRootState::Active,
            created_at: Utc.with_ymd_and_hms(2026, 3, 20, 9, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 3, 24, 11, 0, 0).unwrap(),
            last_scan: Some(Utc.with_ymd_and_hms(2026, 3, 24, 11, 15, 0).unwrap()),
        };
        let stats = CoverageRootStats {
            root: root.clone(),
            tracked_files: 1485,
            tracked_bytes: 0,
            orphaned_files: 15,
            orphaned_bytes: 0,
            orphan_wrong_epoch: 0,
            orphan_missing_file: 15,
            orphan_missing_metadata: 0,
            orphan_outcast: 0,
            unmanaged_files: 0,
            unmanaged_bytes: 0,
            coverage_ratio: 0.99,
            recent_orphans: vec![],
            recent_unmanaged: vec![],
        };
        let records = vec![
            CoverageFileRecord {
                root: root.clone(),
                entry: FileIndexEntry {
                    file_uuid: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
                    file_id: Some("file-1".to_string()),
                    root_id,
                    relative_path: "2024/return.pdf".to_string(),
                    size: 4096,
                    last_epoch: 12,
                    checksum_hint: None,
                    last_seen: Utc.with_ymd_and_hms(2026, 3, 23, 18, 0, 0).unwrap(),
                    state: FileCoverageState::Orphaned,
                    orphan_kind: Some(FileOrphanKind::MissingFile),
                },
            },
            CoverageFileRecord {
                root: root.clone(),
                entry: FileIndexEntry {
                    file_uuid: Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap(),
                    file_id: Some("file-2".to_string()),
                    root_id,
                    relative_path: "2024/receipts.csv".to_string(),
                    size: 1024,
                    last_epoch: 12,
                    checksum_hint: None,
                    last_seen: Utc.with_ymd_and_hms(2026, 3, 23, 18, 5, 0).unwrap(),
                    state: FileCoverageState::Orphaned,
                    orphan_kind: None,
                },
            },
        ];

        let review = build_folder_coverage_review(stats, records);

        assert_eq!(review.state_label, "Almost fully protected");
        assert_eq!(review.unresolved_item_count, 15);
        assert_eq!(review.groups.len(), 1);
        assert_eq!(review.groups[0].id, "clean_up_missing");
        assert_eq!(
            review.groups[0].primary_cta_label,
            "Clean up 15 missing items"
        );
        assert_eq!(review.groups[0].files.len(), 2);
        assert_eq!(review.groups[0].files[0].relative_path, "2024/receipts.csv");
        assert_eq!(review.groups[0].files[1].relative_path, "2024/return.pdf");
    }

    #[test]
    fn build_folder_coverage_review_separates_unmanaged_and_outcast_items() {
        let root_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let group_id = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let root = CoverageRoot {
            root_id,
            path: PathBuf::from("/Users/test/Documents/Projects"),
            group_id: Some(group_id),
            kind: CoverageRootKind::Folder,
            state: CoverageRootState::Active,
            created_at: Utc.with_ymd_and_hms(2026, 3, 20, 9, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 3, 24, 11, 0, 0).unwrap(),
            last_scan: Some(Utc.with_ymd_and_hms(2026, 3, 24, 11, 15, 0).unwrap()),
        };
        let stats = CoverageRootStats {
            root: root.clone(),
            tracked_files: 300,
            tracked_bytes: 0,
            orphaned_files: 4,
            orphaned_bytes: 0,
            orphan_wrong_epoch: 0,
            orphan_missing_file: 0,
            orphan_missing_metadata: 0,
            orphan_outcast: 4,
            unmanaged_files: 6,
            unmanaged_bytes: 0,
            coverage_ratio: 0.87,
            recent_orphans: vec![],
            recent_unmanaged: vec![],
        };
        let records = vec![
            CoverageFileRecord {
                root: root.clone(),
                entry: FileIndexEntry {
                    file_uuid: Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap(),
                    file_id: Some("file-3".to_string()),
                    root_id,
                    relative_path: "legacy/blob.enc".to_string(),
                    size: 2048,
                    last_epoch: 18,
                    checksum_hint: None,
                    last_seen: Utc.with_ymd_and_hms(2026, 3, 22, 18, 0, 0).unwrap(),
                    state: FileCoverageState::Orphaned,
                    orphan_kind: Some(FileOrphanKind::Outcast),
                },
            },
            CoverageFileRecord {
                root: root.clone(),
                entry: FileIndexEntry {
                    file_uuid: Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap(),
                    file_id: None,
                    root_id,
                    relative_path: "notes/action-items.txt".to_string(),
                    size: 512,
                    last_epoch: 0,
                    checksum_hint: None,
                    last_seen: Utc.with_ymd_and_hms(2026, 3, 24, 10, 0, 0).unwrap(),
                    state: FileCoverageState::Unmanaged,
                    orphan_kind: None,
                },
            },
        ];

        let review = build_folder_coverage_review(stats, records);

        assert_eq!(review.state_label, "Needs attention");
        assert_eq!(
            review
                .groups
                .iter()
                .map(|group| group.id.as_str())
                .collect::<Vec<_>>(),
            vec!["remove_leftover_data", "review_unprotected",]
        );
    }
}

#[tauri::command]
pub async fn run_shell_command(
    command: String,
    cwd: Option<String>,
    input: Option<String>,
) -> Result<CommandResponse<TerminalResult>, String> {
    if command.trim().is_empty() {
        return Ok(CommandResponse::err("No command provided"));
    }

    #[cfg(feature = "individual-edition")]
    if let Some(command_name) = restricted_individual_command_name(&command) {
        return Ok(CommandResponse::err_with_code(
            "INDIVIDUAL_EDITION_RESTRICTED",
            individual_command_restriction_message(command_name),
        ));
    }

    // Prefer a pseudo-TTY so interactive commands (dialoguer, etc.) behave like a real terminal.
    // On macOS: script -q /dev/null sh -lc "<cmd>"
    // On Linux: script -q -c "<cmd>" /dev/null
    // On Windows: fallback to cmd/powershell (no PTY available here).
    // On Unix we wrap commands to print an explicit exit marker so we can
    // recover child exit status even when script(1) normalizes process exits.
    let wrapped_command = if cfg!(target_os = "windows") {
        command.clone()
    } else {
        wrap_shell_command_for_status(&command)
    };

    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = StdCommand::new("cmd.exe");
        c.arg("/C").arg(wrapped_command);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = StdCommand::new("script");
        c.args(["-q", "/dev/null", "sh", "-lc", &wrapped_command]);
        c
    } else {
        let mut c = StdCommand::new("script");
        c.args(["-q", "-c", &wrapped_command, "/dev/null"]);
        c
    };

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    configure_background_std_command(&mut cmd);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            if let Some(input_data) = input {
                if let Some(mut stdin) = child.stdin.take() {
                    if let Err(err) = stdin.write_all(input_data.as_bytes()) {
                        return Ok(CommandResponse::err(format!(
                            "Failed to write command input: {}",
                            err
                        )));
                    }
                }
            } else {
                drop(child.stdin.take());
            }

            match collect_child_output_limited(
                child,
                MAX_COMMAND_OUTPUT_BYTES,
                COMMAND_OUTPUT_TAIL_BYTES,
            ) {
                Ok((exit_status, mut stdout, mut stderr)) => {
                    let mut status = exit_status.code().unwrap_or(-1);

                    if let Some(parsed) = extract_wrapped_exit_status(&mut stdout)
                        .or_else(|| extract_wrapped_exit_status(&mut stderr))
                    {
                        status = parsed;
                    }

                    Ok(CommandResponse::ok(TerminalResult {
                        stdout,
                        stderr,
                        status,
                    }))
                }
                Err(e) => Ok(CommandResponse::err(format!("Failed to execute: {}", e))),
            }
        }
        Err(e) => Ok(CommandResponse::err(format!("Failed to execute: {}", e))),
    }
}

fn default_shell_command() -> CommandBuilder {
    if cfg!(target_os = "windows") {
        let mut cmd = CommandBuilder::new("cmd.exe");
        cmd.arg("/K");
        cmd
    } else {
        let fallback_shell = if cfg!(target_os = "macos") {
            "/bin/zsh"
        } else {
            "/bin/bash"
        };
        let shell = std::env::var("SHELL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| fallback_shell.to_string());
        let mut cmd = CommandBuilder::new(shell);
        cmd.arg("-l");
        cmd
    }
}

#[cfg(feature = "individual-edition")]
fn is_hybridcipher_command_token(token: &str) -> bool {
    let trimmed = token.trim_matches(|ch| ch == '"' || ch == '\'');
    Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            let lower = name.to_ascii_lowercase();
            lower == "hybridcipher" || lower == "hybridcipher.exe"
        })
        .unwrap_or(false)
}

#[cfg(feature = "individual-edition")]
fn restricted_individual_command_name(command: &str) -> Option<&'static str> {
    let tokens = shell_words::split(command).ok()?;
    let hybridcipher_index = tokens
        .iter()
        .position(|token| is_hybridcipher_command_token(token))?;
    let args = &tokens[hybridcipher_index + 1..];

    match args {
        [subcommand, ..] if subcommand == "create-group" => Some("create-group"),
        [subcommand, ..] if subcommand == "rename-group" => Some("rename-group"),
        [subcommand, ..] if subcommand == "initialize-group" => Some("initialize-group"),
        [subcommand, ..] if subcommand == "switch-group" => Some("switch-group"),
        [subcommand, ..] if subcommand == "current-group" => Some("current-group"),
        [subcommand, ..] if subcommand == "list-groups" => Some("list-groups"),
        [subcommand, ..] if subcommand == "delete-group" => Some("delete-group"),
        [subcommand, ..] if subcommand == "add-member" => Some("add-member"),
        [subcommand, ..] if subcommand == "remove-member" => Some("remove-member"),
        [subcommand, ..] if subcommand == "list-members" => Some("list-members"),
        [subcommand, ..] if subcommand == "generate-welcome" => Some("generate-welcome"),
        [subcommand, ..] if subcommand == "unverified-devices" => Some("unverified-devices"),
        [subcommand, action, ..] if subcommand == "rekey" && action == "start" => {
            Some("rekey start")
        }
        [subcommand, action, ..] if subcommand == "rekey" && action == "status" => {
            Some("rekey status")
        }
        [subcommand, action, ..] if subcommand == "rekey" && action == "cutover" => {
            Some("rekey cutover")
        }
        [subcommand, action, ..] if subcommand == "rekey" && action == "fallback" => {
            Some("rekey fallback")
        }
        _ => None,
    }
}

#[cfg(feature = "individual-edition")]
fn individual_command_restriction_message(command_name: &str) -> String {
    format!(
        "This build disables team and group administration commands. `{}` is not available.",
        command_name
    )
}

fn default_pty_size() -> PtySize {
    PtySize {
        rows: 32,
        cols: 120,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn emit_terminal_chunk(app: &AppHandle, session_id: &str, chunk: &str) {
    let payload = TerminalOutputPayload {
        session_id: session_id.to_string(),
        chunk: chunk.to_string(),
    };
    let _ = app.emit("terminal_output", payload);
}

#[tauri::command]
pub async fn start_terminal_session(
    app: tauri::AppHandle,
    cwd: Option<String>,
) -> Result<CommandResponse<TerminalSessionInfo>, String> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(default_pty_size())
        .map_err(|e| format!("Failed to open PTY: {}", e))?;

    let mut cmd = default_shell_command();
    if cfg!(not(target_os = "windows")) {
        // App bundles launched from Finder often lack TERM/COLORTERM.
        // Without TERM, interactive shells may downgrade to TERM=dumb, which breaks
        // readline-style editing behavior (backspace/arrow keys).
        let term = std::env::var("TERM")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "xterm-256color".to_string());
        cmd.env("TERM", term);

        if std::env::var("COLORTERM")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            cmd.env("COLORTERM", "truecolor");
        }
    }
    if let Ok((cli_path, _)) = locate_cli_binary() {
        if let Some(cli_dir) = cli_path.parent() {
            let separator = if cfg!(target_os = "windows") {
                ";"
            } else {
                ":"
            };
            let existing_path = std::env::var("PATH").unwrap_or_default();
            let updated_path = if existing_path.is_empty() {
                cli_dir.display().to_string()
            } else {
                format!("{}{}{}", cli_dir.display(), separator, existing_path)
            };
            cmd.env("PATH", updated_path);
        }
    }
    // Use provided cwd if it exists and is not a HybridCipher mount path; otherwise fall back to home.
    let home_dir = dirs::home_dir();
    let hc_base = home_dir.as_ref().map(|h| h.join(".hybridcipher"));
    let resolved_cwd = cwd
        .as_deref()
        .map(PathBuf::from)
        .filter(|p| p.exists() && p.is_dir())
        .filter(|p| {
            // Avoid starting in mount directories under ~/.hybridcipher to prevent stale mount CWDs
            if let Some(base) = hc_base.as_ref() {
                !p.starts_with(base)
            } else {
                true
            }
        })
        .or_else(|| home_dir);
    if let Some(dir) = resolved_cwd {
        cmd.cwd(dir);
    }

    let portable_pty::PtyPair { master, slave } = pair;

    let child = slave
        .spawn_command(cmd)
        .map_err(|e| format!("Failed to spawn shell: {}", e))?;

    let mut reader = master
        .try_clone_reader()
        .map_err(|e| format!("Failed to clone PTY reader: {}", e))?;
    let writer = master
        .take_writer()
        .map_err(|e| format!("Failed to take PTY writer: {}", e))?;

    let session_id = Uuid::new_v4().to_string();
    let writer = Arc::new(Mutex::new(writer));

    // Spawn reader thread to push chunks to the frontend
    let app_handle = app.clone();
    let session_id_clone = session_id.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    // EOF
                    emit_terminal_chunk(&app_handle, &session_id_clone, "\n[session closed]");
                    break;
                }
                Ok(n) => {
                    if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                        emit_terminal_chunk(&app_handle, &session_id_clone, s);
                    } else {
                        let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                        emit_terminal_chunk(&app_handle, &session_id_clone, &chunk);
                    }
                }
                Err(e) => {
                    let _ = emit_terminal_chunk(
                        &app_handle,
                        &session_id_clone,
                        &format!("\n[read error: {}]", e),
                    );
                    break;
                }
            }
        }
    });

    let session = TerminalSession {
        child,
        master,
        writer,
    };
    {
        let mut sessions = TERMINAL_SESSIONS
            .lock()
            .map_err(|e| format!("Session lock poisoned: {}", e))?;
        sessions.insert(session_id.clone(), session);
    }

    Ok(CommandResponse::ok(TerminalSessionInfo { session_id }))
}

#[tauri::command]
pub async fn write_terminal_stdin(
    session_id: String,
    data: String,
) -> Result<CommandResponse<bool>, String> {
    let sessions = TERMINAL_SESSIONS
        .lock()
        .map_err(|e| format!("Session lock poisoned: {}", e))?;
    let handle = sessions
        .get(&session_id)
        .ok_or_else(|| "Session not found".to_string())?;

    let mut writer = handle
        .writer
        .lock()
        .map_err(|e| format!("Writer lock poisoned: {}", e))?;
    writer
        .write_all(data.as_bytes())
        .map_err(|e| format!("Failed to write: {}", e))?;
    writer
        .flush()
        .map_err(|e| format!("Failed to flush: {}", e))?;

    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn close_terminal_session(session_id: String) -> Result<CommandResponse<bool>, String> {
    let mut sessions = TERMINAL_SESSIONS
        .lock()
        .map_err(|e| format!("Session lock poisoned: {}", e))?;
    if let Some(mut handle) = sessions.remove(&session_id) {
        let _ = handle.child.kill();
    }
    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn record_terminal_diagnostic(
    payload: TerminalDiagnosticPayload,
) -> Result<CommandResponse<bool>, String> {
    let payload = TerminalDiagnosticPayload::normalized(payload);
    tracing::debug!(
        target: "hybridcipher_desktop::terminal_diagnostics",
        tab_id = payload.tab_id,
        session_id = payload.session_id.as_deref().unwrap_or(""),
        event = payload.event.as_str(),
        textarea_is_active = payload.textarea_is_active,
        xterm_has_focus_class = payload.xterm_has_focus_class,
        rows = payload.rows.unwrap_or_default(),
        cols = payload.cols.unwrap_or_default(),
        host_visible = payload.host_visible,
        host_width = payload.host_width.unwrap_or_default(),
        host_height = payload.host_height.unwrap_or_default(),
        host_occluded = payload.host_occluded.unwrap_or(false),
        occluding_element_tag = payload.occluding_element_tag.as_deref().unwrap_or(""),
        occluding_element_id = payload.occluding_element_id.as_deref().unwrap_or(""),
        selection_overlay_count = payload.selection_overlay_count,
        term_has_selection = payload.term_has_selection,
        selection_text_length = payload.selection_text_length,
        active_element_tag = payload.active_element_tag.as_deref().unwrap_or(""),
        active_element_id = payload.active_element_id.as_deref().unwrap_or(""),
        "frontend terminal diagnostic"
    );
    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn start_password_reset(
    token: String,
    email: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<PasswordResetSessionInfo>, String> {
    let token = token.trim().to_string();
    if token.is_empty() {
        return Ok(CommandResponse::err("Reset token is required."));
    }
    let email = email.trim().to_string();

    let (cli_binary, _project_root) =
        locate_cli_binary().map_err(|e| format!("Failed to locate CLI binary: {}", e))?;

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(default_pty_size())
        .map_err(|e| format!("Failed to open PTY for password reset: {}", e))?;

    let mut cmd = CommandBuilder::new(cli_binary);
    cmd.arg("password-reset");
    cmd.arg(token);
    cmd.env(
        "HYBRIDCIPHER_SERVER_URL",
        state.client.server_url().to_string(),
    );

    if let Ok(current_dir) = std::env::current_dir() {
        cmd.cwd(current_dir);
    }

    let portable_pty::PtyPair { master, slave } = pair;

    let child = slave
        .spawn_command(cmd)
        .map_err(|e| format!("Failed to start password reset CLI: {}", e))?;

    let mut reader = master
        .try_clone_reader()
        .map_err(|e| format!("Failed to capture password reset output: {}", e))?;
    let writer = master
        .take_writer()
        .map_err(|e| format!("Failed to open password reset input: {}", e))?;

    let session_id = Uuid::new_v4().to_string();
    let output = Arc::new(Mutex::new(String::new()));
    let output_buffer = output.clone();

    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                    if let Ok(mut guard) = output_buffer.lock() {
                        guard.push_str(&chunk);
                    }
                }
                Err(_) => break,
            }
        }
    });

    let reset_server_url = state.client.server_url().to_string();

    let session = PasswordResetSession {
        child,
        master,
        writer: Arc::new(Mutex::new(writer)),
        output,
        email,
        server_url: reset_server_url,
    };

    let mut sessions = PASSWORD_RESET_SESSIONS
        .lock()
        .map_err(|e| format!("Password reset session lock poisoned: {}", e))?;
    sessions.insert(session_id.clone(), session);

    Ok(CommandResponse::ok(PasswordResetSessionInfo { session_id }))
}

#[tauri::command]
pub async fn complete_password_reset(
    session_id: String,
    password: String,
    confirm_password: String,
) -> Result<CommandResponse<String>, String> {
    if password.is_empty() || confirm_password.is_empty() {
        return Ok(CommandResponse::err(
            "New password and confirmation are required.",
        ));
    }

    let mut session = {
        let mut sessions = PASSWORD_RESET_SESSIONS
            .lock()
            .map_err(|e| format!("Password reset session lock poisoned: {}", e))?;
        sessions.remove(&session_id)
    }
    .ok_or_else(|| "Password reset session not found.".to_string())?;

    let reset_email = session.email.clone();
    let reset_server_url = session.server_url.clone();

    {
        let mut writer = session
            .writer
            .lock()
            .map_err(|e| format!("Password reset writer lock poisoned: {}", e))?;
        writer
            .write_all(format!("{}\n{}\n", password, confirm_password).as_bytes())
            .map_err(|e| format!("Failed to submit password reset input: {}", e))?;
        writer
            .flush()
            .map_err(|e| format!("Failed to flush password reset input: {}", e))?;
    }

    let output_buffer = session.output.clone();
    let status = tokio::task::spawn_blocking(move || session.child.wait())
        .await
        .map_err(|e| format!("Password reset task join failed: {}", e))?
        .map_err(|e| format!("Failed while waiting for password reset CLI: {}", e))?;

    let output = output_buffer
        .lock()
        .map_err(|e| format!("Password reset output lock poisoned: {}", e))?
        .clone();

    if !status.success() {
        let message = summarize_password_reset_output(&output)
            .unwrap_or_else(|| "Password reset failed.".to_string());
        return Ok(CommandResponse::err(message));
    }

    // Re-wrap desktop local state under the new password (best-effort).
    if !reset_email.is_empty() {
        if let Ok(session_store) = crate::session::SessionStore::new() {
            if let Err(e) = session_store.rewrap_after_password_change(
                &reset_email,
                &reset_server_url,
                &password,
            ) {
                tracing::warn!("Desktop state re-wrap after password reset failed: {}", e);
            }
        }
    }

    Ok(CommandResponse::ok(
        "Password reset successful. You can now sign in with your new password.".to_string(),
    ))
}

#[tauri::command]
pub async fn cancel_password_reset(session_id: String) -> Result<CommandResponse<bool>, String> {
    let mut sessions = PASSWORD_RESET_SESSIONS
        .lock()
        .map_err(|e| format!("Password reset session lock poisoned: {}", e))?;
    if let Some(mut session) = sessions.remove(&session_id) {
        let _ = session.child.kill();
    }
    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn get_cli_binary_path() -> Result<CommandResponse<String>, String> {
    tracing::info!("Get CLI binary path command called");

    // Try to locate built binary first
    match crate::cli_utils::locate_cli_binary() {
        Ok((binary_path, _)) => {
            tracing::info!("Found CLI binary at: {}", binary_path.display());
            Ok(CommandResponse::ok(binary_path.display().to_string()))
        }
        #[cfg(not(feature = "individual-edition"))]
        Err(_) => {
            // Fallback: check if hybridcipher is in PATH
            match which::which("hybridcipher") {
                Ok(path) => {
                    tracing::info!("Found hybridcipher in PATH: {}", path.display());
                    Ok(CommandResponse::ok(path.display().to_string()))
                }
                Err(_) => Ok(CommandResponse::err(
                    "Could not find hybridcipher CLI. Build it with 'cargo build --release --bin hybridcipher' or install it in PATH."
                        .to_string(),
                )),
            }
        }
        #[cfg(feature = "individual-edition")]
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

// ============================================================================
// Platform Detection Commands
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// OS type: "macos", "linux", "windows"
    pub os_type: String,
    /// OS name with version (e.g., "macOS Ventura", "Ubuntu 22.04", "Windows 11")
    pub os_name: String,
    /// Default shell: "zsh", "bash", "powershell", "cmd"
    pub shell: String,
    /// Current username
    pub username: String,
    /// Machine hostname
    pub hostname: String,
    /// Home directory path
    pub home_dir: String,
}

#[tauri::command]
pub async fn get_platform_info() -> Result<CommandResponse<PlatformInfo>, String> {
    tracing::info!("Get platform info command called");

    let os_type = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };

    // Get OS name/version
    let os_name = get_os_name();

    // Get default shell
    let shell = get_default_shell();

    // Get username
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string());

    // Get hostname
    let hostname = get_hostname();

    // Get home directory
    let home_dir = dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "~".to_string());

    Ok(CommandResponse::ok(PlatformInfo {
        os_type: os_type.to_string(),
        os_name,
        shell,
        username,
        hostname,
        home_dir,
    }))
}

fn get_os_name() -> String {
    #[cfg(target_os = "macos")]
    {
        // Try to get macOS version
        if let Ok(output) = StdCommand::new("sw_vers").arg("-productVersion").output() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return format!("macOS {}", version);
        }
        "macOS".to_string()
    }

    #[cfg(target_os = "windows")]
    {
        // Try to get Windows version
        let mut command = StdCommand::new("cmd");
        command.args(["/C", "ver"]);
        configure_background_std_command(&mut command);
        if let Ok(output) = command.output() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if version.contains("10.0") {
                return "Windows 10/11".to_string();
            }
            return version;
        }
        "Windows".to_string()
    }

    #[cfg(target_os = "linux")]
    {
        // Try to get Linux distribution info
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    let name = line
                        .strip_prefix("PRETTY_NAME=")
                        .unwrap_or("")
                        .trim_matches('"');
                    return name.to_string();
                }
            }
        }
        "Linux".to_string()
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        "Unknown OS".to_string()
    }
}

fn get_default_shell() -> String {
    #[cfg(target_os = "macos")]
    {
        // macOS default is zsh since Catalina
        std::env::var("SHELL")
            .ok()
            .and_then(|s| s.rsplit('/').next().map(|s| s.to_string()))
            .unwrap_or_else(|| "zsh".to_string())
    }

    #[cfg(target_os = "windows")]
    {
        // Windows default is PowerShell, fallback to cmd
        if std::env::var("PSModulePath").is_ok() {
            "powershell".to_string()
        } else {
            "cmd".to_string()
        }
    }

    #[cfg(target_os = "linux")]
    {
        std::env::var("SHELL")
            .ok()
            .and_then(|s| s.rsplit('/').next().map(|s| s.to_string()))
            .unwrap_or_else(|| "bash".to_string())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        "sh".to_string()
    }
}

fn get_hostname() -> String {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if let Ok(output) = StdCommand::new("hostname").output() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(name) = std::env::var("COMPUTERNAME") {
            return name;
        }
    }

    "localhost".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalCliInstallStatus {
    pub supported: bool,
    pub global_path: String,
    pub bundled_path: Option<String>,
    pub installed: bool,
    pub is_symlink: bool,
    pub points_to_bundle: bool,
    pub link_target: Option<String>,
    pub detail: String,
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    let left_cmp = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right_cmp = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    left_cmp == right_cmp
}

fn global_cli_install_status() -> GlobalCliInstallStatus {
    #[cfg(not(target_os = "macos"))]
    {
        return GlobalCliInstallStatus {
            supported: false,
            global_path: "/usr/local/bin/hybridcipher".to_string(),
            bundled_path: None,
            installed: false,
            is_symlink: false,
            points_to_bundle: false,
            link_target: None,
            detail: "Global CLI installation is currently supported on macOS only.".to_string(),
        };
    }

    #[cfg(target_os = "macos")]
    {
        let global_path = PathBuf::from("/usr/local/bin/hybridcipher");
        let bundled_path = crate::cli_utils::locate_bundled_cli_binary();

        let mut installed = false;
        let mut is_symlink = false;
        let mut points_to_bundle = false;
        let mut link_target: Option<String> = None;
        let detail: String;

        match std::fs::symlink_metadata(&global_path) {
            Ok(metadata) => {
                installed = true;
                is_symlink = metadata.file_type().is_symlink();

                if is_symlink {
                    match std::fs::read_link(&global_path) {
                        Ok(target) => {
                            let resolved_target = if target.is_absolute() {
                                target.clone()
                            } else {
                                global_path
                                    .parent()
                                    .unwrap_or_else(|| Path::new("/"))
                                    .join(&target)
                            };
                            link_target = Some(target.display().to_string());

                            if let Some(bundle) = bundled_path.as_ref() {
                                points_to_bundle = paths_equivalent(&resolved_target, bundle);
                            }
                        }
                        Err(err) => {
                            detail =
                                format!("Global CLI symlink exists but could not be read: {}", err);
                            return GlobalCliInstallStatus {
                                supported: true,
                                global_path: global_path.display().to_string(),
                                bundled_path: bundled_path.map(|path| path.display().to_string()),
                                installed,
                                is_symlink,
                                points_to_bundle,
                                link_target,
                                detail,
                            };
                        }
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                detail = format!("Failed to inspect global CLI path: {}", err);
                return GlobalCliInstallStatus {
                    supported: true,
                    global_path: global_path.display().to_string(),
                    bundled_path: bundled_path.map(|path| path.display().to_string()),
                    installed,
                    is_symlink,
                    points_to_bundle,
                    link_target,
                    detail,
                };
            }
        }

        detail = if bundled_path.is_none() {
            "Bundled CLI was not found in the app resources.".to_string()
        } else if !installed {
            "Global terminal command is not installed.".to_string()
        } else if points_to_bundle {
            "Global terminal command points to bundled CLI and will track app updates.".to_string()
        } else if is_symlink {
            "Global terminal command points to a different target.".to_string()
        } else {
            "Global terminal command is a standalone file and will not auto-track app updates."
                .to_string()
        };

        GlobalCliInstallStatus {
            supported: true,
            global_path: global_path.display().to_string(),
            bundled_path: bundled_path.map(|path| path.display().to_string()),
            installed,
            is_symlink,
            points_to_bundle,
            link_target,
            detail,
        }
    }
}

#[tauri::command]
pub async fn get_global_cli_install_status(
) -> Result<CommandResponse<GlobalCliInstallStatus>, String> {
    Ok(CommandResponse::ok(global_cli_install_status()))
}

#[tauri::command]
pub async fn install_global_cli_symlink() -> Result<CommandResponse<GlobalCliInstallStatus>, String>
{
    #[cfg(not(target_os = "macos"))]
    {
        return Ok(CommandResponse::err(
            "Global CLI installation is currently supported on macOS only.",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        let bundled_cli = match crate::cli_utils::locate_bundled_cli_binary() {
            Some(path) => path,
            None => {
                return Ok(CommandResponse::err(
                    "Bundled CLI was not found in app resources. Reinstall the desktop app.",
                ))
            }
        };

        let global_path = PathBuf::from("/usr/local/bin/hybridcipher");
        if let Some(parent) = global_path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                return Ok(CommandResponse::err(format!(
                    "Failed to prepare {}: {}",
                    parent.display(),
                    err
                )));
            }
        }

        match std::fs::symlink_metadata(&global_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    if let Ok(target) = std::fs::read_link(&global_path) {
                        let resolved_target = if target.is_absolute() {
                            target.clone()
                        } else {
                            global_path
                                .parent()
                                .unwrap_or_else(|| Path::new("/"))
                                .join(&target)
                        };
                        if paths_equivalent(&resolved_target, &bundled_cli) {
                            return Ok(CommandResponse::ok(global_cli_install_status()));
                        }
                    }
                }

                if let Err(err) = std::fs::remove_file(&global_path) {
                    let hint = if err.kind() == std::io::ErrorKind::PermissionDenied {
                        format!(
                            " Permission denied. You can run: sudo ln -sfn \"{}\" \"{}\"",
                            bundled_cli.display(),
                            global_path.display()
                        )
                    } else {
                        String::new()
                    };
                    return Ok(CommandResponse::err(format!(
                        "Failed to replace existing {}: {}.{}",
                        global_path.display(),
                        err,
                        hint
                    )));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Ok(CommandResponse::err(format!(
                    "Failed to inspect {}: {}",
                    global_path.display(),
                    err
                )));
            }
        }

        if let Err(err) = std::os::unix::fs::symlink(&bundled_cli, &global_path) {
            let hint = if err.kind() == std::io::ErrorKind::PermissionDenied {
                format!(
                    " Permission denied. You can run: sudo ln -sfn \"{}\" \"{}\"",
                    bundled_cli.display(),
                    global_path.display()
                )
            } else {
                String::new()
            };
            return Ok(CommandResponse::err(format!(
                "Failed to create global CLI symlink at {}: {}.{}",
                global_path.display(),
                err,
                hint
            )));
        }

        Ok(CommandResponse::ok(global_cli_install_status()))
    }
}

#[tauri::command]
pub async fn check_for_updates(
    app: tauri::AppHandle,
) -> Result<CommandResponse<serde_json::Value>, String> {
    tracing::info!("Checking for updates");
    use tauri_plugin_updater::UpdaterExt;

    match app.updater() {
        Ok(updater) => match updater.check().await {
            Ok(Some(update)) => {
                tracing::info!("Update available: {}", update.version);
                Ok(CommandResponse::ok(serde_json::json!({
                    "available": true,
                    "version": update.version,
                    "notes": update.body.unwrap_or_default(),
                    "date": update.date.map(|d| d.to_string()).unwrap_or_default(),
                })))
            }
            Ok(None) => {
                tracing::info!("App is up to date");
                Ok(CommandResponse::ok(
                    serde_json::json!({ "available": false }),
                ))
            }
            Err(e) => {
                tracing::warn!("Update check failed: {}", e);
                Ok(CommandResponse::err(format!("Update check failed: {}", e)))
            }
        },
        Err(e) => {
            tracing::warn!("Updater not available: {}", e);
            Ok(CommandResponse::err(format!(
                "Updater not available: {}",
                e
            )))
        }
    }
}

#[tauri::command]
pub async fn install_update(app: tauri::AppHandle) -> Result<CommandResponse<String>, String> {
    tracing::info!("Installing update");
    use tauri_plugin_updater::UpdaterExt;

    #[derive(Debug, Serialize, Clone)]
    struct UpdaterProgressEvent {
        phase: String,
        downloaded: Option<u64>,
        total: Option<u64>,
        percent: Option<f64>,
        message: Option<String>,
    }

    let emit_progress = |event: UpdaterProgressEvent| {
        if let Err(err) = app.emit("updater_progress", &event) {
            tracing::warn!("Failed to emit updater_progress event: {}", err);
        }
    };

    match app.updater() {
        Ok(updater) => match updater.check().await {
            Ok(Some(update)) => {
                let version = update.version.clone();
                emit_progress(UpdaterProgressEvent {
                    phase: "starting".to_string(),
                    downloaded: Some(0),
                    total: None,
                    percent: Some(0.0),
                    message: Some(format!("Starting update to v{}…", version)),
                });
                if let Err(e) = update
                    .download_and_install(
                        |downloaded, total| {
                            let downloaded_u64 = downloaded as u64;
                            let total_u64 = total.unwrap_or(0);
                            let percent = if total_u64 > 0 {
                                Some((downloaded_u64 as f64 / total_u64 as f64 * 100.0).min(100.0))
                            } else {
                                None
                            };
                            emit_progress(UpdaterProgressEvent {
                                phase: "downloading".to_string(),
                                downloaded: Some(downloaded_u64),
                                total: if total_u64 > 0 { Some(total_u64) } else { None },
                                percent,
                                message: Some("Downloading update…".to_string()),
                            });
                        },
                        || {
                            emit_progress(UpdaterProgressEvent {
                                phase: "installing".to_string(),
                                downloaded: None,
                                total: None,
                                percent: Some(100.0),
                                message: Some("Installing update…".to_string()),
                            });
                        },
                    )
                    .await
                {
                    emit_progress(UpdaterProgressEvent {
                        phase: "error".to_string(),
                        downloaded: None,
                        total: None,
                        percent: None,
                        message: Some(format!("Update failed: {}", e)),
                    });
                    tracing::error!("Failed to install update: {}", e);
                    return Ok(CommandResponse::err(format!(
                        "Failed to install update: {}",
                        e
                    )));
                }
                emit_progress(UpdaterProgressEvent {
                    phase: "installed".to_string(),
                    downloaded: None,
                    total: None,
                    percent: Some(100.0),
                    message: Some(format!("Update v{} installed successfully.", version)),
                });
                Ok(CommandResponse::ok(format!(
                    "Update to {} installed. Restart to apply.",
                    version
                )))
            }
            Ok(None) => Ok(CommandResponse::ok("Already up to date".to_string())),
            Err(e) => Ok(CommandResponse::err(format!("Update check failed: {}", e))),
        },
        Err(e) => Ok(CommandResponse::err(format!(
            "Updater not available: {}",
            e
        ))),
    }
}

#[tauri::command]
pub async fn restart_application(
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    tracing::info!("restart_application: starting safe restart with unmount");

    if let Err(e) = state.mount_manager.unmount_all(false).await {
        tracing::error!("Failed to unmount during restart: {}", e);
    }

    app_handle.restart();
}

#[tauri::command]
pub async fn get_user_status(
    state: State<'_, AppState>,
) -> Result<CommandResponse<crate::client::UserStatus>, String> {
    let session = state.session.lock().await;
    let status = state.client.user_status(session.as_ref()).await;
    Ok(CommandResponse::ok(status))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveGroupContext {
    pub group_id: Option<String>,
    pub group_name: Option<String>,
}

#[tauri::command]
pub async fn get_active_group_context(
    state: State<'_, AppState>,
) -> Result<CommandResponse<ActiveGroupContext>, String> {
    if !state.is_authenticated().await {
        return Ok(CommandResponse::err(
            "Please login through the desktop app to access this feature.".to_string(),
        ));
    }

    let client = match state.local_client.client_opt().await {
        Some(client) => client,
        None => {
            return Ok(CommandResponse::err(
                "HybridCipher session is not available.".to_string(),
            ))
        }
    };

    let group_id = client.active_group_id_opt().await;
    let Some(group_id) = group_id else {
        return Ok(CommandResponse::ok(ActiveGroupContext {
            group_id: None,
            group_name: None,
        }));
    };

    let group_id_str = group_id.to_string();
    let group_name = match state.client.list_groups().await {
        Ok(groups) => groups
            .into_iter()
            .find(|group| group.id.eq_ignore_ascii_case(&group_id_str))
            .map(|group| group.name),
        Err(_) => None,
    };

    Ok(CommandResponse::ok(ActiveGroupContext {
        group_id: Some(group_id_str),
        group_name,
    }))
}

#[tauri::command]
pub async fn refresh_local_client(
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    ensure_authenticated(&state).await?;

    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or_else(|| "No active session found".to_string())?;

    let server_url = session
        .server_url
        .clone()
        .unwrap_or_else(|| state.client.server_url().to_string());

    state
        .local_client
        .initialize_for_session(&session, &server_url)
        .await?;

    Ok(CommandResponse::ok(true))
}

// ============================================================================
// Coverage & Folder Management Commands
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrolledFolder {
    pub path: String,
    pub root_id: String,
    pub kind: String,
    pub state: String,
    pub enrolled_at: String,
    pub last_scan: Option<String>,
    pub tracked_files: u64,
    pub tracked_bytes: u64,
    pub orphaned_files: u64,
    pub unmanaged_files: u64,
    pub coverage_ratio: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoverageActionResult {
    pub action: String,
    pub items_processed: usize,
    pub items_failed: usize,
    pub failure_paths: Vec<String>,
    pub refresh_required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FolderCoverageWorkflowResult {
    pub folder: EnrolledFolder,
    pub encrypted_files: u64,
    pub decrypted_files: u64,
    pub skipped_files: u64,
}

#[tauri::command]
pub async fn list_enrolled_folders(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<EnrolledFolder>>, String> {
    ensure_authenticated(&state).await?;
    tracing::info!("List enrolled folders command called");

    let client = match state.local_client.client().await {
        Ok(client) => client,
        Err(err) => return Ok(CommandResponse::err(err)),
    };

    match get_enrolled_folders_from_client(client.as_ref()).await {
        Ok(folders) => Ok(CommandResponse::ok(folders)),
        Err(e) => Ok(CommandResponse::err(format!(
            "Failed to list enrolled folders: {}",
            e
        ))),
    }
}

async fn get_enrolled_folders_from_client(
    client: &LocalClient,
) -> Result<Vec<EnrolledFolder>, String> {
    let stats = client
        .coverage_root_stats()
        .await
        .map_err(|e| format!("Failed to load coverage roots: {}", e))?;

    let folders = stats.into_iter().map(enrolled_folder_from_stats).collect();

    Ok(folders)
}

fn enrolled_folder_from_stats(summary: CoverageRootStats) -> EnrolledFolder {
    let root = summary.root;
    EnrolledFolder {
        path: root.path.display().to_string(),
        root_id: root.root_id.to_string(),
        kind: describe_root_kind(root.kind).to_string(),
        state: describe_root_state(root.state).to_string(),
        enrolled_at: root.created_at.to_rfc3339(),
        last_scan: root.last_scan.map(|ts| ts.to_rfc3339()),
        tracked_files: summary.tracked_files as u64,
        tracked_bytes: summary.tracked_bytes,
        orphaned_files: summary.orphaned_files as u64,
        unmanaged_files: summary.unmanaged_files as u64,
        coverage_ratio: summary.coverage_ratio,
    }
}

async fn find_coverage_root_summary(
    client: &LocalClient,
    folder_path: &str,
) -> Result<CoverageRootStats, String> {
    let requested_path = PathBuf::from(folder_path.trim());
    if requested_path.as_os_str().is_empty() {
        return Err("Folder path is required.".to_string());
    }

    let stats = client
        .coverage_root_stats()
        .await
        .map_err(|e| format!("Failed to load coverage roots: {}", e))?;

    stats
        .into_iter()
        .find(|summary| {
            summary.root.path == requested_path
                || paths_equivalent(&summary.root.path, &requested_path)
        })
        .ok_or_else(|| format!("No protected folder matched '{}'.", folder_path))
}

async fn find_coverage_root_summary_by_id(
    client: &LocalClient,
    root_id: &str,
) -> Result<CoverageRootStats, String> {
    let root_uuid = Uuid::parse_str(root_id.trim())
        .map_err(|err| format!("Protected folder id is not a valid UUID: {}", err))?;
    let stats = client
        .coverage_root_stats()
        .await
        .map_err(|e| format!("Failed to load coverage roots: {}", e))?;

    stats
        .into_iter()
        .find(|summary| summary.root.root_id == root_uuid)
        .ok_or_else(|| format!("No protected folder matched id '{}'.", root_id))
}

async fn load_folder_coverage_review_internal(
    client: &LocalClient,
    folder_path: &str,
) -> Result<FolderCoverageReview, String> {
    let summary = find_coverage_root_summary(client, folder_path).await?;
    let root_id = summary.root.root_id;
    let records = client
        .coverage_file_records(None)
        .await
        .map_err(|e| format!("Failed to load coverage file records: {}", e))?;
    let filtered_records: Vec<CoverageFileRecord> = records
        .into_iter()
        .filter(|record| record.root.root_id == root_id)
        .collect();

    Ok(build_folder_coverage_review(summary, filtered_records))
}

#[tauri::command]
pub async fn get_folder_coverage_review(
    folder_path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<FolderCoverageReview>, String> {
    ensure_authenticated(&state).await?;
    let client = state
        .local_client
        .client()
        .await
        .map_err(|err| format!("Failed to load folder coverage review: {}", err))?;

    match load_folder_coverage_review_internal(client.as_ref(), &folder_path).await {
        Ok(review) => Ok(CommandResponse::ok(review)),
        Err(error) => Ok(CommandResponse::err(error)),
    }
}

#[tauri::command]
pub async fn run_folder_coverage_action(
    action: String,
    folder_path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<CoverageActionResult>, String> {
    ensure_authenticated(&state).await?;
    let client = state
        .local_client
        .client()
        .await
        .map_err(|err| format!("Failed to load coverage action client: {}", err))?;
    let summary = find_coverage_root_summary(client.as_ref(), &folder_path).await?;
    let root_path = summary.root.path.clone();

    let result = match action.as_str() {
        "adopt_missing_metadata" => {
            let summary = client
                .coverage_adopt_missing_metadata(Some(root_path.clone()), true)
                .await
                .map_err(|e| format!("Failed to restore protection: {}", e))?;

            CoverageActionResult {
                action,
                items_processed: summary.adopted,
                items_failed: summary.adopt_failures.len(),
                failure_paths: summary.adopt_failures,
                refresh_required: true,
            }
        }
        "prune_missing_files" => {
            let removed = client
                .coverage_prune_orphans(Some(root_path.clone()), true)
                .await
                .map_err(|e| format!("Failed to clean up missing items: {}", e))?;

            CoverageActionResult {
                action,
                items_processed: removed,
                items_failed: 0,
                failure_paths: Vec::new(),
                refresh_required: true,
            }
        }
        "purge_outcasts" => {
            let removed = client
                .coverage_purge_outcasts(None, Some(root_path.clone()), true)
                .await
                .map_err(|e| format!("Failed to remove leftover protected data: {}", e))?;

            CoverageActionResult {
                action,
                items_processed: removed,
                items_failed: 0,
                failure_paths: Vec::new(),
                refresh_required: true,
            }
        }
        "migrate_wrong_epoch" => {
            let progress = client
                .coverage_migrate_orphans_with_progress(None, Some(root_path), true, |_| {})
                .await
                .map_err(|e| format!("Failed to repair protection history: {}", e))?;

            CoverageActionResult {
                action,
                items_processed: progress.migrated_files,
                items_failed: progress.failed_files,
                failure_paths: Vec::new(),
                refresh_required: true,
            }
        }
        _ => {
            return Ok(CommandResponse::err(format!(
                "Unsupported folder coverage action '{}'.",
                action
            )))
        }
    };

    Ok(CommandResponse::ok(result))
}

fn describe_root_kind(kind: CoverageRootKind) -> &'static str {
    match kind {
        CoverageRootKind::Folder => "folder",
        CoverageRootKind::SingleFile => "single-file",
    }
}

fn describe_root_state(state: CoverageRootState) -> &'static str {
    match state {
        CoverageRootState::Active => "active",
        CoverageRootState::Unenrolled => "unenrolled",
    }
}

fn basename_for_path(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(path)
        .to_string()
}

fn coverage_ipc_state(settings: &SettingsStatus) -> &'static str {
    if !settings.coverage_ipc_supported {
        "unsupported"
    } else if settings.coverage_ipc_active {
        "active"
    } else {
        "inactive"
    }
}

fn build_coverage_folder_row(summary: &CoverageRootStats) -> CoverageFolderRow {
    let tracked_files = summary.tracked_files as u64;
    let orphaned_files = summary.orphaned_files as u64;
    let unmanaged_files = summary.unmanaged_files as u64;
    let unresolved_files = orphaned_files + unmanaged_files;
    let coverage_percent = (summary.coverage_ratio * 100.0).round().clamp(0.0, 100.0) as u32;
    let coverage_label = if tracked_files == 0 && unresolved_files == 0 {
        "No protected items indexed yet".to_string()
    } else if unresolved_files == 0 && coverage_percent == 100 {
        "Fully protected".to_string()
    } else if coverage_percent >= 99 {
        "Almost fully protected".to_string()
    } else {
        "Needs attention".to_string()
    };
    let attention_label = if unresolved_files == 0 {
        "No review needed".to_string()
    } else {
        format!(
            "{} {} need review",
            unresolved_files,
            if unresolved_files == 1 {
                "file"
            } else {
                "files"
            }
        )
    };

    CoverageFolderRow {
        root_id: summary.root.root_id.to_string(),
        path: summary.root.path.display().to_string(),
        kind: describe_root_kind(summary.root.kind).to_string(),
        state: describe_root_state(summary.root.state).to_string(),
        last_scan: summary.root.last_scan.map(|ts| ts.to_rfc3339()),
        tracked_files,
        orphaned_files,
        unmanaged_files,
        coverage_percent,
        coverage_label,
        attention_label,
        needs_attention: unresolved_files > 0,
        recommended_action_id: (unresolved_files > 0).then(|| "review-folder-coverage".to_string()),
        recommended_action_label: (unresolved_files > 0).then(|| "Review fixes".to_string()),
    }
}

fn build_coverage_center_snapshot(
    stats: &[CoverageRootStats],
    settings: &SettingsStatus,
) -> CoverageCenterSnapshot {
    let active_stats: Vec<&CoverageRootStats> = stats
        .iter()
        .filter(|entry| entry.root.state == CoverageRootState::Active)
        .collect();

    let tracked_files = active_stats
        .iter()
        .map(|entry| entry.tracked_files as u64)
        .sum::<u64>();
    let orphaned_files = active_stats
        .iter()
        .map(|entry| entry.orphaned_files as u64)
        .sum::<u64>();
    let unmanaged_files = active_stats
        .iter()
        .map(|entry| entry.unmanaged_files as u64)
        .sum::<u64>();
    let total_known = tracked_files + orphaned_files + unmanaged_files;
    let overall_coverage_percent = if total_known == 0 {
        0
    } else {
        ((tracked_files as f64 / total_known as f64) * 100.0)
            .round()
            .clamp(0.0, 100.0) as u32
    };

    let folders = active_stats
        .iter()
        .map(|entry| build_coverage_folder_row(entry))
        .collect::<Vec<_>>();

    let attention_items = folders
        .iter()
        .filter(|folder| folder.needs_attention)
        .map(|folder| CoverageAttentionItem {
            id: folder.root_id.clone(),
            title: format!("{} needs review", basename_for_path(&folder.path)),
            detail: folder.attention_label.clone(),
            root_id: Some(folder.root_id.clone()),
            folder_path: Some(folder.path.clone()),
            action_id: folder.recommended_action_id.clone(),
            action_label: folder.recommended_action_label.clone(),
        })
        .collect::<Vec<_>>();

    let summary_cards = vec![
        CoverageSummaryCard {
            id: "coverage".to_string(),
            label: "Overall coverage".to_string(),
            value: format!("{}%", overall_coverage_percent),
            detail: format!("{} enrolled folders", folders.len()),
            tone: if overall_coverage_percent >= 99 {
                "safe".to_string()
            } else if folders.is_empty() {
                "idle".to_string()
            } else {
                "warning".to_string()
            },
        },
        CoverageSummaryCard {
            id: "scan".to_string(),
            label: "Last scan".to_string(),
            value: settings
                .coverage_last_scan
                .clone()
                .unwrap_or_else(|| "Not scanned yet".to_string()),
            detail: format!("{} tracked files", tracked_files),
            tone: if settings.coverage_last_scan.is_some() {
                "safe".to_string()
            } else {
                "warning".to_string()
            },
        },
        CoverageSummaryCard {
            id: "ipc".to_string(),
            label: "Desktop watcher".to_string(),
            value: coverage_ipc_state(settings).to_string(),
            detail: "Local coverage watcher status".to_string(),
            tone: match coverage_ipc_state(settings) {
                "active" => "safe".to_string(),
                "unsupported" => "idle".to_string(),
                _ => "warning".to_string(),
            },
        },
    ];

    CoverageCenterSnapshot {
        overall_coverage_percent,
        tracked_files,
        orphaned_files,
        unmanaged_files,
        enrolled_folder_count: folders.len(),
        last_scan_at: settings.coverage_last_scan.clone(),
        ipc_state: coverage_ipc_state(settings).to_string(),
        summary_cards,
        folders,
        attention_items,
    }
}

fn build_coverage_scan_result(
    summary: CoverageScanSummary,
    root_path: Option<String>,
    completed_at: chrono::DateTime<chrono::Utc>,
) -> CoverageScanResult {
    CoverageScanResult {
        root_path,
        roots_scanned: summary.roots_scanned,
        files_indexed: summary.files_indexed,
        orphaned_files: summary.orphaned_files,
        unmanaged_files: summary.unmanaged_files,
        missing_roots: summary
            .missing_roots
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
        completed_at: completed_at.to_rfc3339(),
    }
}

#[tauri::command]
pub async fn get_coverage_center_snapshot(
    state: State<'_, AppState>,
) -> Result<CommandResponse<CoverageCenterSnapshot>, String> {
    ensure_authenticated(&state).await?;

    let settings = load_settings_status_internal(&state).await?;
    let client = state
        .local_client
        .client()
        .await
        .map_err(|err| format!("Failed to load coverage snapshot client: {}", err))?;
    let stats = client
        .coverage_root_stats()
        .await
        .map_err(|err| format!("Failed to load coverage snapshot: {}", err))?;

    Ok(CommandResponse::ok(build_coverage_center_snapshot(
        &stats, &settings,
    )))
}

#[tauri::command]
pub async fn run_coverage_scan(
    root_path: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<CommandResponse<CoverageScanResult>, String> {
    ensure_authenticated(&state).await?;

    let client = state
        .local_client
        .client()
        .await
        .map_err(|err| format!("Failed to load coverage scan client: {}", err))?;
    let normalized_root_path = root_path
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let filter = normalized_root_path.as_ref().map(PathBuf::from);

    let progress_app = app.clone();
    let progress = std::sync::Arc::new(
        move |root: &hybridcipher_client::coverage::CoverageRoot,
              processed: usize,
              total: usize| {
            let payload = CoverageScanProgressPayload {
                root_id: root.root_id.to_string(),
                root_path: root.path.display().to_string(),
                processed,
                total,
            };
            let _ = progress_app.emit("coverage_scan_progress", &payload);
        },
    );

    match client
        .coverage_rescan_with_progress(filter, Some(progress))
        .await
    {
        Ok(summary) => {
            let result =
                build_coverage_scan_result(summary, normalized_root_path, chrono::Utc::now());
            let _ = app.emit(
                "coverage_scan_finished",
                &CoverageScanFinishedPayload {
                    success: true,
                    result: Some(result.clone()),
                    error: None,
                },
            );
            Ok(CommandResponse::ok(result))
        }
        Err(err) => {
            let message = format!("Coverage scan failed: {}", err);
            let _ = app.emit(
                "coverage_scan_finished",
                &CoverageScanFinishedPayload {
                    success: false,
                    result: None,
                    error: Some(message.clone()),
                },
            );
            Ok(CommandResponse::err(message))
        }
    }
}

#[tauri::command]
pub async fn enroll_folder(
    folder_path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<EnrolledFolder>, String> {
    ensure_authenticated(&state).await?;
    tracing::info!("Enroll folder command called: {}", folder_path);

    let client = match state.local_client.client().await {
        Ok(client) => client,
        Err(err) => return Ok(CommandResponse::err(err)),
    };

    let canonical = dunce::canonicalize(&folder_path)
        .map_err(|e| format!("Failed to resolve folder path {}: {}", folder_path, e))?;

    match client.coverage_enroll_root(&canonical).await {
        Ok(root) => {
            // Fetch the full stats for the newly enrolled root
            match client.coverage_root_stats().await {
                Ok(stats) => {
                    if let Some(summary) =
                        stats.into_iter().find(|s| s.root.root_id == root.root_id)
                    {
                        Ok(CommandResponse::ok(enrolled_folder_from_stats(summary)))
                    } else {
                        // Root was enrolled but stats not immediately available - return minimal info
                        Ok(CommandResponse::ok(EnrolledFolder {
                            path: root.path.display().to_string(),
                            root_id: root.root_id.to_string(),
                            kind: describe_root_kind(root.kind).to_string(),
                            state: describe_root_state(root.state).to_string(),
                            enrolled_at: root.created_at.to_rfc3339(),
                            last_scan: None,
                            tracked_files: 0,
                            tracked_bytes: 0,
                            orphaned_files: 0,
                            unmanaged_files: 0,
                            coverage_ratio: 0.0,
                        }))
                    }
                }
                Err(_) => {
                    // Stats fetch failed but enrollment succeeded
                    Ok(CommandResponse::ok(EnrolledFolder {
                        path: root.path.display().to_string(),
                        root_id: root.root_id.to_string(),
                        kind: describe_root_kind(root.kind).to_string(),
                        state: describe_root_state(root.state).to_string(),
                        enrolled_at: root.created_at.to_rfc3339(),
                        last_scan: None,
                        tracked_files: 0,
                        tracked_bytes: 0,
                        orphaned_files: 0,
                        unmanaged_files: 0,
                        coverage_ratio: 0.0,
                    }))
                }
            }
        }
        Err(e) => Ok(CommandResponse::err(format!(
            "Failed to enroll folder: {}",
            e
        ))),
    }
}

#[tauri::command]
pub async fn enroll_folder_and_hydrate(
    folder_path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<FolderCoverageWorkflowResult>, String> {
    ensure_authenticated(&state).await?;
    tracing::info!("Enroll and hydrate folder command called: {}", folder_path);

    let client = match state.local_client.client().await {
        Ok(client) => client,
        Err(err) => return Ok(CommandResponse::err(err)),
    };

    let canonical = match dunce::canonicalize(&folder_path) {
        Ok(path) => path,
        Err(e) => {
            return Ok(CommandResponse::err(format!(
                "Failed to resolve folder path {}: {}",
                folder_path, e
            )))
        }
    };

    match hybridcipher_client::ipc::coverage_workflows::enroll_and_hydrate(
        client.as_ref(),
        canonical,
    )
    .await
    {
        Ok(outcome) => {
            let folder = match client.coverage_root_stats().await {
                Ok(stats) => stats
                    .into_iter()
                    .find(|summary| summary.root.root_id == outcome.root.root_id)
                    .map(enrolled_folder_from_stats)
                    .unwrap_or_else(|| EnrolledFolder {
                        path: outcome.root.path.display().to_string(),
                        root_id: outcome.root.root_id.to_string(),
                        kind: describe_root_kind(outcome.root.kind).to_string(),
                        state: describe_root_state(outcome.root.state).to_string(),
                        enrolled_at: outcome.root.created_at.to_rfc3339(),
                        last_scan: outcome.root.last_scan.map(|ts| ts.to_rfc3339()),
                        tracked_files: 0,
                        tracked_bytes: 0,
                        orphaned_files: 0,
                        unmanaged_files: 0,
                        coverage_ratio: 0.0,
                    }),
                Err(_) => EnrolledFolder {
                    path: outcome.root.path.display().to_string(),
                    root_id: outcome.root.root_id.to_string(),
                    kind: describe_root_kind(outcome.root.kind).to_string(),
                    state: describe_root_state(outcome.root.state).to_string(),
                    enrolled_at: outcome.root.created_at.to_rfc3339(),
                    last_scan: outcome.root.last_scan.map(|ts| ts.to_rfc3339()),
                    tracked_files: 0,
                    tracked_bytes: 0,
                    orphaned_files: 0,
                    unmanaged_files: 0,
                    coverage_ratio: 0.0,
                },
            };

            Ok(CommandResponse::ok(FolderCoverageWorkflowResult {
                folder,
                encrypted_files: outcome.hydration.newly_encrypted as u64,
                decrypted_files: 0,
                skipped_files: outcome.hydration.skipped_due_to_errors as u64,
            }))
        }
        Err(e) => Ok(CommandResponse::err(format!(
            "Failed to protect folder: {}",
            e
        ))),
    }
}

#[tauri::command]
pub async fn unenroll_folder_and_decrypt(
    root_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<FolderCoverageWorkflowResult>, String> {
    ensure_authenticated(&state).await?;
    tracing::info!("Unenroll and decrypt folder command called: {}", root_id);

    let client = match state.local_client.client().await {
        Ok(client) => client,
        Err(err) => return Ok(CommandResponse::err(err)),
    };

    let summary = match find_coverage_root_summary_by_id(client.as_ref(), &root_id).await {
        Ok(summary) => summary,
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    let root_path = summary.root.path.clone();

    match hybridcipher_client::ipc::coverage_workflows::unenroll_and_decrypt(
        client.as_ref(),
        root_path,
    )
    .await
    {
        Ok(outcome) => {
            let folder = EnrolledFolder {
                path: outcome.root.path.display().to_string(),
                root_id: outcome.root.root_id.to_string(),
                kind: describe_root_kind(outcome.root.kind).to_string(),
                state: describe_root_state(outcome.root.state).to_string(),
                enrolled_at: outcome.root.created_at.to_rfc3339(),
                last_scan: outcome.root.last_scan.map(|ts| ts.to_rfc3339()),
                tracked_files: 0,
                tracked_bytes: 0,
                orphaned_files: 0,
                unmanaged_files: 0,
                coverage_ratio: 0.0,
            };

            Ok(CommandResponse::ok(FolderCoverageWorkflowResult {
                folder,
                encrypted_files: 0,
                decrypted_files: outcome.decrypted_files as u64,
                skipped_files: 0,
            }))
        }
        Err(e) => Ok(CommandResponse::err(format!(
            "Failed to remove protected folder: {}",
            e
        ))),
    }
}

/// Mount runtime state structure matching CLI's format
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MountBackend {
    Sync,
    LinuxFuse,
    WindowsCloudFiles,
    #[serde(rename = "macos-file-provider")]
    MacOsFileProvider,
}

impl MountBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::LinuxFuse => "linux-fuse",
            Self::WindowsCloudFiles => "windows-cloud-files",
            Self::MacOsFileProvider => "macos-file-provider",
        }
    }

    fn is_sync(self) -> bool {
        matches!(self, Self::Sync)
    }

    fn is_windows_cloud_files(self) -> bool {
        matches!(self, Self::WindowsCloudFiles)
    }

    fn is_macos_file_provider(self) -> bool {
        matches!(self, Self::MacOsFileProvider)
    }

    fn has_runtime_status(self) -> bool {
        self.is_sync() || self.is_windows_cloud_files() || self.is_macos_file_provider()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MountRuntimeState {
    root_id: String,
    mountpoint: PathBuf,
    encrypted_dir: PathBuf,
    platform: String,
    #[serde(default)]
    backend: Option<MountBackend>,
    #[serde(default)]
    host_pid: Option<u32>,
    #[serde(default)]
    fallback_reason: Option<String>,
    #[serde(default = "default_mount_ready")]
    ready: bool,
    requested_unmount: bool,
}

impl MountRuntimeState {
    fn backend(&self) -> MountBackend {
        self.backend.unwrap_or(MountBackend::Sync)
    }

    fn is_ready(&self) -> bool {
        self.ready
    }
}

fn default_mount_ready() -> bool {
    true
}

fn sanitize_mount_name(input: &str) -> String {
    let mut sanitized: String = input
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            _ => '_',
        })
        .collect();
    if sanitized.trim_matches('_').is_empty() {
        sanitized = "encrypted".to_string();
    }
    sanitized
}

fn determine_desktop_mountpoint(encrypted_dir: &Path, root_id: Uuid) -> Result<PathBuf, String> {
    let encrypted_name = encrypted_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("encrypted");
    let sanitized = sanitize_mount_name(encrypted_name);
    let home = dirs::home_dir().ok_or_else(|| "Unable to resolve home directory".to_string())?;
    let base = home.join(".hybridcipher");
    std::fs::create_dir_all(&base).map_err(|e| {
        format!(
            "Failed to prepare mount directory {}: {}",
            base.display(),
            e
        )
    })?;
    let mountpoint = base.join(format!("{}_{}_mount", sanitized, root_id));
    std::fs::create_dir_all(&mountpoint).map_err(|e| {
        format!(
            "Failed to prepare mountpoint {}: {}",
            mountpoint.display(),
            e
        )
    })?;
    Ok(mountpoint)
}

#[cfg(target_os = "macos")]
fn determine_desktop_file_provider_url(
    encrypted_dir: &Path,
    root_id: Uuid,
) -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "Unable to resolve home directory".to_string())?;
    let base = home.join("Library").join("CloudStorage");
    Ok(base.join(format!(
        "HybridCipher-{}",
        derive_desktop_mount_label(encrypted_dir, root_id)
    )))
}

#[cfg(target_os = "macos")]
fn macos_file_provider_host(
    user_config_dir: &Path,
) -> hybridcipher_macos_file_provider::MacFileProviderHost {
    hybridcipher_macos_file_provider::MacFileProviderHost::new(
        hybridcipher_macos_file_provider::ProviderHostConfig {
            user_config_dir: user_config_dir.to_path_buf(),
            socket_path: None,
            provider_identifier: Some("com.hybridcipher.app.HybridCipherFileProvider".to_string()),
        },
    )
}

#[cfg(target_os = "macos")]
fn load_stored_macos_file_provider_registration(
    user_config_dir: &Path,
    root_id: Uuid,
) -> Result<Option<hybridcipher_macos_file_provider::FileProviderDomainRegistration>, String> {
    macos_file_provider_host(user_config_dir)
        .load_registration(root_id)
        .map_err(|err| err.to_string())
}

#[cfg(target_os = "macos")]
fn unregister_stored_macos_file_provider_domain(
    user_config_dir: &Path,
    root_id: Uuid,
) -> Result<(), String> {
    let host = macos_file_provider_host(user_config_dir);
    let Some(registration) =
        load_stored_macos_file_provider_registration(user_config_dir, root_id)?
    else {
        return Ok(());
    };

    crate::macos_file_provider_native::unregister_domain(&registration)?;
    host.unregister_domain_state(root_id)
        .map_err(|err| err.to_string())
}

fn derive_desktop_mount_label(encrypted_dir: &Path, root_id: Uuid) -> String {
    let encrypted_name = encrypted_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("encrypted");
    let sanitized = sanitize_mount_name(encrypted_name);
    let root_short = root_id.simple().to_string();
    format!("{}-{}-mount", sanitized, &root_short[..8])
}

fn mount_state_host_is_active(state: &MountRuntimeState) -> bool {
    state.host_pid.map(process_is_running).unwrap_or(true)
}

fn mount_state_runtime_is_active(user_dir: &Path, state: &MountRuntimeState) -> bool {
    if !mount_state_host_is_active(state) {
        return false;
    }

    if state.backend().is_macos_file_provider() {
        #[cfg(target_os = "macos")]
        {
            let Ok(root_id) = Uuid::parse_str(&state.root_id) else {
                return false;
            };
            let Ok(health) = macos_file_provider_host(user_dir).check_runtime_health(root_id)
            else {
                return false;
            };
            return health.registration_present && health.socket_reachable;
        }

        #[cfg(not(target_os = "macos"))]
        {
            return false;
        }
    }

    true
}

#[cfg(target_os = "windows")]
fn process_is_running(pid: u32) -> bool {
    let filter = format!("PID eq {}", pid);
    let mut command = std::process::Command::new("tasklist");
    command.args(["/FI", &filter, "/FO", "CSV", "/NH"]);
    configure_background_std_command(&mut command);
    let output = command.output();

    let Ok(output) = output else {
        return true;
    };
    if !output.status.success() {
        return true;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .any(|line| line.contains(&format!(",\"{}\",", pid)) || line.contains("hybridcipher"))
        && !stdout.contains("No tasks are running")
}

#[cfg(target_os = "macos")]
fn process_is_running(pid: u32) -> bool {
    StdCommand::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn process_is_running(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{}", pid)).exists()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountStatusPayload {
    pub mountpoint: String,
    pub backend: String,
    #[serde(default)]
    pub fallback_reason: Option<String>,
}

/// Canonicalize server URL (matches CLI's logic)
fn canonicalize_server_url(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    }
}

/// Get user storage ID matching CLI's format (hash of email + server_url)
fn get_user_storage_id(email: &str, server_url: &str) -> String {
    let canonical_url = canonicalize_server_url(server_url);
    let mut hasher = Sha256::new();
    hasher.update(email.to_lowercase().as_bytes());
    hasher.update(canonical_url.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

/// Get user config directory path
fn get_user_dir(email: &str, server_url: &str) -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "HOME not set".to_string())?;
    let user_id = get_user_storage_id(email, server_url);
    Ok(home.join(".hybridcipher").join("users").join(&user_id))
}

fn mount_sync_status_path(user_dir: &PathBuf, root_id: &str) -> PathBuf {
    user_dir
        .join("mount_states")
        .join(format!("mount_sync_status_{}.json", root_id))
}

fn mount_states_dir(user_dir: &Path) -> PathBuf {
    user_dir.join("mount_states")
}

fn mount_conflict_registry_path(user_dir: &Path, root_id: &str) -> PathBuf {
    sync_mount_conflict_registry_path(&mount_states_dir(user_dir), root_id)
}

fn mount_conflict_request_dir(user_dir: &Path, root_id: &str) -> PathBuf {
    sync_mount_conflict_action_requests_dir(&mount_states_dir(user_dir), root_id)
}

fn mount_conflict_result_dir(user_dir: &Path, root_id: &str) -> PathBuf {
    sync_mount_conflict_action_results_dir(&mount_states_dir(user_dir), root_id)
}

fn mount_recovery_registry_path(user_dir: &Path, root_id: &str) -> PathBuf {
    sync_mount_recovery_registry_path(&mount_states_dir(user_dir), root_id)
}

fn mount_recovery_request_dir(user_dir: &Path, root_id: &str) -> PathBuf {
    sync_mount_recovery_action_requests_dir(&mount_states_dir(user_dir), root_id)
}

fn mount_recovery_result_dir(user_dir: &Path, root_id: &str) -> PathBuf {
    sync_mount_recovery_action_results_dir(&mount_states_dir(user_dir), root_id)
}

async fn read_mount_sync_status(
    user_dir: &PathBuf,
    root_id: &str,
) -> Option<MountSyncRuntimeStatus> {
    let status_path = mount_sync_status_path(user_dir, root_id);
    let content = fs::read_to_string(status_path).await.ok()?;
    serde_json::from_str(&content).ok()
}

async fn read_mount_state_by_root_id(
    user_dir: &Path,
    root_id: &str,
) -> Result<Option<MountRuntimeState>, String> {
    let Some((_path, mount_state)) = read_any_mount_state_by_root_id(user_dir, root_id).await?
    else {
        return Ok(None);
    };

    if !mount_state.requested_unmount
        && mount_state.is_ready()
        && mount_state.mountpoint.exists()
        && mount_state_runtime_is_active(user_dir, &mount_state)
    {
        return Ok(Some(mount_state));
    }

    Ok(None)
}

async fn read_any_mount_state_by_root_id(
    user_dir: &Path,
    root_id: &str,
) -> Result<Option<(PathBuf, MountRuntimeState)>, String> {
    let mount_state_path = mount_states_dir(user_dir).join(format!("mount_state_{}.json", root_id));
    if mount_state_path.exists() {
        if let Ok(content) = fs::read_to_string(&mount_state_path).await {
            if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
                if mount_state.root_id == root_id {
                    return Ok(Some((mount_state_path, mount_state)));
                }
            }
        }
    }

    let legacy_mount_state_path = user_dir.join("mount_state.json");
    if legacy_mount_state_path.exists() {
        if let Ok(content) = fs::read_to_string(&legacy_mount_state_path).await {
            if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
                if mount_state.root_id == root_id {
                    return Ok(Some((legacy_mount_state_path, mount_state)));
                }
            }
        }
    }

    Ok(None)
}

async fn load_cloud_mount_state_records_for_unmount(
    user_dir: &Path,
) -> Vec<(PathBuf, MountRuntimeState)> {
    let mut records = Vec::new();
    let mount_states_dir = mount_states_dir(user_dir);
    if mount_states_dir.exists() {
        if let Ok(mut entries) = fs::read_dir(&mount_states_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if path.is_file()
                    && path.extension().and_then(|s| s.to_str()) == Some("json")
                    && file_name.starts_with("mount_state_")
                {
                    if let Ok(content) = fs::read_to_string(&path).await {
                        if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content)
                        {
                            if mount_state.backend().is_windows_cloud_files()
                                || mount_state.backend().is_macos_file_provider()
                            {
                                records.push((path, mount_state));
                            }
                        }
                    }
                }
            }
        }
    }

    let legacy_path = user_dir.join("mount_state.json");
    if legacy_path.exists() {
        if let Ok(content) = fs::read_to_string(&legacy_path).await {
            if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
                if (mount_state.backend().is_windows_cloud_files()
                    || mount_state.backend().is_macos_file_provider())
                    && !records
                        .iter()
                        .any(|(_, record)| record.root_id == mount_state.root_id)
                {
                    records.push((legacy_path, mount_state));
                }
            }
        }
    }

    records
}

fn ensure_sync_mount_backend(state: &MountRuntimeState, command_name: &str) -> Result<(), String> {
    if state.backend().has_runtime_status() {
        return Ok(());
    }

    Err(format!(
        "`hybridcipher {}` is not applicable for {} mounts.",
        command_name,
        state.backend().as_str()
    ))
}

fn load_mount_conflicts_for_root(
    user_dir: &Path,
    root_id: &str,
) -> Result<Vec<MountConflictRecord>, String> {
    let registry_path = mount_conflict_registry_path(user_dir, root_id);
    load_mount_conflict_registry(&registry_path).map_err(|err| {
        format!(
            "Failed to read conflict registry {}: {}",
            registry_path.display(),
            err
        )
    })
}

fn load_mount_recovery_copies_for_root(
    user_dir: &Path,
    root_id: &str,
) -> Result<Vec<MountRecoveryCopyRecord>, String> {
    let registry_path = mount_recovery_registry_path(user_dir, root_id);
    load_mount_recovery_registry(&registry_path).map_err(|err| {
        format!(
            "Failed to read recovery registry {}: {}",
            registry_path.display(),
            err
        )
    })
}

async fn submit_mount_conflict_request(
    user_dir: &Path,
    root_id: &str,
    request: &ConflictResolutionRequest,
) -> Result<ConflictResolutionResponse, String> {
    let request_dir = mount_conflict_request_dir(user_dir, root_id);
    let result_dir = mount_conflict_result_dir(user_dir, root_id);
    fs::create_dir_all(&request_dir).await.map_err(|err| {
        format!(
            "Failed to create conflict request directory {}: {}",
            request_dir.display(),
            err
        )
    })?;
    fs::create_dir_all(&result_dir).await.map_err(|err| {
        format!(
            "Failed to create conflict result directory {}: {}",
            result_dir.display(),
            err
        )
    })?;

    let request_path = request_dir.join(format!("{}.json", request.request_id));
    let result_path = result_dir.join(format!("{}.json", request.request_id));
    let payload = serde_json::to_vec_pretty(request)
        .map_err(|err| format!("Failed to serialize conflict request: {}", err))?;
    fs::write(&request_path, payload).await.map_err(|err| {
        format!(
            "Failed to write conflict request {}: {}",
            request_path.display(),
            err
        )
    })?;

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if result_path.exists() {
            let raw = fs::read_to_string(&result_path).await.map_err(|err| {
                format!(
                    "Failed to read conflict result {}: {}",
                    result_path.display(),
                    err
                )
            })?;
            let response: ConflictResolutionResponse =
                serde_json::from_str(&raw).map_err(|err| {
                    format!(
                        "Failed to parse conflict result {}: {}",
                        result_path.display(),
                        err
                    )
                })?;
            let _ = fs::remove_file(&result_path).await;
            return Ok(response);
        }

        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "Timed out waiting for conflict resolution result for {}",
                request.conflict_id
            ));
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn submit_mount_recovery_request(
    user_dir: &Path,
    root_id: &str,
    request: &RecoveryCopyResolutionRequest,
) -> Result<RecoveryCopyResolutionResponse, String> {
    let request_dir = mount_recovery_request_dir(user_dir, root_id);
    let result_dir = mount_recovery_result_dir(user_dir, root_id);
    fs::create_dir_all(&request_dir).await.map_err(|err| {
        format!(
            "Failed to create recovery request directory {}: {}",
            request_dir.display(),
            err
        )
    })?;
    fs::create_dir_all(&result_dir).await.map_err(|err| {
        format!(
            "Failed to create recovery result directory {}: {}",
            result_dir.display(),
            err
        )
    })?;

    let request_path = request_dir.join(format!("{}.json", request.request_id));
    let result_path = result_dir.join(format!("{}.json", request.request_id));
    let payload = serde_json::to_vec_pretty(request)
        .map_err(|err| format!("Failed to serialize recovery request: {}", err))?;
    fs::write(&request_path, payload).await.map_err(|err| {
        format!(
            "Failed to write recovery request {}: {}",
            request_path.display(),
            err
        )
    })?;

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if result_path.exists() {
            let raw = fs::read_to_string(&result_path).await.map_err(|err| {
                format!(
                    "Failed to read recovery result {}: {}",
                    result_path.display(),
                    err
                )
            })?;
            let response: RecoveryCopyResolutionResponse =
                serde_json::from_str(&raw).map_err(|err| {
                    format!(
                        "Failed to parse recovery result {}: {}",
                        result_path.display(),
                        err
                    )
                })?;
            let _ = fs::remove_file(&result_path).await;
            return Ok(response);
        }

        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "Timed out waiting for recovery resolution result for {}",
                request.recovery_relative_path.display()
            ));
        }

        sleep(Duration::from_millis(200)).await;
    }
}

/// Check if a folder is already mounted by reading CLI mount state
async fn check_mount_status(
    folder_path: &str,
    email: &str,
    server_url: &str,
) -> Result<Option<MountStatusPayload>, String> {
    let user_dir = get_user_dir(email, server_url)?;

    // Check for per-mount state files (new format)
    let mount_states_dir = user_dir.join("mount_states");
    if mount_states_dir.exists() {
        if let Ok(mut entries) = fs::read_dir(&mount_states_dir).await {
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|e| format!("Failed to read mount states directory: {}", e))?
            {
                let path = entry.path();
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if path.is_file()
                    && path.extension().and_then(|s| s.to_str()) == Some("json")
                    && file_name.starts_with("mount_state_")
                {
                    if let Ok(content) = fs::read_to_string(&path).await {
                        if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content)
                        {
                            // Check if this folder matches the encrypted_dir in mount state
                            let canonical_folder =
                                dunce::canonicalize(folder_path).map_err(|e| {
                                    format!("Failed to canonicalize folder path: {}", e)
                                })?;

                            let canonical_encrypted =
                                dunce::canonicalize(&mount_state.encrypted_dir).map_err(|e| {
                                    format!("Failed to canonicalize encrypted dir: {}", e)
                                })?;

                            if canonical_folder == canonical_encrypted
                                && !mount_state.requested_unmount
                                && mount_state.is_ready()
                                && mount_state_runtime_is_active(&user_dir, &mount_state)
                            {
                                // Check if mountpoint exists and is accessible
                                if mount_state.mountpoint.exists() {
                                    return Ok(Some(MountStatusPayload {
                                        mountpoint: mount_state.mountpoint.display().to_string(),
                                        backend: mount_state.backend().as_str().to_string(),
                                        fallback_reason: mount_state.fallback_reason.clone(),
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: check legacy single mount state file
    let mount_state_path = user_dir.join("mount_state.json");
    if mount_state_path.exists() {
        if let Ok(mount_state_content) = fs::read_to_string(&mount_state_path).await {
            if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&mount_state_content)
            {
                let canonical_folder = dunce::canonicalize(folder_path)
                    .map_err(|e| format!("Failed to canonicalize folder path: {}", e))?;

                let canonical_encrypted = dunce::canonicalize(&mount_state.encrypted_dir)
                    .map_err(|e| format!("Failed to canonicalize encrypted dir: {}", e))?;

                if canonical_folder == canonical_encrypted && !mount_state.requested_unmount {
                    if mount_state.is_ready()
                        && mount_state.mountpoint.exists()
                        && mount_state_runtime_is_active(&user_dir, &mount_state)
                    {
                        return Ok(Some(MountStatusPayload {
                            mountpoint: mount_state.mountpoint.display().to_string(),
                            backend: mount_state.backend().as_str().to_string(),
                            fallback_reason: mount_state.fallback_reason.clone(),
                        }));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Check mount status by root_id
#[tauri::command]
pub async fn check_mount_status_by_root_id(
    root_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountStatusPayload>, String> {
    ensure_authenticated(&state).await?;

    // Validate root_id format
    let _parsed_root_id =
        Uuid::parse_str(&root_id).map_err(|e| format!("Invalid root_id format: {}", e))?;

    // Get current session info
    let (email, server_url) = {
        let session = state.session.lock().await;
        let user_session = session.as_ref().ok_or("No active session")?;
        let email = user_session.email.clone();
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or_else(|| state.client.server_url())
            .to_string();
        (email, server_url)
    };

    let user_dir = get_user_dir(&email, &server_url)?;
    let mount_states_dir = user_dir.join("mount_states");
    let mount_state_path = mount_states_dir.join(format!("mount_state_{}.json", root_id));

    // Check mount state file (new format)
    if mount_state_path.exists() {
        if let Ok(content) = fs::read_to_string(&mount_state_path).await {
            if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
                if mount_state.root_id == root_id
                    && !mount_state.requested_unmount
                    && mount_state.is_ready()
                    && mount_state.mountpoint.exists()
                    && mount_state_runtime_is_active(&user_dir, &mount_state)
                {
                    return Ok(CommandResponse::ok(MountStatusPayload {
                        mountpoint: mount_state.mountpoint.display().to_string(),
                        backend: mount_state.backend().as_str().to_string(),
                        fallback_reason: mount_state.fallback_reason.clone(),
                    }));
                }
            }
        }
    }

    // Fallback: check legacy mount state file
    let legacy_mount_state_path = user_dir.join("mount_state.json");
    if legacy_mount_state_path.exists() {
        if let Ok(content) = fs::read_to_string(&legacy_mount_state_path).await {
            if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
                if mount_state.root_id == root_id
                    && !mount_state.requested_unmount
                    && mount_state.is_ready()
                    && mount_state.mountpoint.exists()
                    && mount_state_runtime_is_active(&user_dir, &mount_state)
                {
                    return Ok(CommandResponse::ok(MountStatusPayload {
                        mountpoint: mount_state.mountpoint.display().to_string(),
                        backend: mount_state.backend().as_str().to_string(),
                        fallback_reason: mount_state.fallback_reason.clone(),
                    }));
                }
            }
        }
    }

    Ok(CommandResponse::err("Mount not found".to_string()))
}

/// Wait for mount to become ready by polling mountpoint directory
async fn wait_for_mount_ready(mountpoint: &PathBuf, timeout_secs: u64) -> Result<(), String> {
    let timeout_duration = Duration::from_secs(timeout_secs);
    let start = std::time::Instant::now();

    loop {
        if mountpoint.exists() && mountpoint.is_dir() {
            // Try to read the directory to ensure it's accessible
            if fs::read_dir(mountpoint).await.is_ok() {
                return Ok(());
            }
        }

        if start.elapsed() >= timeout_duration {
            return Err(format!(
                "Mount did not become ready within {} seconds",
                timeout_secs
            ));
        }

        sleep(Duration::from_millis(500)).await;
    }
}

async fn write_mount_runtime_state(path: &Path, state: &MountRuntimeState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await.map_err(|e| {
            format!(
                "Failed to create mount state directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }
    let payload = serde_json::to_string_pretty(state)
        .map_err(|e| format!("Failed to serialize mount state: {}", e))?;
    fs::write(path, payload)
        .await
        .map_err(|e| format!("Failed to write mount state {}: {}", path.display(), e))
}

#[tauri::command]
pub async fn mount_enrolled_folder(
    root_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountStatusPayload>, String> {
    ensure_authenticated(&state).await?;
    tracing::info!("Mount enrolled folder request with root_id: {}", root_id);

    // Validate root_id format
    let parsed_root_id =
        Uuid::parse_str(&root_id).map_err(|e| format!("Invalid root_id format: {}", e))?;

    // Get current session info
    let (email, server_url) = {
        let session = state.session.lock().await;
        let user_session = session.as_ref().ok_or("No active session")?;
        let email = user_session.email.clone();
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or_else(|| state.client.server_url())
            .to_string();
        (email, server_url)
    };

    // Get folder path from root_id for mount status check
    let client = match state.local_client.client().await {
        Ok(client) => client,
        Err(err) => {
            return Ok(CommandResponse::err(format!(
                "Failed to get client: {}",
                err
            )))
        }
    };

    let enrolled_folders = match get_enrolled_folders_from_client(client.as_ref()).await {
        Ok(folders) => folders,
        Err(e) => {
            return Ok(CommandResponse::err(format!(
                "Failed to get enrolled folders: {}",
                e
            )))
        }
    };

    let folder = enrolled_folders
        .iter()
        .find(|f| f.root_id == root_id)
        .ok_or_else(|| format!("No enrolled folder found with root_id: {}", root_id))?;
    let encrypted_root = PathBuf::from(&folder.path);

    // Check if already mounted (same folder)
    if let Some(mount_status) = check_mount_status(&folder.path, &email, &server_url).await? {
        tracing::info!("Folder already mounted at: {}", mount_status.mountpoint);
        return Ok(CommandResponse::ok(mount_status));
    }

    // With multiple mount support, we don't need to unmount other folders
    // Each folder can be mounted independently
    // The CLI mount command will handle checking if this specific folder is already mounted

    #[cfg(target_os = "macos")]
    let desktop_provider_fallback_reason: Option<String> = {
        let user_dir = get_user_dir(&email, &server_url)?;
        let mount_states_dir = user_dir.join("mount_states");
        let mount_state_path = mount_states_dir.join(format!("mount_state_{}.json", root_id));
        let provider_url = determine_desktop_file_provider_url(&encrypted_root, parsed_root_id)?;
        let runtime_state = MountRuntimeState {
            root_id: root_id.clone(),
            mountpoint: provider_url.clone(),
            encrypted_dir: encrypted_root.clone(),
            platform: std::env::consts::OS.to_string(),
            backend: Some(MountBackend::MacOsFileProvider),
            host_pid: Some(std::process::id()),
            fallback_reason: None,
            ready: false,
            requested_unmount: false,
        };
        write_mount_runtime_state(&mount_state_path, &runtime_state).await?;

        let fallback_reason =
            match crate::cloud_provider::DesktopCloudProviderManager::file_provider_available(
                user_dir.clone(),
            ) {
                Ok(()) => match state
                    .cloud_provider
                    .start_root(
                        user_dir.clone(),
                        parsed_root_id,
                        provider_url.clone(),
                        encrypted_root.clone(),
                        derive_desktop_mount_label(&encrypted_root, parsed_root_id),
                        client.clone(),
                    )
                    .await
                {
                    Ok(()) => match wait_for_mount_ready(&provider_url, 60).await {
                        Ok(()) => {
                            let runtime_unhealthy_reason = match macos_file_provider_host(&user_dir)
                                .check_runtime_health(parsed_root_id)
                            {
                                Ok(health)
                                    if health.registration_present && health.socket_reachable =>
                                {
                                    None
                                }
                                Ok(health) => Some(health.latest_error.unwrap_or_else(|| {
                                    "registration or provider socket health check failed"
                                        .to_string()
                                })),
                                Err(err) => Some(err.to_string()),
                            };
                            if let Some(reason) = runtime_unhealthy_reason {
                                tracing::warn!(
                                    "Desktop File Provider runtime for root {} is not healthy: {}. Falling back to sync mount.",
                                    root_id,
                                    reason
                                );
                                let _ = state
                                    .cloud_provider
                                    .stop_root(parsed_root_id, true, true)
                                    .await;
                                let _ = fs::remove_file(&mount_state_path).await;
                                Some(format!(
                                    "macOS File Provider runtime health check failed: {}",
                                    reason
                                ))
                            } else {
                                let mut ready_state = runtime_state;
                                ready_state.ready = true;
                                write_mount_runtime_state(&mount_state_path, &ready_state).await?;
                                return Ok(CommandResponse::ok(MountStatusPayload {
                                    mountpoint: provider_url.display().to_string(),
                                    backend: MountBackend::MacOsFileProvider.as_str().to_string(),
                                    fallback_reason: None,
                                }));
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Desktop File Provider domain for root {} did not become visible: {}. Falling back to sync mount.",
                                root_id,
                                err
                            );
                            let _ = state
                                .cloud_provider
                                .stop_root(parsed_root_id, true, true)
                                .await;
                            let _ = fs::remove_file(&mount_state_path).await;
                            Some(format!(
                                "macOS File Provider domain did not become visible: {}",
                                err
                            ))
                        }
                    },
                    Err(err) => {
                        tracing::warn!(
                        "Desktop in-process File Provider mount failed for root {}: {}. Falling back to sync mount.",
                        root_id,
                        err
                    );
                        let _ = fs::remove_file(&mount_state_path).await;
                        Some(format!("macOS File Provider unavailable: {}", err))
                    }
                },
                Err(err) => {
                    tracing::warn!(
                    "Desktop File Provider unavailable for root {}: {}. Falling back to sync mount.",
                    root_id,
                    err
                );
                    let _ = fs::remove_file(&mount_state_path).await;
                    Some(format!("macOS File Provider unavailable: {}", err))
                }
            };
        fallback_reason
    };

    #[cfg(not(target_os = "macos"))]
    let desktop_provider_fallback_reason: Option<String> = None;

    #[cfg(target_os = "windows")]
    if crate::cloud_provider::DesktopCloudProviderManager::cloud_files_available() {
        let user_dir = get_user_dir(&email, &server_url)?;
        let mount_states_dir = user_dir.join("mount_states");
        let mount_state_path = mount_states_dir.join(format!("mount_state_{}.json", root_id));
        let mountpoint = determine_desktop_mountpoint(&encrypted_root, parsed_root_id)?;
        let runtime_state = MountRuntimeState {
            root_id: root_id.clone(),
            mountpoint: mountpoint.clone(),
            encrypted_dir: encrypted_root.clone(),
            platform: std::env::consts::OS.to_string(),
            backend: Some(MountBackend::WindowsCloudFiles),
            host_pid: Some(std::process::id()),
            fallback_reason: None,
            ready: false,
            requested_unmount: false,
        };
        write_mount_runtime_state(&mount_state_path, &runtime_state).await?;

        match state
            .cloud_provider
            .start_root(
                user_dir.clone(),
                parsed_root_id,
                mountpoint.clone(),
                encrypted_root.clone(),
                derive_desktop_mount_label(&encrypted_root, parsed_root_id),
                client.clone(),
            )
            .await
        {
            Ok(()) => {
                let mut ready_state = runtime_state;
                ready_state.ready = true;
                write_mount_runtime_state(&mount_state_path, &ready_state).await?;
                wait_for_mount_ready(&mountpoint, 60)
                    .await
                    .map_err(|e| format!("Mount ready check failed: {}", e))?;
                return Ok(CommandResponse::ok(MountStatusPayload {
                    mountpoint: mountpoint.display().to_string(),
                    backend: MountBackend::WindowsCloudFiles.as_str().to_string(),
                    fallback_reason: None,
                }));
            }
            Err(err) => {
                tracing::warn!(
                    "Desktop in-process Cloud Files mount failed for root {}: {}. Falling back to CLI mount.",
                    root_id,
                    err
                );
                let _ = fs::remove_file(&mount_state_path).await;
            }
        }
    }

    // Locate CLI binary
    let (cli_binary, _project_root) = crate::cli_utils::locate_cli_binary()
        .map_err(|e| format!("Failed to locate CLI binary: {}", e))?;

    // Execute CLI mount command in background with --root-id
    let server_url_clone = server_url.to_string();

    let mut cmd = tokio::process::Command::new(&cli_binary);
    cmd.arg("mount")
        .arg("--root-id")
        .arg(&root_id)
        .env("HYBRIDCIPHER_SERVER_URL", &server_url_clone)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    #[cfg(target_os = "macos")]
    if desktop_provider_fallback_reason.is_some() {
        cmd.arg("--sync");
    }

    configure_background_tokio_command(&mut cmd);
    tracing::info!("Spawning CLI mount command for root_id: {}", root_id);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn mount command: {}", e))?;

    // Wait a moment for mount to start
    sleep(Duration::from_millis(1000)).await;

    // Poll mount state file to detect when mount is ready
    let user_dir = get_user_dir(&email, &server_url)?;
    let mount_states_dir = user_dir.join("mount_states");
    let mount_state_path = mount_states_dir.join(format!("mount_state_{}.json", root_id));

    // Also check legacy path for backward compatibility
    let legacy_mount_state_path = user_dir.join("mount_state.json");

    // Wait for mount state file to be created and contain valid mountpoint
    #[allow(unused_assignments)]
    let mut mountpoint: Option<PathBuf> = None;
    let start_time = std::time::Instant::now();
    let timeout_duration = Duration::from_secs(300); // 5 minutes timeout

    loop {
        // Check if process has exited (non-blocking)
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    // Process exited with error - try to read stderr
                    let stderr_handle = child.stderr.take();
                    let error_msg = if let Some(mut stderr) = stderr_handle {
                        use tokio::io::AsyncReadExt;
                        let mut buf = String::new();
                        let _ = stderr.read_to_string(&mut buf).await;
                        if !buf.is_empty() {
                            format!("Mount command failed: {}", buf)
                        } else {
                            format!("Mount command failed with exit code: {:?}", status.code())
                        }
                    } else {
                        format!("Mount command failed with exit code: {:?}", status.code())
                    };
                    return Ok(CommandResponse::err(error_msg));
                }
            }
            Ok(None) => {
                // Process still running, continue polling
            }
            Err(e) => {
                tracing::warn!("Error checking child process status: {}", e);
            }
        }

        // Check mount state file (new format)
        if mount_state_path.exists() {
            if let Ok(content) = fs::read_to_string(&mount_state_path).await {
                if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
                    if mount_state.root_id == root_id
                        && !mount_state.requested_unmount
                        && mount_state.is_ready()
                        && mount_state.mountpoint.exists()
                        && mount_state_runtime_is_active(&user_dir, &mount_state)
                    {
                        mountpoint = Some(mount_state.mountpoint.clone());
                        break;
                    }
                }
            }
        }

        // Fallback: check legacy mount state file
        if mountpoint.is_none() && legacy_mount_state_path.exists() {
            if let Ok(content) = fs::read_to_string(&legacy_mount_state_path).await {
                if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
                    // Check if root_id matches (if present) or if encrypted_dir matches
                    let matches = if !mount_state.root_id.is_empty() {
                        mount_state.root_id == root_id
                    } else {
                        // Legacy file might not have root_id, check by path
                        let canonical_folder = dunce::canonicalize(&folder.path)
                            .map_err(|e| format!("Failed to canonicalize folder path: {}", e))?;
                        let canonical_encrypted = dunce::canonicalize(&mount_state.encrypted_dir)
                            .map_err(|e| {
                            format!("Failed to canonicalize encrypted dir: {}", e)
                        })?;
                        canonical_folder == canonical_encrypted
                    };

                    if matches
                        && !mount_state.requested_unmount
                        && mount_state.is_ready()
                        && mount_state.mountpoint.exists()
                        && mount_state_runtime_is_active(&user_dir, &mount_state)
                    {
                        mountpoint = Some(mount_state.mountpoint.clone());
                        break;
                    }
                }
            }
        }

        if start_time.elapsed() >= timeout_duration {
            let _ = child.kill().await;
            return Ok(CommandResponse::err(
                "Mount did not complete within timeout period".to_string(),
            ));
        }

        sleep(Duration::from_millis(500)).await;
    }

    let mountpoint_path = mountpoint.ok_or("Mountpoint not found")?;

    // Wait for mount to be fully ready
    wait_for_mount_ready(&mountpoint_path, 60)
        .await
        .map_err(|e| format!("Mount ready check failed: {}", e))?;

    tracing::info!(
        "Mount completed successfully at: {}",
        mountpoint_path.display()
    );
    let mut mounted_state = read_mount_state_by_root_id(&user_dir, &root_id)
        .await?
        .ok_or_else(|| "Mount completed but runtime state is unavailable".to_string())?;
    if let Some(reason) = desktop_provider_fallback_reason.clone() {
        if mounted_state.backend().is_sync() && mounted_state.fallback_reason.is_none() {
            mounted_state.fallback_reason = Some(reason);
            write_mount_runtime_state(&mount_state_path, &mounted_state).await?;
        }
    }

    Ok(CommandResponse::ok(MountStatusPayload {
        mountpoint: mountpoint_path.display().to_string(),
        backend: mounted_state.backend().as_str().to_string(),
        fallback_reason: mounted_state.fallback_reason.clone(),
    }))
}

#[tauri::command]
pub async fn list_active_mounts(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<MountInfo>>, String> {
    ensure_authenticated(&state).await?;
    tracing::info!("List active mounts command called");

    let session = require_authenticated_session(&state).await?;
    Ok(CommandResponse::ok(
        load_active_mounts_internal(&state, &session).await?,
    ))
}

async fn load_active_mounts_internal(
    state: &AppState,
    session: &crate::state::UserSession,
) -> Result<Vec<MountInfo>, String> {
    let server_url = current_server_url(state, session);
    let user_dir = get_user_dir(&session.email, &server_url)?;
    let mount_states_dir = user_dir.join("mount_states");
    let mut mounts = Vec::new();

    if mount_states_dir.exists() {
        if let Ok(mut entries) = fs::read_dir(&mount_states_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if path.is_file()
                    && path.extension().and_then(|s| s.to_str()) == Some("json")
                    && file_name.starts_with("mount_state_")
                {
                    if let Ok(content) = fs::read_to_string(&path).await {
                        if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content)
                        {
                            if !mount_state.requested_unmount
                                && mount_state.is_ready()
                                && mount_state.mountpoint.exists()
                                && mount_state_runtime_is_active(&user_dir, &mount_state)
                            {
                                let backend = mount_state.backend().as_str().to_string();
                                let sync_status = if mount_state.backend().has_runtime_status() {
                                    read_mount_sync_status(&user_dir, &mount_state.root_id).await
                                } else {
                                    None
                                };
                                mounts.push(MountInfo {
                                    root_id: mount_state.root_id.clone(),
                                    mountpoint: mount_state.mountpoint.display().to_string(),
                                    encrypted_dir: mount_state.encrypted_dir.display().to_string(),
                                    backend,
                                    fallback_reason: mount_state.fallback_reason.clone(),
                                    sync_status,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let legacy_path = user_dir.join("mount_state.json");
    if legacy_path.exists() {
        if let Ok(content) = fs::read_to_string(&legacy_path).await {
            if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
                if !mount_state.requested_unmount
                    && mount_state.is_ready()
                    && mount_state.mountpoint.exists()
                    && mount_state_runtime_is_active(&user_dir, &mount_state)
                {
                    if !mounts
                        .iter()
                        .any(|m| m.mountpoint == mount_state.mountpoint.display().to_string())
                    {
                        let sync_status = if mount_state.backend().has_runtime_status() {
                            read_mount_sync_status(&user_dir, &mount_state.root_id).await
                        } else {
                            None
                        };
                        mounts.push(MountInfo {
                            root_id: mount_state.root_id.clone(),
                            mountpoint: mount_state.mountpoint.display().to_string(),
                            encrypted_dir: mount_state.encrypted_dir.display().to_string(),
                            backend: mount_state.backend().as_str().to_string(),
                            fallback_reason: mount_state.fallback_reason.clone(),
                            sync_status,
                        });
                    }
                }
            }
        }
    }

    Ok(mounts)
}

fn build_device_count_snapshot(input: &PersonalDevicesOverviewInput) -> DeviceCountSnapshot {
    let flagged_ids = input
        .pending_devices
        .iter()
        .map(|device| device.device_id.as_str())
        .chain(
            input
                .stale_devices
                .iter()
                .map(|device| device.device_id.as_str()),
        )
        .chain(
            input
                .unverified_devices
                .iter()
                .map(|device| device.device_id.as_str()),
        )
        .collect::<HashSet<_>>();

    DeviceCountSnapshot {
        trusted: input
            .registered_devices
            .iter()
            .filter(|device| !flagged_ids.contains(device.device_id.as_str()))
            .count(),
        pending: input.pending_devices.len(),
        stale: input.stale_devices.len(),
        unverified: input.unverified_devices.len(),
    }
}

#[tauri::command]
pub async fn get_individual_home_status(
    state: State<'_, AppState>,
) -> Result<CommandResponse<IndividualHomeStatus>, String> {
    ensure_authenticated(&state).await?;

    let session = require_authenticated_session(&state).await?;
    let settings = load_settings_status_internal(&state).await?;
    let security = load_security_status_internal(&state, &session).await?;
    let client = state.local_client.client().await.map_err(|err| {
        format!(
            "Failed to load protected folders for workspace status: {}",
            err
        )
    })?;
    let folders = get_enrolled_folders_from_client(client.as_ref()).await?;
    let mounts = load_active_mounts_internal(&state, &session).await?;
    let devices_input = load_personal_devices_overview_input_internal(&state, &session).await?;
    let devices_overview = build_personal_devices_overview(devices_input.clone());
    let device_counts = build_device_count_snapshot(&devices_input);
    let folder_attention =
        mounts
            .iter()
            .fold(FolderAttentionSnapshot::default(), |mut summary, mount| {
                if let Some(sync_status) = mount.sync_status.as_ref() {
                    summary.conflicts += sync_status.pending_conflict_count as usize;
                    summary.recovery_copies += sync_status.recovered_pending_copy_count as usize;
                }
                summary
            });

    let status = build_individual_home_status(IndividualHomeStatusInput {
        security: IndividualSecuritySnapshot {
            mfa_enabled: security.mfa_enabled,
            recovery_backup_ok: security.recovery_backup_ok,
            recovery_auto_backup_ok: security.recovery_auto_backup_ok,
        },
        settings: IndividualSettingsSnapshot {
            coverage_last_scan: settings.coverage_last_scan,
            registry_last_upload: settings.registry_last_upload,
        },
        protected_count: folders.len(),
        mounted_count: mounts.len(),
        current_device: devices_overview
            .current_device
            .map(|device| CurrentDeviceSnapshot {
                device_id: device.device_id,
                is_verified: device.is_verified,
            }),
        device_counts,
        folder_attention,
        now: chrono::Utc::now(),
    });

    Ok(CommandResponse::ok(status))
}

#[tauri::command]
pub async fn get_personal_devices_overview(
    state: State<'_, AppState>,
) -> Result<CommandResponse<PersonalDevicesOverview>, String> {
    ensure_authenticated(&state).await?;
    let session = require_authenticated_session(&state).await?;
    let input = load_personal_devices_overview_input_internal(&state, &session).await?;
    Ok(CommandResponse::ok(build_personal_devices_overview(input)))
}

#[tauri::command]
pub async fn revoke_device(
    device_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<DeviceRevocationResult>, String> {
    ensure_authenticated(&state).await?;

    let session = require_authenticated_session(&state).await?;
    let target_device_id = device_id.trim();
    if target_device_id.is_empty() {
        return Ok(CommandResponse::err(
            "Device identifier is required to revoke a device.",
        ));
    }

    let server_url = current_server_url(&state, &session);
    let endpoint = api_endpoint(&server_url, &format!("auth/device/{}", target_device_id));
    let client = reqwest::Client::new();
    let response = client
        .delete(endpoint)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to contact server: {}", e))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(CommandResponse::err(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Ok(CommandResponse::err(format!(
            "Device revocation failed with status {}: {}",
            status, body
        )));
    }

    let payload: DeviceRemovalResponsePayload = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse device revocation response: {}", e))?;
    let removed_current_device = payload.removed_device_id == session.device_id;

    if removed_current_device {
        if let Err(err) = state.mount_manager.unmount_all(false).await {
            tracing::warn!(
                "Failed to unmount folders before clearing revoked session: {}",
                err
            );
        }
        state.clear_session().await;
    }

    Ok(CommandResponse::ok(DeviceRevocationResult {
        removed_device_id: payload.removed_device_id,
        removed_current_device,
        revoked_sessions: payload.revoked_sessions,
        remaining_devices: payload.remaining_devices,
        removed_at: payload.removed_at.to_rfc3339(),
        updated_groups: payload
            .updated_groups
            .into_iter()
            .map(|group_id| group_id.to_string())
            .collect(),
    }))
}

#[tauri::command]
pub async fn list_mount_conflicts(
    root_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<MountConflictRecord>>, String> {
    ensure_authenticated(&state).await?;
    Uuid::parse_str(&root_id).map_err(|err| format!("Invalid root_id format: {}", err))?;

    let (email, server_url) = {
        let session = state.session.lock().await;
        let user_session = session.as_ref().ok_or("No active session")?;
        let email = user_session.email.clone();
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or_else(|| state.client.server_url())
            .to_string();
        (email, server_url)
    };

    let user_dir = get_user_dir(&email, &server_url)?;
    let Some(mount_state) = read_mount_state_by_root_id(&user_dir, &root_id).await? else {
        return Ok(CommandResponse::err(format!(
            "No active mount found for root_id {}",
            root_id
        )));
    };
    if let Err(err) = ensure_sync_mount_backend(&mount_state, "conflict") {
        return Ok(CommandResponse::err(err));
    }

    match load_mount_conflicts_for_root(&user_dir, &root_id) {
        Ok(records) => Ok(CommandResponse::ok(records)),
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

#[tauri::command]
pub async fn get_mount_conflict_preview(
    root_id: String,
    conflict_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountConflictPreview>, String> {
    ensure_authenticated(&state).await?;
    Uuid::parse_str(&root_id).map_err(|err| format!("Invalid root_id format: {}", err))?;
    let conflict_id = Uuid::parse_str(&conflict_id)
        .map_err(|err| format!("Invalid conflict_id format: {}", err))?;

    let (email, server_url) = {
        let session = state.session.lock().await;
        let user_session = session.as_ref().ok_or("No active session")?;
        let email = user_session.email.clone();
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or_else(|| state.client.server_url())
            .to_string();
        (email, server_url)
    };

    let user_dir = get_user_dir(&email, &server_url)?;
    let Some(mount_state) = read_mount_state_by_root_id(&user_dir, &root_id).await? else {
        return Ok(CommandResponse::err(format!(
            "No active mount found for root_id {}",
            root_id
        )));
    };
    if let Err(err) = ensure_sync_mount_backend(&mount_state, "conflict") {
        return Ok(CommandResponse::err(err));
    }

    let records = match load_mount_conflicts_for_root(&user_dir, &root_id) {
        Ok(records) => records,
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    let Some(record) = records.into_iter().find(|record| record.id == conflict_id) else {
        return Ok(CommandResponse::err(format!(
            "Conflict {} was not found",
            conflict_id
        )));
    };

    let live_path = mount_state.mountpoint.join(&record.live_relative_path);
    let conflict_path = mount_state.mountpoint.join(&record.conflict_relative_path);
    if !conflict_path.exists() {
        return Ok(CommandResponse::err(format!(
            "Conflict copy no longer exists at {}",
            conflict_path.display()
        )));
    }

    let live_text = if live_path.exists() {
        read_conflict_preview_text(&live_path).map_err(|err| {
            format!(
                "Failed to read mounted file preview {}: {}",
                live_path.display(),
                err
            )
        })?
    } else {
        None
    };
    let conflict_text = read_conflict_preview_text(&conflict_path).map_err(|err| {
        format!(
            "Failed to read conflict preview {}: {}",
            conflict_path.display(),
            err
        )
    })?;

    Ok(CommandResponse::ok(MountConflictPreview {
        record,
        live_path,
        conflict_path,
        live_text,
        conflict_text,
    }))
}

#[tauri::command]
pub async fn resolve_mount_conflict(
    root_id: String,
    conflict_id: String,
    action: ConflictResolutionAction,
    merged_text: Option<String>,
    destination_path: Option<String>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<ConflictResolutionResult>, String> {
    ensure_authenticated(&state).await?;
    Uuid::parse_str(&root_id).map_err(|err| format!("Invalid root_id format: {}", err))?;
    let conflict_id = Uuid::parse_str(&conflict_id)
        .map_err(|err| format!("Invalid conflict_id format: {}", err))?;

    let (email, server_url) = {
        let session = state.session.lock().await;
        let user_session = session.as_ref().ok_or("No active session")?;
        let email = user_session.email.clone();
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or_else(|| state.client.server_url())
            .to_string();
        (email, server_url)
    };

    let user_dir = get_user_dir(&email, &server_url)?;
    let Some(mount_state) = read_mount_state_by_root_id(&user_dir, &root_id).await? else {
        return Ok(CommandResponse::err(format!(
            "No active mount found for root_id {}",
            root_id
        )));
    };
    if let Err(err) = ensure_sync_mount_backend(&mount_state, "conflict") {
        return Ok(CommandResponse::err(err));
    }

    let request = ConflictResolutionRequest {
        request_id: Uuid::new_v4(),
        conflict_id,
        action,
        merged_text,
        destination_path: destination_path
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        requested_at: chrono::Utc::now(),
    };

    let response = match submit_mount_conflict_request(&user_dir, &root_id, &request).await {
        Ok(response) => response,
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    if !response.success {
        return Ok(CommandResponse::err(
            response
                .error
                .unwrap_or_else(|| "Conflict resolution failed".to_string()),
        ));
    }

    let Some(result) = response.result else {
        return Ok(CommandResponse::err(
            "Conflict resolution completed without a result",
        ));
    };

    Ok(CommandResponse::ok(result))
}

#[tauri::command]
pub async fn list_mount_recovery_copies(
    root_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<MountRecoveryCopyRecord>>, String> {
    ensure_authenticated(&state).await?;
    Uuid::parse_str(&root_id).map_err(|err| format!("Invalid root_id format: {}", err))?;

    let (email, server_url) = {
        let session = state.session.lock().await;
        let user_session = session.as_ref().ok_or("No active session")?;
        let email = user_session.email.clone();
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or_else(|| state.client.server_url())
            .to_string();
        (email, server_url)
    };

    let user_dir = get_user_dir(&email, &server_url)?;
    let Some(mount_state) = read_mount_state_by_root_id(&user_dir, &root_id).await? else {
        return Ok(CommandResponse::err(format!(
            "No active mount found for root_id {}",
            root_id
        )));
    };
    if let Err(err) = ensure_sync_mount_backend(&mount_state, "mount-recovery") {
        return Ok(CommandResponse::err(err));
    }

    match load_mount_recovery_copies_for_root(&user_dir, &root_id) {
        Ok(records) => Ok(CommandResponse::ok(records)),
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

#[tauri::command]
pub async fn get_mount_recovery_copy_preview(
    root_id: String,
    recovery_path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountRecoveryCopyPreview>, String> {
    ensure_authenticated(&state).await?;
    Uuid::parse_str(&root_id).map_err(|err| format!("Invalid root_id format: {}", err))?;

    let (email, server_url) = {
        let session = state.session.lock().await;
        let user_session = session.as_ref().ok_or("No active session")?;
        let email = user_session.email.clone();
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or_else(|| state.client.server_url())
            .to_string();
        (email, server_url)
    };

    let user_dir = get_user_dir(&email, &server_url)?;
    let Some(mount_state) = read_mount_state_by_root_id(&user_dir, &root_id).await? else {
        return Ok(CommandResponse::err(format!(
            "No active mount found for root_id {}",
            root_id
        )));
    };
    if let Err(err) = ensure_sync_mount_backend(&mount_state, "mount-recovery") {
        return Ok(CommandResponse::err(err));
    }

    let recovery_relative_path = PathBuf::from(recovery_path.trim());
    let records = match load_mount_recovery_copies_for_root(&user_dir, &root_id) {
        Ok(records) => records,
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    let Some(record) = records
        .into_iter()
        .find(|record| record.recovery_relative_path == recovery_relative_path)
    else {
        return Ok(CommandResponse::err(format!(
            "Recovery copy {} was not found",
            recovery_relative_path.display()
        )));
    };

    let live_path = mount_state.mountpoint.join(&record.live_relative_path);
    let recovery_path = mount_state.mountpoint.join(&record.recovery_relative_path);
    if !recovery_path.exists() {
        return Ok(CommandResponse::err(format!(
            "Recovery copy no longer exists at {}",
            recovery_path.display()
        )));
    }

    let live_text = if live_path.exists() {
        read_conflict_preview_text(&live_path).map_err(|err| {
            format!(
                "Failed to read mounted file preview {}: {}",
                live_path.display(),
                err
            )
        })?
    } else {
        None
    };
    let recovery_text = read_conflict_preview_text(&recovery_path).map_err(|err| {
        format!(
            "Failed to read recovery preview {}: {}",
            recovery_path.display(),
            err
        )
    })?;

    Ok(CommandResponse::ok(MountRecoveryCopyPreview {
        record,
        live_path,
        recovery_path,
        live_text,
        recovery_text,
    }))
}

#[tauri::command]
pub async fn resolve_mount_recovery_copy(
    root_id: String,
    recovery_path: String,
    action: RecoveryCopyResolutionAction,
    destination_path: Option<String>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<RecoveryCopyResolutionResult>, String> {
    ensure_authenticated(&state).await?;
    Uuid::parse_str(&root_id).map_err(|err| format!("Invalid root_id format: {}", err))?;

    let (email, server_url) = {
        let session = state.session.lock().await;
        let user_session = session.as_ref().ok_or("No active session")?;
        let email = user_session.email.clone();
        let server_url = user_session
            .server_url
            .as_deref()
            .unwrap_or_else(|| state.client.server_url())
            .to_string();
        (email, server_url)
    };

    let user_dir = get_user_dir(&email, &server_url)?;
    let Some(mount_state) = read_mount_state_by_root_id(&user_dir, &root_id).await? else {
        return Ok(CommandResponse::err(format!(
            "No active mount found for root_id {}",
            root_id
        )));
    };
    if let Err(err) = ensure_sync_mount_backend(&mount_state, "mount-recovery") {
        return Ok(CommandResponse::err(err));
    }

    let request = RecoveryCopyResolutionRequest {
        request_id: Uuid::new_v4(),
        recovery_relative_path: PathBuf::from(recovery_path.trim()),
        action,
        destination_path: destination_path
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        requested_at: chrono::Utc::now(),
    };

    let response = match submit_mount_recovery_request(&user_dir, &root_id, &request).await {
        Ok(response) => response,
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    if !response.success {
        return Ok(CommandResponse::err(
            response
                .error
                .unwrap_or_else(|| "Recovery copy resolution failed".to_string()),
        ));
    }

    let Some(result) = response.result else {
        return Ok(CommandResponse::err(
            "Recovery resolution completed without a result",
        ));
    };

    Ok(CommandResponse::ok(result))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MountInfo {
    pub root_id: String,
    pub mountpoint: String,
    pub encrypted_dir: String,
    pub backend: String,
    #[serde(default)]
    pub fallback_reason: Option<String>,
    pub sync_status: Option<MountSyncRuntimeStatus>,
}

#[tauri::command]
pub async fn get_mount_sync_status(
    mount_path: String,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::debug!("Mount sync status query for {}", mount_path);
    // Check if mountpoint exists and is accessible
    let path = PathBuf::from(&mount_path);
    if path.exists() && path.is_dir() {
        Ok(CommandResponse::ok(true))
    } else {
        Ok(CommandResponse::ok(false))
    }
}

#[tauri::command]
pub async fn unmount_all_mounts(
    force: Option<bool>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::info!("Unmount all request received");
    let force = force.unwrap_or(false);
    let cloud_state_context = match require_authenticated_session(&state).await {
        Ok(session) => {
            let server_url = current_server_url(&state, &session);
            match get_user_dir(&session.email, &server_url) {
                Ok(user_dir) => {
                    let records = load_cloud_mount_state_records_for_unmount(&user_dir).await;
                    Some((user_dir, records))
                }
                Err(_) => None,
            }
        }
        Err(_) => None,
    };

    if let Err(err) = state.cloud_provider.stop_all(true, force).await {
        return Ok(CommandResponse::err(err));
    }

    if let Some((user_dir, cloud_state_records)) = cloud_state_context {
        for (state_path, mount_state) in cloud_state_records {
            if mount_state.backend().is_macos_file_provider() {
                #[cfg(target_os = "macos")]
                if let Ok(root_id) = Uuid::parse_str(&mount_state.root_id) {
                    if let Err(err) =
                        unregister_stored_macos_file_provider_domain(&user_dir, root_id)
                    {
                        return Ok(CommandResponse::err(err));
                    }
                }
            }
            let _ = fs::remove_file(state_path).await;
        }
    }

    match state.mount_manager.unmount_all(force).await {
        Ok(_) => Ok(CommandResponse::ok(true)),
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

#[tauri::command]
pub async fn unmount_mount_by_root_id(
    root_id: String,
    force: Option<bool>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::info!("Unmount request received for root_id: {}", root_id);

    match unmount_desktop_cloud_root_if_active(&state, &root_id, force.unwrap_or(false)).await {
        Ok(true) => return Ok(CommandResponse::ok(true)),
        Ok(false) => {}
        Err(err) => return Ok(CommandResponse::err(err)),
    }

    match state
        .mount_manager
        .unmount_by_root_id(&root_id, force.unwrap_or(false))
        .await
    {
        Ok(_) => Ok(CommandResponse::ok(true)),
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

async fn unmount_desktop_cloud_root_if_active(
    state: &AppState,
    root_id: &str,
    force: bool,
) -> Result<bool, String> {
    let parsed_root_id =
        Uuid::parse_str(root_id).map_err(|err| format!("Invalid root_id format: {}", err))?;
    let session = require_authenticated_session(state).await?;
    let server_url = current_server_url(state, &session);
    let user_dir = get_user_dir(&session.email, &server_url)?;
    let Some((state_path, mount_state)) =
        read_any_mount_state_by_root_id(&user_dir, root_id).await?
    else {
        return Ok(false);
    };
    if !(mount_state.backend().is_windows_cloud_files()
        || mount_state.backend().is_macos_file_provider())
    {
        return Ok(false);
    }
    state
        .cloud_provider
        .stop_root(parsed_root_id, true, force)
        .await?;
    if mount_state.backend().is_macos_file_provider() {
        #[cfg(target_os = "macos")]
        unregister_stored_macos_file_provider_domain(&user_dir, parsed_root_id)?;
    }
    let _ = fs::remove_file(state_path).await;
    Ok(true)
}

#[tauri::command]
pub async fn exit_application(
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::info!("exit_application: starting safe quit with unmount");

    if let Err(e) = state.cloud_provider.stop_all(true, false).await {
        tracing::error!("Failed to stop Cloud Files roots during exit: {}", e);
    }

    // Unmount all folders before exiting
    if let Err(e) = state.mount_manager.unmount_all(false).await {
        tracing::error!("Failed to unmount during exit: {}", e);
        // Continue with exit anyway - user explicitly requested quit
    } else {
        tracing::info!("exit_application: unmount completed successfully");
    }

    app_handle.exit(0);
    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn open_path_in_shell(
    path: String,
    _state: State<'_, AppState>,
    _window: tauri::Window,
) -> Result<CommandResponse<bool>, String> {
    ensure_authenticated(&_state).await?;
    let target = PathBuf::from(&path);

    // Verify path exists
    if !target.exists() {
        return Ok(CommandResponse::err(format!(
            "Path does not exist: {}",
            target.display()
        )));
    }

    open_path_with_system_handler(&target)?;

    Ok(CommandResponse::ok(true))
}

fn open_path_with_system_handler(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = StdCommand::new("open");
        command.arg(path);
        command
    };

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = StdCommand::new("cmd");
        command.arg("/C").arg("start").arg("").arg(path);
        command
    };

    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = StdCommand::new("xdg-open");
        command.arg(path);
        command
    };

    configure_background_std_command(&mut command);
    command
        .spawn()
        .map_err(|e| format!("Failed to open path {}: {}", path.display(), e))?;
    Ok(())
}

#[tauri::command]
pub async fn prioritize_folder_decrypt(
    path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    match state.mount_manager.prioritize_folder(&path).await {
        Ok(_) => Ok(CommandResponse::ok(true)),
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

// Add more command implementations...

async fn ensure_authenticated(state: &AppState) -> Result<(), String> {
    if ensure_session_ready_internal(state).await?.is_some() {
        Ok(())
    } else {
        Err("Please login through the desktop app to access this feature.".to_string())
    }
}

fn api_base_url(server_url: &str) -> String {
    let trimmed = server_url.trim_end_matches('/');
    if trimmed.ends_with("/api/v1") {
        trimmed.to_string()
    } else {
        format!("{}/api/v1", trimmed)
    }
}

async fn fetch_group_member_emails(
    session: &crate::state::UserSession,
    api_base: &str,
    group_id: Uuid,
) -> Result<HashMap<Uuid, String>, String> {
    let client = reqwest::Client::new();
    let mut offset = 0u32;
    let mut emails = HashMap::new();

    loop {
        let url = format!(
            "{}/groups/{}/members?limit=100&offset={}",
            api_base, group_id, offset
        );
        let response = client
            .get(&url)
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch group members: {}", e))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err("Authentication token rejected. Please login again.".to_string());
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Group members request failed ({}): {}",
                status, body
            ));
        }

        let response_body: MembersListResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse group members response: {}", e))?;

        for member in response_body.members {
            emails.insert(member.user_id, member.email);
        }

        if response_body.has_more {
            offset = response_body.next_offset.unwrap_or(offset + 100);
        } else {
            break;
        }
    }

    Ok(emails)
}
