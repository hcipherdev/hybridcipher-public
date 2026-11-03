//! Current identity trust and explicit OPAQUE recovery confirmation without device eviction.
use super::*;
use hybridcipher_client::{
    auth::opaque::{DeviceLoginMetadata, DeviceRecoveryFinalization, OpaqueAuth, OpaqueError},
    device_actions::{complete_device_trust_recovery, fetch_device_trust, DeviceActionContext},
};
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use hybridcipher_messages::device_actions::DeviceTrustStatus;

struct PendingTrustConfirmation {
    finalization: DeviceRecoveryFinalization,
    expires_at: i64,
    recovery_session_id: Option<Uuid>,
}
impl Drop for PendingTrustConfirmation {
    fn drop(&mut self) {
        self.finalization.credential_finalization.zeroize();
        self.finalization.session_key.zeroize();
        self.finalization.export_key.zeroize();
    }
}
static PENDING_TRUST_CONFIRMATIONS: Lazy<
    tokio::sync::Mutex<HashMap<String, PendingTrustConfirmation>>,
> = Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));

pub(crate) async fn clear_device_trust_confirmations() {
    PENDING_TRUST_CONFIRMATIONS.lock().await.clear();
}

fn confirmation_scope(
    session: &crate::state::UserSession,
    server: &str,
    generation: u64,
) -> String {
    format!(
        "{}@{}:{}:{}",
        session.user_id,
        hybridcipher_client::device_actions::api_base(server),
        session.device_id,
        generation
    )
}

pub(super) async fn current_device_trust(
    state: &AppState,
    session: &crate::state::UserSession,
) -> Result<DeviceTrustStatus, String> {
    let server = current_server_url(state, session);
    let material = state.client.device_crypto_material(&session.email)?;
    if material.device_id != session.device_id {
        return Err("Local identity does not match the signed-in device.".into());
    }
    let status = fetch_device_trust(&DeviceActionContext {
        server_url: &server,
        token: &session.token,
        user_id: &session.user_id,
        device_id: &session.device_id,
    })
    .await?;
    if status.identity_key_sha256 != hex::encode(Sha256::digest(&material.identity_public)) {
        return Err(
            "The registered identity key changed. Device management is unavailable.".into(),
        );
    }
    Ok(status)
}

#[tauri::command]
pub async fn get_device_trust_status(
    state: State<'_, AppState>,
) -> Result<CommandResponse<DeviceTrustStatus>, String> {
    let _guard = ensure_authenticated(&state).await?;
    let session = current_authenticated_session(&state).await?;
    match current_device_trust(&state, &session).await {
        Ok(status) => Ok(CommandResponse::ok(status)),
        Err(error) => Ok(CommandResponse::err_with_code(
            "DEVICE_TRUST_UNAVAILABLE",
            error,
        )),
    }
}

#[derive(Serialize)]
pub struct DeviceTrustConfirmationStart {
    otp_required: bool,
    otp_expires_at: Option<String>,
}

#[tauri::command]
pub async fn start_device_trust_confirmation(
    password: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<DeviceTrustConfirmationStart>, String> {
    let _guard = ensure_authenticated(&state).await?;
    let password = Zeroizing::new(password);
    let session = current_authenticated_session(&state).await?;
    let generation = state.auth_generation();
    let server = current_server_url(&state, &session);
    let status = current_device_trust(&state, &session).await?;
    if !status.confirmation_required {
        return Ok(CommandResponse::err("This identity is not eligible for trust confirmation. Use another trusted device to approve and verify it."));
    }
    let material = state.client.device_crypto_material(&session.email)?;
    let opaque = OpaqueAuth::new(session.device_id.clone());
    let challenge = opaque
        .device_trust_recovery_start(
            &session.email,
            &password,
            &server,
            DeviceLoginMetadata {
                identity_public_key_hex: hex::encode(&material.identity_public),
                invitation_public_key_hex: hex::encode(&material.invitation_public),
                device_display_name: None,
                mfa_code: None,
                backup_code: None,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    let response = DeviceTrustConfirmationStart {
        otp_required: challenge.otp_required(),
        otp_expires_at: challenge.otp_expires_at().map(|time| time.to_rfc3339()),
    };
    let expires_at = challenge
        .otp_expires_at()
        .map(|time| time.timestamp())
        .unwrap_or_else(|| chrono::Utc::now().timestamp() + 300);
    let finalization = challenge
        .finalize(&password)
        .map_err(|error| error.to_string())?;
    let current = current_authenticated_session(&state).await?;
    if confirmation_scope(&session, &server, generation)
        != confirmation_scope(
            &current,
            &current_server_url(&state, &current),
            state.auth_generation(),
        )
    {
        return Err("The account changed during trust confirmation.".into());
    }
    let mut pending = PENDING_TRUST_CONFIRMATIONS.lock().await;
    pending.clear();
    pending.insert(
        confirmation_scope(&session, &server, generation),
        PendingTrustConfirmation {
            finalization,
            expires_at,
            recovery_session_id: None,
        },
    );
    Ok(CommandResponse::ok(response))
}

#[tauri::command]
pub async fn complete_device_trust_confirmation(
    otp_code: Option<String>,
    mfa_code: Option<String>,
    backup_code: Option<String>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<DeviceTrustStatus>, String> {
    let _guard = ensure_authenticated(&state).await?;
    let session = current_authenticated_session(&state).await?;
    let server = current_server_url(&state, &session);
    let scope = confirmation_scope(&session, &server, state.auth_generation());
    let (finalization, recovery_session_id) = {
        let mut pending = PENDING_TRUST_CONFIRMATIONS.lock().await;
        pending.retain(|_, confirmation| confirmation.expires_at > chrono::Utc::now().timestamp());
        let confirmation = pending
            .get(&scope)
            .ok_or("Trust confirmation expired. Start again.")?;
        (
            confirmation.finalization.clone(),
            confirmation.recovery_session_id,
        )
    };
    let opaque = OpaqueAuth::new(session.device_id.clone());
    let recovery_session_id = match recovery_session_id {
        Some(id) => id,
        None => match opaque
            .device_trust_recovery_verify(&server, otp_code, finalization, mfa_code, backup_code)
            .await
        {
            Ok(mut verified) => {
                let id = verified.recovery_session_id;
                verified.session_key.zeroize();
                verified.export_key.zeroize();
                if let Some(pending) = PENDING_TRUST_CONFIRMATIONS.lock().await.get_mut(&scope) {
                    pending.recovery_session_id = Some(id);
                }
                id
            }
            Err(OpaqueError::MfaRequired(message)) => {
                return Ok(CommandResponse::err_with_code("MFA_REQUIRED", message))
            }
            Err(error) => {
                return Ok(CommandResponse::err_with_code(
                    "TRUST_CONFIRMATION_FAILED",
                    error,
                ))
            }
        },
    };
    let current = current_authenticated_session(&state).await?;
    if confirmation_scope(
        &current,
        &current_server_url(&state, &current),
        state.auth_generation(),
    ) != scope
    {
        PENDING_TRUST_CONFIRMATIONS.lock().await.remove(&scope);
        return Err("The account changed during trust confirmation.".into());
    }
    let material = state.client.device_crypto_material(&session.email)?;
    if material.device_id != session.device_id {
        return Err("The device identity changed.".into());
    }
    let identity =
        Ed25519KeyPair::from_bytes(&material.identity_secret).map_err(|error| error.to_string())?;
    let status = complete_device_trust_recovery(
        &identity,
        &DeviceActionContext {
            server_url: &server,
            token: &session.token,
            user_id: &session.user_id,
            device_id: &session.device_id,
        },
        recovery_session_id,
    )
    .await?;
    PENDING_TRUST_CONFIRMATIONS.lock().await.remove(&scope);
    Ok(CommandResponse::ok(status))
}
