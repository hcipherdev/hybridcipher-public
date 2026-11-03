//! Native recovery is available before workspace readiness and in temporary sessions.
use super::*;
use hybridcipher_client::{
    auth::opaque::DeviceLoginMetadata,
    device_actions::DeviceActionContext,
    saved_code_recovery::RecoveryGroupScope,
    saved_code_transport::{
        authorize_saved_code_recovery, enroll_recovery_credential, fetch_recovery_credential,
    },
};
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use hybridcipher_messages::device_actions::DeviceTrustStatus;

#[derive(Serialize)]
pub struct SavedCodeRecoveryResult {
    pub trust: DeviceTrustStatus,
    pub imported_epochs: usize,
    pub readiness: String,
    pub personal_default_group_id: Option<String>,
    pub personal_workspace_error: Option<String>,
    pub auto_backup_available: bool,
    pub backup_warning: Option<String>,
    pub security_status: Option<SecurityStatus>,
}

async fn recovery_security_status(
    state: &AppState,
    session: &crate::state::UserSession,
) -> Option<SecurityStatus> {
    tokio::time::timeout(
        Duration::from_secs(8),
        load_security_status_internal(state, session),
    )
    .await
    .ok()
    .and_then(Result::ok)
}

async fn recovery_group_scopes(
    server: &str,
    token: &str,
) -> Result<Vec<RecoveryGroupScope>, String> {
    let http = reqwest::Client::new();
    let mut scopes = Vec::new();
    let mut cursor: Option<String> = None;
    let mut cursors = HashSet::new();
    loop {
        let mut request = http
            .get(api_endpoint(server, "groups"))
            .bearer_auth(token)
            .query(&[("limit", "100")])
            .timeout(Duration::from_secs(20));
        if let Some(value) = &cursor {
            request = request.query(&[("cursor", value)]);
        }
        let response = request
            .send()
            .await
            .map_err(|_| "Cannot fetch current recovery group metadata")?;
        if !response.status().is_success() {
            return Err(format!(
                "Recovery group metadata unavailable ({})",
                response.status()
            ));
        }
        let page: GroupListResponse = response
            .json()
            .await
            .map_err(|_| "Recovery group metadata is invalid")?;
        for group in page.groups {
            let current_epoch_uuid = group
                .current_epoch
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| "Current server epoch identifier is invalid")?;
            scopes.push(RecoveryGroupScope {
                group_id: group.id,
                group_name: group.name,
                user_role: if matches!(group.user_role, GroupRole::Admin) {
                    hybridcipher_client::state::client::GroupRole::Admin
                } else {
                    hybridcipher_client::state::client::GroupRole::Member
                },
                current_epoch_uuid,
            });
        }
        if !page.has_more {
            break;
        }
        let next = page
            .next_cursor
            .filter(|value| !value.is_empty())
            .ok_or("Recovery group pagination is incomplete")?;
        if !cursors.insert(next.clone()) {
            return Err("Recovery group pagination repeated a page".into());
        }
        cursor = Some(next);
    }
    Ok(scopes)
}

#[tauri::command]
pub async fn restore_saved_code_recovery(
    password: String,
    recovery_code: String,
    expected_account_email: Option<String>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<SavedCodeRecoveryResult>, String> {
    let entry_scope = {
        let entry_session = state.session.lock().await;
        super::personal_workspace::WorkspaceSessionScope::capture(
            &state,
            entry_session.as_ref().ok_or("No account is open")?,
        )
    };
    // Keep account/logout changes out of the entire validate/authorize/commit operation.
    let _guard = ensure_authenticated(&state).await?;
    entry_scope.ensure_current(&state).await?;
    let password = Zeroizing::new(password);
    let recovery_code = Zeroizing::new(recovery_code);
    let session = current_authenticated_session(&state).await?;
    if expected_account_email
        .as_deref()
        .is_some_and(|email| email != session.email)
    {
        return Err("The account changed before recovery started".into());
    }
    restore_saved_code_internal(&state, &session, &password, &recovery_code).await
}

pub(super) async fn restore_saved_code_internal(
    state: &AppState,
    session: &crate::state::UserSession,
    password: &str,
    recovery_code: &str,
) -> Result<CommandResponse<SavedCodeRecoveryResult>, String> {
    if password.trim().is_empty() || recovery_code.trim().is_empty() {
        return Ok(CommandResponse::err_with_code(
            "RECOVERY_CREDENTIALS_REQUIRED",
            "Enter your account password and saved encryption recovery code.",
        ));
    }
    let raw_code = Zeroizing::new(parse_recovery_code_input(recovery_code)?);
    let server = current_server_url(state, session);
    let context = DeviceActionContext {
        server_url: &server,
        token: &session.token,
        user_id: &session.user_id,
        device_id: &session.device_id,
    };
    let material = state.client.device_crypto_material(&session.email)?;
    if material.device_id != session.device_id {
        return Err("Recovery identity does not match this session".into());
    }
    let identity =
        Ed25519KeyPair::from_bytes(&material.identity_secret).map_err(|e| e.to_string())?;
    let mut downloaded = download_recovery_artifact_with_version(&server, &session.token)
        .await?
        .ok_or("No recovery backup is available for this account")?;
    let unlocked = downloaded.artifact.unlock(password, &raw_code)?;
    let scopes = recovery_group_scopes(&server, &session.token).await?;
    let validated = unlocked.validate_for_groups(&scopes, None)?;
    let client = state
        .local_client
        .client()
        .await
        .map_err(|e| e.to_string())?;
    client
        .validate_authenticated_recovery(&validated)
        .await
        .map_err(|e| e.to_string())?;
    let mut status = fetch_recovery_credential(&context).await?;
    if status.credential.is_none() {
        let trust = super::device_trust::current_device_trust(state, session).await?;
        if !trust.approved || !trust.fingerprint_verified {
            return Ok(CommandResponse::err_with_code("RECOVERY_MIGRATION_REQUIRED",
                "This older backup needs a one-time upgrade. Use a trusted device, or confirm your account with MFA or email when no trusted device remains."));
        }
        status = enroll_recovery_credential(
            &identity,
            &context,
            unlocked.recovery_secret(),
            &downloaded.artifact,
            Some(downloaded.server_version),
            None,
            None,
        )
        .await?;
        // Enrollment changes the server revision; prove the exact committed snapshot.
        let fresh = download_recovery_artifact_with_version(&server, &session.token)
            .await?
            .ok_or("The recovery backup disappeared during migration")?;
        if fresh.artifact.to_base64()? != downloaded.artifact.to_base64()? {
            return Err(
                "The recovery backup changed during migration. Retry with the latest backup."
                    .into(),
            );
        }
        downloaded = fresh;
    }
    let credential = status
        .credential
        .ok_or("Recovery credential is unavailable")?;
    let envelope = hybridcipher_messages::recovery_credentials::recovery_envelope_sha256(
        &serde_json::to_value(&downloaded.artifact).map_err(|e| e.to_string())?,
    )?;
    if credential.recovery_envelope_sha256 != envelope {
        return Err(
            "The recovery backup does not match the account's saved code credential".into(),
        );
    }
    let receipt = authorize_saved_code_recovery(
        &identity,
        &context,
        &session.email,
        password,
        DeviceLoginMetadata {
            identity_public_key_hex: hex::encode(&material.identity_public),
            invitation_public_key_hex: hex::encode(&material.invitation_public),
            device_display_name: None,
            mfa_code: None,
            backup_code: None,
        },
        unlocked.recovery_secret(),
        &credential,
        downloaded.server_version,
        &recovery_artifact_blob_sha256_hex(&downloaded.artifact_blob)?,
    )
    .await?;
    // Memberships and current epochs can change while password proof is in flight.
    // Validate every entry again before committing any part of this account restore.
    let fresh_plan = match recovery_group_scopes(&server, &session.token).await {
        Ok(scopes) => unlocked.validate_for_groups(&scopes, None),
        Err(error) => Err(error),
    };
    let fresh_plan = match fresh_plan {
        Ok(plan) => plan,
        Err(error) => return Ok(CommandResponse::ok(SavedCodeRecoveryResult {
            trust:receipt.trust, imported_epochs:0, readiness:"key_installation_failed".into(),
            personal_default_group_id:None, personal_workspace_error:None, auto_backup_available:false,
            backup_warning:Some(format!("This device is fully trusted. Current encryption metadata could not be validated: {error}. Fetch a newer backup or retry recovery.")),
            security_status:recovery_security_status(state, session).await,
        })),
    };
    let installed = match client.install_authenticated_recovery(&fresh_plan).await {
        Ok(installed) => installed,
        Err(_) => return Ok(CommandResponse::ok(SavedCodeRecoveryResult {
            trust:receipt.trust, imported_epochs:0, readiness:"key_installation_failed".into(),
            personal_default_group_id:None, personal_workspace_error:None, auto_backup_available:false,
            backup_warning:Some("This device is fully trusted. Encryption keys could not be saved; retry recovery before enrolling folders.".into()),
            security_status:recovery_security_status(state, session).await,
        })),
    };
    // Register the recovered keys server-side so the next sign-in does not treat
    // this trusted device as awaiting approval. Group access self-heals on sync if this fails.
    let welcome_warning = match client
        .publish_recovered_self_welcomes(&installed.ready_groups)
        .await
    {
        Ok(failed) if failed.is_empty() => None,
        _ => Some("This device is fully trusted. Group key access could not be registered with the server yet; it will retry on the next sync.".to_string()),
    };
    // Re-read authoritative metadata: the current epoch can advance while proof is in flight.
    let (personal, personal_workspace_error) =
        match super::personal_workspace::personal_workspace_snapshot(state, session, true).await {
            Ok(snapshot) => (Some(snapshot), None),
            Err(error) => (None, Some(error)),
        };
    let personal_id = personal.as_ref().and_then(|snapshot| {
        snapshot["personal_default_group_id"]
            .as_str()
            .map(str::to_owned)
    });
    let readiness = if let Some(personal) = personal
        .as_ref()
        .filter(|snapshot| snapshot["state"] == "available")
    {
        let current = personal["group"]["current_epoch_id"]
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok());
        let id = personal_id
            .as_deref()
            .and_then(|id| Uuid::parse_str(id).ok());
        let ready = match (id, current) {
            (Some(id), Some(epoch)) => client
                .has_cached_group_epoch_key(id, epoch)
                .await
                .unwrap_or(false),
            _ => false,
        };
        if ready {
            "ready"
        } else {
            "missing_current_epoch"
        }
    } else if personal.is_some() {
        "personal_setup_required"
    } else {
        "personal_workspace_unavailable"
    }
    .to_string();
    // Keys are already committed. Writer persistence is optional and cannot undo recovery.
    let mut backup_warning = None;
    let auto_backup_available = if session.persistent {
        match persist_recovery_writer_material(
            state,
            session,
            unlocked.file_key(),
            unlocked.entry_key(),
        ) {
            Ok(()) => true,
            Err(_) => {
                backup_warning = Some("Encryption keys recovered. Automatic backup credentials could not be saved; enable backup again later.".into());
                false
            }
        }
    } else {
        false
    };
    if session.persistent {
        if let Ok(path) = recovery_artifact_path(state, &session.email, &server) {
            if downloaded.artifact.save_to_path(&path).is_err() && backup_warning.is_none() {
                backup_warning = Some(
                    "Encryption keys recovered. The local backup cache could not be saved.".into(),
                );
            }
        }
    }
    let backup_warning = backup_warning.or(welcome_warning);
    let security_status = recovery_security_status(state, session).await;
    Ok(CommandResponse::ok(SavedCodeRecoveryResult {
        trust: receipt.trust,
        imported_epochs: installed.imported_epochs,
        readiness,
        personal_default_group_id: personal_id,
        personal_workspace_error,
        auto_backup_available,
        backup_warning,
        security_status,
    }))
}
