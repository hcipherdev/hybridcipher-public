//! Authoritative Personal workspace identity and explicit legacy repair.
use super::*;
use hybridcipher_client::device_actions::{api_base, signed_device_action, DeviceActionContext};
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use hybridcipher_messages::device_actions::DeviceAction;
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "../../tests/personal/test_personal_workspace.rs"]
mod tests;

fn canonical_personal_server(server: &str) -> String {
    api_base(server).trim_end_matches('/').to_string()
}

fn cache_key(account_id: &str, server: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(account_id.as_bytes());
    digest.update([0]);
    digest.update(canonical_personal_server(server).as_bytes());
    format!(
        "desktop_personal_workspace_v1_{}",
        hex::encode(digest.finalize())
    )
}

pub(super) struct WorkspaceSessionScope {
    account_id: String,
    email: String,
    device_id: String,
    server: String,
    generation: u64,
}

impl WorkspaceSessionScope {
    pub(super) fn capture(state: &AppState, session: &crate::state::UserSession) -> Self {
        Self {
            account_id: session.user_id.clone(),
            email: session.email.clone(),
            device_id: session.device_id.clone(),
            server: canonical_personal_server(&current_server_url(state, session)),
            generation: state.auth_generation(),
        }
    }

    fn matches(&self, session: &crate::state::UserSession, server: &str, generation: u64) -> bool {
        self.account_id == session.user_id
            && self.email.eq_ignore_ascii_case(&session.email)
            && self.device_id == session.device_id
            && self.server == canonical_personal_server(server)
            && self.generation == generation
    }

    pub(super) async fn ensure_current(&self, state: &AppState) -> Result<(), String> {
        let session = state.session.lock().await;
        let current = session
            .as_ref()
            .ok_or("The account changed. Reopen Personal setup.")?;
        if !self.matches(
            current,
            &current_server_url(state, current),
            state.auth_generation(),
        ) {
            return Err("The account changed. Reopen Personal setup.".into());
        }
        Ok(())
    }
}

fn validate_group(group: &Value) -> Result<&str, String> {
    let id = group["id"]
        .as_str()
        .ok_or("Personal group identity is missing")?;
    Uuid::parse_str(id).map_err(|_| "Personal group identity is invalid")?;
    if group.get("organization_id") != Some(&Value::Null)
        || group["role"].as_str() != Some("owner")
        || !group["name"].is_string()
    {
        return Err("Personal group metadata does not match this account".into());
    }
    match group.get("current_epoch_id") {
        Some(Value::Null) => {}
        Some(Value::String(epoch)) => {
            Uuid::parse_str(epoch).map_err(|_| "Personal current epoch is invalid")?;
        }
        _ => return Err("Personal current epoch is missing".into()),
    }
    Ok(id)
}

fn validate_snapshot(value: &Value) -> Result<(), String> {
    let state = value["state"]
        .as_str()
        .ok_or("Personal workspace state is missing")?;
    if !matches!(state, "available" | "deleted" | "missing" | "unresolved") {
        return Err("Personal workspace state is invalid".into());
    }
    let default = match value.get("personal_default_group_id") {
        Some(Value::Null) => None,
        Some(Value::String(id)) => {
            Uuid::parse_str(id).map_err(|_| "Personal default identity is invalid")?;
            Some(id.as_str())
        }
        _ => return Err("Personal default identity is missing".into()),
    };
    if let Some(group) = value.get("group").filter(|group| !group.is_null()) {
        if Some(validate_group(group)?) != default {
            return Err("Personal default metadata does not match this account".into());
        }
    } else if state == "available" || state == "deleted" {
        return Err("Personal default metadata is missing".into());
    }
    for group in value["candidates"]
        .as_array()
        .ok_or("Personal repair candidates are missing")?
    {
        validate_group(group)?;
    }
    Ok(())
}

fn cached_snapshot(cached: Option<&str>) -> Result<Value, String> {
    let encoded = cached.ok_or("Personal workspace metadata is unavailable on this device. Connect to the server and choose Check status to retry.")?;
    let value = serde_json::from_str(encoded).map_err(|_| "Saved Personal workspace metadata could not be read. Reconnect and choose Check status to refresh it.")?;
    validate_snapshot(&value).map_err(|_| "Saved Personal workspace metadata is invalid. Reconnect and choose Check status to refresh it.")?;
    Ok(value)
}

async fn online_snapshot<F, E>(
    value: Value,
    persist: impl FnOnce(String) -> F,
) -> Result<Value, String>
where
    F: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    validate_snapshot(&value)?;
    if let Err(error) = persist(value.to_string()).await {
        tracing::warn!(error = %error, "Could not cache authoritative Personal workspace metadata");
    }
    Ok(value)
}

pub(super) fn available_personal_group(
    snapshot: &Value,
    selected: Option<Uuid>,
) -> Result<Value, String> {
    validate_snapshot(snapshot)?;
    if snapshot["state"] != "available" {
        return Err(
            "Your Personal default group needs repair before folders can be protected.".into(),
        );
    }
    let id = snapshot["personal_default_group_id"]
        .as_str()
        .ok_or("Personal default identity is missing")?;
    if selected.is_some_and(|selected| selected.to_string() != id) {
        return Err("Personal mode always uses the account's Personal default group. Reopen Personal workspace.".into());
    }
    Ok(snapshot["group"].clone())
}

pub(super) fn validate_expected_group(
    expected: Option<&str>,
    resolved: Uuid,
) -> Result<(), String> {
    if let Some(expected) = expected {
        let expected =
            Uuid::parse_str(expected).map_err(|_| "The folder's workspace identity is invalid")?;
        if expected != resolved {
            return Err(
                "The workspace changed. Select the folder again in the current workspace.".into(),
            );
        }
    }
    Ok(())
}

pub(super) async fn personal_workspace_snapshot(
    state: &AppState,
    session: &crate::state::UserSession,
    refresh: bool,
) -> Result<Value, String> {
    let scope = WorkspaceSessionScope::capture(state, session);
    scope.ensure_current(state).await?;
    let client = state.local_client.client().await?;
    let server = current_server_url(state, session);
    let key = cache_key(&session.user_id, &server);
    if refresh && session.expires_at > chrono::Utc::now().timestamp() {
        let response = reqwest::Client::new()
            .get(format!("{}/personal-workspace", api_base(&server)))
            .bearer_auth(&session.token)
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => {
                let value: Value = response
                    .json()
                    .await
                    .map_err(|_| "Personal workspace response is invalid")?;
                scope.ensure_current(state).await?;
                let value = online_snapshot(value, |encoded| async move {
                    client.store_local_config(&key, &encoded).await
                })
                .await?;
                scope.ensure_current(state).await?;
                return Ok(value);
            }
            Ok(response) if response.status().is_client_error() => {
                return Err(if response.status() == reqwest::StatusCode::NOT_FOUND {
                    "The server needs an update before Personal workspace setup can complete."
                        .into()
                } else {
                    "Personal workspace authorization failed. Reconnect and sign in again.".into()
                });
            }
            _ => {}
        }
    }
    scope.ensure_current(state).await?;
    let cached = client
        .load_local_config(&key)
        .await
        .map_err(|e| e.to_string())?;
    let value = cached_snapshot(cached.as_deref())?;
    scope.ensure_current(state).await?;
    Ok(value)
}

#[tauri::command]
pub async fn get_personal_workspace(
    expected_account_email: Option<String>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Value>, String> {
    let _guard = ensure_local_data_access(&state).await?;
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    if expected_account_email
        .as_deref()
        .is_some_and(|email| !email.eq_ignore_ascii_case(&session.email))
    {
        return Err("The account changed. Reopen Personal setup.".into());
    }
    Ok(CommandResponse::ok(
        personal_workspace_snapshot(&state, &session, true).await?,
    ))
}

/// Ask the server to keep a just-upgraded local vault's group as this
/// account's Personal default, so files sealed before the account stay valid.
pub(super) async fn adopt_local_personal_group(
    state: &AppState,
    session: &crate::state::UserSession,
    group_id: Uuid,
) -> Result<Value, String> {
    let scope = WorkspaceSessionScope::capture(state, session);
    let payload = json!({"action":"adopt_local","group_id":group_id});
    let server = current_server_url(state, session);
    let material = state.client.device_crypto_material(&session.email)?;
    if material.device_id != session.device_id {
        return Err("Local device identity changed".into());
    }
    let identity =
        Ed25519KeyPair::from_bytes(&material.identity_secret).map_err(|e| e.to_string())?;
    let context = DeviceActionContext {
        server_url: &server,
        token: &session.token,
        user_id: &session.user_id,
        device_id: &session.device_id,
    };
    let proof = signed_device_action(
        &identity,
        &context,
        DeviceAction::RepairPersonalWorkspace,
        &session.device_id,
        None,
        &payload,
    )
    .await?;
    scope.ensure_current(state).await?;
    let response = proof
        .apply(
            reqwest::Client::new()
                .post(format!(
                    "{}/personal-workspace/default-group",
                    api_base(&server)
                ))
                .bearer_auth(&session.token)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(20)),
        )
        .send()
        .await
        .map_err(|_| "Account setup could not reach the server")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(
            "The server needs an update before a local vault can become an account.".into(),
        );
    }
    if !response.status().is_success() {
        let error: Value = response.json().await.unwrap_or_default();
        return Err(error["error"]
            .as_str()
            .unwrap_or("The server could not link this vault to the account")
            .to_string());
    }
    let value: Value = response
        .json()
        .await
        .map_err(|_| "Personal setup response is invalid")?;
    validate_snapshot(&value)?;
    available_personal_group(&value, Some(group_id))?;
    scope.ensure_current(state).await?;
    let client = state.local_client.client().await?;
    let key = cache_key(&session.user_id, &server);
    online_snapshot(value, |encoded| async move {
        client.store_local_config(&key, &encoded).await
    })
    .await
}

#[tauri::command]
pub async fn repair_personal_default_group(
    action: String,
    group_id: Option<String>,
    expected_account_email: Option<String>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Value>, String> {
    let _guard = ensure_authenticated(&state).await?;
    if super::local_vault::pending_vault_upgrade(&state).is_some() {
        return Ok(CommandResponse::err_with_code(
            "LOCAL_VAULT_UPGRADE_PENDING",
            super::local_vault::LOCAL_VAULT_UPGRADE_PENDING,
        ));
    }
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    let scope = WorkspaceSessionScope::capture(&state, &session);
    if expected_account_email
        .as_deref()
        .is_some_and(|email| !email.eq_ignore_ascii_case(&session.email))
    {
        return Err("The account changed. Reopen Personal setup.".into());
    }
    let payload = match action.as_str() {
        "assign" => {
            json!({"action":"assign","group_id":Uuid::parse_str(group_id.as_deref().unwrap_or_default()).map_err(|_| "Select a valid Personal group")?})
        }
        "create" if group_id.is_none() => json!({"action":"create"}),
        _ => return Err("Unknown Personal setup action".into()),
    };
    let server = current_server_url(&state, &session);
    let material = state.client.device_crypto_material(&session.email)?;
    if material.device_id != session.device_id {
        return Err("Local device identity changed".into());
    }
    let identity =
        Ed25519KeyPair::from_bytes(&material.identity_secret).map_err(|e| e.to_string())?;
    let context = DeviceActionContext {
        server_url: &server,
        token: &session.token,
        user_id: &session.user_id,
        device_id: &session.device_id,
    };
    let proof = signed_device_action(
        &identity,
        &context,
        DeviceAction::RepairPersonalWorkspace,
        &session.device_id,
        None,
        &payload,
    )
    .await?;
    scope.ensure_current(&state).await?;
    let response = proof
        .apply(
            reqwest::Client::new()
                .post(format!(
                    "{}/personal-workspace/default-group",
                    api_base(&server)
                ))
                .bearer_auth(&session.token)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(20)),
        )
        .send()
        .await
        .map_err(|_| "Personal setup could not reach the server")?;
    if !response.status().is_success() {
        let error: Value = response.json().await.unwrap_or_default();
        return Ok(CommandResponse::err_with_code(
            "PERSONAL_REPAIR_FAILED",
            error["error"].as_str().unwrap_or("Personal setup failed"),
        ));
    }
    let mut value: Value = response
        .json()
        .await
        .map_err(|_| "Personal setup response is invalid")?;
    validate_snapshot(&value)?;
    scope.ensure_current(&state).await?;
    available_personal_group(
        &value,
        if action == "assign" {
            group_id.as_deref().and_then(|id| Uuid::parse_str(id).ok())
        } else {
            None
        },
    )?;
    if action == "create" {
        // Only the explicitly created namespace may receive new genesis keys.
        let id = Uuid::parse_str(
            value["personal_default_group_id"]
                .as_str()
                .ok_or("Created Personal group is missing")?,
        )
        .map_err(|_| "Created Personal group is invalid")?;
        state
            .local_client
            .client()
            .await?
            .prepare_group_for_use(id)
            .await
            .map_err(|e| e.to_string())?;
        value = personal_workspace_snapshot(&state, &session, true).await?;
    }
    scope.ensure_current(&state).await?;
    let client = state.local_client.client().await?;
    let key = cache_key(&session.user_id, &server);
    let value = online_snapshot(value, |encoded| async move {
        client.store_local_config(&key, &encoded).await
    })
    .await?;
    scope.ensure_current(&state).await?;
    Ok(CommandResponse::ok(value))
}
