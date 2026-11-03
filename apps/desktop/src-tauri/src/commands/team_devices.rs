//! Organization "Members & devices": every member's devices with their status, and an
//! owner or admin revoking another member's device.
use super::*;
use chrono::{DateTime, Utc};
use hybridcipher_client::device_actions::{signed_device_action, DeviceActionContext};
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use hybridcipher_messages::device_actions::DeviceAction;

/// Error code the UI uses to hide the page on servers without the roster endpoint.
pub const TEAM_DEVICES_UNSUPPORTED: &str = "TEAM_DEVICES_UNSUPPORTED";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMemberGroupRef {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMemberDevice {
    pub device_id: String,
    #[serde(default)]
    pub device_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// `pending`, `unverified`, `missing_key`, `stale` or `trusted`.
    pub status: String,
    #[serde(default)]
    pub pending: bool,
    #[serde(default)]
    pub approved: bool,
    #[serde(default)]
    pub fingerprint_verified: bool,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub stale_reasons: Vec<String>,
    #[serde(default)]
    pub missing_key_groups: Vec<TeamMemberGroupRef>,
    /// The member can set this device up from another trusted device of theirs.
    #[serde(default)]
    pub owner_can_self_approve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMemberDevices {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    #[serde(default)]
    pub groups: Vec<TeamMemberGroupRef>,
    #[serde(default)]
    pub devices: Vec<TeamMemberDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamDeviceRoster {
    pub organization_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub stale_threshold_days: i64,
    pub members: Vec<TeamMemberDevices>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamDeviceRevokeResult {
    pub removed_device_id: String,
    pub revoked_sessions: usize,
    /// The member's groups, whose keys the admin may rotate so the device cannot open new files.
    #[serde(default)]
    pub group_ids: Vec<Uuid>,
}

/// Turns a failed roster or revoke response into the message the UI shows.
fn team_devices_error<T>(
    status: reqwest::StatusCode,
    body: &str,
    action: &str,
) -> CommandResponse<T> {
    let server_message = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|body| body["error"].as_str().map(str::to_string));
    match status {
        reqwest::StatusCode::UNAUTHORIZED => {
            CommandResponse::err("Authentication token rejected. Please login again.")
        }
        reqwest::StatusCode::NOT_FOUND if body.trim().is_empty() => CommandResponse::err_with_code(
            TEAM_DEVICES_UNSUPPORTED,
            "This server does not support the Members & devices page yet.",
        ),
        reqwest::StatusCode::PRECONDITION_REQUIRED => CommandResponse::err_with_code(
            "device_trust_required",
            server_message.unwrap_or_else(|| {
                "Team administration needs a verified device. Verify this device from a trusted device, or confirm it with your password.".into()
            }),
        ),
        reqwest::StatusCode::FORBIDDEN => CommandResponse::err(server_message.unwrap_or_else(|| {
            "Only organization owners and admins can manage members' devices.".into()
        })),
        _ => CommandResponse::err(server_message.unwrap_or_else(|| {
            format!("{action} failed with status {status}")
        })),
    }
}

#[tauri::command]
pub async fn get_team_member_devices(
    state: State<'_, AppState>,
) -> Result<CommandResponse<TeamDeviceRoster>, String> {
    let _guard = ensure_authenticated(&state).await?;
    let session = current_authenticated_session(&state).await?;
    let server_url = current_server_url(&state, &session);
    let response = reqwest::Client::new()
        .get(api_endpoint(&server_url, "organizations/me/devices"))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch members and devices: {}", e))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Ok(team_devices_error(
            status,
            &body,
            "Loading members and devices",
        ));
    }
    let roster: TeamDeviceRoster = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse members and devices: {}", e))?;
    Ok(CommandResponse::ok(roster))
}

#[tauri::command]
pub async fn admin_revoke_member_device(
    user_id: String,
    device_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<TeamDeviceRevokeResult>, String> {
    let _guard = ensure_authenticated(&state).await?;
    let session = current_authenticated_session(&state).await?;
    let Ok(target_user_id) = Uuid::parse_str(user_id.trim()) else {
        return Ok(CommandResponse::err("The member could not be identified."));
    };
    let target_device_id = device_id.trim();
    if target_device_id.is_empty() {
        return Ok(CommandResponse::err(
            "Device identifier is required to revoke a device.",
        ));
    }
    if target_device_id.eq_ignore_ascii_case(&session.device_id) {
        return Ok(CommandResponse::err("Use Devices to revoke this device."));
    }

    let server_url = current_server_url(&state, &session);
    let material = state.client.device_crypto_material(&session.email)?;
    if material.device_id != session.device_id {
        return Ok(CommandResponse::err(
            "Local identity does not match the signed-in device.",
        ));
    }
    let identity =
        Ed25519KeyPair::from_bytes(&material.identity_secret).map_err(|error| error.to_string())?;
    // The server checks this payload, which binds the revoke to the device's owner.
    let proof = signed_device_action(
        &identity,
        &DeviceActionContext {
            server_url: &server_url,
            token: &session.token,
            user_id: &session.user_id,
            device_id: &session.device_id,
        },
        DeviceAction::AdminRevoke,
        target_device_id,
        None,
        &json!({ "user_id": target_user_id }),
    )
    .await?;

    let endpoint = api_endpoint(
        &server_url,
        &format!(
            "organizations/me/members/{}/devices/{}",
            target_user_id, target_device_id
        ),
    );
    let response = proof
        .apply(
            reqwest::Client::new()
                .delete(endpoint)
                .bearer_auth(&session.token),
        )
        .send()
        .await
        .map_err(|e| format!("Failed to contact server: {}", e))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Ok(team_devices_error(status, &body, "Device revocation"));
    }
    let result: TeamDeviceRevokeResult = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse device revocation response: {}", e))?;
    tracing::info!(
        target_user_id = %target_user_id,
        device_id = %result.removed_device_id,
        "Revoked a member's device"
    );
    Ok(CommandResponse::ok(result))
}

#[cfg(test)]
#[path = "../../tests/device_security/test_team_member_devices.rs"]
mod team_member_devices_tests;
