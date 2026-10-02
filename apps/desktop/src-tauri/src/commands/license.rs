//! Desktop Team activation and verified, account-scoped license status.

use super::*;
use hybridcipher_client::entitlement::{self, Claims};
use hybridcipher_client::team_requests::{PendingTeamRequest, TeamAdminRequest};
use rand::RngCore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationStatus {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    pub license_status: String,
    pub seat_limit: i32,
    pub seats_used: i64,
    pub entitlement_version: i64,
    #[serde(default)]
    pub default_group_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct EntitlementResponse {
    organization: OrganizationStatus,
    token: String,
}

#[derive(Debug, Serialize)]
pub struct TeamLicenseStatus {
    pub workspace: &'static str,
    pub organization: Option<OrganizationStatus>,
    pub entitlement_expires_at: Option<i64>,
    pub can_write: bool,
    pub online: bool,
    pub revoked: bool,
    pub message: Option<String>,
}

pub(super) fn verified_claims(
    session: &crate::state::UserSession,
    allow_expired: bool,
) -> Result<Option<Claims>, String> {
    let Some(token) = session.team_entitlement.as_deref() else {
        return Ok(None);
    };
    let keys = entitlement::trusted_keys_from_build()?;
    let server = current_server_url_for_license(session);
    let now = chrono::Utc::now().timestamp();
    let claims = if allow_expired {
        entitlement::verify_for_existing_data(token, &keys, &server, &session.user_id, now)?
    } else {
        entitlement::verify(token, &keys, &server, &session.user_id, now)?
    };
    Ok(Some(claims))
}

pub(super) async fn require_team_write(state: &AppState) -> Result<(), String> {
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    if session.team_revoked {
        return Err("Team license has been revoked".into());
    }
    verified_claims(&session, false)?.ok_or("Activate Team to use this action".to_string())?;
    Ok(())
}

fn current_server_url_for_license(session: &crate::state::UserSession) -> String {
    session
        .server_url
        .as_deref()
        .unwrap_or_default()
        .trim_end_matches('/')
        .trim_end_matches("/api/v1")
        .to_string()
}

async fn status_from_cache(
    state: &AppState,
    session: &crate::state::UserSession,
    message: Option<String>,
) -> TeamLicenseStatus {
    let cached_org = match state.local_client.client().await {
        Ok(client) => client
            .load_local_config("desktop_organization_status")
            .await
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<OrganizationStatus>(&json).ok()),
        Err(_) => None,
    };
    match verified_claims(session, true) {
        Ok(Some(claims)) => TeamLicenseStatus {
            workspace: "team",
            organization: cached_org.filter(|org| org.id.to_string() == claims.organization_id),
            entitlement_expires_at: Some(claims.exp),
            can_write: !session.team_revoked && claims.exp > chrono::Utc::now().timestamp(),
            online: false,
            revoked: session.team_revoked,
            message,
        },
        Ok(None) => TeamLicenseStatus {
            workspace: "personal",
            organization: None,
            entitlement_expires_at: None,
            can_write: false,
            online: false,
            revoked: false,
            message,
        },
        Err(err) => TeamLicenseStatus {
            workspace: if session.team_entitlement.is_some() {
                "team"
            } else {
                "personal"
            },
            organization: None,
            entitlement_expires_at: None,
            can_write: false,
            online: false,
            revoked: session.team_revoked,
            message: Some(format!("Cached Team license could not be verified: {err}")),
        },
    }
}

fn verify_server_entitlement(
    session: &crate::state::UserSession,
    response: &EntitlementResponse,
) -> Result<Claims, String> {
    let keys = entitlement::trusted_keys_from_build()?;
    let claims = entitlement::verify(
        &response.token,
        &keys,
        &current_server_url_for_license(session),
        &session.user_id,
        chrono::Utc::now().timestamp(),
    )?;
    if claims.organization_id != response.organization.id.to_string()
        || claims.entitlement_version != response.organization.entitlement_version
        || claims.max_members != response.organization.seat_limit as u32
    {
        return Err("Team license does not match organization status".into());
    }
    Ok(claims)
}

async fn save_team_state(
    state: &AppState,
    session: &crate::state::UserSession,
    token: Option<String>,
    revoked: bool,
) -> Result<(), String> {
    let _queue_guard = state.team_queue.lock().await;
    let mut updated = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    if updated.user_id != session.user_id {
        return Err("Account changed while saving Team access".into());
    }
    updated.team_entitlement = token;
    updated.team_revoked = revoked;
    state.local_client.update_write_access(&updated).await?;
    state.persist_refreshed_session(updated).await
}

#[tauri::command]
pub async fn get_team_license_status(
    state: State<'_, AppState>,
) -> Result<TeamLicenseStatus, String> {
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    if session.expires_at <= chrono::Utc::now().timestamp() {
        return Ok(status_from_cache(
            &state,
            &session,
            Some("Sign in again to refresh Team access".into()),
        )
        .await);
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|err| err.to_string())?;
    let status_url = api_endpoint(&current_server_url(&state, &session), "organizations/me");
    let response = match client
        .get(status_url)
        .bearer_auth(&session.token)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return Ok(status_from_cache(
                &state,
                &session,
                Some("Offline: showing cached Team access".into()),
            )
            .await)
        }
    };
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(status_from_cache(
            &state,
            &session,
            Some("Sign in again to refresh Team access".into()),
        )
        .await);
    }
    if !response.status().is_success() {
        return Err(format!("Organization status failed: {}", response.status()));
    }
    let org: Option<OrganizationStatus> = response.json().await.map_err(|err| err.to_string())?;
    let Some(org) = org else {
        if session.team_entitlement.is_some() {
            if !session.team_revoked {
                save_team_state(&state, &session, session.team_entitlement.clone(), true).await?;
            }
            let mut status = status_from_cache(
                &state,
                &session,
                Some("Team membership ended; existing local data can still be exported".into()),
            )
            .await;
            status.online = true;
            status.revoked = true;
            status.can_write = false;
            return Ok(status);
        }
        return Ok(TeamLicenseStatus {
            workspace: "personal",
            organization: None,
            entitlement_expires_at: None,
            can_write: false,
            online: true,
            revoked: false,
            message: None,
        });
    };
    let local = state.local_client.client().await?;
    local
        .store_local_config(
            "desktop_organization_status",
            &serde_json::to_string(&org).map_err(|error| error.to_string())?,
        )
        .await
        .map_err(|error| error.to_string())?;
    if org.license_status != "active" {
        if !session.team_revoked {
            save_team_state(&state, &session, session.team_entitlement.clone(), true).await?;
        }
        let mut status = status_from_cache(
            &state,
            &session,
            Some("Team license revoked; existing local data remains available for export".into()),
        )
        .await;
        status.workspace = "team";
        status.organization = Some(org);
        status.online = true;
        status.can_write = false;
        status.revoked = true;
        return Ok(status);
    }
    if !session.team_revoked {
        if let Ok(Some(claims)) = verified_claims(&session, false) {
            if claims.organization_id == org.id.to_string()
                && claims.entitlement_version == org.entitlement_version
                && claims.max_members == org.seat_limit as u32
                && claims.exp - chrono::Utc::now().timestamp() > 7 * 24 * 60 * 60
            {
                return Ok(TeamLicenseStatus {
                    workspace: "team",
                    organization: Some(org),
                    entitlement_expires_at: Some(claims.exp),
                    can_write: true,
                    online: true,
                    revoked: false,
                    message: None,
                });
            }
        }
    }
    let url = api_endpoint(
        &current_server_url(&state, &session),
        "organizations/me/entitlement",
    );
    let response = client
        .get(url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|err| format!("Entitlement refresh failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("Entitlement refresh failed: {}", response.status()));
    }
    let entitlement: EntitlementResponse = response.json().await.map_err(|err| err.to_string())?;
    let claims = verify_server_entitlement(&session, &entitlement)?;
    state
        .local_client
        .client()
        .await?
        .store_local_config(
            "desktop_organization_status",
            &serde_json::to_string(&entitlement.organization).map_err(|error| error.to_string())?,
        )
        .await
        .map_err(|error| error.to_string())?;
    if session.team_entitlement.as_deref() != Some(entitlement.token.as_str())
        || session.team_revoked
    {
        save_team_state(&state, &session, Some(entitlement.token), false).await?;
    }
    Ok(TeamLicenseStatus {
        workspace: "team",
        organization: Some(org),
        entitlement_expires_at: Some(claims.exp),
        can_write: true,
        online: true,
        revoked: false,
        message: None,
    })
}

#[tauri::command]
pub async fn redeem_team_code(
    code: String,
    organization_name: String,
    state: State<'_, AppState>,
) -> Result<TeamLicenseStatus, String> {
    let _guard = ensure_authenticated(&state).await?;
    let session = current_authenticated_session(&state).await?;
    let response = reqwest::Client::new()
        .post(api_endpoint(
            &current_server_url(&state, &session),
            "organizations/redeem",
        ))
        .bearer_auth(&session.token)
        .json(&json!({"code": code.trim(), "organization_name": organization_name.trim()}))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("Team activation failed: {}", response.status()));
    }
    let entitlement: EntitlementResponse = response.json().await.map_err(|err| err.to_string())?;
    let claims = verify_server_entitlement(&session, &entitlement)?;
    state
        .local_client
        .client()
        .await?
        .store_local_config(
            "desktop_organization_status",
            &serde_json::to_string(&entitlement.organization).map_err(|error| error.to_string())?,
        )
        .await
        .map_err(|error| error.to_string())?;
    save_team_state(&state, &session, Some(entitlement.token), false).await?;
    Ok(TeamLicenseStatus {
        workspace: "team",
        organization: Some(entitlement.organization),
        entitlement_expires_at: Some(claims.exp),
        can_write: true,
        online: true,
        revoked: false,
        message: None,
    })
}

#[tauri::command]
pub async fn accept_team_invitation(
    code: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let _guard = ensure_authenticated(&state).await?;
    let session = current_authenticated_session(&state).await?;
    let response = reqwest::Client::new()
        .post(api_endpoint(
            &current_server_url(&state, &session),
            "organizations/invitations/accept",
        ))
        .bearer_auth(&session.token)
        .json(&json!({"invitation_code": code.trim()}))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "Team invitation could not be accepted: {}",
            response.status()
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn invite_team_member(
    email: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let _guard = ensure_authenticated(&state).await?;
    let session = current_authenticated_session(&state).await?;
    let response = reqwest::Client::new()
        .post(api_endpoint(
            &current_server_url(&state, &session),
            "organizations/me/invitations",
        ))
        .bearer_auth(&session.token)
        .json(&json!({"email": email.trim()}))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("Team invitation failed: {}", response.status()));
    }
    let value: Value = response.json().await.map_err(|err| err.to_string())?;
    value
        .get("invitation_code")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or("Server did not return an invitation code".into())
}

#[derive(Debug, Deserialize)]
struct TeamAdminResult {
    request_id: Uuid,
    result_id: Option<Uuid>,
}

#[tauri::command]
pub async fn list_team_admin_requests(
    state: State<'_, AppState>,
) -> Result<Vec<PendingTeamRequest>, String> {
    let session = state.session.lock().await;
    Ok(session
        .as_ref()
        .ok_or("No account is open")?
        .pending_team_requests
        .clone())
}

#[tauri::command]
pub async fn get_team_directory(state: State<'_, AppState>) -> Result<Value, String> {
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    let local = state.local_client.client().await?;
    let mut cached = local
        .cached_team_directory()
        .await
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| json!({"members": [], "invitations": [], "role": null}));
    cached["online"] = json!(false);
    if session.expires_at <= chrono::Utc::now().timestamp() {
        return Ok(cached);
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|error| error.to_string())?;
    let members = match http
        .get(api_endpoint(
            &current_server_url(&state, &session),
            "organizations/me/members",
        ))
        .bearer_auth(&session.token)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response
            .json::<Vec<Value>>()
            .await
            .map_err(|error| error.to_string())?,
        _ => return Ok(cached),
    };
    let role = members
        .iter()
        .find(|member| member["user_id"].as_str() == Some(session.user_id.as_str()))
        .and_then(|member| member["role"].as_str())
        .map(str::to_string);
    let invitations = if role
        .as_deref()
        .is_some_and(|role| matches!(role, "owner" | "admin"))
    {
        match http
            .get(api_endpoint(
                &current_server_url(&state, &session),
                "organizations/me/invitations",
            ))
            .bearer_auth(&session.token)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => response
                .json::<Vec<Value>>()
                .await
                .map_err(|error| error.to_string())?,
            _ => return Ok(cached),
        }
    } else {
        Vec::new()
    };
    let directory =
        json!({"members": members, "invitations": invitations, "role": role, "online": true});
    local
        .cache_team_directory(&directory)
        .await
        .map_err(|error| error.to_string())?;
    Ok(directory)
}

#[tauri::command]
pub async fn queue_team_admin_request(
    kind: String,
    email: Option<String>,
    group_name: Option<String>,
    description: Option<String>,
    target_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<PendingTeamRequest, String> {
    require_team_write(&state).await?;
    let _queue_guard = state.team_queue.lock().await;
    let mut session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    if !session.persistent {
        return Err("Save this account on this device before queuing offline requests".into());
    }
    if session.pending_team_requests.len() >= 100 {
        return Err("Review earlier Team requests before adding more".into());
    }
    let claims = verified_claims(&session, false)?.ok_or("Activate Team first")?;
    let organization_id =
        Uuid::parse_str(&claims.organization_id).map_err(|_| "Invalid Team organization ID")?;
    let email = email.map(|value| value.trim().to_lowercase());
    let group_name = group_name.map(|value| value.trim().to_string());
    let target_id = target_id
        .map(|value| Uuid::parse_str(&value).map_err(|_| "Invalid target ID"))
        .transpose()?;
    let invitation_code = match kind.as_str() {
        "invite_member"
            if email
                .as_deref()
                .is_some_and(|value| value.contains('@') && value.len() <= 255) =>
        {
            let mut bytes = [0u8; 24];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            Some(format!("HC-INVITE-{}", hex::encode_upper(bytes)))
        }
        "create_group"
            if group_name
                .as_deref()
                .is_some_and(|value| !value.is_empty() && value.len() <= 100) =>
        {
            None
        }
        "cancel_invitation" | "remove_member" if target_id.is_some() => None,
        _ => return Err("Invalid Team administration request".into()),
    };
    let entry = PendingTeamRequest {
        request: TeamAdminRequest {
            id: Uuid::new_v4(),
            organization_id,
            kind,
            email,
            invitation_code,
            group_name,
            description,
            target_id,
        },
        created_at: chrono::Utc::now().timestamp(),
        status: "pending".into(),
        result_id: None,
        last_error: None,
    };
    session.pending_team_requests.push(entry.clone());
    state.persist_team_queue(session).await?;
    Ok(entry)
}

#[tauri::command]
pub async fn sync_team_admin_requests(
    state: State<'_, AppState>,
) -> Result<Vec<PendingTeamRequest>, String> {
    let _guard = ensure_authenticated(&state).await?;
    require_team_write(&state).await?;
    let _queue_guard = state.team_queue.lock().await;
    let mut session = current_authenticated_session(&state).await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|err| err.to_string())?;
    let endpoint = api_endpoint(
        &current_server_url(&state, &session),
        "organizations/me/requests",
    );
    for index in 0..session.pending_team_requests.len() {
        if session.pending_team_requests[index].status == "initializing" {
            let group_id = session.pending_team_requests[index]
                .result_id
                .ok_or("Missing created group ID")?;
            let local = state.local_client.client().await?;
            match local.ensure_group_initialized(group_id).await {
                Ok(()) => {
                    session.pending_team_requests[index].status = "accepted".into();
                    session.pending_team_requests[index].last_error = None;
                }
                Err(error) => {
                    session.pending_team_requests[index].last_error =
                        Some(format!("Group created; encryption setup pending: {error}"));
                    state.persist_team_queue(session.clone()).await?;
                    break;
                }
            }
            state.persist_team_queue(session.clone()).await?;
            continue;
        }
        if session.pending_team_requests[index].status != "pending" {
            continue;
        }
        let request = session.pending_team_requests[index].request.clone();
        let response = match client
            .post(&endpoint)
            .bearer_auth(&session.token)
            .json(&request)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => break,
        };
        if response.status().is_success() {
            let result: TeamAdminResult = response.json().await.map_err(|err| err.to_string())?;
            if result.request_id != request.id {
                return Err("Mismatched Team request result".into());
            }
            session.pending_team_requests[index].status = if request.kind == "create_group" {
                "initializing"
            } else {
                "accepted"
            }
            .into();
            session.pending_team_requests[index].result_id = result.result_id;
            session.pending_team_requests[index].last_error = None;
        } else if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED
                | reqwest::StatusCode::REQUEST_TIMEOUT
                | reqwest::StatusCode::TOO_MANY_REQUESTS
        ) {
            break;
        } else if response.status().is_client_error() {
            session.pending_team_requests[index].status = "rejected".into();
            session.pending_team_requests[index].last_error =
                Some(format!("Server rejected request: {}", response.status()));
        } else {
            break;
        }
        state.persist_team_queue(session.clone()).await?;
        if session.pending_team_requests[index].status == "initializing" {
            let group_id = session.pending_team_requests[index]
                .result_id
                .ok_or("Missing created group ID")?;
            let local = state.local_client.client().await?;
            match local.ensure_group_initialized(group_id).await {
                Ok(()) => {
                    session.pending_team_requests[index].status = "accepted".into();
                    session.pending_team_requests[index].last_error = None;
                }
                Err(error) => {
                    session.pending_team_requests[index].last_error =
                        Some(format!("Group created; encryption setup pending: {error}"));
                    state.persist_team_queue(session.clone()).await?;
                    break;
                }
            }
            state.persist_team_queue(session.clone()).await?;
        }
    }
    Ok(session.pending_team_requests.clone())
}

#[tauri::command]
pub async fn dismiss_team_admin_request(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    dismiss_team_admin_request_internal(request_id, state).await
}

/// Persist request identity before sending, so an uncertain response cannot create another group.
pub(super) async fn create_group_durably(
    state: &AppState,
    name: &str,
    description: Option<String>,
) -> Result<Uuid, String> {
    require_team_write(state).await?;
    let _queue_guard = state.team_queue.lock().await;
    let mut session = current_authenticated_session(state).await?;
    if !session.persistent {
        return Err("Save this account on this device before creating a Team group".into());
    }
    let claims = verified_claims(&session, false)?.ok_or("Activate Team first")?;
    let organization_id =
        Uuid::parse_str(&claims.organization_id).map_err(|_| "Invalid organization ID")?;
    let existing = session.pending_team_requests.iter().position(|entry| {
        entry.request.kind == "create_group"
            && entry.request.organization_id == organization_id
            && entry.request.group_name.as_deref() == Some(name)
            && entry.request.description == description
            && matches!(entry.status.as_str(), "pending" | "initializing")
    });
    let index = if let Some(index) = existing {
        index
    } else {
        if session.pending_team_requests.len() >= 100 {
            return Err("Review earlier Team requests before adding more".into());
        }
        session.pending_team_requests.push(PendingTeamRequest {
            request: TeamAdminRequest {
                id: Uuid::new_v4(),
                organization_id,
                kind: "create_group".into(),
                email: None,
                invitation_code: None,
                group_name: Some(name.into()),
                description,
                target_id: None,
            },
            created_at: chrono::Utc::now().timestamp(),
            status: "pending".into(),
            result_id: None,
            last_error: None,
        });
        state.persist_team_queue(session.clone()).await?;
        session.pending_team_requests.len() - 1
    };
    if let Some(id) = session.pending_team_requests[index].result_id {
        return Ok(id);
    }
    let request = session.pending_team_requests[index].request.clone();
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| error.to_string())?;
    let response = http
        .post(api_endpoint(
            &current_server_url(state, &session),
            "organizations/me/requests",
        ))
        .bearer_auth(&session.token)
        .json(&request)
        .send()
        .await
        .map_err(|_| {
            "The request was saved. Reconnect and retry to recover the same group.".to_string()
        })?;
    if !response.status().is_success() {
        if response.status().is_client_error()
            && !matches!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED
                    | reqwest::StatusCode::REQUEST_TIMEOUT
                    | reqwest::StatusCode::TOO_MANY_REQUESTS
            )
        {
            session.pending_team_requests[index].status = "rejected".into();
            session.pending_team_requests[index].last_error = Some(format!(
                "Server rejected group creation ({})",
                response.status()
            ));
            state.persist_team_queue(session).await?;
        }
        return Err(format!(
            "Group creation could not continue ({})",
            response.status()
        ));
    }
    let result: TeamAdminResult = response
        .json()
        .await
        .map_err(|_| "The request was saved. Retry to recover its group ID.".to_string())?;
    if result.request_id != request.id {
        return Err("Group creation returned a mismatched request identity".into());
    }
    let group = result.result_id.ok_or("Created group ID missing")?;
    session.pending_team_requests[index].status = "initializing".into();
    session.pending_team_requests[index].result_id = Some(group);
    state.persist_team_queue(session).await?;
    Ok(group)
}

pub(super) async fn finish_group_creation(state: &AppState, group: Uuid) -> Result<(), String> {
    let _queue_guard = state.team_queue.lock().await;
    let mut session = current_authenticated_session(state).await?;
    for entry in &mut session.pending_team_requests {
        if entry.request.kind == "create_group"
            && entry.result_id == Some(group)
            && entry.status == "initializing"
        {
            entry.status = "accepted".into();
            entry.last_error = None;
        }
    }
    state.persist_team_queue(session).await
}

async fn dismiss_team_admin_request_internal(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let id = Uuid::parse_str(&request_id).map_err(|_| "Invalid request ID")?;
    let _queue_guard = state.team_queue.lock().await;
    let mut session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    let before = session.pending_team_requests.len();
    session.pending_team_requests.retain(|entry| {
        entry.request.id != id || !matches!(entry.status.as_str(), "accepted" | "rejected")
    });
    if session.pending_team_requests.len() == before {
        return Err("Only accepted or rejected requests can be cleared".into());
    }
    state.persist_team_queue(session).await
}
