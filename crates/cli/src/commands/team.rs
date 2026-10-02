//! Team activation and organization administration from the unified CLI.

use crate::{
    error::CliError,
    session::{Session, SessionManager},
};
use clap::Subcommand;
use hybridcipher_client::entitlement::{self, Claims};
use hybridcipher_client::team_requests::{PendingTeamRequest, TeamAdminRequest};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Clone, Debug, Subcommand)]
pub enum TeamCommand {
    /// Redeem a single-use code and create an organization
    Redeem {
        code: String,
        #[arg(long)]
        name: String,
    },
    /// Show the current organization's license and refresh the entitlement
    Status,
    /// Reserve a seat and issue an invitation code
    Invite { email: String },
    /// Join the organization named by an invitation code
    Accept { code: String },
    /// List organization members
    Members,
    /// Cancel a pending invitation and release its seat
    CancelInvitation { invitation_id: Uuid },
    /// Remove a member from the organization
    RemoveMember { user_id: Uuid },
    /// Save an invitation request for ordered replay after reconnecting
    QueueInvite { email: String },
    /// Save a group creation request for ordered replay after reconnecting
    QueueCreateGroup {
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    /// Save an invitation cancellation request for ordered replay
    QueueCancelInvitation { invitation_id: Uuid },
    /// Save a member removal request for ordered replay
    QueueRemoveMember { user_id: Uuid },
    /// Show pending, accepted, and rejected administration requests
    Requests,
    /// Replay pending administration requests in order
    SyncRequests,
    /// Clear an accepted or rejected request from the journal
    DismissRequest { request_id: Uuid },
}

#[derive(Debug, Deserialize)]
struct OrganizationStatus {
    id: Uuid,
    name: String,
    role: String,
    license_status: String,
    seat_limit: i32,
    seats_used: i64,
    entitlement_version: i64,
}

#[derive(Debug, Deserialize)]
struct EntitlementResponse {
    organization: OrganizationStatus,
    token: String,
}

fn api_endpoint(server_url: &str, path: &str) -> String {
    let trimmed = server_url.trim_end_matches('/');
    if trimmed.ends_with("/api/v1") {
        format!("{trimmed}/{path}")
    } else {
        format!("{trimmed}/api/v1/{path}")
    }
}

fn session(manager: &SessionManager) -> Result<Session, CliError> {
    manager.ensure_session_loaded()?;
    manager
        .current_session()
        .ok_or_else(|| CliError::session("Sign in before using Team commands"))
}

fn verify_entitlement(
    session: &Session,
    response: &EntitlementResponse,
) -> Result<Claims, CliError> {
    let keys = entitlement::trusted_keys_from_build().map_err(CliError::configuration)?;
    let claims = entitlement::verify(
        &response.token,
        &keys,
        session.server_url.trim_end_matches("/api/v1"),
        &session.user_id,
        chrono::Utc::now().timestamp(),
    )
    .map_err(CliError::permission)?;
    if claims.organization_id != response.organization.id.to_string()
        || claims.entitlement_version != response.organization.entitlement_version
        || claims.max_members != response.organization.seat_limit as u32
    {
        return Err(CliError::permission(
            "Team entitlement does not match organization status",
        ));
    }
    Ok(claims)
}

async fn online_status(manager: &SessionManager) -> Result<Option<OrganizationStatus>, CliError> {
    let mut session = session(manager)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|err| CliError::network(err.to_string()))?;
    let response = client
        .get(api_endpoint(&session.server_url, "organizations/me"))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|err| CliError::network(err.to_string()))?;
    if !response.status().is_success() {
        return Err(CliError::permission(format!(
            "Organization status rejected: {}",
            response.status()
        )));
    }
    let org: Option<OrganizationStatus> = response
        .json()
        .await
        .map_err(|err| CliError::permission(format!("Invalid organization status: {err}")))?;
    let Some(org) = org else {
        if session.team_entitlement.is_some() && !session.team_revoked {
            session.team_revoked = true;
            manager.store_session(session)?;
            manager.persist_local_write_access().await?;
        }
        return Ok(None);
    };
    if org.license_status != "active" {
        session.team_revoked = true;
        manager.store_session(session)?;
        manager.persist_local_write_access().await?;
        return Ok(Some(org));
    }
    if !session.team_revoked {
        if let Some(token) = session.team_entitlement.as_deref() {
            if let Ok(keys) = entitlement::trusted_keys_from_build() {
                if let Ok(claims) = entitlement::verify(
                    token,
                    &keys,
                    session.server_url.trim_end_matches("/api/v1"),
                    &session.user_id,
                    chrono::Utc::now().timestamp(),
                ) {
                    if claims.organization_id == org.id.to_string()
                        && claims.entitlement_version == org.entitlement_version
                        && claims.max_members == org.seat_limit as u32
                        && claims.exp - chrono::Utc::now().timestamp() > 7 * 24 * 60 * 60
                    {
                        return Ok(Some(org));
                    }
                }
            }
        }
    }
    let response = client
        .get(api_endpoint(
            &session.server_url,
            "organizations/me/entitlement",
        ))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|err| CliError::network(err.to_string()))?;
    if !response.status().is_success() {
        return Err(CliError::permission(format!(
            "Entitlement refresh rejected: {}",
            response.status()
        )));
    }
    let entitlement: EntitlementResponse = response
        .json()
        .await
        .map_err(|err| CliError::permission(format!("Invalid entitlement response: {err}")))?;
    verify_entitlement(&session, &entitlement)?;
    session.team_entitlement = Some(entitlement.token);
    session.team_revoked = false;
    manager.store_session(session)?;
    manager.persist_local_write_access().await?;
    Ok(Some(org))
}

/// Server status wins when reachable; a signed cached entitlement permits
/// local Team work for at most 30 days when the network is unavailable.
pub async fn require_team_write_entitlement(manager: &SessionManager) -> Result<(), CliError> {
    let saved = session(manager)?;
    // An expired login cannot make server requests. Its signed entitlement can
    // still authorize local work until the entitlement itself expires.
    if saved.expires_at > chrono::Utc::now() {
        match online_status(manager).await {
            Ok(Some(org)) if org.license_status != "active" => {
                return Err(CliError::permission("Team license has been revoked"));
            }
            Ok(None) => return Err(CliError::permission("Activate Team to use this command")),
            Ok(Some(_)) | Err(CliError::Network { .. }) => {}
            Err(err) => return Err(err),
        }
    }
    let session = session(manager)?;
    if session.team_revoked {
        return Err(CliError::permission("Team license has been revoked"));
    }
    let token = session
        .team_entitlement
        .as_deref()
        .ok_or_else(|| CliError::permission("Activate Team to use this command"))?;
    let keys = entitlement::trusted_keys_from_build().map_err(CliError::configuration)?;
    entitlement::verify(
        token,
        &keys,
        session.server_url.trim_end_matches("/api/v1"),
        &session.user_id,
        chrono::Utc::now().timestamp(),
    )
    .map_err(CliError::permission)?;
    Ok(())
}

/// Personal groups remain usable; a Team group's local encryption requires a
/// valid cached entitlement, even when the login session has expired offline.
pub async fn require_local_file_write_for_group(
    manager: &SessionManager,
    group_id: Uuid,
) -> Result<(), CliError> {
    let organization = match manager.cached_group_organization(&group_id).await? {
        Some(organization) => Some(organization),
        None if manager.is_authenticated() => {
            let groups = manager.list_groups_http().await?;
            groups
                .into_iter()
                .find(|group| group.id == group_id.to_string())
                .map(|group| group.organization_id)
        }
        None => None,
    };
    match organization {
        Some(Some(_)) => manager
            .create_local_client()
            .await?
            .require_local_write_for_group(group_id)
            .await
            .map_err(|error| CliError::permission(error.to_string())),
        Some(None) => Ok(()),
        None => {
            let saved = session(manager)?;
            if saved.team_entitlement.is_none() && !saved.team_revoked {
                // Before Team activation, existing offline groups are Personal.
                Ok(())
            } else {
                Err(CliError::permission(
                    "The selected group's workspace is unknown. Sign in and refresh the group list before writing.",
                ))
            }
        }
    }
}

pub async fn refresh_entitlement_after_login(manager: &SessionManager) {
    let _ = online_status(manager).await;
    if manager.load_team_request_queue().ok().is_some_and(|queue| {
        queue
            .iter()
            .any(|entry| matches!(entry.status.as_str(), "pending" | "initializing"))
    }) {
        if let Err(err) = sync_requests(manager).await {
            eprintln!("Team request replay paused: {err}");
        }
    }
}

fn cached_team_claims(manager: &SessionManager) -> Result<Claims, CliError> {
    let saved = session(manager)?;
    if saved.team_revoked {
        return Err(CliError::permission("Team license has been revoked"));
    }
    let token = saved
        .team_entitlement
        .as_deref()
        .ok_or_else(|| CliError::permission("Activate Team before queuing administration"))?;
    let keys = entitlement::trusted_keys_from_build().map_err(CliError::configuration)?;
    entitlement::verify(
        token,
        &keys,
        saved.server_url.trim_end_matches("/api/v1"),
        &saved.user_id,
        chrono::Utc::now().timestamp(),
    )
    .map_err(CliError::permission)
}

fn queue_request(manager: &SessionManager, request: TeamAdminRequest) -> Result<(), CliError> {
    let mut queue = manager.load_team_request_queue()?;
    let request_id = request.id;
    queue.push(PendingTeamRequest {
        request,
        created_at: chrono::Utc::now().timestamp(),
        status: "pending".into(),
        result_id: None,
        last_error: None,
    });
    manager.store_team_request_queue(&queue)?;
    println!("Saved Team request {request_id}. It takes effect only after server acceptance.");
    Ok(())
}

fn new_request(manager: &SessionManager, kind: &str) -> Result<TeamAdminRequest, CliError> {
    let claims = cached_team_claims(manager)?;
    let organization_id = Uuid::parse_str(&claims.organization_id)
        .map_err(|_| CliError::permission("Invalid organization in Team entitlement"))?;
    Ok(TeamAdminRequest {
        id: Uuid::new_v4(),
        organization_id,
        kind: kind.into(),
        email: None,
        invitation_code: None,
        group_name: None,
        description: None,
        target_id: None,
    })
}

async fn sync_requests(manager: &SessionManager) -> Result<(), CliError> {
    let saved = manager.require_auth()?;
    let org = online_status(manager)
        .await?
        .ok_or_else(|| CliError::permission("No Team organization is active"))?;
    if org.license_status != "active" {
        return Err(CliError::permission("Team license has been revoked"));
    }
    let mut queue = manager.load_team_request_queue()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|err| CliError::network(err.to_string()))?;
    for index in 0..queue.len() {
        if queue[index].status == "initializing" {
            if !finish_group_setup(manager, &mut queue, index).await? {
                break;
            }
            continue;
        }
        if queue[index].status != "pending" {
            continue;
        }
        let request = queue[index].request.clone();
        let response = match client
            .post(api_endpoint(&saved.server_url, "organizations/me/requests"))
            .bearer_auth(&saved.token)
            .json(&request)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                println!("Replay paused: {err}");
                break;
            }
        };
        if response.status().is_success() {
            let value: Value = response
                .json()
                .await
                .map_err(|err| CliError::network(format!("Invalid request result: {err}")))?;
            if value["request_id"].as_str() != Some(&request.id.to_string()) {
                return Err(CliError::network(
                    "Server returned a mismatched Team request ID",
                ));
            }
            queue[index].status = if request.kind == "create_group" {
                "initializing"
            } else {
                "accepted"
            }
            .into();
            queue[index].result_id = value["result_id"]
                .as_str()
                .and_then(|id| Uuid::parse_str(id).ok());
            queue[index].last_error = None;
        } else if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED
                | reqwest::StatusCode::REQUEST_TIMEOUT
                | reqwest::StatusCode::TOO_MANY_REQUESTS
        ) {
            println!("Replay paused: {}", response.status());
            break;
        } else if response.status().is_client_error() {
            queue[index].status = "rejected".into();
            queue[index].last_error =
                Some(format!("Server rejected request: {}", response.status()));
        } else {
            println!("Replay paused: {}", response.status());
            break;
        }
        manager.store_team_request_queue(&queue)?;
        if queue[index].status == "initializing"
            && !finish_group_setup(manager, &mut queue, index).await?
        {
            break;
        }
    }
    println!(
        "Team request journal: {} pending, {} accepted, {} rejected",
        queue
            .iter()
            .filter(|entry| entry.status == "pending")
            .count(),
        queue
            .iter()
            .filter(|entry| entry.status == "accepted")
            .count(),
        queue
            .iter()
            .filter(|entry| entry.status == "rejected")
            .count()
    );
    Ok(())
}

async fn finish_group_setup(
    manager: &SessionManager,
    queue: &mut [PendingTeamRequest],
    index: usize,
) -> Result<bool, CliError> {
    let group_id = queue[index]
        .result_id
        .ok_or_else(|| CliError::configuration("Missing created group ID"))?;
    let client = manager.create_client().await?;
    match client.ensure_group_initialized(group_id).await {
        Ok(()) => {
            queue[index].status = "accepted".into();
            queue[index].last_error = None;
        }
        Err(error) => {
            queue[index].last_error =
                Some(format!("Group created; encryption setup pending: {error}"));
            manager.store_team_request_queue(queue)?;
            return Ok(false);
        }
    }
    manager.store_team_request_queue(queue)?;
    Ok(true)
}

pub async fn handle_team_command(
    command: TeamCommand,
    manager: &SessionManager,
) -> Result<(), CliError> {
    match command {
        TeamCommand::Redeem { code, name } => {
            let mut session = session(manager)?;
            let response = reqwest::Client::new()
                .post(api_endpoint(&session.server_url, "organizations/redeem"))
                .bearer_auth(&session.token)
                .json(&json!({"code": code.trim(), "organization_name": name.trim()}))
                .send()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            if !response.status().is_success() {
                return Err(CliError::network(format!(
                    "Team activation failed: {}",
                    response.status()
                )));
            }
            let entitlement: EntitlementResponse = response
                .json()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            verify_entitlement(&session, &entitlement)?;
            session.team_entitlement = Some(entitlement.token);
            session.team_revoked = false;
            manager.store_session(session)?;
            manager.persist_local_write_access().await?;
            println!(
                "Team organization '{}' activated ({} seats)",
                entitlement.organization.name, entitlement.organization.seat_limit
            );
        }
        TeamCommand::Status => match online_status(manager).await {
            Ok(Some(org)) => println!(
                "{}: {} ({}/{} seats, role {})",
                org.name, org.license_status, org.seats_used, org.seat_limit, org.role
            ),
            Ok(None) => {
                let saved = session(manager)?;
                if saved.team_entitlement.is_some() {
                    println!(
                        "Team membership ended. Existing local data remains available for export."
                    );
                } else {
                    println!("Personal workspace. No Team organization is active.");
                }
            }
            Err(err @ CliError::Network { .. }) => {
                let session = session(manager)?;
                if let Some(token) = session.team_entitlement.as_deref() {
                    let keys =
                        entitlement::trusted_keys_from_build().map_err(CliError::configuration)?;
                    let claims = entitlement::verify_for_existing_data(
                        token,
                        &keys,
                        session.server_url.trim_end_matches("/api/v1"),
                        &session.user_id,
                        chrono::Utc::now().timestamp(),
                    )
                    .map_err(CliError::permission)?;
                    println!(
                        "Offline Team access: {} ({}; expires {})",
                        claims.organization_id,
                        if session.team_revoked || claims.exp <= chrono::Utc::now().timestamp() {
                            "read-only"
                        } else {
                            "cached"
                        },
                        claims.exp
                    );
                } else {
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        },
        TeamCommand::Accept { code } => {
            let session = session(manager)?;
            let response = reqwest::Client::new()
                .post(api_endpoint(
                    &session.server_url,
                    "organizations/invitations/accept",
                ))
                .bearer_auth(&session.token)
                .json(&json!({"invitation_code": code.trim()}))
                .send()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            if !response.status().is_success() {
                return Err(CliError::network(format!(
                    "Team invitation failed: {}",
                    response.status()
                )));
            }
            online_status(manager).await?;
            println!("Joined Team organization");
        }
        TeamCommand::Invite { email } => {
            let session = session(manager)?;
            let response = reqwest::Client::new()
                .post(api_endpoint(
                    &session.server_url,
                    "organizations/me/invitations",
                ))
                .bearer_auth(&session.token)
                .json(&json!({"email": email.trim()}))
                .send()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            if !response.status().is_success() {
                return Err(CliError::network(format!(
                    "Invitation failed: {}",
                    response.status()
                )));
            }
            let value: Value = response
                .json()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            let code = value
                .get("invitation_code")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::network("Invitation code missing from response"))?;
            println!("{code}");
        }
        TeamCommand::Members => {
            let session = session(manager)?;
            let response = reqwest::Client::new()
                .get(api_endpoint(
                    &session.server_url,
                    "organizations/me/members",
                ))
                .bearer_auth(&session.token)
                .send()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            if !response.status().is_success() {
                return Err(CliError::network(format!(
                    "Members request failed: {}",
                    response.status()
                )));
            }
            let members: Vec<Value> = response
                .json()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            for member in members {
                println!(
                    "{}  {}  {}",
                    member["user_id"], member["email"], member["role"]
                );
            }
        }
        TeamCommand::CancelInvitation { invitation_id } => {
            let session = session(manager)?;
            let response = reqwest::Client::new()
                .delete(api_endpoint(
                    &session.server_url,
                    &format!("organizations/me/invitations/{invitation_id}"),
                ))
                .bearer_auth(&session.token)
                .send()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            if !response.status().is_success() {
                return Err(CliError::network(format!(
                    "Cancellation failed: {}",
                    response.status()
                )));
            }
            println!("Invitation cancelled");
        }
        TeamCommand::RemoveMember { user_id } => {
            let session = session(manager)?;
            let response = reqwest::Client::new()
                .delete(api_endpoint(
                    &session.server_url,
                    &format!("organizations/me/members/{user_id}"),
                ))
                .bearer_auth(&session.token)
                .send()
                .await
                .map_err(|err| CliError::network(err.to_string()))?;
            if !response.status().is_success() {
                return Err(CliError::network(format!(
                    "Member removal failed: {}",
                    response.status()
                )));
            }
            println!("Member removed. Rekey affected groups to stop use of previously held keys.");
        }
        TeamCommand::QueueInvite { email } => {
            let email = email.trim().to_lowercase();
            if email.len() > 255 || !email.contains('@') {
                return Err(CliError::configuration("Enter a valid invitation email"));
            }
            let mut request = new_request(manager, "invite_member")?;
            let mut random = [0u8; 24];
            OsRng.fill_bytes(&mut random);
            request.email = Some(email);
            request.invitation_code = Some(format!("HC-INVITE-{}", hex::encode_upper(random)));
            queue_request(manager, request)?;
        }
        TeamCommand::QueueCreateGroup { name, description } => {
            let name = name.trim();
            if name.is_empty()
                || name.len() > 100
                || description.as_deref().is_some_and(|text| text.len() > 1000)
            {
                return Err(CliError::configuration(
                    "Invalid Team group name or description",
                ));
            }
            let mut request = new_request(manager, "create_group")?;
            request.group_name = Some(name.into());
            request.description = description;
            queue_request(manager, request)?;
        }
        TeamCommand::QueueCancelInvitation { invitation_id } => {
            let mut request = new_request(manager, "cancel_invitation")?;
            request.target_id = Some(invitation_id);
            queue_request(manager, request)?;
        }
        TeamCommand::QueueRemoveMember { user_id } => {
            let mut request = new_request(manager, "remove_member")?;
            request.target_id = Some(user_id);
            queue_request(manager, request)?;
        }
        TeamCommand::Requests => {
            session(manager)?;
            for entry in manager.load_team_request_queue()? {
                println!(
                    "{}  {}  {}  {}",
                    entry.request.id,
                    entry.status,
                    entry.request.kind,
                    entry
                        .request
                        .email
                        .as_deref()
                        .or(entry.request.group_name.as_deref())
                        .unwrap_or("")
                );
                if let Some(error) = entry.last_error.as_deref() {
                    println!("  {error}");
                }
                if entry.status == "accepted" {
                    if let Some(code) = entry.request.invitation_code.as_deref() {
                        println!("  invitation code: {code}");
                    }
                    if let Some(id) = entry.result_id {
                        println!("  result ID: {id}");
                    }
                }
            }
        }
        TeamCommand::SyncRequests => sync_requests(manager).await?,
        TeamCommand::DismissRequest { request_id } => {
            session(manager)?;
            let mut queue = manager.load_team_request_queue()?;
            let before = queue.len();
            queue.retain(|entry| {
                entry.request.id != request_id
                    || !matches!(entry.status.as_str(), "accepted" | "rejected")
            });
            if queue.len() == before {
                return Err(CliError::configuration(
                    "Only accepted or rejected requests can be cleared",
                ));
            }
            manager.store_team_request_queue(&queue)?;
            println!("Cleared Team request {request_id}");
        }
    }
    Ok(())
}
