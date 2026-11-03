//! Task-level Team actions (add a person, remove access, rotate keys, approve a device).
//! Each runs the bundled CLI's audited crypto steps and returns a structured result for the UI.
use super::operations::{
    last_task_result, progress_percent, run_cli_operation, update_phase, update_progress,
    validate_cli_args, DesktopOperationAnswer, DesktopOperationRequest,
};
use super::*;
use crate::state::UserSession;
use tokio::sync::{mpsc, watch};

const PENDING_GROUP_ADDS: &str = "desktop_pending_group_adds";

#[cfg(test)]
#[path = "../../tests/operations/test_team_tasks.rs"]
mod tests;

type TaskError = (String, String);

fn task_error(code: &str, message: impl Into<String>) -> TaskError {
    (code.into(), message.into())
}

/// Emails become CLI arguments, so anything that could read as an option is rejected.
pub(super) fn normalize_email(value: Option<&str>) -> Result<String, String> {
    let email = value.unwrap_or_default().trim().to_lowercase();
    let valid = email.len() <= 255
        && !email.starts_with('-')
        && !email.chars().any(char::is_whitespace)
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    if valid {
        Ok(email)
    } else {
        Err("Enter a valid email address".into())
    }
}

/// A member to remove is identified by user ID or email.
pub(super) fn normalize_member(value: Option<&str>) -> Result<String, String> {
    let member = value.unwrap_or_default().trim();
    if let Ok(id) = Uuid::parse_str(member) {
        return Ok(id.to_string());
    }
    normalize_email(Some(member)).map_err(|_| "Choose a member to remove".into())
}

pub(super) fn normalize_device_id(value: Option<&str>) -> Result<String, String> {
    let device = value.unwrap_or_default().trim();
    let valid = !device.is_empty()
        && device.len() <= 128
        && !device.starts_with('-')
        && device
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));
    if valid {
        Ok(device.to_string())
    } else {
        Err("Choose a device to approve".into())
    }
}

pub(super) async fn run_task_operation(
    id: &str,
    request: &DesktopOperationRequest,
    group: Option<Uuid>,
    session: &UserSession,
    state: &AppState,
    answers: &mut mpsc::Receiver<DesktopOperationAnswer>,
    cancel: &mut watch::Receiver<bool>,
) -> Result<Value, TaskError> {
    let group = group.ok_or_else(|| task_error("invalid_request", "Select a group"))?;
    let mut steps = Steps {
        id,
        group,
        session,
        state,
        answers,
        cancel,
    };
    match request.kind.as_str() {
        "add_member" => {
            let email = normalize_email(request.email.as_deref())
                .map_err(|message| task_error("invalid_request", message))?;
            steps.add_member(&email).await
        }
        "add_person" => {
            let email = normalize_email(request.email.as_deref())
                .map_err(|message| task_error("invalid_request", message))?;
            add_person(&mut steps, &email).await
        }
        "stage_invitation_access" => {
            let email = normalize_email(request.email.as_deref())
                .map_err(|message| task_error("invalid_request", message))?;
            let invitation = request
                .invitation_id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or_else(|| task_error("invalid_request", "Choose an invitation"))?;
            let access = steps.stage_invitation(invitation, &email).await;
            Ok(json!({
                "action": "invitation_access",
                "group_id": group,
                "email": email,
                "access": access,
            }))
        }
        "remove_access" => {
            let member = normalize_member(request.member.as_deref())
                .map_err(|message| task_error("invalid_request", message))?;
            update_phase(id, "Removing access", None).await;
            steps.cli(&["remove-member", &member, "--yes"]).await?;
            let rotation = if request.rotate_keys.unwrap_or(true) {
                Some(
                    steps
                        .rotate_keys(request.skip_unreachable.unwrap_or(false))
                        .await?,
                )
            } else {
                None
            };
            Ok(json!({
                "action": "access_removed",
                "group_id": group,
                "member": member,
                "keys_rotated": rotation.is_some(),
                "rotation": rotation,
            }))
        }
        "rotate_keys" => {
            let rotation = steps
                .rotate_keys(request.skip_unreachable.unwrap_or(false))
                .await?;
            Ok(json!({"action": "keys_rotated", "group_id": group, "rotation": rotation}))
        }
        "approve_device" => {
            let device = normalize_device_id(request.device_id.as_deref())
                .map_err(|message| task_error("invalid_request", message))?;
            update_phase(id, "Approving device", None).await;
            steps.cli(&["issue-welcome", "--device", &device]).await?;
            Ok(json!({
                "action": "device_approved",
                "group_id": group,
                "device_id": device,
                "detail": last_task_result(id, "device_approved").await,
            }))
        }
        _ => Err(task_error("invalid_request", "Unknown Team action")),
    }
}

struct Steps<'a> {
    id: &'a str,
    group: Uuid,
    session: &'a UserSession,
    state: &'a AppState,
    answers: &'a mut mpsc::Receiver<DesktopOperationAnswer>,
    cancel: &'a mut watch::Receiver<bool>,
}

impl Steps<'_> {
    async fn cli(&mut self, args: &[&str]) -> Result<Value, TaskError> {
        if *self.cancel.borrow() {
            return Err(task_error(
                "operation_cancelled",
                "Operation cancelled. Review its state before retrying.",
            ));
        }
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        validate_cli_args(&args, Some(self.group))
            .map_err(|message| task_error("invalid_request", message))?;
        run_cli_operation(
            self.id,
            &args,
            Some(self.group),
            self.session,
            self.state,
            self.answers,
            self.cancel,
        )
        .await
    }

    async fn add_member(&mut self, email: &str) -> Result<Value, TaskError> {
        update_phase(self.id, &format!("Giving {} access", email), None).await;
        self.cli(&["add-member", email]).await?;
        let detail = last_task_result(self.id, "member_added").await;
        Ok(json!({
            "action": "member_added",
            "group_id": self.group,
            "email": email,
            "devices_added": detail.as_ref().and_then(|d| d["devices_added"].as_u64()).unwrap_or(0),
            "unverified_devices": detail.as_ref().map(|d| d["unverified_devices"].clone()).unwrap_or(json!([])),
        }))
    }

    /// Gives an invited person's existing devices the group key now, kept with the invitation
    /// until they accept. Returns `on_accept`, or `after_signup` when they have no devices yet
    /// or this step failed; then a group admin's app finishes after they join. The invitation
    /// itself already went out, so a failure here does not fail the task.
    async fn stage_invitation(&mut self, invitation: Uuid, email: &str) -> &'static str {
        update_phase(self.id, &format!("Preparing {}'s access", email), None).await;
        let invitation = invitation.to_string();
        if self
            .cli(&["add-member", "--for-invitation", &invitation, email])
            .await
            .is_err()
        {
            return "after_signup";
        }
        let staged = last_task_result(self.id, "invitation_staged")
            .await
            .is_some_and(|detail| detail["staged"].as_bool() == Some(true));
        if staged {
            "on_accept"
        } else {
            "after_signup"
        }
    }

    /// Rotate the group key, then put this computer on it in the same operation: fetch the new
    /// key here and move this computer's files to it, with progress. The admin confirmed in the
    /// app, so the CLI's own confirmation is skipped (`--yes`).
    async fn rotate_keys(&mut self, skip_unreachable: bool) -> Result<Value, TaskError> {
        update_phase(self.id, "Creating the new key", None).await;
        let mut args = vec!["rekey", "start", "--yes", "--local-migration", "defer"];
        if skip_unreachable {
            args.push("--force");
        }
        self.cli(&args).await?;
        let mut rotation = last_task_result(self.id, "keys_rotation_started")
            .await
            .unwrap_or(json!({}));
        rotation["files"] = self.move_files_to_new_key().await;
        Ok(rotation)
    }

    /// The rotation already finished, so a problem here is reported in the result rather than
    /// failing the task (a retry would rotate again). Files left behind move on the next pass.
    async fn move_files_to_new_key(&mut self) -> Value {
        update_phase(self.id, "Getting the new key on this computer", None).await;
        let client = match self.state.local_client.client().await {
            Ok(client) => client,
            Err(error) => return json!({ "error": error }),
        };
        if let Err(error) = client.report_key_receipts().await {
            tracing::warn!("Key receipt after rotation failed: {}", error);
        }
        let client = client.for_local_group(self.group);
        update_phase(self.id, "Moving this computer's files to the new key", None).await;
        let (sender, mut receiver) = watch::channel(None::<f64>);
        let id = self.id.to_string();
        let forward = tokio::spawn(async move {
            while receiver.changed().await.is_ok() {
                let progress = *receiver.borrow();
                update_progress(&id, progress).await;
            }
        });
        let outcome = client
            .migrate_leftover_key_files_with_progress(true, move |progress| {
                let done = progress.migrated_files + progress.failed_files;
                let _ = sender.send(progress_percent(done, progress.total_files));
            })
            .await;
        // The sender went with the callback, so the forwarder ends after its last update.
        let _ = forward.await;
        match outcome {
            Ok(moved) => files_moved_result(&moved),
            Err(error) => json!({ "error": desktop_safe_client_error(error) }),
        }
    }
}

/// What the rotation did with this computer's files, for the operation's summary.
fn files_moved_result(moved: &hybridcipher_client::LeftoverKeyMigration) -> Value {
    json!({
        "moved": moved.migrated,
        "failed": moved.failed,
        "failures": moved.failures.iter().take(5).collect::<Vec<_>>(),
        "rotation_running": moved.rotation_running,
    })
}

/// Adds a Team member to the group, or invites someone new to the Team with this group
/// attached on the server, so any admin of the group can finish the add once they join.
async fn add_person(steps: &mut Steps<'_>, email: &str) -> Result<Value, TaskError> {
    update_phase(steps.id, "Checking your organization", None).await;
    let members = organization_list(steps.state, steps.session, "organizations/me/members")
        .await
        .map_err(|message| task_error("organization_unavailable", message))?;
    if members.iter().any(|member| same_email(member, email)) {
        return steps.add_member(email).await;
    }
    let invitations =
        organization_list(steps.state, steps.session, "organizations/me/invitations")
            .await
            .map_err(|message| task_error("organization_unavailable", message))?;
    let pending = invitations
        .iter()
        .find(|invite| same_email(invite, email) && invite["status"].as_str() == Some("pending"))
        .and_then(|invite| invite["id"].as_str())
        .and_then(|id| Uuid::parse_str(id).ok());
    let (invitation, code) = if let Some(invitation) = pending {
        update_phase(steps.id, &format!("Adding this group to {}'s invitation", email), None).await;
        add_group_grant(
            steps.state,
            steps.session,
            &format!("organizations/me/invitations/{invitation}/groups"),
            steps.group,
        )
        .await
        .map_err(|message| task_error("invite_failed", message))?;
        (invitation, None)
    } else {
        update_phase(steps.id, &format!("Inviting {}", email), None).await;
        let (invitation, code) = invite(steps.state, steps.session, email, Some(steps.group)).await?;
        (invitation, Some(code))
    };
    let access = steps.stage_invitation(invitation, email).await;
    Ok(json!({
        "action": if pending.is_some() { "already_invited" } else { "person_invited" },
        "group_id": steps.group,
        "email": email,
        "invitation_code": code,
        "access": access,
    }))
}

fn same_email(entry: &Value, email: &str) -> bool {
    entry["email"]
        .as_str()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(email))
}

async fn organization_list(
    state: &AppState,
    session: &UserSession,
    path: &str,
) -> Result<Vec<Value>, String> {
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|error| error.to_string())?
        .get(api_endpoint(&current_server_url(state, session), path))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|_| "Connect to the server to manage your organization".to_string())?;
    if !response.status().is_success() {
        return Err(match response.status().as_u16() {
            403 => "Only organization owners and admins can invite people".into(),
            status => format!("Organization details are unavailable ({})", status),
        });
    }
    response.json().await.map_err(|error| error.to_string())
}

async fn invite(
    state: &AppState,
    session: &UserSession,
    email: &str,
    group: Option<Uuid>,
) -> Result<(Uuid, String), TaskError> {
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|error| task_error("invite_failed", error.to_string()))?
        .post(api_endpoint(
            &current_server_url(state, session),
            "organizations/me/invitations",
        ))
        .bearer_auth(&session.token)
        .json(&json!({ "email": email, "group_ids": group.into_iter().collect::<Vec<_>>() }))
        .send()
        .await
        .map_err(|_| task_error("invite_failed", "Connect to the server to send invitations"))?;
    match response.status().as_u16() {
        200..=299 => {}
        409 => {
            return Err(task_error(
                "no_seats",
                "No seats are free. Remove a member or cancel an unused invitation first.",
            ))
        }
        403 => {
            return Err(task_error(
                "not_allowed",
                "Only organization owners and admins can invite people",
            ))
        }
        status => {
            return Err(task_error(
                "invite_failed",
                format!("The invitation could not be created ({})", status),
            ))
        }
    }
    let value: Value = response
        .json()
        .await
        .map_err(|error| task_error("invite_failed", error.to_string()))?;
    let id = value["invitation_id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok());
    match (id, value["invitation_code"].as_str()) {
        (Some(id), Some(code)) => Ok((id, code.to_string())),
        _ => Err(task_error(
            "invite_failed",
            "Server did not return an invitation code",
        )),
    }
}

/// Attaches a group to an invitation or member on the server (`path` ends in `/groups`).
pub(super) async fn add_group_grant(
    state: &AppState,
    session: &UserSession,
    path: &str,
    group: Uuid,
) -> Result<(), String> {
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|error| error.to_string())?
        .post(api_endpoint(&current_server_url(state, session), path))
        .bearer_auth(&session.token)
        .json(&json!({ "group_ids": [group] }))
        .send()
        .await
        .map_err(|_| "Connect to the server to invite people to a group".to_string())?;
    match response.status().as_u16() {
        200..=299 => Ok(()),
        403 => Err("Only Team owners and admins can choose groups for people".into()),
        404 => Err("That invitation is no longer pending".into()),
        status => Err(format!("The group could not be added ({})", status)),
    }
}

/// Earlier versions kept "add to this group after they join" on the inviting computer only.
/// Moves those notes to the server once, so every admin of the group sees them.
pub(super) async fn migrate_local_pending_group_adds(state: &AppState, session: &UserSession) {
    let Ok(client) = state.local_client.client().await else {
        return;
    };
    let entries: Vec<Value> = match client.load_local_config(PENDING_GROUP_ADDS).await {
        Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
        _ => return,
    };
    if entries.is_empty() {
        return;
    }
    {
        let (Ok(members), Ok(invitations)) = (
            organization_list(state, session, "organizations/me/members").await,
            organization_list(state, session, "organizations/me/invitations").await,
        ) else {
            return;
        };
        for entry in &entries {
            let (Some(email), Some(group)) = (
                entry["email"].as_str(),
                entry["group_id"].as_str().and_then(|id| Uuid::parse_str(id).ok()),
            ) else {
                continue;
            };
            let path = if let Some(id) = members
                .iter()
                .find(|member| same_email(member, email))
                .and_then(|member| member["user_id"].as_str())
            {
                format!("organizations/me/members/{id}/groups")
            } else if let Some(id) = invitations
                .iter()
                .find(|invite| same_email(invite, email) && invite["status"].as_str() == Some("pending"))
                .and_then(|invite| invite["id"].as_str())
            {
                format!("organizations/me/invitations/{id}/groups")
            } else {
                continue;
            };
            // A note the server refuses (group gone, invitation ended) is dropped with the rest.
            if add_group_grant(state, session, &path, group)
                .await
                .is_err_and(|message| message.starts_with("Connect"))
            {
                return;
            }
        }
    }
    let _ = client.store_local_config(PENDING_GROUP_ADDS, "[]").await;
}
