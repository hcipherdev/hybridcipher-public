use crate::{
    error::CliError,
    session::{CurrentDevicePinState, GroupInfo, SessionManager},
    ui,
};
use hybridcipher_client::state::client::{GroupMembership, GroupRole};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{self};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct CreateGroupResponse {
    id: Uuid,
    name: String,
}

/// Handle the `create-group` command
pub async fn handle_create_group(
    name: String,
    description: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    ui::section("Create Group");
    ui::info(&format!("Creating group '{}'.", name));

    let request_body = serde_json::json!({
        "name": name,
        "description": description,
        "settings": serde_json::Value::Null,
    });

    let base_url = session.server_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/v1/groups", base_url))
        .header("Authorization", format!("Bearer {}", session.token))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to contact server: {}", e)))?;

    if response.status() == StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("create_group")?;
        return Err(CliError::authentication(
            "Authentication token rejected. Please run 'hybridcipher login' again.",
        ));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        ui::error(&format!("Server returned {}: {}", status, body));
        return Err(CliError::network(format!(
            "Group creation failed with status {}",
            status
        )));
    }

    let payload: CreateGroupResponse = response
        .json()
        .await
        .map_err(|e| CliError::network(format!("Failed to parse group response: {}", e)))?;

    ui::success(&format!(
        "Group '{}' created (ID: {}).",
        payload.name, payload.id
    ));

    // Update client state with the new group membership
    let device_id = session.device_id.clone();

    if let Err(e) =
        update_client_state_with_group(payload.id.to_string(), payload.name.clone(), device_id)
            .await
    {
        ui::warning(&format!(
            "Group created successfully, but failed to update local state: {}",
            e
        ));
        ui::info("You may need to run 'hybridcipher sync' to update your local group list.");
    } else {
        ui::info("Local client state updated successfully.");
    }

    match session_manager.set_current_group_id(payload.id).await {
        Ok(()) => ui::info("Activated newly created group as the current context."),
        Err(e) => ui::warning(&format!(
            "Group created, but failed to activate it locally: {}",
            e
        )),
    }

    match session_manager
        .ensure_current_device_pin_verified("group creation")
        .await
    {
        Ok(CurrentDevicePinState::AlreadyVerified) => {}
        Ok(CurrentDevicePinState::PromotedUnverified) => {
            ui::dim("Auto-verified local device pin.");
        }
        Ok(CurrentDevicePinState::PinnedVerified) => {
            ui::dim("Pinned and verified local device key.");
        }
        Err(err) => {
            ui::warning(&format!(
                "Local device pin auto-verification failed: {}",
                err
            ));
        }
    }

    ui::info("Run 'hybridcipher initialize-group [GROUP_ID]' to create the first epoch.");
    Ok(())
}

/// Handle the `rename-group` command
pub async fn handle_rename_group(
    group_id: Option<String>,
    new_name: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;

    let trimmed = new_name.trim();
    if trimmed.is_empty() {
        return Err(CliError::invalid_input(
            "Group name cannot be empty. Provide a non-empty name to rename the group.",
        ));
    }
    if trimmed.len() > 100 {
        return Err(CliError::invalid_input(
            "Group name must be 100 characters or fewer.",
        ));
    }

    ui::section("Rename Group");
    ui::info(&format!("New name: '{}'", trimmed));

    let target_group_id = match group_id {
        Some(raw_id) => Uuid::parse_str(&raw_id).map_err(|_| {
            CliError::configuration(format!("Invalid group ID provided: {}", raw_id))
        })?,
        None => session_manager.ensure_active_group().await?,
    };

    session_manager
        .require_group_admin(target_group_id, "hybridcipher rename-group")
        .await?;

    ui::info(&format!("Target group: {}", target_group_id));

    let updated_group = session_manager
        .rename_group_http(target_group_id, trimmed)
        .await?;

    ui::success(&format!(
        "Group {} renamed to '{}'.",
        target_group_id, updated_group.name
    ));

    match rename_group_in_client_state(&target_group_id, &updated_group.name).await {
        Ok(true) => ui::info("Updated local group metadata cache."),
        Ok(false) => ui::dim("Local group cache not updated (group not cached locally)."),
        Err(err) => ui::warning(&format!(
            "Group renamed, but failed to update local cache: {}",
            err
        )),
    }

    Ok(())
}

/// Handle the `delete-group` command
pub async fn handle_delete_group(
    group_id: &str,
    yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    let group_uuid = Uuid::parse_str(group_id)
        .map_err(|_| CliError::configuration(format!("Invalid group ID: {}", group_id)))?;

    session_manager
        .require_group_admin(group_uuid, "hybridcipher delete-group")
        .await?;

    let group_label = session_manager.group_label(&group_uuid).await;

    let active_group = match session_manager.current_group_id().await {
        Ok(value) => value,
        Err(err) => {
            ui::warning(&format!("Failed to load active group context: {}", err));
            None
        }
    };
    if active_group == Some(group_uuid) {
        ui::warning("You are about to delete your currently active group.");
    }

    let proceed = if yes {
        true
    } else {
        ui::prompts::confirm_with_default(
            &format!(
                "Are you sure you want to permanently delete group {}?",
                group_label
            ),
            false,
        )?
    };

    if !proceed {
        ui::info("Aborted group deletion.");
        return Ok(());
    }

    ui::section("Delete Group");
    ui::info(&format!("Deleting group {}...", group_label));

    let base_url = session.server_url.trim_end_matches('/');
    let api_base = if base_url.ends_with("/api/v1") {
        base_url.to_string()
    } else {
        format!("{}/api/v1", base_url)
    };
    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/groups/{}", api_base, group_uuid))
        .header("Authorization", format!("Bearer {}", session.token))
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to contact server: {}", e)))?;

    match response.status() {
        StatusCode::NO_CONTENT => {
            ui::success(&format!("Group {} deleted.", group_label));

            if let Err(e) = remove_group_from_client_state(group_id).await {
                ui::warning(&format!(
                    "Group deleted, but failed to update local client state: {}",
                    e
                ));
            }

            if active_group == Some(group_uuid) {
                if let Err(e) = session_manager.clear_current_group_id().await {
                    ui::warning(&format!(
                        "Group deleted, but failed to clear active group context: {}",
                        e
                    ));
                }
            }

            Ok(())
        }
        StatusCode::UNAUTHORIZED => {
            session_manager.invalidate_session("delete_group")?;
            Err(CliError::authentication(
                "Authentication token rejected. Please run 'hybridcipher login' again.",
            ))
        }
        StatusCode::FORBIDDEN => Err(CliError::session(
            "You do not have permission to delete this group.",
        )),
        StatusCode::NOT_FOUND => Err(CliError::not_found("Group not found")),
        status => {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            Err(CliError::network(format!(
                "Group deletion failed with status {}: {}",
                status, body
            )))
        }
    }
}

/// Update the client state file with a new group membership
async fn update_client_state_with_group(
    group_id: String,
    group_name: String,
    device_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = device_id;
    // Get current active user
    let home_dir = dirs::home_dir().ok_or("Failed to get home directory")?;
    let global_dir = home_dir.join(".hybridcipher").join("global");
    let active_user_path = global_dir.join("active_user.json");

    let active_user_content = tokio::fs::read_to_string(&active_user_path)
        .await
        .map_err(|_| "No active user found. Please login first.")?;
    let active_user: serde_json::Value = serde_json::from_str(&active_user_content)?;
    let user_id = active_user["user_id"]
        .as_str()
        .ok_or("Invalid active user data")?;

    // Use per-user client state path
    let user_dir = home_dir.join(".hybridcipher").join("users").join(user_id);
    let client_state_path = user_dir.join("client_state.json");

    let now = chrono::Utc::now();
    let mut client_state_value = if client_state_path.exists() {
        let content = tokio::fs::read_to_string(&client_state_path).await?;
        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(value) => value,
            Err(_) => default_client_state(now),
        }
    } else {
        default_client_state(now)
    };

    if !client_state_value.is_object() {
        client_state_value = default_client_state(now);
    }

    let state_object = client_state_value
        .as_object_mut()
        .ok_or("Client state is not a JSON object")?;

    // Remove legacy fields introduced by earlier multi-user prototypes
    state_object.remove("device_id");
    state_object.remove("groups");

    state_object
        .entry("epochs")
        .or_insert_with(|| serde_json::json!({}));
    state_object
        .entry("current_epoch")
        .or_insert_with(|| serde_json::json!(0));
    state_object
        .entry("migration")
        .or_insert(serde_json::Value::Null);
    state_object.insert("last_sync".to_string(), serde_json::json!(now.to_rfc3339()));
    state_object
        .entry("version")
        .or_insert_with(|| serde_json::json!(1));
    state_object
        .entry("auth_credentials")
        .or_insert(serde_json::Value::Null);
    state_object
        .entry("invitation_keypair")
        .or_insert(serde_json::Value::Null);

    let memberships_value = state_object
        .entry("group_memberships")
        .or_insert_with(|| serde_json::json!({}));

    let memberships_map = memberships_value
        .as_object_mut()
        .ok_or("group_memberships is not a JSON object")?;

    let group_uuid = Uuid::parse_str(&group_id)?;
    let membership = GroupMembership {
        group_id: group_uuid,
        group_name,
        group_description: None,
        user_role: GroupRole::Admin,
        joined_at: now,
        current_epoch_id: None,
        last_sync: now,
        members: Vec::new(),
    };

    let membership_value = serde_json::to_value(membership)?;
    memberships_map.insert(group_id, membership_value);

    let content = serde_json::to_string_pretty(&client_state_value)?;
    tokio::fs::write(&client_state_path, content).await?;

    Ok(())
}

async fn rename_group_in_client_state(
    group_id: &Uuid,
    new_name: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let home_dir = dirs::home_dir().ok_or("Failed to get home directory")?;
    let global_dir = home_dir.join(".hybridcipher").join("global");
    let active_user_path = global_dir.join("active_user.json");

    let active_user_content = tokio::fs::read_to_string(&active_user_path)
        .await
        .map_err(|_| "No active user found. Please login first.")?;
    let active_user: serde_json::Value = serde_json::from_str(&active_user_content)?;
    let user_id = active_user["user_id"]
        .as_str()
        .ok_or("Invalid active user data")?;

    let client_state_path = home_dir
        .join(".hybridcipher")
        .join("users")
        .join(user_id)
        .join("client_state.json");

    if !client_state_path.exists() {
        return Ok(false);
    }

    let content = tokio::fs::read_to_string(&client_state_path).await?;
    let mut client_state_value: serde_json::Value = serde_json::from_str(&content)?;
    let Some(state_obj) = client_state_value.as_object_mut() else {
        return Ok(false);
    };

    let Some(memberships_map) = state_obj
        .get_mut("group_memberships")
        .and_then(|v| v.as_object_mut())
    else {
        return Ok(false);
    };

    let Some(entry) = memberships_map.get_mut(&group_id.to_string()) else {
        return Ok(false);
    };

    let Some(entry_obj) = entry.as_object_mut() else {
        return Ok(false);
    };

    entry_obj.insert("group_name".to_string(), serde_json::json!(new_name));

    let content = serde_json::to_string_pretty(&client_state_value)?;
    tokio::fs::write(&client_state_path, content).await?;

    Ok(true)
}

async fn remove_group_from_client_state(group_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let home_dir = dirs::home_dir().ok_or("Failed to get home directory")?;
    let global_dir = home_dir.join(".hybridcipher").join("global");
    let active_user_path = global_dir.join("active_user.json");

    let active_user_content = match tokio::fs::read_to_string(&active_user_path).await {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Box::new(e)),
    };

    let active_user: serde_json::Value = serde_json::from_str(&active_user_content)?;
    let user_id = match active_user["user_id"].as_str() {
        Some(id) => id,
        None => return Ok(()),
    };

    let user_dir = home_dir.join(".hybridcipher").join("users").join(user_id);
    let client_state_path = user_dir.join("client_state.json");

    if !client_state_path.exists() {
        return Ok(());
    }

    let content = tokio::fs::read_to_string(&client_state_path).await?;
    let mut client_state_value: serde_json::Value = serde_json::from_str(&content)?;
    let state_object = match client_state_value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(()),
    };

    let memberships_value = state_object
        .get_mut("group_memberships")
        .and_then(|v| v.as_object_mut());

    let Some(memberships_map) = memberships_value else {
        return Ok(());
    };

    if memberships_map.remove(group_id).is_none() {
        return Ok(());
    }

    let content = serde_json::to_string_pretty(&client_state_value)?;
    tokio::fs::write(&client_state_path, content).await?;

    Ok(())
}

fn default_client_state(timestamp: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
    serde_json::json!({
        "epochs": {},
        "current_epoch": 0,
        "migration": null,
        "last_sync": timestamp.to_rfc3339(),
        "version": 1,
        "group_memberships": {},
        "auth_credentials": null,
        "invitation_keypair": null
    })
}

/// Handle the `initialize-group` command
pub async fn handle_initialize_group(
    group_id: Option<String>,
    epoch: u64,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;

    ui::section("Initialize Group Epoch");

    let group_uuid = match group_id {
        Some(raw_id) => Uuid::parse_str(raw_id.trim()).map_err(|e| {
            CliError::invalid_input(format!("Invalid group ID '{}': {}", raw_id, e))
        })?,
        None => session_manager.ensure_current_group().await?,
    };

    if epoch == 0 {
        return Err(CliError::invalid_input(
            "Epoch identifier must be >= 1 for genesis initialization",
        ));
    }

    session_manager
        .require_group_admin(group_uuid, "hybridcipher initialize-group")
        .await?;

    let client = session_manager.create_client().await?;
    let group_label = session_manager.group_label(&group_uuid).await;

    ui::info(&format!(
        "Initializing genesis epoch {} for group {}",
        epoch, group_label
    ));

    match client.initialize_group_epoch(group_uuid, epoch).await {
        Ok(epoch_id) => {
            ui::success(&format!(
                "Genesis epoch {} initialized for group {}",
                epoch_id, group_label
            ));
            ui::info("Devices can now fetch Welcome messages for this epoch.");
            if let Err(err) = crate::commands::recovery::append_active_epoch_to_artifact(
                session_manager,
                group_uuid,
            )
            .await
            {
                ui::warning(&format!(
                    "Group initialized but failed to append recovery backup: {}",
                    err
                ));
            }
            match session_manager
                .ensure_current_device_pin_verified("group initialization")
                .await
            {
                Ok(CurrentDevicePinState::AlreadyVerified) => {}
                Ok(CurrentDevicePinState::PromotedUnverified) => {
                    ui::dim("Auto-verified local device pin.");
                }
                Ok(CurrentDevicePinState::PinnedVerified) => {
                    ui::dim("Pinned and verified local device key.");
                }
                Err(err) => {
                    ui::warning(&format!(
                        "Local device pin auto-verification failed: {}",
                        err
                    ));
                }
            }
            Ok(())
        }
        Err(e) => {
            ui::error(&format!("Failed to initialize group: {}", e));
            Err(CliError::from(e))
        }
    }
}

/// Switch the active group used for local encryption/decryption context
pub async fn handle_switch_group(
    group_identifier: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;

    ui::section("Switch Active Group");

    let query = group_identifier.trim();
    if query.is_empty() {
        return Err(CliError::invalid_input(
            "Group identifier cannot be empty. Provide a UUID or prefix.",
        ));
    }

    let groups = session_manager.list_groups_http().await?;

    if groups.is_empty() {
        return Err(CliError::session(
            "No groups available for the current user. Ask an administrator to add you to a group or create one with 'hybridcipher create-group'.",
        ));
    }

    let query_lower = query.to_lowercase();

    let target_group = if let Some(exact) = groups.iter().find(|g| g.id.eq_ignore_ascii_case(query))
    {
        exact
    } else {
        let matches: Vec<&GroupInfo> = groups
            .iter()
            .filter(|g| {
                let id_lower = g.id.to_lowercase();
                id_lower.starts_with(&query_lower) || g.name.to_lowercase() == query_lower
            })
            .collect();

        match matches.len() {
            0 => {
                ui::warning(&format!(
                    "No group matches '{}'. Available groups:",
                    group_identifier
                ));
                for item in &groups {
                    ui::info(&format!("  • {} ({})", item.name, item.id));
                }
                return Err(CliError::invalid_input(format!(
                    "Unknown group identifier '{}'. Use 'hybridcipher list-groups' to inspect memberships.",
                    group_identifier
                )));
            }
            1 => matches[0],
            _ => {
                ui::warning("Group identifier is ambiguous. Matching groups:");
                for item in matches {
                    ui::info(&format!("  • {} ({})", item.name, item.id));
                }
                return Err(CliError::invalid_input(
                    "Group identifier matches multiple entries. Provide a full UUID.",
                ));
            }
        }
    };

    let group_uuid = uuid::Uuid::parse_str(&target_group.id).map_err(|e| {
        CliError::invalid_input(format!(
            "Server returned invalid group ID '{}': {}",
            target_group.id, e
        ))
    })?;

    if let Some(current_id) = session_manager.current_group_id().await? {
        if current_id == group_uuid {
            ui::info(&format!(
                "Already using group '{}' ({})",
                target_group.name, target_group.id
            ));
            return Ok(());
        }
    }

    session_manager.set_current_group_id(group_uuid).await?;

    ui::success(&format!(
        "Active group switched to '{}' ({})",
        target_group.name, target_group.id
    ));

    if let Some(role) = session_manager
        .group_membership_from_state(&group_uuid)
        .and_then(|(_, role)| role)
    {
        ui::info(&format!("Your role in this group: {}", role));
    } else {
        ui::info("Role information unavailable locally; run 'hybridcipher list-groups --verbose' for details.");
    }

    if let Some(dir) = session_manager.user_config_dir() {
        let group_file = dir.join("group_id.json");
        ui::info(&format!("Stored at: {}", group_file.display()));
    }

    Ok(())
}

/// Display the currently active group context
pub async fn handle_current_group(session_manager: &SessionManager) -> Result<(), CliError> {
    session_manager.require_auth()?;

    ui::section("Current Group Context");

    let group_id = match session_manager.current_group_id().await? {
        Some(id) => id,
        None => {
            ui::warning("No active group cached locally. Attempting to discover from server...");
            let resolved = session_manager.ensure_current_group().await?;
            if let Err(err) = session_manager
                .sync_current_group_into_state(resolved)
                .await
            {
                ui::warning(&format!(
                    "Failed to sync client_state.json after discovering group: {}",
                    err
                ));
            }
            resolved
        }
    };

    let mut name_role = session_manager.group_membership_from_state(&group_id);

    if name_role.is_none() {
        if let Ok(groups) = session_manager.list_groups_http().await {
            if let Some(info) = groups
                .into_iter()
                .find(|g| g.id.eq_ignore_ascii_case(&group_id.to_string()))
            {
                name_role = Some((info.name, Some(info.role)));
            }
        }
    }

    if let Some((name, role)) = name_role {
        ui::success(&format!("Active group: {} ({})", name, group_id));
        if let Some(role) = role {
            ui::info(&format!("Role: {}", role));
        }
    } else {
        ui::success(&format!("Active group: {}", group_id));
        ui::warning(
            "Group name not available locally. Run 'hybridcipher list-groups' to refresh metadata.",
        );
    }

    if let Some(dir) = session_manager.user_config_dir() {
        let group_file = dir.join("group_id.json");
        ui::info(&format!("Metadata stored in: {}", group_file.display()));
    }

    Ok(())
}
