use super::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub group_name: String,
    pub description: Option<String>,
}

#[tauri::command]
pub async fn create_group(
    request: CreateGroupRequest,
    state: State<'_, AppState>,
) -> Result<CommandResponse<crate::client::CreateGroupResult>, String> {
    tracing::info!("Create group command called: {}", request.group_name);

    match state.client.create_group(request.group_name).await {
        Ok(result) => Ok(CommandResponse::ok(result)),
        Err(e) => Ok(CommandResponse::err(e)),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeGroupRequest {
    pub group_id: String,
    pub welcome_message: Option<String>,
}

#[tauri::command]
pub async fn initialize_group(
    request: InitializeGroupRequest,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    tracing::info!("Initialize group command called: {}", request.group_id);
    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn list_groups(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<crate::client::GroupInfo>>, String> {
    tracing::info!("List groups command called");

    match state.client.list_groups().await {
        Ok(groups) => Ok(CommandResponse::ok(groups)),
        Err(e) => Ok(CommandResponse::err(e)),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminGroupSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub member_count: u32,
    pub device_count: Option<u32>,
    pub current_epoch_id: Option<String>,
}

#[tauri::command]
pub async fn get_group_summaries(
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<AdminGroupSummary>>, String> {
    ensure_authenticated(&state).await?;

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
    let group_payload = fetch_group_list(&server_url, &session.token).await?;
    let api_base = api_base_url(&server_url);
    let client = reqwest::Client::new();

    let mut summaries = Vec::with_capacity(group_payload.groups.len());
    for group in group_payload.groups {
        let mut device_count = None;
        let audit_url = format!("{}/groups/{}/devices?stale_days=30", api_base, group.id);

        match client
            .get(&audit_url)
            .bearer_auth(&session.token)
            .send()
            .await
        {
            Ok(response) => {
                if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                    return Ok(CommandResponse::err(
                        "Authentication token rejected. Please login again.".to_string(),
                    ));
                }
                if response.status().is_success() {
                    match response.json::<GroupDeviceAuditResponse>().await {
                        Ok(audit) => {
                            device_count = Some(audit.devices.len() as u32);
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Failed to parse device audit for group {}: {}",
                                group.id,
                                err
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        "Device audit request failed for group {} with status {}",
                        group.id,
                        response.status()
                    );
                }
            }
            Err(err) => {
                tracing::warn!("Device audit request error for group {}: {}", group.id, err);
            }
        }

        summaries.push(AdminGroupSummary {
            id: group.id.to_string(),
            name: group.name,
            description: group.description,
            created_at: group.created_at.to_rfc3339(),
            member_count: group.member_count,
            device_count,
            current_epoch_id: group.current_epoch,
        });
    }

    Ok(CommandResponse::ok(summaries))
}

#[tauri::command]
pub async fn get_group_info(
    group_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Option<crate::client::GroupInfo>>, String> {
    tracing::info!("Get group info command called: {}", group_id);

    match state.client.list_groups().await {
        Ok(groups) => {
            let info = groups.into_iter().find(|g| g.id == group_id);
            Ok(CommandResponse::ok(info))
        }
        Err(e) => Ok(CommandResponse::err(e)),
    }
}
