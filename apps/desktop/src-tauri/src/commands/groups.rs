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
    super::license::require_team_write(&state).await?;
    tracing::info!("Create group command called: {}", request.group_name);
    let _operation_guard = ensure_authenticated(&state).await?;
    let session = current_authenticated_session(&state).await?;
    let response = reqwest::Client::new()
        .post(api_endpoint(
            &current_server_url(&state, &session),
            "groups",
        ))
        .bearer_auth(&session.token)
        .json(&json!({"name": request.group_name, "description": request.description}))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Ok(CommandResponse::err(format!(
            "Group creation failed: {}",
            response.status()
        )));
    }
    let value: Value = response.json().await.map_err(|err| err.to_string())?;
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or("Group ID missing from server response")?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(CommandResponse::ok(crate::client::CreateGroupResult {
        group_id: id.to_string(),
        name: name.to_string(),
        created: true,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeGroupRequest {
    pub group_id: String,
    pub welcome_message: Option<String>,
}

#[tauri::command]
pub async fn initialize_group(
    request: InitializeGroupRequest,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    super::license::require_team_write(&state).await?;
    let _guard = ensure_authenticated(&state).await?;
    let group_id = Uuid::parse_str(&request.group_id).map_err(|_| "Invalid group ID")?;
    let client = state.local_client.client().await?;
    client
        .ensure_group_initialized(group_id)
        .await
        .map_err(|error| error.to_string())?;
    Ok(CommandResponse::ok(true))
}

#[tauri::command]
pub async fn list_groups(
    _state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<crate::client::GroupInfo>>, String> {
    Ok(CommandResponse::err(
        "Use get_group_summaries for the current server groups",
    ))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminGroupSummary {
    pub id: String,
    pub organization_id: Option<String>,
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
    let _operation_guard = ensure_authenticated(&state).await?;

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
            organization_id: group.organization_id.map(|id| id.to_string()),
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
    _state: State<'_, AppState>,
) -> Result<CommandResponse<Option<crate::client::GroupInfo>>, String> {
    tracing::info!("Get group info command called: {}", group_id);
    Ok(CommandResponse::err(
        "Use get_group_summaries for the current server groups",
    ))
}
