use super::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct RekeyStartRequest {
    pub group_id: String,
    pub reason: Option<String>,
}

#[tauri::command]
pub async fn rekey_start(
    request: RekeyStartRequest,
    state: State<'_, AppState>,
) -> Result<CommandResponse<String>, String> {
    super::license::require_team_write(&state).await?;
    tracing::info!("Rekey start command called for group: {}", request.group_id);
    Ok(CommandResponse::err(
        "Start rekey through the bundled CLI so group keys are updated",
    ))
}

async fn actual_rekey_status(
    group_id: String,
    state: &AppState,
) -> Result<CommandResponse<Value>, String> {
    let _guard = ensure_authenticated(state).await?;
    let group = Uuid::parse_str(&group_id).map_err(|_| "Invalid group ID")?;
    let local = state.local_client.client().await?;
    let client = local.for_local_group(group);
    let operation = client
        .rekey_status()
        .await
        .map_err(|error| error.to_string())?;
    let current_epoch = client
        .get_group_memberships()
        .await
        .into_iter()
        .find(|member| member.group_id == group)
        .and_then(|member| member.current_epoch_id);
    match operation {
        Some(operation) => {
            let progress = if operation.progress.total_files > 0 {
                Some(
                    operation.progress.migrated_files as f64
                        / operation.progress.total_files as f64,
                )
            } else {
                None
            };
            Ok(CommandResponse::ok(
                json!({"group_id":group,"current_epoch":current_epoch,"new_epoch_label":operation.new_epoch_label,"migration_progress":progress,"phase":operation.status,"operation":operation}),
            ))
        }
        None => Ok(CommandResponse::ok(
            json!({"group_id":group,"current_epoch":current_epoch,"new_epoch_label":null,"migration_progress":null,"phase":"idle","operation":null}),
        )),
    }
}

#[tauri::command]
pub async fn rekey_status(
    group_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Value>, String> {
    actual_rekey_status(group_id, &state).await
}

#[tauri::command]
pub async fn rekey_cutover(
    group_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    super::license::require_team_write(&state).await?;
    tracing::info!("Rekey cutover command called for group: {}", group_id);
    Ok(CommandResponse::err(
        "Complete rekey through the bundled CLI so group keys are updated",
    ))
}

#[tauri::command]
pub async fn get_migration_status(
    group_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Value>, String> {
    actual_rekey_status(group_id, &state).await
}
