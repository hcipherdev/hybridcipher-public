use super::*;

#[tauri::command]
pub async fn update_server_url(
    _request: UpdateServerUrlRequest,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<String>, String> {
    tracing::info!("Update server URL command called");
    Ok(CommandResponse::ok(
        "Server URL updates are not implemented yet".to_string(),
    ))
}

#[tauri::command]
pub async fn get_app_version() -> Result<CommandResponse<String>, String> {
    let version = env!("CARGO_PKG_VERSION").to_string();
    Ok(CommandResponse::ok(version))
}

#[tauri::command]
pub async fn get_legal_documents(
    app_handle: AppHandle,
) -> Result<CommandResponse<legal::LegalDocumentsPayload>, String> {
    let resource_dir = app_handle.path().resource_dir().ok();
    let payload = legal::load_legal_documents(resource_dir.as_deref())?;
    Ok(CommandResponse::ok(payload))
}

#[tauri::command]
pub async fn get_release_notes_payload(
    app_handle: AppHandle,
) -> Result<CommandResponse<release_notes::ReleaseNotesPayload>, String> {
    let resource_dir = app_handle.path().resource_dir().ok();
    let payload = release_notes::load_release_notes(resource_dir.as_deref())?;
    Ok(CommandResponse::ok(payload))
}
