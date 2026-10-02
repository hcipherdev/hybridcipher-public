use super::*;

#[tauri::command]
pub async fn export_existing_team_file(
    encrypted_path: String,
    output_path: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    let _guard = ensure_local_data_access(&state).await?;
    let client = state.local_client.client().await?;
    let source = PathBuf::from(encrypted_path);
    let destination = PathBuf::from(output_path);
    if destination.exists() {
        return Ok(CommandResponse::err("Export destination already exists"));
    }
    match hybridcipher_client::ipc::coverage_workflows::export_encrypted_file(
        client.as_ref(),
        &source,
        &destination,
    )
    .await
    {
        Ok(()) => Ok(CommandResponse::ok(true)),
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptFileRequest {
    pub file_path: String,
    pub group_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptProgress {
    pub file_name: String,
    pub percent: u8,
    pub bytes_processed: u64,
    pub total_bytes: u64,
}

#[tauri::command]
pub async fn encrypt_file(
    request: EncryptFileRequest,
    _state: State<'_, AppState>,
    _window: tauri::Window,
) -> Result<CommandResponse<crate::client::EncryptFileResult>, String> {
    tracing::info!("Encrypt file command called: {}", request.file_path);
    Ok(CommandResponse::err(
        "This legacy file command is unavailable; use an enrolled folder or the bundled CLI",
    ))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptFileRequest {
    pub file_path: String,
    pub output_path: Option<String>,
}

#[tauri::command]
pub async fn decrypt_file(
    request: DecryptFileRequest,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<crate::client::DecryptFileResult>, String> {
    tracing::info!("Decrypt file command called: {}", request.file_path);
    Ok(CommandResponse::err(
        "This legacy file command is unavailable; use Export existing encrypted file or the bundled CLI",
    ))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptDirectoryRequest {
    pub directory_path: String,
    pub group_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DirectoryEncryptResult {
    pub files_processed: usize,
    pub success: bool,
    pub message: String,
}

#[tauri::command]
pub async fn encrypt_directory(
    request: EncryptDirectoryRequest,
    _state: State<'_, AppState>,
) -> Result<CommandResponse<DirectoryEncryptResult>, String> {
    tracing::info!(
        "Encrypt directory command called: {}",
        request.directory_path
    );

    Ok(CommandResponse::ok(DirectoryEncryptResult {
        files_processed: 0,
        success: false,
        message: "Directory encryption not implemented yet".to_string(),
    }))
}

#[tauri::command]
pub async fn list_encrypted_files(
    _state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<String>>, String> {
    tracing::info!("List encrypted files command called");
    Ok(CommandResponse::ok(Vec::new()))
}
