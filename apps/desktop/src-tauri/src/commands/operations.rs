//! Account-scoped desktop operations; ordinary UI actions never launch shells or PTYs.
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch};

const PROMPT_PREFIX: &str = "__HC_DESKTOP_EVENT__";
#[cfg(test)]
#[path = "../../tests/operations/test_desktop_operations.rs"]
mod tests;
#[derive(Clone, Serialize, Deserialize)]
pub struct DesktopInputRequest {
    pub id: String,
    pub kind: String,
    pub message: String,
    pub default_value: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct DesktopOperationError {
    pub code: String,
    pub message: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct DesktopOperationSnapshot {
    pub id: String,
    pub account_id: String,
    pub group_id: Option<String>,
    pub status: String,
    pub phase: String,
    pub output: Vec<String>,
    pub result: Option<Value>,
    pub error: Option<DesktopOperationError>,
    pub input_request: Option<DesktopInputRequest>,
}
#[derive(Deserialize)]
pub struct DesktopOperationRequest {
    pub kind: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub group_id: Option<String>,
    pub title: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub expected_account_email: Option<String>,
}
#[derive(Deserialize, Serialize)]
pub struct DesktopOperationAnswer {
    pub request_id: String,
    pub value: Option<String>,
}
impl Drop for DesktopOperationAnswer {
    fn drop(&mut self) {
        if let Some(value) = &mut self.value {
            value.zeroize();
        }
    }
}
struct Operation {
    snapshot: DesktopOperationSnapshot,
    server: String,
    answers: mpsc::Sender<DesktopOperationAnswer>,
    cancel: watch::Sender<bool>,
}
static OPERATIONS: Lazy<tokio::sync::Mutex<HashMap<String, Operation>>> =
    Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));
static WORKSPACE_SELECTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static WORKSPACE_SELECTIONS: Lazy<tokio::sync::Mutex<HashMap<String, u64>>> =
    Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));
fn validate_expected_account(expected: Option<&str>, actual: &str) -> Result<(), String> {
    if expected.is_some_and(|email| !email.eq_ignore_ascii_case(actual)) {
        return Err("The account changed. Reopen this action for the current account.".into());
    }
    Ok(())
}
async fn register_workspace_selection(key: &str, sequence: u64) -> Result<(), String> {
    let mut latest = WORKSPACE_SELECTIONS.lock().await;
    if latest.get(key).is_some_and(|last| sequence < *last) {
        return Err("Workspace selection was superseded".into());
    }
    latest.insert(key.to_owned(), sequence);
    Ok(())
}
async fn validate_workspace_selection(key: &str, sequence: u64) -> Result<(), String> {
    if WORKSPACE_SELECTIONS.lock().await.get(key) != Some(&sequence) {
        return Err("Workspace selection was superseded".into());
    }
    Ok(())
}
fn active(snapshot: &DesktopOperationSnapshot) -> bool {
    matches!(snapshot.status.as_str(), "running" | "needs_input")
}
fn canonical_server(server: &str) -> &str {
    server.trim_end_matches('/').trim_end_matches("/api/v1")
}

async fn authorize_operation(state: &AppState, operation: &Operation) -> Result<(), String> {
    let session = state.session.lock().await;
    let session = session.as_ref().ok_or("Sign in to view this operation")?;
    if session.user_id != operation.snapshot.account_id
        || canonical_server(&current_server_url(state, session))
            != canonical_server(&operation.server)
    {
        return Err("This operation belongs to another account".into());
    }
    Ok(())
}
pub(super) async fn cancel_all_desktop_operations(state: &AppState) {
    let account = state
        .session
        .lock()
        .await
        .as_ref()
        .map(|session| session.user_id.clone());
    if let Some(account) = account {
        WORKSPACE_SELECTIONS
            .lock()
            .await
            .retain(|key, _| !key.starts_with(&format!("{}@", account)));
        for op in OPERATIONS.lock().await.values() {
            if op.snapshot.account_id == account && active(&op.snapshot) {
                let _ = op.cancel.send(true);
            }
        }
    }
}
#[tauri::command]
pub async fn get_desktop_operation(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<DesktopOperationSnapshot, String> {
    let registry = OPERATIONS.lock().await;
    let op = registry
        .get(&operation_id)
        .ok_or("Operation no longer available")?;
    authorize_operation(&state, op).await?;
    Ok(op.snapshot.clone())
}
#[tauri::command]
pub async fn answer_desktop_operation(
    operation_id: String,
    answer: DesktopOperationAnswer,
    state: State<'_, AppState>,
) -> Result<DesktopOperationSnapshot, String> {
    let mut registry = OPERATIONS.lock().await;
    let op = registry
        .get_mut(&operation_id)
        .ok_or("Operation no longer available")?;
    authorize_operation(&state, op).await?;
    let prompt = op
        .snapshot
        .input_request
        .as_ref()
        .ok_or("No input is requested")?;
    if op.snapshot.status != "needs_input" || answer.request_id != prompt.id {
        return Err("The requested input has changed".into());
    }
    if answer
        .value
        .as_ref()
        .is_some_and(|value| value.len() > 32_768 || value.contains('\0'))
    {
        return Err("Invalid input".into());
    }
    if answer.value.is_none() {
        let _ = op.cancel.send(true);
    } else {
        op.answers
            .try_send(answer)
            .map_err(|_| "The operation is no longer waiting for input")?;
        op.snapshot.status = "running".into();
        op.snapshot.input_request = None;
        op.snapshot.phase = "Continuing operation".into();
    }
    Ok(op.snapshot.clone())
}
#[tauri::command]
pub async fn cancel_desktop_operation(
    operation_id: String,
    state: State<'_, AppState>,
) -> Result<DesktopOperationSnapshot, String> {
    let registry = OPERATIONS.lock().await;
    let op = registry
        .get(&operation_id)
        .ok_or("Operation no longer available")?;
    authorize_operation(&state, op).await?;
    let _ = op.cancel.send(true);
    Ok(op.snapshot.clone())
}

pub(super) fn validate_cli_args(args: &[String], group: Option<Uuid>) -> Result<(), String> {
    let first = args
        .first()
        .map(String::as_str)
        .ok_or("No action provided")?;
    let help = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"));
    let allowed = matches!(
        first,
        "add-member"
            | "remove-member"
            | "verify-membership"
            | "process-welcome-messages"
            | "issue-welcome"
            | "pending-devices"
            | "audit-devices"
            | "unverified-devices"
            | "list-members"
            | "list-groups"
            | "current-group"
            | "rekey"
            | "coverage"
            | "pin"
            | "server-trust"
            | "recovery"
            | "health-check"
            | "devices"
            | "current-user"
            | "keystore-status"
            | "rename-group"
            | "delete-group"
    );
    if !allowed && !help {
        return Err("This action has no desktop adapter".into());
    }
    if !help && matches!(first, "rename-group" | "delete-group") {
        let supplied = args.get(1).and_then(|value| Uuid::parse_str(value).ok());
        if supplied.is_none() || supplied != group {
            return Err("Group argument does not match the selected workspace".into());
        }
    }
    if args.len() > 64
        || args
            .iter()
            .any(|arg| arg.len() > 32_768 || arg.contains('\0'))
    {
        return Err("Invalid operation arguments".into());
    }
    for (index, arg) in args.iter().enumerate() {
        if [
            "--config",
            "--server",
            "--server-url",
            "--token",
            "--password",
            "--recovery-code",
            "--watch",
        ]
        .iter()
        .any(|blocked| arg == blocked || arg.starts_with(&format!("{}=", blocked)))
        {
            return Err("This argument must be provided through the desktop UI".into());
        }
        let supplied = if arg == "--group" || arg == "--group-id" {
            Some(
                args.get(index + 1)
                    .and_then(|value| Uuid::parse_str(value).ok()),
            )
        } else if arg.starts_with("--group=") || arg.starts_with("--group-id=") {
            Some(
                arg.split_once('=')
                    .and_then(|(_, value)| Uuid::parse_str(value).ok()),
            )
        } else {
            None
        };
        if supplied.is_some_and(|value| value.is_none() || value != group) {
            return Err("Group argument does not match the selected workspace".into());
        }
    }
    if !help
        && matches!(
            first,
            "add-member"
                | "remove-member"
                | "verify-membership"
                | "process-welcome-messages"
                | "issue-welcome"
                | "pending-devices"
                | "audit-devices"
                | "unverified-devices"
                | "devices"
                | "health-check"
                | "current-group"
                | "list-members"
                | "rekey"
                | "coverage"
                | "pin"
                | "recovery"
                | "rename-group"
                | "delete-group"
        )
        && group.is_none()
    {
        return Err("Select a group before starting this action".into());
    }
    Ok(())
}

pub(super) fn background_cli_args_allowed(args: &[String]) -> bool {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        return true;
    }
    let command = args.first().map(String::as_str).unwrap_or_default();
    let action = args.get(1).map(String::as_str).unwrap_or_default();
    matches!(
        command,
        "current-user"
            | "current-group"
            | "list-groups"
            | "list-members"
            | "keystore-status"
            | "health-check"
            | "pending-devices"
            | "unverified-devices"
    ) || command == "server-trust" && action == "show"
        || command == "pin" && matches!(action, "list" | "fingerprint" | "show")
        || command == "rekey" && action == "status"
        || command == "coverage" && matches!(action, "status" | "audit" | "verify")
}
#[tauri::command]
pub async fn start_desktop_operation(
    request: DesktopOperationRequest,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<DesktopOperationSnapshot, String> {
    let guard = if request.kind == "switch_group" {
        ensure_local_data_access(&state).await?
    } else {
        ensure_authenticated(&state).await?
    };
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    validate_expected_account(request.expected_account_email.as_deref(), &session.email)?;
    let group = request
        .group_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| "Invalid group ID")?;
    if request.kind == "cli" {
        validate_cli_args(&request.args, group)?;
        let help = request
            .args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-h" | "--help"));
        if !session.persistent && !help {
            return Err("This action needs a saved login. Sign in with Remember me.".into());
        }
        if let Some(id) = group {
            let metadata = validate_group_access(&state, &session, id, true).await?;
            let first = request.args.first().map(String::as_str).unwrap_or_default();
            let action = request.args.get(1).map(String::as_str).unwrap_or_default();
            let administer = !help
                && (matches!(
                    first,
                    "add-member"
                        | "remove-member"
                        | "issue-welcome"
                        | "rename-group"
                        | "delete-group"
                ) || first == "rekey" && action != "status");
            let writes = !help
                && (administer
                    || first == "coverage"
                        && matches!(action, "migrate" | "migration" | "recover-markers" | "scan")
                    || first == "pin" && matches!(action, "add" | "verify" | "remove"));
            let role = metadata["role"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if administer && !matches!(role.as_str(), "admin" | "owner") {
                return Err("Your role cannot administer this group".into());
            }
            if writes && matches!(role.as_str(), "viewer" | "observer") {
                return Err("Your role has read access to this group".into());
            }
            if writes && metadata["organization_id"].is_string() {
                super::license::require_team_write(&state).await?;
            }
        }
    } else if !matches!(
        request.kind.as_str(),
        "team_setup" | "create_group" | "initialize_group" | "switch_group"
    ) {
        return Err("Unknown desktop action".into());
    }
    let id = Uuid::new_v4().to_string();
    let snapshot = DesktopOperationSnapshot {
        id: id.clone(),
        account_id: session.user_id.clone(),
        group_id: group.map(|id| id.to_string()),
        status: "running".into(),
        phase: request
            .title
            .clone()
            .unwrap_or_else(|| "Starting operation".into()),
        output: Vec::new(),
        result: None,
        error: None,
        input_request: None,
    };
    let (answers_tx, answers_rx) = mpsc::channel(1);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    {
        let mut registry = OPERATIONS.lock().await;
        if registry
            .values()
            .any(|op| op.snapshot.account_id == session.user_id && active(&op.snapshot))
        {
            return Err("Another operation is still running for this account".into());
        }
        if registry.len() >= 64 {
            registry.retain(|_, op| active(&op.snapshot));
        }
        registry.insert(
            id.clone(),
            Operation {
                snapshot: snapshot.clone(),
                server: current_server_url(&state, &session),
                answers: answers_tx,
                cancel: cancel_tx,
            },
        );
    }
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let result = if request.kind == "cli" {
            run_cli_operation(
                &id,
                &request.args,
                group,
                &session,
                &state,
                answers_rx,
                &mut cancel_rx,
            )
            .await
        } else {
            tokio::select! { result = run_typed_operation(&id, request, group, &session, &state) => result, _ = cancel_rx.changed() => Err(("operation_cancelled".into(), "Operation cancelled. Review its state before retrying.".into())) }
        };
        if let Some(op) = OPERATIONS.lock().await.get_mut(&id) {
            op.snapshot.input_request = None;
            match result {
                Ok(result) => {
                    op.snapshot.status = "succeeded".into();
                    op.snapshot.phase = "Completed".into();
                    op.snapshot.result = Some(result);
                }
                Err((code, message)) => {
                    op.snapshot.status = if code == "operation_cancelled" {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    op.snapshot.phase = "Action needs attention".into();
                    op.snapshot.error = Some(DesktopOperationError { code, message });
                }
            }
        }
        drop(guard);
    });
    Ok(snapshot)
}
async fn update_phase(id: &str, phase: &str, group: Option<Uuid>) {
    if let Some(op) = OPERATIONS.lock().await.get_mut(id) {
        op.snapshot.phase = phase.into();
        if let Some(group) = group {
            op.snapshot.group_id = Some(group.to_string());
        }
    }
}
async fn read_lines<R: tokio::io::AsyncRead + Unpin>(reader: R, sender: mpsc::Sender<String>) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if sender
            .send(line.chars().take(16_384).collect())
            .await
            .is_err()
        {
            break;
        }
    }
}
async fn run_cli_operation(
    id: &str,
    args: &[String],
    group: Option<Uuid>,
    session: &crate::state::UserSession,
    state: &AppState,
    mut answers: mpsc::Receiver<DesktopOperationAnswer>,
    cancel: &mut watch::Receiver<bool>,
) -> Result<Value, (String, String)> {
    let (binary, _) = locate_cli_binary().map_err(|error| ("cli_unavailable".into(), error))?;
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("--no-color")
        .args(args)
        .env("HYBRIDCIPHER_DESKTOP_OPERATION", "1")
        .env("HYBRIDCIPHER_DESKTOP_ACCOUNT", &session.user_id)
        .env(
            "HYBRIDCIPHER_DESKTOP_SERVER",
            current_server_url(state, session),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(group) = group {
        command.env("HYBRIDCIPHER_DESKTOP_GROUP", group.to_string());
    }
    configure_background_tokio_command(&mut command);
    let mut child = command.spawn().map_err(|_| {
        (
            "cli_launch_failed".into(),
            "The action could not start. Verify the bundled app installation.".into(),
        )
    })?;
    let mut stdin = child.stdin.take().ok_or((
        "cli_launch_failed".into(),
        "Input transport unavailable".into(),
    ))?;
    let (sender, mut lines) = mpsc::channel(64);
    if let Some(stdout) = child.stdout.take() {
        tauri::async_runtime::spawn(read_lines(stdout, sender.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        tauri::async_runtime::spawn(read_lines(stderr, sender.clone()));
    }
    drop(sender);
    let mut secrets: Vec<Zeroizing<String>> = Vec::new();
    let status = loop {
        tokio::select! {
            result = child.wait() => break result.map_err(|_| ("cli_wait_failed".into(), "The action stopped unexpectedly".into()))?,
            _ = cancel.changed() => { let _ = child.kill().await; return Err(("operation_cancelled".into(), "Operation cancelled. Review its state before retrying.".into())); },
            Some(answer) = answers.recv() => {
                if let Some(value) = &answer.value { if !value.is_empty() { secrets.push(Zeroizing::new(value.clone())); } }
                let mut json = Zeroizing::new(serde_json::to_string(&answer).map_err(|_| ("input_failed".into(), "Could not send requested input".into()))?); json.push('\n');
                stdin.write_all(json.as_bytes()).await.map_err(|_| ("input_failed".into(), "The action is no longer waiting for input".into()))?;
                stdin.flush().await.map_err(|_| ("input_failed".into(), "Input transport closed".into()))?;
            },
            Some(line) = lines.recv() => record_cli_line(id, line, &secrets).await,
        }
    };
    while let Some(line) = lines.recv().await {
        record_cli_line(id, line, &secrets).await;
    }
    let output = OPERATIONS
        .lock()
        .await
        .get(id)
        .map(|op| op.snapshot.output.join("\n"))
        .unwrap_or_default();
    if !status.success() {
        return Err((
            "action_failed".into(),
            if output.is_empty() {
                "The action failed. Review account and group access before retrying.".into()
            } else {
                output
            },
        ));
    }
    let structured = serde_json::from_str::<Value>(&output).ok();
    Ok(json!({"exit_status":status.code().unwrap_or(-1),"output":output,"data":structured}))
}
async fn record_cli_line(id: &str, mut line: String, secrets: &[Zeroizing<String>]) {
    for secret in secrets {
        line = line.replace(secret.as_str(), "[protected input]");
    }
    let mut registry = OPERATIONS.lock().await;
    let Some(op) = registry.get_mut(id) else {
        return;
    };
    if let Some(event) = line
        .strip_prefix(PROMPT_PREFIX)
        .and_then(|json| serde_json::from_str::<Value>(json).ok())
    {
        if event.get("event").and_then(Value::as_str) == Some("needs_input") {
            if let Ok(prompt) = serde_json::from_value::<DesktopInputRequest>(event) {
                if matches!(
                    prompt.kind.as_str(),
                    "password" | "text" | "confirm" | "file"
                ) {
                    op.snapshot.phase = "Waiting for your input".into();
                    op.snapshot.status = "needs_input".into();
                    op.snapshot.input_request = Some(prompt);
                    return;
                }
            }
        }
    }
    if line.trim().is_empty() {
        return;
    }
    if op.snapshot.status == "running" {
        op.snapshot.phase = line.chars().take(180).collect();
    }
    op.snapshot.output.push(line);
    if op.snapshot.output.len() > 512 {
        op.snapshot.output.remove(0);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WorkspaceGroupContext {
    pub group_id: Option<String>,
    pub name: Option<String>,
    pub organization_id: Option<String>,
    pub role: Option<String>,
    pub readiness: String,
    pub groups: Vec<Value>,
}
async fn cached_group_list(
    state: &AppState,
    session: &crate::state::UserSession,
    refresh: bool,
) -> Result<Vec<Value>, String> {
    let client = state.local_client.client().await?;
    if refresh && session.expires_at > chrono::Utc::now().timestamp() {
        if let Ok(Ok(list)) = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            fetch_group_list(&current_server_url(state, session), &session.token),
        )
        .await
        {
            let groups = list.groups.into_iter().map(|group| json!({"id":group.id,"name":group.name,"organization_id":group.organization_id,"role":group.user_role,"current_epoch_id":group.current_epoch})).collect::<Vec<_>>();
            client
                .store_local_config(
                    "desktop_workspace_groups",
                    &serde_json::to_string(&groups).map_err(|error| error.to_string())?,
                )
                .await
                .map_err(|error| error.to_string())?;
            return Ok(groups);
        }
    }
    let cached = client
        .load_local_config("desktop_workspace_groups")
        .await
        .map_err(|error| error.to_string())?;
    Ok(cached
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default())
}
async fn validate_group_access(
    state: &AppState,
    session: &crate::state::UserSession,
    id: Uuid,
    refresh: bool,
) -> Result<Value, String> {
    cached_group_list(state, session, refresh)
        .await?
        .into_iter()
        .find(|group| group["id"].as_str() == Some(&id.to_string()))
        .ok_or("The selected group is not available to this account".into())
}
#[tauri::command]
pub async fn get_workspace_group_context(
    workspace: String,
    selection_sequence: Option<u64>,
    expected_account_email: Option<String>,
    state: State<'_, AppState>,
) -> Result<WorkspaceGroupContext, String> {
    if !matches!(workspace.as_str(), "personal" | "team") {
        return Err("Unknown workspace".into());
    }
    let _guard = ensure_local_data_access(&state).await?;
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    validate_expected_account(expected_account_email.as_deref(), &session.email)?;
    let selection_key = format!(
        "{}@{}",
        session.user_id,
        canonical_server(&current_server_url(&state, &session))
    );
    if let Some(sequence) = selection_sequence {
        register_workspace_selection(&selection_key, sequence).await?;
    }
    let _selection_guard = WORKSPACE_SELECTION_LOCK.lock().await;
    let organization = super::license::verified_claims(&session, true)
        .ok()
        .flatten()
        .map(|claims| claims.organization_id);
    let groups = cached_group_list(&state, &session, true)
        .await?
        .into_iter()
        .filter(|group| {
            group["organization_id"].is_string() == (workspace == "team")
                && (workspace != "team"
                    || organization
                        .as_deref()
                        .is_none_or(|id| group["organization_id"].as_str() == Some(id)))
        })
        .collect::<Vec<_>>();
    let client = state.local_client.client().await?;
    let selected_key = format!("desktop_selected_{}_group", workspace);
    let selected = client
        .load_local_config(&selected_key)
        .await
        .map_err(|error| error.to_string())?;
    let active = client.active_group_id_opt().await.map(|id| id.to_string());
    let group = groups
        .iter()
        .find(|group| group["id"].as_str() == selected.as_deref())
        .or_else(|| {
            groups
                .iter()
                .find(|group| group["id"].as_str() == active.as_deref())
        })
        .or_else(|| groups.first());
    let mut context = WorkspaceGroupContext {
        group_id: None,
        name: None,
        organization_id: None,
        role: None,
        readiness: "no_groups".into(),
        groups: groups.clone(),
    };
    if let Some(sequence) = selection_sequence {
        validate_workspace_selection(&selection_key, sequence).await?;
    }
    client
        .store_local_config("desktop_ui_group_id", "")
        .await
        .map_err(|error| error.to_string())?;
    if let Some(group) = group {
        context.group_id = group["id"].as_str().map(str::to_string);
        context.name = group["name"].as_str().map(str::to_string);
        context.organization_id = group["organization_id"].as_str().map(str::to_string);
        context.role = group["role"].as_str().map(|role| role.to_ascii_lowercase());
        let id = Uuid::parse_str(context.group_id.as_deref().unwrap_or_default())
            .map_err(|_| "Invalid cached group")?;
        let has_keys = client
            .has_cached_group_key(id)
            .await
            .map_err(|error| error.to_string())?;
        context.readiness = if has_keys {
            "ready"
        } else if group["current_epoch_id"].is_string() {
            "waiting_for_device_approval"
        } else {
            "uninitialized"
        }
        .into();
        client
            .store_local_config("desktop_ui_group_id", &id.to_string())
            .await
            .map_err(|error| error.to_string())?;
        if !has_keys && session.expires_at > chrono::Utc::now().timestamp() {
            let _ = client.use_group(id).await;
        }
        if has_keys {
            client
                .use_group(id)
                .await
                .map_err(|error| error.to_string())?;
            client
                .store_local_config("group_id", &id.to_string())
                .await
                .map_err(|error| error.to_string())?;
            client
                .store_local_config(&selected_key, &id.to_string())
                .await
                .map_err(|error| error.to_string())?;
        }
    } else if workspace == "team" {
        if let Some(setup) = client
            .load_local_config("desktop_team_setup")
            .await
            .map_err(|error| error.to_string())?
            .and_then(|value| serde_json::from_str::<Value>(&value).ok())
        {
            if let Some(id) = setup["group_id"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok())
                .filter(|_| {
                    organization.is_some()
                        && setup["organization_id"].as_str() == organization.as_deref()
                })
            {
                context.group_id = Some(id.to_string());
                context.name = setup["name"].as_str().map(str::to_string);
                context.organization_id = organization.clone();
                context.role = Some("admin".into());
                context.readiness = if setup["readiness"] == "deleted" {
                    "deleted"
                } else if client
                    .has_cached_group_key(id)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    "ready"
                } else if setup["readiness"] == "waiting_for_device_approval" {
                    "waiting_for_device_approval"
                } else {
                    "uninitialized"
                }
                .into();
                if context.readiness != "deleted" {
                    client
                        .store_local_config("desktop_ui_group_id", &id.to_string())
                        .await
                        .map_err(|error| error.to_string())?;
                    context.groups.push(json!({"id":id,"name":context.name,"organization_id":context.organization_id,"role":"admin","current_epoch_id":null}));
                    if context.readiness == "ready" {
                        client
                            .use_group(id)
                            .await
                            .map_err(|error| error.to_string())?;
                        client
                            .store_local_config("group_id", &id.to_string())
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                }
            }
        }
    }
    Ok(context)
}
async fn prepare_group(state: &AppState, group: Uuid) -> Result<String, String> {
    let client = state.local_client.client().await?;
    let readiness = client.prepare_group_for_use(group).await.map_err(|error| {
        error
            .context()
            .map(|context| context.message.clone())
            .unwrap_or_else(|| error.to_string())
    })?;
    Ok(match readiness {
        hybridcipher_client::GroupInitializationReadiness::Ready { .. } => "ready",
        hybridcipher_client::GroupInitializationReadiness::WaitingDeviceApproval => {
            "waiting_for_device_approval"
        }
    }
    .into())
}
/// File choices for a coverage proof belong to the currently selected workspace.
#[tauri::command]
pub async fn list_coverage_verification_files(
    state: State<'_, AppState>,
) -> Result<Vec<Value>, String> {
    let _guard = ensure_local_data_access(&state).await?;
    let session = state
        .session
        .lock()
        .await
        .clone()
        .ok_or("No account is open")?;
    let group = active_group_id_for_session(&state)
        .await
        .ok_or("Select a group before verifying coverage")?;
    validate_group_access(&state, &session, group, false).await?;
    let client = state.local_client.client().await?.for_local_group(group);
    let records = client
        .coverage_file_records(None)
        .await
        .map_err(|error| error.to_string())?;
    Ok(records.into_iter().filter_map(|record| {
        let file_id = record.entry.file_id?;
        let path = if record.root.kind == hybridcipher_client::coverage::CoverageRootKind::SingleFile {
            record.root.path
        } else {
            record.root.path.join(&record.entry.relative_path)
        };
        Some(json!({"file_id":file_id,"path":path.to_string_lossy(),"relative_path":record.entry.relative_path}))
    }).collect())
}
async fn run_typed_operation(
    id: &str,
    request: DesktopOperationRequest,
    group: Option<Uuid>,
    session: &crate::state::UserSession,
    state: &AppState,
) -> Result<Value, (String, String)> {
    let run = async {
        if request.kind == "switch_group" {
            let _selection_guard = WORKSPACE_SELECTION_LOCK.lock().await;
            let group = group.ok_or("Select a group")?;
            let metadata = validate_group_access(
                state,
                session,
                group,
                session.expires_at > chrono::Utc::now().timestamp(),
            )
            .await?;
            let client = state.local_client.client().await?;
            let workspace = if metadata["organization_id"].is_string() {
                "team"
            } else {
                "personal"
            };
            client
                .store_local_config("desktop_ui_group_id", &group.to_string())
                .await
                .map_err(|error| error.to_string())?;
            client
                .store_local_config(
                    &format!("desktop_selected_{}_group", workspace),
                    &group.to_string(),
                )
                .await
                .map_err(|error| error.to_string())?;
            let has_keys = client
                .has_cached_group_key(group)
                .await
                .map_err(|error| error.to_string())?;
            let readiness = if session.expires_at <= chrono::Utc::now().timestamp() {
                if !has_keys {
                    return Err("This device has no cached keys for the selected group".into());
                }
                "ready".into()
            } else {
                prepare_group(state, group).await?
            };
            if readiness == "ready" {
                client
                    .use_group(group)
                    .await
                    .map_err(|error| error.to_string())?;
                client
                    .store_local_config("group_id", &group.to_string())
                    .await
                    .map_err(|error| error.to_string())?;
                client
                    .store_local_config("desktop_ui_group_id", &group.to_string())
                    .await
                    .map_err(|error| error.to_string())?;
                client
                    .store_local_config(
                        &format!("desktop_selected_{}_group", workspace),
                        &group.to_string(),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
            }
            return Ok(json!({"group_id":group,"name":metadata["name"],"readiness":readiness}));
        }
        super::license::require_team_write(state).await?;
        let organization_id = super::license::verified_claims(session, false)?
            .ok_or("The Team license is unavailable")?
            .organization_id;
        let first_setup = if request.kind == "team_setup" {
            let client = state.local_client.client().await?;
            !client
                .load_local_config("desktop_team_setup")
                .await
                .map_err(|error| error.to_string())?
                .and_then(|value| serde_json::from_str::<Value>(&value).ok())
                .is_some_and(|setup| {
                    setup["organization_id"].as_str() == Some(organization_id.as_str())
                        && matches!(setup["readiness"].as_str(), Some("ready" | "deleted"))
                })
        } else {
            false
        };
        let server = current_server_url(state, session);
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|error| error.to_string())?;
        let (target, name) = match request.kind.as_str() {
            "team_setup" => {
                update_phase(id, "Preparing the Team default group", None).await;
                let response = http
                    .post(api_endpoint(
                        &server,
                        "organizations/me/default-group/ensure",
                    ))
                    .bearer_auth(&session.token)
                    .send()
                    .await
                    .map_err(|error| error.to_string())?;
                if !response.status().is_success() {
                    return Err(format!(
                        "Default group setup could not continue ({})",
                        response.status()
                    ));
                }
                let group: Value = response.json().await.map_err(|error| error.to_string())?;
                let target = group["group_id"]
                    .as_str()
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or("Default group ID missing")?;
                if group["status"] == "deleted" {
                    update_phase(id, "Default Team group deleted", Some(target)).await;
                    state
                        .local_client
                        .client()
                        .await?
                        .store_local_config(
                            "desktop_team_setup",
                            &json!({"group_id":target,"name":group["name"],"organization_id":organization_id,"readiness":"deleted"})
                                .to_string(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                    return Ok(
                        json!({"group_id":target,"name":group["name"],"organization_id":organization_id,"readiness":"deleted","first_setup":false}),
                    );
                }
                (
                    target,
                    group["name"].as_str().unwrap_or("init-group").to_string(),
                )
            }
            "create_group" => {
                let name = request.name.as_deref().unwrap_or("").trim();
                if name.is_empty() || name.len() > 100 {
                    return Err("Enter a group name between 1 and 100 characters".into());
                }
                update_phase(id, "Creating group", None).await;
                let target =
                    super::license::create_group_durably(state, name, request.description.clone())
                        .await?;
                (target, name.to_string())
            }
            "initialize_group" => {
                let target = group.ok_or("Group ID is required")?;
                let metadata = validate_group_access(state, session, target, true).await?;
                (
                    target,
                    metadata["name"]
                        .as_str()
                        .unwrap_or("Team group")
                        .to_string(),
                )
            }
            _ => return Err("Unknown group operation".into()),
        };
        update_phase(id, "Initializing encrypted group keys", Some(target)).await;
        let client = state.local_client.client().await?;
        let setup = json!({"group_id":target,"name":name,"organization_id":organization_id,"readiness":"uninitialized"});
        if request.kind == "team_setup" {
            client
                .store_local_config("desktop_team_setup", &setup.to_string())
                .await
                .map_err(|error| error.to_string())?;
            // Metadata and device approval must address Team even before this device has keys.
            client
                .store_local_config("desktop_selected_team_group", &target.to_string())
                .await
                .map_err(|error| error.to_string())?;
        }
        let readiness = prepare_group(state, target).await?;
        if readiness == "ready" && request.kind != "team_setup" {
            super::license::finish_group_creation(state, target).await?;
        }
        let result = json!({"group_id":target,"name":name,"organization_id":organization_id,"readiness":readiness,"first_setup":first_setup});
        if request.kind == "team_setup" {
            client
                .store_local_config("desktop_team_setup", &result.to_string())
                .await
                .map_err(|error| error.to_string())?;
        }
        let _ = cached_group_list(state, session, true).await;
        Ok(result)
    };
    run.await
        .map_err(|message: String| ("group_setup_failed".into(), message))
}
