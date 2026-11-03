//! Account-scoped desktop operations; ordinary UI actions never launch shells or PTYs.
use super::*;
use crate::state::UserSession;
use hybridcipher_crypto::epoch_id::EpochIdMapper;
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
    /// 0–100 while a step can say how far it is (moving files); otherwise the bar just runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
}
#[derive(Deserialize)]
pub struct DesktopOperationRequest {
    pub kind: String,
    pub workspace: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    pub group_id: Option<String>,
    pub title: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub expected_account_email: Option<String>,
    /// Person to add or invite (task-level actions).
    #[serde(default)]
    pub email: Option<String>,
    /// Member to remove: user ID or email.
    #[serde(default)]
    pub member: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    /// Pending Team invitation that should carry this group's access.
    #[serde(default)]
    pub invitation_id: Option<String>,
    /// Rotate group keys after removing a member (default true).
    #[serde(default)]
    pub rotate_keys: Option<bool>,
    /// Rotate keys even if some devices cannot receive the new key; the admin
    /// confirmed they catch up through device approval.
    #[serde(default)]
    pub skip_unreachable: Option<bool>,
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
    device_id: String,
    auth_generation: u64,
    answers: mpsc::Sender<DesktopOperationAnswer>,
    cancel: watch::Sender<bool>,
    /// Structured `result` events reported by CLI steps, newest last.
    results: Vec<Value>,
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
fn group_matches_workspace(group: &Value, workspace: &str, organization: Option<&str>) -> bool {
    match workspace {
        "personal" => !group["organization_id"].is_string(),
        "team" => organization.is_some_and(|id| group["organization_id"].as_str() == Some(id)),
        _ => false,
    }
}

async fn authorize_operation(state: &AppState, operation: &Operation) -> Result<(), String> {
    let session = state.session.lock().await;
    let session = session.as_ref().ok_or("Sign in to view this operation")?;
    validate_operation_session(
        session,
        &current_server_url(state, session),
        state.auth_generation(),
        operation,
    )
}
fn validate_operation_session(
    session: &UserSession,
    server: &str,
    auth_generation: u64,
    operation: &Operation,
) -> Result<(), String> {
    if session.user_id != operation.snapshot.account_id
        || session.device_id != operation.device_id
        || auth_generation != operation.auth_generation
        || canonical_server(server) != canonical_server(&operation.server)
    {
        return Err("This operation belongs to a previous or different login".into());
    }
    Ok(())
}
pub(super) async fn cancel_all_desktop_operations(state: &AppState) {
    super::mount_queue::cancel_for_transition();
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

/// Task-level Team actions implemented in `team_tasks`.
pub(super) const TASK_KINDS: [&str; 6] = [
    "add_member",
    "add_person",
    "stage_invitation_access",
    "remove_access",
    "rotate_keys",
    "approve_device",
];

/// Group administrators only; Team groups also need a writable Team license.
pub(super) async fn authorize_group_administration(
    state: &AppState,
    session: &UserSession,
    group: Uuid,
) -> Result<Value, String> {
    let metadata = validate_group_access(state, session, group, true).await?;
    let role = metadata["role"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(role.as_str(), "admin" | "owner") {
        return Err("Your role cannot administer this group".into());
    }
    if metadata["organization_id"].is_string() {
        super::license::require_team_write(state).await?;
    }
    Ok(metadata)
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
            | "repair-own-devices"
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
            // Sends keys only to this account's own devices that this account verified.
            | "repair-own-devices"
    ) || command == "server-trust" && action == "show"
        // publish-attestations only shares verifications already made on this device.
        || command == "pin" && matches!(action, "list" | "fingerprint" | "show" | "publish-attestations")
        // The rotation's own device checks, run before a rotation without starting one.
        || command == "rekey" && matches!(action, "status" | "preflight")
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
    let (session, auth_generation) = {
        let session = state.session.lock().await;
        (
            session.clone().ok_or("No account is open")?,
            state.auth_generation(),
        )
    };
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
    } else if TASK_KINDS.contains(&request.kind.as_str()) {
        // Task-level actions run CLI steps, which need a saved login like other CLI actions.
        if !session.persistent {
            return Err("This action needs a saved login. Sign in with Remember me.".into());
        }
        let group = group.ok_or("Select a group before starting this action")?;
        authorize_group_administration(&state, &session, group).await?;
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
        progress: None,
    };
    let (answers_tx, mut answers_rx) = mpsc::channel(1);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    {
        let mut registry = OPERATIONS.lock().await;
        if registry.values().any(|op| {
            op.snapshot.account_id == session.user_id
                && op.auth_generation == auth_generation
                && active(&op.snapshot)
        }) {
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
                device_id: session.device_id.clone(),
                auth_generation,
                answers: answers_tx,
                cancel: cancel_tx,
                results: Vec::new(),
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
                &mut answers_rx,
                &mut cancel_rx,
            )
            .await
        } else if TASK_KINDS.contains(&request.kind.as_str()) {
            super::team_tasks::run_task_operation(
                &id,
                &request,
                group,
                &session,
                &state,
                &mut answers_rx,
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
/// Newest structured result of `kind` reported by a CLI step of this operation.
pub(super) async fn last_task_result(id: &str, kind: &str) -> Option<Value> {
    OPERATIONS.lock().await.get(id).and_then(|op| {
        op.results
            .iter()
            .rev()
            .find(|event| event["kind"].as_str() == Some(kind))
            .map(|event| event["data"].clone())
    })
}
/// How far a step is, as 0–100, from items done out of a total (`None` while the total is unknown).
pub(super) fn progress_percent(done: usize, total: usize) -> Option<f64> {
    (total > 0).then(|| (done.min(total) as f64 * 100.0 / total as f64).round())
}

pub(super) async fn update_progress(id: &str, progress: Option<f64>) {
    if let Some(op) = OPERATIONS.lock().await.get_mut(id) {
        op.snapshot.progress = progress;
    }
}

pub(super) async fn update_phase(id: &str, phase: &str, group: Option<Uuid>) {
    if let Some(op) = OPERATIONS.lock().await.get_mut(id) {
        op.snapshot.phase = phase.into();
        // A new step starts without a known progress.
        op.snapshot.progress = None;
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
pub(super) async fn run_cli_operation(
    id: &str,
    args: &[String],
    group: Option<Uuid>,
    session: &crate::state::UserSession,
    state: &AppState,
    answers: &mut mpsc::Receiver<DesktopOperationAnswer>,
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
    let (output, results) = OPERATIONS
        .lock()
        .await
        .get(id)
        .map(|op| (op.snapshot.output.join("\n"), op.results.clone()))
        .unwrap_or_default();
    if !status.success() {
        // The full transcript stays in the operation output ("Technical details").
        return Err(("action_failed".into(), summarize_cli_failure(&output)));
    }
    let structured = serde_json::from_str::<Value>(&output).ok();
    Ok(json!({"exit_status":status.code().unwrap_or(-1),"output":output,"data":structured,"results":results}))
}
/// One readable sentence for a failed CLI command: the text of its last `✗ Error:` line.
fn summarize_cli_failure(output: &str) -> String {
    let error = output.lines().rev().find_map(|line| {
        let line = line.trim().trim_start_matches('✗').trim_start();
        line.strip_prefix("Error:").map(str::trim).filter(|text| !text.is_empty())
    });
    match error {
        Some(text) => text.to_string(),
        None if output.trim().is_empty() => {
            "The action failed. Review account and group access before retrying.".into()
        }
        None => "The action failed. Open Technical details for the full output.".into(),
    }
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
        if event.get("event").and_then(Value::as_str) == Some("result") {
            if op.results.len() < 32 {
                op.results.push(event);
            }
            return;
        }
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
pub(super) fn group_epoch_uuid(group: &Value) -> Result<Option<Uuid>, String> {
    match group.get("current_epoch_id") {
        Some(Value::String(id)) => Uuid::parse_str(id)
            .map(Some)
            .map_err(|_| "Invalid current group epoch".into()),
        Some(Value::Null) | None => Ok(None),
        _ => Err("Invalid current group epoch".into()),
    }
}
pub(super) async fn cached_group_list(
    state: &AppState,
    session: &crate::state::UserSession,
    refresh: bool,
) -> Result<Vec<Value>, String> {
    let scope = super::personal_workspace::WorkspaceSessionScope::capture(state, session);
    scope.ensure_current(state).await?;
    let client = state.local_client.client().await?;
    if refresh && session.expires_at > chrono::Utc::now().timestamp() {
        if let Ok(Ok(list)) = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            fetch_group_list(&current_server_url(state, session), &session.token),
        )
        .await
        {
            let groups = list.groups.into_iter().map(|group| json!({"id":group.id,"name":group.name,"organization_id":group.organization_id,"role":group.user_role,"current_epoch_id":group.current_epoch})).collect::<Vec<_>>();
            scope.ensure_current(state).await?;
            if let Ok(mut watch) = state.group_key_watch.lock() {
                watch.list_refreshed_at = Some(std::time::Instant::now());
            }
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
    scope.ensure_current(state).await?;
    Ok(cached
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default())
}
/// A group list fetched this recently is reused by the key update check instead of fetching
/// another one; the app's workspace refresh already fetches it about once a minute.
const GROUP_LIST_REUSE: std::time::Duration = std::time::Duration::from_secs(55);

/// Each group's current key version from the server's group list. Groups without a key, and
/// key IDs that do not map to a version (legacy groups), are left out.
pub(super) fn server_group_key_versions(groups: &[Value]) -> Vec<(Uuid, u64)> {
    groups
        .iter()
        .filter_map(|group| {
            let group_id = Uuid::parse_str(group["id"].as_str()?).ok()?;
            let epoch_id = group_epoch_uuid(group).ok().flatten()?;
            let version = EpochIdMapper::uuid_to_u64(epoch_id, group_id.as_bytes())?;
            Some((group_id, version))
        })
        .collect()
}

/// Whether a group's current key is one this device does not hold yet, and was not reported
/// before. The app then runs its key check at once instead of waiting for the hourly one, so a
/// member picks up a rotation within about a minute. Fetches the group list only when no
/// recent one is cached.
#[tauri::command]
pub async fn group_key_update_available(
    state: State<'_, AppState>,
) -> Result<CommandResponse<bool>, String> {
    let _guard = ensure_authenticated(&state).await?;
    let Some(session) = state.session.lock().await.clone() else {
        return Ok(CommandResponse::ok(false));
    };
    let refresh = state.group_key_watch.lock().map_or(true, |watch| {
        watch
            .list_refreshed_at
            .map_or(true, |at| at.elapsed() >= GROUP_LIST_REUSE)
    });
    let groups = match cached_group_list(&state, &session, refresh).await {
        Ok(groups) => groups,
        Err(_) => return Ok(CommandResponse::ok(false)),
    };
    let client = state.local_client.client().await?;
    let mut newer = Vec::new();
    for (group_id, version) in server_group_key_versions(&groups) {
        if !client.holds_group_key(group_id, version).await {
            newer.push((group_id, version));
        }
    }
    let mut watch = state
        .group_key_watch
        .lock()
        .map_err(|_| "Group key watch unavailable".to_string())?;
    let mut announce = false;
    for key in newer {
        announce |= watch.announced.insert(key);
    }
    Ok(CommandResponse::ok(announce))
}

#[cfg(test)]
#[path = "../../tests/operations/test_group_key_updates.rs"]
mod group_key_updates_tests;

pub(super) async fn validate_group_access(
    state: &AppState,
    session: &crate::state::UserSession,
    id: Uuid,
    refresh: bool,
) -> Result<Value, String> {
    let group = cached_group_list(state, session, refresh)
        .await?
        .into_iter()
        .find(|group| group["id"].as_str() == Some(&id.to_string()));
    if let Some(group) = group {
        return Ok(group);
    }
    // The Personal default is resolved independently of the paginated group list.
    let personal =
        super::personal_workspace::personal_workspace_snapshot(state, session, refresh).await?;
    if personal["state"] == "available" && personal["group"]["id"].as_str() == Some(&id.to_string())
    {
        return Ok(personal["group"].clone());
    }
    Err("The selected group is not available to this account".into())
}
#[tauri::command]
pub async fn get_workspace_group_context(
    workspace: String,
    selection_sequence: Option<u64>,
    expected_account_email: Option<String>,
    read_only: Option<bool>,
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
    let session_scope = super::personal_workspace::WorkspaceSessionScope::capture(&state, &session);
    let selection_key = format!(
        "{}@{}",
        session.user_id,
        canonical_server(&current_server_url(&state, &session))
    );
    let read_only = read_only.unwrap_or(false);
    if let Some(sequence) = selection_sequence.filter(|_| !read_only) {
        register_workspace_selection(&selection_key, sequence).await?;
    }
    let _selection_guard = WORKSPACE_SELECTION_LOCK.lock().await;
    let organization = if workspace == "team" {
        Some(
            super::license::verified_claims(&session, true)?
                .ok_or("The Team license is unavailable for this workspace")?
                .organization_id,
        )
    } else {
        None
    };
    let personal = if workspace == "personal" {
        Some(super::personal_workspace::personal_workspace_snapshot(&state, &session, true).await?)
    } else {
        None
    };
    let groups = if let Some(personal) = &personal {
        if personal["state"] == "available" {
            vec![personal["group"].clone()]
        } else {
            Vec::new()
        }
    } else {
        cached_group_list(&state, &session, true)
            .await?
            .into_iter()
            .filter(|group| group_matches_workspace(group, &workspace, organization.as_deref()))
            .collect::<Vec<_>>()
    };
    let client = state.local_client.client().await?;
    let selected_key = format!("desktop_selected_{}_group", workspace);
    let selected = if workspace == "team" {
        client
            .load_local_config(&selected_key)
            .await
            .map_err(|error| error.to_string())?
    } else {
        None
    };
    let active = if workspace == "team" {
        client.active_group_id_opt().await.map(|id| id.to_string())
    } else {
        None
    };
    let group = if workspace == "personal" {
        groups.first()
    } else {
        groups
            .iter()
            .find(|group| group["id"].as_str() == selected.as_deref())
            .or_else(|| {
                groups
                    .iter()
                    .find(|group| group["id"].as_str() == active.as_deref())
            })
            .or_else(|| groups.first())
    };
    let mut context = WorkspaceGroupContext {
        group_id: None,
        name: None,
        organization_id: None,
        role: None,
        readiness: personal
            .as_ref()
            .and_then(|value| value["state"].as_str())
            .filter(|state| *state != "available")
            .unwrap_or("no_groups")
            .into(),
        groups: groups.clone(),
    };
    if let Some(sequence) = selection_sequence.filter(|_| !read_only) {
        validate_workspace_selection(&selection_key, sequence).await?;
    }
    if let Some(group) = group {
        context.group_id = group["id"].as_str().map(str::to_string);
        context.name = group["name"].as_str().map(str::to_string);
        context.organization_id = group["organization_id"].as_str().map(str::to_string);
        context.role = group["role"].as_str().map(|role| role.to_ascii_lowercase());
        let id = Uuid::parse_str(context.group_id.as_deref().unwrap_or_default())
            .map_err(|_| "Invalid cached group")?;
        let epoch = group_epoch_uuid(group)?;
        let mut has_keys = if let Some(epoch) = epoch {
            client
                .has_cached_group_epoch_key(id, epoch)
                .await
                .map_err(|error| error.to_string())?
        } else {
            false
        };
        if !read_only
            && !has_keys
            && epoch.is_some()
            && session.expires_at > chrono::Utc::now().timestamp()
        {
            // Reconcile an established namespace; acquiring keys never creates genesis.
            let _ = client.refresh_committed_group_epoch(id).await;
            has_keys = client
                .has_cached_group_epoch_key(id, epoch.unwrap())
                .await
                .map_err(|error| error.to_string())?;
        }
        session_scope.ensure_current(&state).await?;
        if let Some(sequence) = selection_sequence.filter(|_| !read_only) {
            validate_workspace_selection(&selection_key, sequence).await?;
        }
        context.readiness = if has_keys {
            "ready"
        } else if epoch.is_some() {
            "waiting_for_device_approval"
        } else {
            "uninitialized"
        }
        .into();
        if !read_only {
            client
                .store_local_config("desktop_ui_group_id", &id.to_string())
                .await
                .map_err(|error| error.to_string())?;
        }
        if has_keys && !read_only {
            client
                .use_group_at_epoch(id, epoch.unwrap())
                .await
                .map_err(|error| error.to_string())?;
            session_scope.ensure_current(&state).await?;
            if let Some(sequence) = selection_sequence.filter(|_| !read_only) {
                validate_workspace_selection(&selection_key, sequence).await?;
            }
            client
                .store_local_config("group_id", &id.to_string())
                .await
                .map_err(|error| error.to_string())?;
            if workspace == "team" {
                client
                    .store_local_config(&selected_key, &id.to_string())
                    .await
                    .map_err(|error| error.to_string())?;
            }
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
                // Setup metadata identifies the group but cannot establish an
                // administrator role without membership metadata.
                context.role = None;
                let epoch = group_epoch_uuid(&setup)?;
                let has_keys = if let Some(epoch) = epoch {
                    client
                        .has_cached_group_epoch_key(id, epoch)
                        .await
                        .map_err(|error| error.to_string())?
                } else {
                    false
                };
                context.readiness = if setup["readiness"] == "deleted" {
                    "deleted"
                } else if has_keys {
                    "ready"
                } else if epoch.is_some()
                    || setup["readiness"] == "waiting_for_device_approval"
                    || setup["readiness"] == "ready"
                {
                    "waiting_for_device_approval"
                } else {
                    "uninitialized"
                }
                .into();
                session_scope.ensure_current(&state).await?;
                if let Some(sequence) = selection_sequence.filter(|_| !read_only) {
                    validate_workspace_selection(&selection_key, sequence).await?;
                }
                if context.readiness != "deleted" {
                    context.groups.push(json!({"id":id,"name":context.name,"organization_id":context.organization_id,"role":null,"current_epoch_id":epoch}));
                    if !read_only {
                        client
                            .store_local_config("desktop_ui_group_id", &id.to_string())
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                    if context.readiness == "ready" && !read_only {
                        client
                            .use_group_at_epoch(id, epoch.unwrap())
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
    session_scope.ensure_current(&state).await?;
    if let Some(sequence) = selection_sequence.filter(|_| !read_only) {
        validate_workspace_selection(&selection_key, sequence).await?;
    }
    if !read_only && context.group_id.is_none() {
        client
            .store_local_config("desktop_ui_group_id", "")
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(context)
}
async fn prepare_group(state: &AppState, group: Uuid) -> Result<String, String> {
    if super::local_vault::pending_vault_upgrade(state)
        .is_some_and(|(vault_group, _)| vault_group != group)
    {
        return Err(super::local_vault::LOCAL_VAULT_UPGRADE_PENDING.into());
    }
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
            let session_scope =
                super::personal_workspace::WorkspaceSessionScope::capture(state, session);
            session_scope.ensure_current(state).await?;
            let _selection_guard = WORKSPACE_SELECTION_LOCK.lock().await;
            let group = group.ok_or("Select a group")?;
            let mut metadata = validate_group_access(
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
            if workspace == "personal" {
                let personal =
                    super::personal_workspace::personal_workspace_snapshot(state, session, true)
                        .await?;
                if personal["state"] != "available"
                    || personal["personal_default_group_id"].as_str() != Some(&group.to_string())
                {
                    return Err("Personal mode always uses the account's Personal default group. Repair Personal setup to change a missing default.".into());
                }
                metadata = personal["group"].clone();
            }
            session_scope.ensure_current(state).await?;
            client
                .store_local_config("desktop_ui_group_id", &group.to_string())
                .await
                .map_err(|error| error.to_string())?;
            if workspace == "team" {
                client
                    .store_local_config("desktop_selected_team_group", &group.to_string())
                    .await
                    .map_err(|error| error.to_string())?;
            }
            let mut epoch = group_epoch_uuid(&metadata)?;
            let has_keys = if let Some(epoch) = epoch {
                client
                    .has_cached_group_epoch_key(group, epoch)
                    .await
                    .map_err(|error| error.to_string())?
            } else {
                false
            };
            let readiness = if session.expires_at <= chrono::Utc::now().timestamp() {
                if !has_keys {
                    return Err(
                        "This device has no verified keys for the selected group's current epoch"
                            .into(),
                    );
                }
                "ready".into()
            } else if epoch.is_some() {
                let _ = client.refresh_committed_group_epoch(group).await;
                if client
                    .has_cached_group_epoch_key(group, epoch.unwrap())
                    .await
                    .map_err(|error| error.to_string())?
                {
                    "ready".into()
                } else {
                    "waiting_for_device_approval".into()
                }
            } else if workspace == "personal" {
                "uninitialized".into()
            } else {
                prepare_group(state, group).await?
            };
            session_scope.ensure_current(state).await?;
            if readiness == "ready" && epoch.is_none() {
                metadata = validate_group_access(state, session, group, true).await?;
                epoch = group_epoch_uuid(&metadata)?;
                if epoch.is_none() {
                    return Err("The current group epoch could not be confirmed".into());
                }
            }
            if readiness == "ready" {
                client
                    .use_group_at_epoch(group, epoch.unwrap())
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
                if workspace == "team" {
                    client
                        .store_local_config(
                            &format!("desktop_selected_{}_group", workspace),
                            &group.to_string(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                }
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
        if request.kind == "team_setup" {
            if request.workspace.as_deref() != Some("team") {
                return Err("Team setup requires an explicit Team workspace context".into());
            }
            let response = http
                .get(api_endpoint(&server, "organizations/me"))
                .bearer_auth(&session.token)
                .send()
                .await
                .map_err(|error| error.to_string())?;
            if !response.status().is_success() {
                return Err(
                    "Connect with an active Team owner account before preparing its workspace"
                        .into(),
                );
            }
            let organization: Option<super::license::OrganizationStatus> =
                response.json().await.map_err(|error| error.to_string())?;
            if !organization.is_some_and(|organization| {
                organization.id.to_string() == organization_id
                    && organization.role == "owner"
                    && organization.license_status == "active"
            }) {
                return Err(
                    "Only the active Team organization owner can prepare its default workspace"
                        .into(),
                );
            }
        }
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
