// Verify GUI operations reject shell/account/group bypasses and safely consume credential prompts.
use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}
#[test]
fn desktop_operation_rejects_an_account_switch_before_execution() {
    assert!(validate_expected_account(Some("old@example.com"), "new@example.com").is_err());
    assert!(validate_expected_account(Some("USER@example.com"), "user@example.com").is_ok());
}
#[tokio::test]
async fn workspace_selection_rejects_a_superseded_context_before_commit() {
    let key = Uuid::new_v4().to_string();
    register_workspace_selection(&key, 1).await.unwrap();
    register_workspace_selection(&key, 2).await.unwrap();
    assert!(validate_workspace_selection(&key, 1).await.is_err());
    assert!(register_workspace_selection(&key, 1).await.is_err());
    validate_workspace_selection(&key, 2).await.unwrap();
    WORKSPACE_SELECTIONS.lock().await.remove(&key);
}
#[test]
fn desktop_adapter_rejects_unowned_commands_and_account_overrides() {
    let group = Some(Uuid::new_v4());
    assert!(validate_cli_args(&args(&["cmd", "/C", "echo hello"]), None).is_err());
    assert!(validate_cli_args(
        &args(&["recovery", "fetch", "--config=other-account"]),
        group
    )
    .is_err());
    assert!(
        validate_cli_args(&args(&["recovery", "fetch", "--password", "secret"]), group).is_err()
    );
}
#[test]
fn desktop_adapter_requires_and_checks_explicit_group_scope() {
    let expected = Uuid::new_v4();
    let other = Uuid::new_v4();
    assert!(validate_cli_args(&args(&["rekey", "start"]), None).is_err());
    for command in [
        "recovery",
        "pin",
        "audit-devices",
        "unverified-devices",
        "devices",
        "health-check",
        "current-group",
    ] {
        assert!(
            validate_cli_args(&args(&[command]), None).is_err(),
            "{} must not inherit a Personal group",
            command
        );
    }
    assert!(validate_cli_args(&args(&["current-user"]), None).is_ok());
    assert!(validate_cli_args(
        &args(&["verify-membership", "--group", &other.to_string()]),
        Some(expected)
    )
    .is_err());
    assert!(validate_cli_args(
        &args(&["verify-membership", "--group", &expected.to_string()]),
        Some(expected)
    )
    .is_ok());
    assert!(validate_cli_args(
        &args(&["rename-group", &other.to_string(), "--name", "renamed"]),
        Some(expected)
    )
    .is_err());
    assert!(validate_cli_args(
        &args(&["delete-group", &expected.to_string(), "--yes"]),
        Some(expected)
    )
    .is_ok());
}
#[test]
fn generated_arguments_are_values_even_when_they_contain_shell_punctuation() {
    assert!(validate_cli_args(
        &args(&["add-member", "person&test@example.com"]),
        Some(Uuid::new_v4())
    )
    .is_ok());
    assert!(validate_cli_args(&args(&["coverage", "--help"]), None).is_ok());
}
#[tokio::test]
async fn prompt_transport_does_not_put_credentials_in_operation_output() {
    let id = Uuid::new_v4().to_string();
    let (answers, _) = mpsc::channel(1);
    let (cancel, _) = watch::channel(false);
    let snapshot = DesktopOperationSnapshot {
        id: id.clone(),
        account_id: "test".into(),
        group_id: None,
        status: "running".into(),
        phase: "Starting".into(),
        output: vec![],
        result: None,
        error: None,
        input_request: None,
    };
    OPERATIONS.lock().await.insert(
        id.clone(),
        Operation {
            snapshot,
            server: "https://example.test".into(),
            answers,
            cancel,
        },
    );
    record_cli_line(&id,format!("{}{}",PROMPT_PREFIX,r#"{"event":"needs_input","id":"1","kind":"password","message":"Enter account password","default_value":null}"#),&[]).await;
    let op = OPERATIONS.lock().await.get(&id).unwrap().snapshot.clone();
    assert_eq!(op.status, "needs_input");
    assert!(op.output.is_empty());
    assert_eq!(op.input_request.unwrap().kind, "password");
    record_cli_line(
        &id,
        "An error mentioned sensitive-input".into(),
        &[Zeroizing::new("sensitive-input".into())],
    )
    .await;
    assert!(!OPERATIONS
        .lock()
        .await
        .get(&id)
        .unwrap()
        .snapshot
        .output
        .join("\n")
        .contains("sensitive-input"));
    OPERATIONS.lock().await.remove(&id);
}
