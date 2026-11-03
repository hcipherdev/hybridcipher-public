// Verify GUI operations reject shell/account/group bypasses and safely consume credential prompts, that a failed command reports only its error line, step progress percentages (progress_percent), and that repairing your own devices may run in the background.
use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}
#[test]
fn desktop_operation_rejects_an_account_switch_before_execution() {
    assert!(validate_expected_account(Some("old@example.com"), "new@example.com").is_err());
    assert!(validate_expected_account(Some("USER@example.com"), "user@example.com").is_ok());
}
#[test]
fn workspace_group_selection_requires_a_verified_matching_team_organization() {
    let team = json!({"organization_id":"org-a"});
    let personal = json!({"organization_id":null});
    assert!(!group_matches_workspace(&team, "team", None));
    assert!(!group_matches_workspace(&team, "team", Some("org-b")));
    assert!(group_matches_workspace(&team, "team", Some("org-a")));
    assert!(!group_matches_workspace(&team, "personal", Some("org-a")));
    assert!(group_matches_workspace(&personal, "personal", None));
}
#[test]
fn operation_session_binding_rejects_relogin_and_preserves_token_refresh() {
    let mut session = UserSession {
        email: "test@example.test".into(),
        device_id: "test-device".into(),
        token: "original-token".into(),
        refresh_token: String::new(),
        team_entitlement: None,
        team_revoked: false,
        pending_team_requests: vec![],
        expires_at: i64::MAX,
        user_id: "test-user".into(),
        server_url: Some("https://example.test".into()),
        opaque_export_key: None,
        persistent: true,
    };
    let (answers, _) = mpsc::channel(1);
    let (cancel, _) = watch::channel(false);
    let operation = Operation {
        snapshot: DesktopOperationSnapshot {
            id: "operation".into(),
            account_id: session.user_id.clone(),
            group_id: None,
            status: "succeeded".into(),
            phase: "Complete".into(),
            output: vec![],
            result: None,
            error: None,
            input_request: None,
            progress: None,
        },
        server: "https://example.test".into(),
        device_id: session.device_id.clone(),
        auth_generation: 7,
        answers,
        cancel,
        results: Vec::new(),
    };
    assert!(
        validate_operation_session(&session, "https://example.test/api/v1/", 7, &operation).is_ok()
    );
    session.token = "refreshed-token".into();
    assert!(validate_operation_session(&session, "https://example.test", 7, &operation).is_ok());
    assert!(validate_operation_session(&session, "https://example.test", 8, &operation).is_err());
    assert!(validate_operation_session(&session, "https://another.test", 7, &operation).is_err());
    session.device_id = "other-device".into();
    assert!(validate_operation_session(&session, "https://example.test", 7, &operation).is_err());
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
fn repairing_own_devices_runs_in_the_background_without_a_group() {
    let repair = args(&["repair-own-devices", "--json", "--no-color"]);
    // It covers every group the account's devices need, so no group is selected for it.
    assert!(validate_cli_args(&repair, None).is_ok());
    assert!(background_cli_args_allowed(&repair));
    // Giving someone access still runs as a visible operation.
    assert!(!background_cli_args_allowed(&args(&["issue-welcome", "--device", "phone"])));
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
        progress: None,
    };
    OPERATIONS.lock().await.insert(
        id.clone(),
        Operation {
            snapshot,
            server: "https://example.test".into(),
            device_id: "test-device".into(),
            auth_generation: 1,
            answers,
            cancel,
            results: Vec::new(),
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

#[tokio::test]
async fn cli_result_events_become_structured_results_not_transcript_lines() {
    let id = Uuid::new_v4().to_string();
    let (answers, _) = mpsc::channel(1);
    let (cancel, _) = watch::channel(false);
    OPERATIONS.lock().await.insert(
        id.clone(),
        Operation {
            snapshot: DesktopOperationSnapshot {
                id: id.clone(),
                account_id: "account".into(),
                group_id: None,
                status: "running".into(),
                phase: "Working".into(),
                output: vec![],
                result: None,
                error: None,
                input_request: None,
                progress: None,
            },
            server: "https://example.test".into(),
            device_id: "test-device".into(),
            auth_generation: 1,
            answers,
            cancel,
            results: Vec::new(),
        },
    );
    for devices in [1, 2] {
        record_cli_line(
            &id,
            format!(
                "{}{{\"event\":\"result\",\"kind\":\"member_added\",\"data\":{{\"devices_added\":{}}}}}",
                PROMPT_PREFIX, devices
            ),
            &[],
        )
        .await;
    }
    record_cli_line(&id, "✓ Member added".into(), &[]).await;
    let op = OPERATIONS.lock().await.get(&id).unwrap().snapshot.clone();
    assert_eq!(op.output, vec!["✓ Member added".to_string()]);
    assert_eq!(
        last_task_result(&id, "member_added").await.unwrap()["devices_added"],
        2
    );
    assert!(last_task_result(&id, "device_approved").await.is_none());
    OPERATIONS.lock().await.remove(&id);
}

#[test]
fn a_failed_command_reports_its_error_line_not_the_whole_transcript() {
    let output = "=== Start Rekey Operation ===\nℹ Generated Welcome payloads for 2 device(s).\n\
        ℹ   3. Review system requirements and network connectivity\n\
        ✗ Error: Migration error: The server rejected the key rotation (400 Bad Request): Key version 3 was already used\n\
          ⏱ Command failed after 7.83s\nPossible solutions:\n  1. Stream the live dashboard";
    assert_eq!(
        summarize_cli_failure(output),
        "Migration error: The server rejected the key rotation (400 Bad Request): Key version 3 was already used"
    );
    assert_eq!(
        summarize_cli_failure("something went wrong\nexit"),
        "The action failed. Open Technical details for the full output."
    );
    assert_eq!(
        summarize_cli_failure("  "),
        "The action failed. Review account and group access before retrying."
    );
}

#[test]
fn step_progress_is_a_whole_percent_and_unknown_without_a_total() {
    assert_eq!(progress_percent(0, 0), None);
    assert_eq!(progress_percent(0, 159), Some(0.0));
    assert_eq!(progress_percent(53, 159), Some(33.0));
    assert_eq!(progress_percent(159, 159), Some(100.0));
    // A count past the total never shows more than 100.
    assert_eq!(progress_percent(170, 159), Some(100.0));
}
