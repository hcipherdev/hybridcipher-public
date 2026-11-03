// Tests classify_rekey_start_response(), server_error_message(), reset_stale_migration() and choose_rekey_target() in src/commands/rekey.rs, which decide how `rekey start` reports the server's answer and clear leftover local migration records, and pick the new key version.
use super::*;

#[test]
fn only_a_conflict_means_a_rotation_is_already_running() {
    assert_eq!(classify_rekey_start_response(StatusCode::OK), RekeyStartOutcome::Accepted);
    assert_eq!(classify_rekey_start_response(StatusCode::CONFLICT), RekeyStartOutcome::AlreadyRunning);
    // A 400 is a rejection (for example missing Welcome payloads), not an active rotation.
    assert_eq!(classify_rekey_start_response(StatusCode::BAD_REQUEST), RekeyStartOutcome::Rejected);
    assert_eq!(classify_rekey_start_response(StatusCode::FORBIDDEN), RekeyStartOutcome::Rejected);
}

#[test]
fn rejections_show_the_server_message() {
    assert_eq!(
        server_error_message(r#"{"error":"Missing Welcome payloads for devices: u:pc"}"#),
        "Missing Welcome payloads for devices: u:pc"
    );
    assert_eq!(server_error_message(r#"{"message":"Group not found"}"#), "Group not found");
    assert_eq!(server_error_message("  bad gateway \n"), "bad gateway");
}

#[test]
fn a_leftover_started_record_is_reset_but_finished_ones_are_kept() {
    let record = |phase| MigrationInfo {
        current_epoch: 1,
        target_epoch: Some(2),
        migration_start: Some(Utc::now()),
        phase,
        pending_files: vec!["device:mac".into()],
        progress: 0.0,
        total_files: 3,
    };
    let mut started = record(MigrationPhase::Started);
    assert!(reset_stale_migration(&mut started));
    assert!(matches!(started.phase, MigrationPhase::Idle));
    assert_eq!(started.target_epoch, None);
    assert!(started.pending_files.is_empty());
    assert!(!started.phase.is_active());

    let mut completed = record(MigrationPhase::Completed);
    assert!(!reset_stale_migration(&mut completed));
    assert_eq!(completed.target_epoch, Some(2));
}

#[test]
fn a_new_rotation_never_reuses_a_cancelled_version() {
    // v2 is current and the v3 rotation was cancelled: the next rotation is v4.
    assert_eq!(choose_rekey_target(2, None, Some(3)), 4);
    // A stale local record of the cancelled v3 rotation doesn't pull it back to v3.
    assert_eq!(choose_rekey_target(2, Some(3), Some(3)), 4);
    // Nothing cancelled: the usual current + 1.
    assert_eq!(choose_rekey_target(2, None, Some(2)), 3);
    // Retrying a start the server never recorded keeps its staged version.
    assert_eq!(choose_rekey_target(2, Some(3), Some(2)), 3);
    // An older server without key status: current + 1 (the server still refuses a used version).
    assert_eq!(choose_rekey_target(2, None, None), 3);
    assert_eq!(choose_rekey_target(2, Some(2), None), 3);
}
