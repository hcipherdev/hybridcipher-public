// Tests is_cutover_complete() and the RekeyCommands parser in src/commands/rekey.rs and src/commands/mod.rs: a rotation finishes as it starts, `rekey start --yes` skips the confirmation, and `rekey cutover`, `rekey fallback` and `--activation-delay` are gone.
use super::*;
use clap::Parser;

#[derive(Parser)]
struct RekeyCli {
    #[command(subcommand)]
    command: RekeyCommands,
}

fn status(state: &str) -> ApiRekeyStatus {
    serde_json::from_value(serde_json::json!({
        "rekey_id": Uuid::nil(), "group_id": Uuid::nil(), "status": state,
        "progress": { "total_files": 0, "migrated_files": 0, "total_members": 2, "confirmed_members": 0,
                      "estimated_time_remaining_minutes": null },
        "started_at": "2026-10-23T09:00:00Z", "last_updated": "2026-10-23T09:00:00Z", "errors": [],
        "can_cutover": false,
    }))
    .unwrap()
}

#[test]
fn a_started_rotation_is_already_finished() {
    let response: ApiRekeyResponse = serde_json::from_value(serde_json::json!({
        "rekey_id": Uuid::nil(), "group_id": Uuid::nil(), "new_epoch_id": Uuid::nil().to_string(),
        "status": "completed", "initiated_at": "2026-10-23T09:00:00Z",
        "estimated_completion": "2026-10-23T09:00:00Z",
        "migration_progress": { "total_files": 0, "migrated_files": 0, "total_members": 2,
                                "confirmed_members": 0, "estimated_time_remaining_minutes": 0 },
    }))
    .unwrap();
    assert!(response.status.eq_ignore_ascii_case("completed"));
    assert!(is_cutover_complete(&status("completed")));
    // An older server keeps the rotation running until it is cut over.
    assert!(!is_cutover_complete(&status("in_progress")));
}

#[test]
fn cancelling_finishing_and_delaying_are_no_longer_commands() {
    for args in [
        vec!["rekey", "cutover"],
        vec!["rekey", "fallback", "--yes"],
        vec!["rekey", "start", "--activation-delay", "immediate"],
    ] {
        assert!(
            RekeyCli::try_parse_from(&args).is_err(),
            "{args:?} should be rejected"
        );
    }
    match RekeyCli::try_parse_from(["rekey", "start", "--local-migration", "now"]) {
        Ok(RekeyCli {
            command:
                RekeyCommands::Start {
                    local_migration,
                    yes,
                    ..
                },
        }) => {
            assert_eq!(local_migration, "now");
            assert!(!yes);
        }
        _ => panic!("`rekey start --local-migration now` should parse"),
    }
    // The desktop app confirms in its own dialog and passes --yes.
    match RekeyCli::try_parse_from(["rekey", "start", "--yes", "--local-migration", "defer"]) {
        Ok(RekeyCli {
            command: RekeyCommands::Start { yes, .. },
        }) => assert!(yes),
        _ => panic!("`rekey start --yes` should parse"),
    }
}
