// Tests input validation and the rotation's files summary (files_moved_result) in src/commands/team_tasks.rs.
use super::*;

#[test]
fn emails_that_could_become_cli_options_are_rejected() {
    assert_eq!(normalize_email(Some(" Alex@Example.COM ")).unwrap(), "alex@example.com");
    for bad in ["", "alex", "--yes@example.com", "-x@example.com", "a b@example.com", "alex@localhost"] {
        assert!(normalize_email(Some(bad)).is_err(), "{bad}");
    }
}

#[test]
fn members_are_user_ids_or_emails() {
    let id = Uuid::new_v4();
    assert_eq!(normalize_member(Some(&id.to_string())).unwrap(), id.to_string());
    assert_eq!(normalize_member(Some("Bo@example.com")).unwrap(), "bo@example.com");
    assert!(normalize_member(Some("--force")).is_err());
}

#[test]
fn device_ids_are_plain_identifiers() {
    assert_eq!(normalize_device_id(Some("device_0650e349")).unwrap(), "device_0650e349");
    for bad in ["", "-d", "device id", "dev;rm", &"x".repeat(129)] {
        assert!(normalize_device_id(Some(bad)).is_err(), "{bad}");
    }
}

#[test]
fn the_rotation_result_says_how_many_files_moved_and_names_a_few_failures() {
    let failure = |index: usize| hybridcipher_client::CoverageMigrationFailure {
        path: format!("/folder/file-{index}.txt"),
        from_version: Some(8),
        reason: "file is open in another app".into(),
    };
    let moved = hybridcipher_client::LeftoverKeyMigration {
        migrated: 152,
        failed: 7,
        failures: (0..7).map(failure).collect(),
        rotation_running: false,
    };
    let result = files_moved_result(&moved);
    assert_eq!((result["moved"].as_u64(), result["failed"].as_u64()), (Some(152), Some(7)));
    assert_eq!(result["failures"].as_array().map(Vec::len), Some(5));
    assert_eq!(result["rotation_running"], false);
}
