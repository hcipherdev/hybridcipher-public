// Tests server_group_key_versions() in src/commands/operations.rs, which reads each group's current key version from the server's group list for the key update check.
use super::*;

#[test]
fn each_group_reports_its_current_key_version() {
    let team = Uuid::new_v4();
    let personal = Uuid::new_v4();
    let groups = vec![
        json!({"id": team, "current_epoch_id": EpochIdMapper::u64_to_uuid(9, team.as_bytes())}),
        json!({"id": personal, "current_epoch_id": EpochIdMapper::u64_to_uuid(2, personal.as_bytes())}),
    ];
    assert_eq!(
        server_group_key_versions(&groups),
        vec![(team, 9), (personal, 2)]
    );
}

#[test]
fn groups_without_a_usable_key_id_are_left_out() {
    let group = Uuid::new_v4();
    let groups = vec![
        // No key yet, a key ID from another group, a legacy random ID, and malformed rows.
        json!({"id": group, "current_epoch_id": null}),
        json!({"id": group, "current_epoch_id": EpochIdMapper::u64_to_uuid(3, Uuid::new_v4().as_bytes())}),
        json!({"id": group, "current_epoch_id": Uuid::new_v4()}),
        json!({"id": "not-a-uuid", "current_epoch_id": EpochIdMapper::u64_to_uuid(3, group.as_bytes())}),
        json!({"id": group, "current_epoch_id": 7}),
    ];
    assert!(server_group_key_versions(&groups).is_empty());
}
