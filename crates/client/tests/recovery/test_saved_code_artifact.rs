// Tests shared saved-code artifacts for authentication, legacy formats, and validated historical/current epoch planning.
use super::*;

fn entry(group: Uuid, number: u64, key: u8) -> BackupEntryPlain {
    BackupEntryPlain {
        group_id: group,
        epoch_number: number,
        epoch_uuid: EpochIdMapper::u64_to_uuid(number, group.as_bytes()),
        created_at: chrono::Utc::now(),
        is_active: true,
        encryption_key_b64: general_purpose::STANDARD.encode([key; 32]),
    }
}
fn scope(group: Uuid, number: u64) -> RecoveryGroupScope {
    RecoveryGroupScope {
        group_id: group,
        group_name: "Personal".into(),
        user_role: GroupRole::Admin,
        current_epoch_uuid: Some(EpochIdMapper::u64_to_uuid(number, group.as_bytes())),
    }
}

#[test]
fn test_saved_code_authenticates_entries_and_retains_history() {
    let group = Uuid::new_v4();
    let mut artifact = BackupArtifact::new("test-password", &[9; 32]).unwrap();
    artifact
        .append_entries(
            &[entry(group, 1, 3), entry(group, 2, 4)],
            "test-password",
            &[9; 32],
        )
        .unwrap();
    assert!(artifact.unlock("wrong-password", &[9; 32]).is_err());
    assert!(artifact.unlock("test-password", &[8; 32]).is_err());
    let unlocked = artifact.unlock("test-password", &[9; 32]).unwrap();
    let current = unlocked
        .validate_for_groups(&[scope(group, 2)], None)
        .unwrap();
    assert_eq!(current.group_readiness()[0].restored_epochs, 2);
    assert!(current.contains_current(group));
    let stale = unlocked
        .validate_for_groups(&[scope(group, 3)], None)
        .unwrap();
    assert!(!stale.contains_current(group));
    assert!(unlocked
        .validate_for_groups(&[scope(group, 2)], Some(Uuid::new_v4()))
        .is_err());
    let mut value = serde_json::to_value(&artifact).unwrap();
    value["version"] = serde_json::json!(2);
    let legacy = general_purpose::STANDARD.encode(serde_json::to_vec(&value).unwrap());
    assert_eq!(BackupArtifact::from_base64(&legacy).unwrap().version, 1);
}

#[test]
fn test_saved_code_rejects_corrupt_entry_and_conflicting_duplicates() {
    let group = Uuid::new_v4();
    let mut artifact = BackupArtifact::new("test-password", &[9; 32]).unwrap();
    artifact
        .append_entries(
            &[entry(group, 1, 3), entry(group, 1, 4)],
            "test-password",
            &[9; 32],
        )
        .unwrap();
    let unlocked = artifact.unlock("test-password", &[9; 32]).unwrap();
    assert!(unlocked
        .validate_for_groups(&[scope(group, 1)], None)
        .is_err());
    let mut corrupt = general_purpose::STANDARD
        .decode(&artifact.entries[0].protected.ciphertext)
        .unwrap();
    corrupt[0] ^= 1;
    artifact.entries[0].protected.ciphertext = general_purpose::STANDARD.encode(corrupt);
    assert!(artifact.unlock("test-password", &[9; 32]).is_err());
}

#[test]
fn test_saved_code_rejects_wrong_uuid_and_invalid_key() {
    let group = Uuid::new_v4();
    let mut artifact = BackupArtifact::new("test-password", &[9; 32]).unwrap();
    let mut invalid = entry(group, 1, 3);
    invalid.epoch_uuid = Uuid::new_v4();
    artifact
        .append_entries(&[invalid], "test-password", &[9; 32])
        .unwrap();
    assert!(artifact
        .unlock("test-password", &[9; 32])
        .unwrap()
        .validate_for_groups(&[scope(group, 1)], None)
        .is_err());
    artifact.entries.clear();
    artifact
        .append_entries(&[entry(group, 1, 0)], "test-password", &[9; 32])
        .unwrap();
    assert!(artifact
        .unlock("test-password", &[9; 32])
        .unwrap()
        .validate_for_groups(&[scope(group, 1)], None)
        .is_err());
    assert!(!crate::epoch_key_source::EpochKeySource::LocalInit.is_verified());
}

#[test]
fn test_saved_code_rejects_foreign_groups_and_conflicts_outside_selected_filter() {
    let personal = Uuid::new_v4();
    let team = Uuid::new_v4();
    let mut artifact = BackupArtifact::new("test-password", &[9; 32]).unwrap();
    artifact
        .append_entries(
            &[entry(personal, 1, 3), entry(team, 1, 4)],
            "test-password",
            &[9; 32],
        )
        .unwrap();
    let unlocked = artifact.unlock("test-password", &[9; 32]).unwrap();
    assert!(unlocked
        .validate_for_groups(&[scope(personal, 1)], Some(personal))
        .is_err());
    assert_eq!(
        unlocked
            .validate_for_groups(&[scope(personal, 1), scope(team, 1)], Some(personal))
            .unwrap()
            .group_ids(),
        vec![personal]
    );
    artifact
        .append_entries(&[entry(team, 1, 5)], "test-password", &[9; 32])
        .unwrap();
    assert!(artifact
        .unlock("test-password", &[9; 32])
        .unwrap()
        .validate_for_groups(&[scope(personal, 1), scope(team, 1)], Some(personal))
        .is_err());
}
