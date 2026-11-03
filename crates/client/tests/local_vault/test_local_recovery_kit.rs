// Tests LocalRecoveryKit create/open, code-only authentication, tamper and format checks in crates/client/src/local_recovery_kit.rs.
use super::*;

fn entry(group: Uuid, number: u64, key: u8) -> BackupEntryPlain {
    BackupEntryPlain {
        group_id: group,
        epoch_number: number,
        epoch_uuid: EpochIdMapper::u64_to_uuid(number, group.as_bytes()),
        created_at: Utc::now(),
        is_active: true,
        encryption_key_b64: general_purpose::STANDARD.encode([key; 32]),
    }
}

#[test]
fn test_kit_round_trips_with_the_code_alone() {
    let group = Uuid::new_v4();
    let code = generate_recovery_code();
    let kit = LocalRecoveryKit::create(code.as_ref(), &[entry(group, 1, 7)]).unwrap();
    let encoded = kit.to_base64().unwrap();
    assert!(!encoded.contains(&general_purpose::STANDARD.encode([7u8; 32])));
    let reopened = LocalRecoveryKit::from_base64(&encoded)
        .unwrap()
        .open(code.as_ref())
        .unwrap();
    assert_eq!(reopened.group_id, group);
    assert_eq!(reopened.epochs.len(), 1);
    assert_eq!(*reopened.epochs[0].key, [7; 32]);
    let backup = reopened.to_backup_entries();
    assert_eq!(backup[0].epoch_uuid, entry(group, 1, 7).epoch_uuid);
}

#[test]
fn test_wrong_code_and_tampered_entry_are_rejected() {
    let group = Uuid::new_v4();
    let code = generate_recovery_code();
    let kit = LocalRecoveryKit::create(code.as_ref(), &[entry(group, 1, 7)]).unwrap();
    let wrong = generate_recovery_code();
    assert!(kit
        .open(wrong.as_ref())
        .err()
        .unwrap()
        .contains("does not match"));
    let mut tampered = kit.clone();
    tampered.salt_b64 = general_purpose::STANDARD.encode([1u8; 16]);
    assert!(tampered.open(code.as_ref()).is_err());
    let mut swapped = kit.clone();
    let other = LocalRecoveryKit::create(code.as_ref(), &[entry(group, 1, 9)]).unwrap();
    swapped.entries = other.entries;
    assert!(
        swapped.open(code.as_ref()).is_err(),
        "entries sealed under another salt cannot be spliced in"
    );
}

#[test]
fn test_invalid_contents_are_refused_when_created() {
    let code = generate_recovery_code();
    let group = Uuid::new_v4();
    assert!(LocalRecoveryKit::create(code.as_ref(), &[]).is_err());
    assert!(LocalRecoveryKit::create(&[1; 8], &[entry(group, 1, 7)]).is_err());
    assert!(
        LocalRecoveryKit::create(
            code.as_ref(),
            &[entry(group, 1, 7), entry(Uuid::new_v4(), 1, 7)]
        )
        .is_err(),
        "a kit holds exactly one vault"
    );
    assert!(
        LocalRecoveryKit::create(code.as_ref(), &[entry(group, 1, 7), entry(group, 1, 8)]).is_err(),
        "one epoch cannot carry two keys"
    );
    assert!(LocalRecoveryKit::create(code.as_ref(), &[entry(group, 1, 0)]).is_err());
    let mut mismatched = entry(group, 2, 7);
    mismatched.epoch_uuid = Uuid::new_v4();
    assert!(LocalRecoveryKit::create(code.as_ref(), &[mismatched]).is_err());
}

#[test]
fn test_foreign_files_and_versions_are_not_treated_as_kits() {
    assert!(LocalRecoveryKit::from_base64("not base64 at all").is_err());
    let account_artifact =
        crate::saved_code_recovery::BackupArtifact::new("password", &[3; 32]).unwrap();
    assert!(
        LocalRecoveryKit::from_base64(&account_artifact.to_base64().unwrap()).is_err(),
        "an account backup is not a local kit"
    );
    let code = generate_recovery_code();
    let mut kit = LocalRecoveryKit::create(code.as_ref(), &[entry(Uuid::new_v4(), 1, 7)]).unwrap();
    kit.version = LOCAL_KIT_VERSION + 1;
    assert!(LocalRecoveryKit::from_base64(&kit.to_base64().unwrap()).is_err());
}

#[test]
fn test_kit_file_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("HybridCipher Recovery Kit.hcrk");
    let code = generate_recovery_code();
    let group = Uuid::new_v4();
    LocalRecoveryKit::create(code.as_ref(), &[entry(group, 1, 7)])
        .unwrap()
        .save_to_path(&path)
        .unwrap();
    let opened = LocalRecoveryKit::load_from_path(&path)
        .unwrap()
        .open(code.as_ref())
        .unwrap();
    assert_eq!(opened.group_id, group);
}

#[test]
fn test_typed_codes_parse_with_dashes_and_spaces() {
    let code = generate_recovery_code();
    let formatted = crate::saved_code_recovery::format_recovery_code(code.as_ref());
    let typed = format!(" {} ", formatted.to_lowercase().replace('-', " - "));
    let parsed = crate::saved_code_recovery::parse_recovery_code(&typed).unwrap();
    assert_eq!(parsed.as_slice(), code.as_ref());
    assert!(crate::saved_code_recovery::parse_recovery_code("ABCD").is_err());
}
