// Tests status_of, verify_recovery_code and map_register_error in apps/desktop/src-tauri/src/commands/local_vault.rs.
use super::*;
use hybridcipher_client::saved_code_recovery::BackupEntryPlain;
use hybridcipher_crypto::epoch_id::EpochIdMapper;

fn record(storage_id: &str, group_id: Uuid) -> LocalVaultRecord {
    LocalVaultRecord {
        storage_id: storage_id.into(),
        group_id,
        created_at: chrono::Utc::now(),
        kit_saved: true,
        upgrade: None,
        merge: None,
    }
}

fn sealed_copy(config: &Path, storage_id: &str, group_id: Uuid) -> String {
    let code = generate_recovery_code();
    let entry = BackupEntryPlain {
        group_id,
        epoch_number: 1,
        epoch_uuid: EpochIdMapper::u64_to_uuid(1, group_id.as_bytes()),
        created_at: chrono::Utc::now(),
        is_active: true,
        encryption_key_b64: general_purpose::STANDARD.encode([9u8; 32]),
    };
    let dir = vault::user_dir(config, storage_id);
    std::fs::create_dir_all(&dir).unwrap();
    LocalRecoveryKit::create(code.as_ref(), &[entry])
        .unwrap()
        .save_to_path(&dir.join(KIT_COPY_FILE))
        .unwrap();
    format_recovery_code(code.as_ref())
}

#[test]
fn status_reports_only_what_the_record_says() {
    assert!(
        !status_of(None, true).active,
        "no vault means not in local mode"
    );
    let group = Uuid::new_v4();
    let mut saved = record("local-0011223344556677", group);
    saved.upgrade = Some(UpgradeProgress {
        email: "owner@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: "a1b2c3d4e5f60718".into(),
        phase: UpgradePhase::StorageMoved,
    });
    let status = status_of(Some(&saved), true);
    assert!(status.available && status.active && status.kit_saved);
    assert_eq!(status.group_id, Some(group.to_string()));
    assert_eq!(status.upgrade_email.as_deref(), Some("owner@example.test"));
    assert_eq!(status.upgrade_phase, Some(UpgradePhase::StorageMoved));
    assert!(!status_of(Some(&saved), false).active);
    assert!(
        !status_of(Some(&saved), true).fresh_device,
        "a device with a vault is never fresh"
    );
}

#[test]
fn typed_codes_are_checked_against_the_sealed_copy() {
    let config = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let storage = "local-8899aabbccddeeff";
    let code = sealed_copy(config.path(), storage, group);
    let saved = record(storage, group);
    let typed = code.to_lowercase().replace('-', " ");
    assert_eq!(
        verify_recovery_code(config.path(), &saved, &typed)
            .unwrap()
            .len(),
        32
    );
    let wrong = format_recovery_code(generate_recovery_code().as_ref());
    assert_eq!(
        verify_recovery_code(config.path(), &saved, &wrong)
            .unwrap_err()
            .0,
        "RECOVERY_CODE_MISMATCH"
    );
    assert_eq!(
        verify_recovery_code(config.path(), &saved, "not a code")
            .unwrap_err()
            .0,
        "RECOVERY_CODE_MISMATCH"
    );
    let other_vault = record(storage, Uuid::new_v4());
    assert_eq!(
        verify_recovery_code(config.path(), &other_vault, &code)
            .unwrap_err()
            .0,
        "RECOVERY_CODE_MISMATCH",
        "a kit for another vault is refused"
    );
    let missing = record("local-0000000000000000", group);
    assert_eq!(
        verify_recovery_code(config.path(), &missing, &code)
            .unwrap_err()
            .0,
        "LOCAL_VAULT_UPGRADE_FAILED"
    );
}

#[test]
fn existing_accounts_get_a_clear_message() {
    let (code, message) =
        map_register_error("Server registration failed (409 Conflict): duplicate".into());
    assert_eq!(code, "ACCOUNT_EXISTS");
    assert!(message.contains("Sign in to it"), "{message}");
    assert_eq!(
        map_register_error("Server registration failed: timed out".into()).0,
        "LOCAL_VAULT_UPGRADE_FAILED"
    );
}

#[test]
fn only_a_record_without_files_is_replaced() {
    use crate::key_bundle;
    keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    let config = tempfile::tempdir().unwrap();
    let id = vault::new_storage_id();
    let saved = record(&id, Uuid::new_v4());
    vault::create_storage_keys(config.path(), &id).unwrap();
    vault::save_record(config.path(), &saved).unwrap();
    assert!(
        replace_missing_record(config.path(), &saved).is_err(),
        "a vault with its files is never replaced"
    );
    assert!(vault::load_record(config.path()).unwrap().is_some());

    std::fs::remove_dir_all(vault::user_dir(config.path(), &id)).unwrap();
    key_bundle::delete_bundle(&id).unwrap();
    let status = missing_status(&saved);
    assert!(status.storage_missing && status.available && !status.active);
    replace_missing_record(config.path(), &saved).unwrap();
    assert!(vault::load_record(config.path()).unwrap().is_none());
}

#[test]
fn a_confirmation_check_waits_only_until_the_vault_has_moved() {
    let mut saved = record("local-0011223344556677", Uuid::new_v4());
    assert!(!upgrade_blocks_login(&saved, "owner@example.test"), "no upgrade, nothing to wait for");
    saved.upgrade = Some(UpgradeProgress {
        email: "Owner@Example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: "a1b2c3d4e5f60718".into(),
        phase: UpgradePhase::Registered,
    });
    assert!(upgrade_blocks_login(&saved, " owner@example.test "));
    assert!(!upgrade_blocks_login(&saved, "someone@example.test"));
    saved.upgrade.as_mut().unwrap().phase = UpgradePhase::StorageMoved;
    assert!(!upgrade_blocks_login(&saved, "owner@example.test"), "the check is safe once storage moved");
}
