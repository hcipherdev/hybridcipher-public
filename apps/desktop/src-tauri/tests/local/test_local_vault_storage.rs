// Tests local vault record persistence, key creation/loading, resumable storage moves, is_fresh_device and is_pristine in apps/desktop/src-tauri/src/local_vault.rs.
use super::*;

fn use_mock_keychain() {
    // Never touch the developer's real keychain; the bundle cache keeps values in-process.
    keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
}

fn record(storage_id: &str) -> LocalVaultRecord {
    LocalVaultRecord {
        storage_id: storage_id.into(),
        group_id: Uuid::new_v4(),
        created_at: Utc::now(),
        kit_saved: false,
        upgrade: None,
        merge: None,
    }
}

#[test]
fn record_round_trips_and_delete_is_idempotent() {
    let config = tempfile::tempdir().unwrap();
    assert!(load_record(config.path()).unwrap().is_none());
    let mut saved = record(&new_storage_id());
    saved.kit_saved = true;
    save_record(config.path(), &saved).unwrap();
    let loaded = load_record(config.path()).unwrap().unwrap();
    assert_eq!(loaded.group_id, saved.group_id);
    assert!(loaded.kit_saved);
    delete_record(config.path()).unwrap();
    delete_record(config.path()).unwrap();
    assert!(load_record(config.path()).unwrap().is_none());
}

#[test]
fn storage_ids_are_random_and_marked_local() {
    let first = new_storage_id();
    assert!(first.starts_with("local-"));
    assert_eq!(first.len(), "local-".len() + 16);
    assert_ne!(first, new_storage_id());
}

#[test]
fn keys_load_without_a_password_and_survive_a_missing_keychain_entry() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let id = new_storage_id();
    let (account, state) = create_storage_keys(config.path(), &id).unwrap();
    let (loaded_account, loaded_state) = load_storage_keys(config.path(), &id).unwrap();
    assert_eq!(*loaded_account, *account);
    assert_eq!(*loaded_state, *state);
    assert!(
        create_storage_keys(config.path(), &id).is_err(),
        "existing storage is never overwritten"
    );
    key_bundle::delete_bundle(&id).unwrap();
    let (_, fallback_state) = load_storage_keys(config.path(), &id).unwrap();
    assert_eq!(
        *fallback_state, *state,
        "the wrapped fallback restores the state key"
    );
}

#[test]
fn storage_move_is_resumable_and_refuses_existing_account_data() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let local = new_storage_id();
    let account = format!("account-{}", hex::encode(Uuid::new_v4().as_bytes()));
    let (_, state) = create_storage_keys(config.path(), &local).unwrap();
    fs::write(user_dir(config.path(), &local).join("marker"), b"vault").unwrap();

    let mut interrupted = record(&local);
    interrupted.upgrade = Some(UpgradeProgress {
        email: "owner@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: account.clone(),
        phase: UpgradePhase::Registered,
    });
    assert_eq!(current_storage_id(config.path(), &interrupted), local);

    move_storage(config.path(), &local, &account).unwrap();
    assert!(!user_dir(config.path(), &local).exists());
    assert_eq!(
        fs::read(user_dir(config.path(), &account).join("marker")).unwrap(),
        b"vault"
    );
    assert_eq!(key_bundle::load_state_key(&account).unwrap(), Some(*state));
    assert_eq!(key_bundle::load_state_key(&local).unwrap(), None);
    assert_eq!(
        current_storage_id(config.path(), &interrupted),
        account,
        "a stale record still finds the moved storage"
    );
    move_storage(config.path(), &local, &account).expect("repeating a finished move succeeds");

    let other = new_storage_id();
    create_storage_keys(config.path(), &other).unwrap();
    assert!(
        move_storage(config.path(), &other, &account).is_err(),
        "a vault never merges into existing account data"
    );
    assert!(user_dir(config.path(), &other).exists());
}

#[test]
fn only_accountless_storage_can_be_removed() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    assert!(remove_storage(config.path(), "a1b2c3d4e5f60708").is_err());
    let id = new_storage_id();
    create_storage_keys(config.path(), &id).unwrap();
    save_record(config.path(), &record(&id)).unwrap();
    remove_storage(config.path(), &id).unwrap();
    assert!(!user_dir(config.path(), &id).exists());
    assert!(load_record(config.path()).unwrap().is_none());
    assert_eq!(key_bundle::load_state_key(&id).unwrap(), None);
}

#[test]
fn an_empty_folder_is_not_a_vault() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let local = new_storage_id();
    let account = format!("account-{}", hex::encode(Uuid::new_v4().as_bytes()));
    let mut saved = record(&local);
    saved.upgrade = Some(UpgradeProgress {
        email: "owner@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: account.clone(),
        phase: UpgradePhase::StorageMoved,
    });
    assert_eq!(find_storage(config.path(), &saved), None, "nothing on disk");

    create_storage_keys(config.path(), &local).unwrap();
    move_storage(config.path(), &local, &account).unwrap();
    // A stale writer recreates the old folder with only its state file.
    fs::create_dir_all(user_dir(config.path(), &local)).unwrap();
    fs::write(user_dir(config.path(), &local).join("client_state.json"), b"{}").unwrap();
    assert!(!storage_present(config.path(), &local));
    assert_eq!(
        find_storage(config.path(), &saved),
        Some(account.clone()),
        "the moved vault is still found"
    );
    move_storage(config.path(), &local, &account).expect("a stray source doesn't block a finished move");

    fs::remove_dir_all(user_dir(config.path(), &account)).unwrap();
    assert_eq!(find_storage(config.path(), &saved), None, "deleted files are reported missing");
}

#[test]
fn a_record_without_files_is_set_aside_not_deleted() {
    let config = tempfile::tempdir().unwrap();
    let saved = record(&new_storage_id());
    save_record(config.path(), &saved).unwrap();
    let aside = set_aside_record(config.path()).unwrap();
    assert!(load_record(config.path()).unwrap().is_none());
    let kept: LocalVaultRecord = serde_json::from_slice(&fs::read(&aside).unwrap()).unwrap();
    assert_eq!(kept.group_id, saved.group_id);
}

#[test]
fn an_upgrade_before_sign_in_returns_to_local_storage() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let local = new_storage_id();
    let account = format!("account-{}", hex::encode(Uuid::new_v4().as_bytes()));
    let (_, state) = create_storage_keys(config.path(), &local).unwrap();
    fs::write(user_dir(config.path(), &local).join("marker"), b"vault").unwrap();
    let mut upgrading = record(&local);
    upgrading.upgrade = Some(UpgradeProgress {
        email: "typo@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: account.clone(),
        phase: UpgradePhase::Registered,
    });
    save_record(config.path(), &upgrading).unwrap();

    // Registered, storage not moved yet: the vault stays where it is.
    let undone = return_to_local(config.path(), &upgrading).unwrap();
    assert_eq!(undone.storage_id, local);
    assert!(undone.upgrade.is_none());
    assert!(load_record(config.path()).unwrap().unwrap().upgrade.is_none());
    assert_eq!(*load_storage_keys(config.path(), &local).unwrap().1, *state);

    // Storage moved and re-protected under the account password, like the upgrade does.
    move_storage(config.path(), &local, &account).unwrap();
    let account_dir = user_dir(config.path(), &account);
    let password_key = [7u8; 32];
    hybridcipher_crypto::local_key_cache::save(&account_dir.join(ACCOUNT_KEY_CACHE_FILE), &password_key).unwrap();
    let wrapped = encrypt_with_ad(state.as_ref(), password_key, DEVICE_KEY_FILE_AAD).unwrap();
    fs::write(account_dir.join(DEVICE_KEY_FILE), serde_json::to_vec(&wrapped).unwrap()).unwrap();
    fs::write(account_dir.join(ACCOUNT_PROTECTION_FILE), b"{}").unwrap();
    let mut moved = upgrading.clone();
    moved.storage_id = account.clone();
    moved.upgrade.as_mut().unwrap().phase = UpgradePhase::StorageMoved;
    save_record(config.path(), &moved).unwrap();

    let undone = return_to_local(config.path(), &moved).unwrap();
    assert!(undone.storage_id.starts_with("local-"));
    assert!(undone.upgrade.is_none());
    let back = user_dir(config.path(), &undone.storage_id);
    assert_eq!(fs::read(back.join("marker")).unwrap(), b"vault", "files come back untouched");
    assert!(!account_dir.exists(), "nothing is left under the account's identity");
    assert!(!back.join(ACCOUNT_PROTECTION_FILE).exists());
    assert_eq!(key_bundle::load_state_key(&account).unwrap(), None);
    let (local_account_key, loaded_state) = load_storage_keys(config.path(), &undone.storage_id).unwrap();
    assert_eq!(*loaded_state, *state);
    assert_ne!(*local_account_key, password_key, "the password no longer protects the vault");
    key_bundle::delete_bundle(&undone.storage_id).unwrap();
    assert_eq!(
        *load_storage_keys(config.path(), &undone.storage_id).unwrap().1,
        *state,
        "the fallback opens under the new local key"
    );
    assert_eq!(load_record(config.path()).unwrap().unwrap().storage_id, undone.storage_id);
}

#[test]
fn an_interrupted_undo_still_finds_the_vault_and_finishes() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let local = new_storage_id();
    let account = format!("account-{}", hex::encode(Uuid::new_v4().as_bytes()));
    let (_, state) = create_storage_keys(config.path(), &local).unwrap();
    move_storage(config.path(), &local, &account).unwrap();
    let mut interrupted = record(&new_storage_id());
    interrupted.upgrade = Some(UpgradeProgress {
        email: "typo@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: account.clone(),
        phase: UpgradePhase::StorageMoved,
    });
    // The undo named its destination, then stopped before moving.
    assert_eq!(find_storage(config.path(), &interrupted), Some(account));
    let undone = return_to_local(config.path(), &interrupted).unwrap();
    assert_eq!(*load_storage_keys(config.path(), &undone.storage_id).unwrap().1, *state);

    let mut signed_in = interrupted.clone();
    signed_in.storage_id = undone.storage_id.clone();
    signed_in.upgrade.as_mut().unwrap().phase = UpgradePhase::SignedIn;
    assert!(return_to_local(config.path(), &signed_in).is_err(), "a signed-in account is never undone");
}

#[test]
fn a_leftover_keychain_entry_neither_blocks_the_move_nor_wins() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let local = new_storage_id();
    let account = format!("account-{}", hex::encode(Uuid::new_v4().as_bytes()));
    let (_, state) = create_storage_keys(config.path(), &local).unwrap();
    // An earlier vault moved here, then its folder was deleted; the entry stayed.
    key_bundle::store_state_key(&account, &[1u8; 32]).unwrap();

    move_storage(config.path(), &local, &account).unwrap();
    assert!(storage_present(config.path(), &account));
    assert_eq!(key_bundle::load_state_key(&account).unwrap(), Some(*state));
    assert_eq!(key_bundle::load_state_key(&local).unwrap(), None);
    assert_eq!(*load_storage_keys(config.path(), &account).unwrap().1, *state);
}

#[test]
fn the_vault_folder_overrules_a_stale_keychain_entry() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let id = new_storage_id();
    let (_, state) = create_storage_keys(config.path(), &id).unwrap();
    key_bundle::store_state_key(&id, &[2u8; 32]).unwrap();
    assert_eq!(*load_storage_keys(config.path(), &id).unwrap().1, *state);
    assert_eq!(
        key_bundle::load_state_key(&id).unwrap(),
        Some(*state),
        "the keychain entry is repaired"
    );
}

#[test]
fn a_half_finished_move_resumes_or_undoes_with_the_right_key() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let local = new_storage_id();
    let account = format!("account-{}", hex::encode(Uuid::new_v4().as_bytes()));
    let (_, state) = create_storage_keys(config.path(), &local).unwrap();
    key_bundle::store_state_key(&account, &[3u8; 32]).unwrap();
    // The state the old code left: folder renamed, keychain refused to follow.
    fs::rename(user_dir(config.path(), &local), user_dir(config.path(), &account)).unwrap();
    let mut upgrading = record(&local);
    upgrading.upgrade = Some(UpgradeProgress {
        email: "owner@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: account.clone(),
        phase: UpgradePhase::Registered,
    });
    save_record(config.path(), &upgrading).unwrap();
    assert_eq!(find_storage(config.path(), &upgrading), Some(account.clone()));
    assert_eq!(
        *load_storage_keys(config.path(), &account).unwrap().1,
        *state,
        "the vault opens with its own key, not the leftover one"
    );

    let undone = return_to_local(config.path(), &upgrading).unwrap();
    assert_eq!(*load_storage_keys(config.path(), &undone.storage_id).unwrap().1, *state);

    // Same state again, resumed instead of undone.
    let resumed_local = new_storage_id();
    let (_, resumed_state) = create_storage_keys(config.path(), &resumed_local).unwrap();
    key_bundle::store_state_key(&account, &[4u8; 32]).unwrap();
    fs::rename(
        user_dir(config.path(), &resumed_local),
        user_dir(config.path(), &account),
    )
    .unwrap();
    move_storage(config.path(), &resumed_local, &account).expect("a retry finishes the move");
    assert_eq!(key_bundle::load_state_key(&account).unwrap(), Some(*resumed_state));
    assert_eq!(key_bundle::load_state_key(&resumed_local).unwrap(), None);
}

#[test]
fn a_missing_vault_forgets_only_keychain_entries_without_folders() {
    use_mock_keychain();
    let config = tempfile::tempdir().unwrap();
    let gone = new_storage_id();
    let account = format!("account-{}", hex::encode(Uuid::new_v4().as_bytes()));
    key_bundle::store_state_key(&gone, &[5u8; 32]).unwrap();
    key_bundle::store_state_key(&account, &[6u8; 32]).unwrap();
    let mut missing = record(&gone);
    missing.upgrade = Some(UpgradeProgress {
        email: "owner@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: account.clone(),
        phase: UpgradePhase::Registered,
    });
    fs::create_dir_all(user_dir(config.path(), &account)).unwrap();
    forget_missing_keys(config.path(), &missing).unwrap();
    assert_eq!(key_bundle::load_state_key(&gone).unwrap(), None);
    assert!(
        key_bundle::load_state_key(&account).unwrap().is_some(),
        "an entry whose folder exists is kept"
    );

    fs::remove_dir_all(user_dir(config.path(), &account)).unwrap();
    missing.upgrade.as_mut().unwrap().phase = UpgradePhase::SignedIn;
    forget_missing_keys(config.path(), &missing).unwrap();
    assert!(
        key_bundle::load_state_key(&account).unwrap().is_some(),
        "a signed-in account's entry is never removed here"
    );
}

#[test]
fn only_a_device_nothing_has_used_counts_as_fresh() {
    let config = tempfile::tempdir().unwrap();
    assert!(is_fresh_device(config.path()), "an empty home is fresh");
    let users = config.path().join(USERS_DIR);
    fs::create_dir_all(users.join(new_storage_id())).unwrap();
    assert!(
        is_fresh_device(config.path()),
        "a leftover vault folder alone isn't an account"
    );
    fs::create_dir_all(users.join("a1b2c3d4e5f60708")).unwrap();
    assert!(!is_fresh_device(config.path()), "an account's storage");
    fs::remove_dir_all(users.join("a1b2c3d4e5f60708")).unwrap();

    let global = config.path().join(GLOBAL_DIR);
    fs::create_dir_all(&global).unwrap();
    for name in [ACTIVE_USER_FILE, LAST_USER_FILE, RECORD_FILE] {
        fs::write(global.join(name), "{}").unwrap();
        assert!(!is_fresh_device(config.path()), "{name} was written");
        fs::remove_file(global.join(name)).unwrap();
    }
    assert!(is_fresh_device(config.path()));
}

#[test]
fn a_vault_is_pristine_until_its_kit_is_saved_or_it_joins_an_account() {
    let mut saved = record(&new_storage_id());
    assert!(is_pristine(&saved));
    saved.kit_saved = true;
    assert!(!is_pristine(&saved), "folders can be protected once the kit is saved");
    saved.kit_saved = false;
    saved.upgrade = Some(UpgradeProgress {
        email: "owner@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: "a1b2c3d4e5f60708".into(),
        phase: UpgradePhase::Registered,
    });
    assert!(!is_pristine(&saved), "an account is being created from it");
}
