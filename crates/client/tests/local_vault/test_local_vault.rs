// Tests Client::create_local_vault, has_local_vault_key, export/import of recovery kits, and offline encryption in crates/client/src/state/client/local_vault.rs.
use super::*;
use crate::local_recovery_kit::{generate_recovery_code, LocalRecoveryKit};
use crate::network::MockNetwork;
use crate::storage::MockStorage;

fn client(storage: Arc<MockStorage>) -> Client<MockStorage, MockNetwork> {
    let client = Client::new(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
    );
    client.set_local_only(true);
    client
}

#[tokio::test]
async fn test_new_vault_is_locally_usable_but_never_account_ready() {
    let storage = Arc::new(MockStorage::new());
    let vault = client(storage.clone());
    let info = vault.create_local_vault().await.unwrap();
    assert_eq!(info.group_id.get_version_num(), 4);
    assert!(vault.has_local_vault_key(info.group_id).await.unwrap());
    assert!(
        !vault.has_cached_group_key(info.group_id).await.unwrap(),
        "a local vault key must not satisfy account readiness"
    );
    let state = vault.state.read().await;
    let epoch =
        Client::<MockStorage, MockNetwork>::get_epoch_state(&state, info.group_id, 1).unwrap();
    assert_eq!(epoch.key_source, EpochKeySource::LocalVault);
    assert!(!epoch.key_source.is_verified());
    assert_ne!(epoch.encryption_key, [0; 32]);
}

#[tokio::test]
async fn test_creation_is_idempotent_and_survives_restart() {
    let storage = Arc::new(MockStorage::new());
    let vault = client(storage.clone());
    let info = vault.create_local_vault().await.unwrap();
    let key = vault.local_vault_genesis_key(info.group_id).await.unwrap();
    assert_eq!(vault.create_local_vault().await.unwrap(), info);
    drop(vault);
    let restarted = client(storage);
    assert_eq!(
        restarted.local_vault_info().await.unwrap(),
        Some(info.clone())
    );
    assert!(restarted.has_local_vault_key(info.group_id).await.unwrap());
    assert_eq!(
        *restarted
            .local_vault_genesis_key(info.group_id)
            .await
            .unwrap(),
        *key
    );
    assert_eq!(restarted.active_group_id_opt().await, Some(info.group_id));
}

#[tokio::test]
async fn test_vault_encrypts_and_decrypts_without_an_account() {
    let vault = client(Arc::new(MockStorage::new()));
    let info = vault.create_local_vault().await.unwrap();
    let encrypted = vault
        .encrypt_file("notes.txt", b"private notes")
        .await
        .unwrap();
    assert_eq!(encrypted.group_id, Some(info.group_id));
    assert_eq!(encrypted.epoch_id, 1);
    assert_eq!(
        vault.decrypt_file(&encrypted).await.unwrap(),
        b"private notes"
    );
}

#[tokio::test]
async fn test_kit_restores_the_vault_on_another_device() {
    let original = client(Arc::new(MockStorage::new()));
    let info = original.create_local_vault().await.unwrap();
    let encrypted = original
        .encrypt_file("plan.txt", b"move day")
        .await
        .unwrap();
    let code = generate_recovery_code();
    let kit = LocalRecoveryKit::create(
        code.as_ref(),
        &original
            .export_local_vault_entries(info.group_id)
            .await
            .unwrap(),
    )
    .unwrap();

    let replacement = client(Arc::new(MockStorage::new()));
    let contents = kit.open(code.as_ref()).unwrap();
    let restored = replacement
        .import_local_recovery_kit(&contents)
        .await
        .unwrap();
    assert_eq!(restored.group_id, info.group_id);
    assert!(replacement
        .has_local_vault_key(info.group_id)
        .await
        .unwrap());
    assert_eq!(
        replacement.decrypt_file(&encrypted).await.unwrap(),
        b"move day"
    );
    assert_eq!(
        replacement
            .import_local_recovery_kit(&contents)
            .await
            .unwrap(),
        restored,
        "importing the same kit twice is harmless"
    );
}

#[tokio::test]
async fn test_conflicting_or_foreign_kits_are_refused() {
    let vault = client(Arc::new(MockStorage::new()));
    let info = vault.create_local_vault().await.unwrap();
    let code = generate_recovery_code();
    let forged = LocalRecoveryKit::create(
        code.as_ref(),
        &[BackupEntryPlain {
            group_id: info.group_id,
            epoch_number: 1,
            epoch_uuid: EpochIdMapper::u64_to_uuid(1, info.group_id.as_bytes()),
            created_at: Utc::now(),
            is_active: true,
            encryption_key_b64: general_purpose::STANDARD.encode([5u8; 32]),
        }],
    )
    .unwrap()
    .open(code.as_ref())
    .unwrap();
    let before = vault.local_vault_genesis_key(info.group_id).await.unwrap();
    let error = vault.import_local_recovery_kit(&forged).await.unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::SecurityTampering));
    assert_eq!(
        *vault.local_vault_genesis_key(info.group_id).await.unwrap(),
        *before
    );

    let other_vault = client(Arc::new(MockStorage::new()));
    let other = other_vault.create_local_vault().await.unwrap();
    let other_kit = LocalRecoveryKit::create(
        code.as_ref(),
        &other_vault
            .export_local_vault_entries(other.group_id)
            .await
            .unwrap(),
    )
    .unwrap()
    .open(code.as_ref())
    .unwrap();
    assert!(vault.import_local_recovery_kit(&other_kit).await.is_err());
}

#[tokio::test]
async fn test_vault_is_never_created_inside_account_storage() {
    let account = client(Arc::new(MockStorage::new()));
    account.ensure_state_loaded().await.unwrap();
    {
        let mut state = account.state.write().await;
        let group = Uuid::new_v4();
        state.group_memberships.insert(
            group,
            GroupMembership {
                group_id: group,
                group_name: "Account Personal".into(),
                group_description: None,
                user_role: GroupRole::Admin,
                joined_at: Utc::now(),
                current_epoch_id: None,
                last_sync: Utc::now(),
                members: Vec::new(),
            },
        );
    }
    assert!(account.create_local_vault().await.is_err());
    assert!(account.local_vault_info().await.unwrap().is_none());
}

#[tokio::test]
async fn test_clearing_the_marker_keeps_keys() {
    let vault = client(Arc::new(MockStorage::new()));
    let info = vault.create_local_vault().await.unwrap();
    vault.clear_local_vault_marker().await.unwrap();
    assert!(vault.local_vault_info().await.unwrap().is_none());
    assert!(vault.has_local_vault_key(info.group_id).await.unwrap());
}

#[tokio::test]
async fn test_only_a_local_only_client_creates_a_vault() {
    let account = client(Arc::new(MockStorage::new()));
    account.set_local_only(false);
    assert!(account.create_local_vault().await.is_err());
    assert!(account.local_vault_info().await.unwrap().is_none());
    account.set_local_only(true);
    let clone = account.clone();
    assert!(clone.is_local_only(), "clones share the local-only setting");
    assert!(
        clone.get_auth_token().await.is_err(),
        "a local-only client never reads the machine's login session"
    );
}
