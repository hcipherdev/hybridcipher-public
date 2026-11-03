// Tests authenticated recovery installation for durable readiness, stale current keys, and atomic conflict rejection.
use super::*;
use crate::network::MockNetwork;
use crate::saved_code_recovery::{BackupArtifact, BackupEntryPlain, RecoveryGroupScope};
use crate::storage::MockStorage;

fn recovered(group: Uuid, number: u64, key: u8) -> BackupEntryPlain {
    BackupEntryPlain {
        group_id: group,
        epoch_number: number,
        epoch_uuid: EpochIdMapper::u64_to_uuid(number, group.as_bytes()),
        created_at: Utc::now(),
        is_active: true,
        encryption_key_b64: general_purpose::STANDARD.encode([key; 32]),
    }
}
fn plan(group: Uuid, current: u64, entries: &[BackupEntryPlain]) -> ValidatedRecovery {
    let mut artifact = BackupArtifact::new("test-password", &[9; 32]).unwrap();
    artifact
        .append_entries(entries, "test-password", &[9; 32])
        .unwrap();
    artifact
        .unlock("test-password", &[9; 32])
        .unwrap()
        .validate_for_groups(
            &[RecoveryGroupScope {
                group_id: group,
                group_name: "Personal".into(),
                user_role: GroupRole::Admin,
                current_epoch_uuid: Some(EpochIdMapper::u64_to_uuid(current, group.as_bytes())),
            }],
            None,
        )
        .unwrap()
}
fn client(storage: Arc<MockStorage>) -> Client<MockStorage, MockNetwork> {
    Client::new(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
    )
}

#[tokio::test]
async fn test_saved_code_import_is_ready_after_restart_with_all_history() {
    let storage = Arc::new(MockStorage::new());
    let original = client(storage.clone());
    let group = Uuid::new_v4();
    let recovery = plan(group, 2, &[recovered(group, 1, 3), recovered(group, 2, 4)]);
    let result = original
        .install_authenticated_recovery(&recovery)
        .await
        .unwrap();
    assert_eq!(result.imported_epochs, 2);
    assert_eq!(result.ready_groups, vec![group]);
    assert!(original.has_cached_group_key(group).await.unwrap());
    assert!(original
        .has_cached_group_epoch_key(group, EpochIdMapper::u64_to_uuid(2, group.as_bytes()))
        .await
        .unwrap());
    assert!(!original
        .has_cached_group_epoch_key(group, EpochIdMapper::u64_to_uuid(3, group.as_bytes()))
        .await
        .unwrap());
    assert_eq!(original.active_group_id_opt().await, None);
    let restarted = client(storage.clone());
    assert!(restarted.has_cached_group_key(group).await.unwrap());
    assert_eq!(
        restarted
            .export_recovery_capsule(group)
            .await
            .unwrap()
            .epochs
            .len(),
        2
    );
    let snapshot = storage.load_config("client_state").await.unwrap().unwrap();
    assert!(snapshot.contains("\"key_source\":\"recovery\""));
}

#[tokio::test]
async fn test_saved_code_stale_backup_restores_history_without_writable_current_epoch() {
    let original = client(Arc::new(MockStorage::new()));
    let group = Uuid::new_v4();
    let result = original
        .install_authenticated_recovery(&plan(
            group,
            3,
            &[recovered(group, 1, 3), recovered(group, 2, 4)],
        ))
        .await
        .unwrap();
    assert_eq!(result.missing_current_groups, vec![group]);
    assert!(!original.has_cached_group_key(group).await.unwrap());
    assert_eq!(
        original
            .export_recovery_capsule(group)
            .await
            .unwrap()
            .epochs
            .len(),
        2
    );
}

#[tokio::test]
async fn test_saved_code_conflict_leaves_all_epochs_and_storage_unchanged() {
    let storage = Arc::new(MockStorage::new());
    let original = client(storage.clone());
    let group = Uuid::new_v4();
    original
        .install_authenticated_recovery(&plan(group, 2, &[recovered(group, 2, 4)]))
        .await
        .unwrap();
    let before = storage.load_config("client_state").await.unwrap();
    let conflicting = plan(group, 2, &[recovered(group, 1, 3), recovered(group, 2, 5)]);
    assert!(original
        .install_authenticated_recovery(&conflicting)
        .await
        .is_err());
    assert_eq!(before, storage.load_config("client_state").await.unwrap());
    assert_eq!(
        original
            .export_recovery_capsule(group)
            .await
            .unwrap()
            .epochs
            .len(),
        1
    );
    assert!(original.has_cached_group_key(group).await.unwrap());
}

#[tokio::test]
async fn test_saved_code_reconciliation_deactivates_old_keys_not_in_backup() {
    let original = client(Arc::new(MockStorage::new()));
    let group = Uuid::new_v4();
    original
        .install_authenticated_recovery(&plan(group, 1, &[recovered(group, 1, 3)]))
        .await
        .unwrap();
    original
        .install_authenticated_recovery(&plan(group, 2, &[recovered(group, 2, 4)]))
        .await
        .unwrap();
    let capsule = original.export_recovery_capsule(group).await.unwrap();
    assert_eq!(capsule.epochs.len(), 2);
    assert!(
        !capsule
            .epochs
            .iter()
            .find(|epoch| epoch.epoch_number == 1)
            .unwrap()
            .is_active
    );
    assert!(
        capsule
            .epochs
            .iter()
            .find(|epoch| epoch.epoch_number == 2)
            .unwrap()
            .is_active
    );
}

#[tokio::test]
async fn test_saved_code_existing_conflict_outside_filter_prevents_import() {
    let storage = Arc::new(MockStorage::new());
    let original = client(storage.clone());
    let personal = Uuid::new_v4();
    let team = Uuid::new_v4();
    original
        .install_authenticated_recovery(&plan(team, 1, &[recovered(team, 1, 3)]))
        .await
        .unwrap();
    let before = storage.load_config("client_state").await.unwrap();
    let mut artifact = BackupArtifact::new("test-password", &[9; 32]).unwrap();
    artifact
        .append_entries(
            &[recovered(personal, 1, 4), recovered(team, 1, 5)],
            "test-password",
            &[9; 32],
        )
        .unwrap();
    let scopes = [personal, team].map(|group| RecoveryGroupScope {
        group_id: group,
        group_name: "Test".into(),
        user_role: GroupRole::Admin,
        current_epoch_uuid: Some(EpochIdMapper::u64_to_uuid(1, group.as_bytes())),
    });
    let filtered = artifact
        .unlock("test-password", &[9; 32])
        .unwrap()
        .validate_for_groups(&scopes, Some(personal))
        .unwrap();
    assert!(original
        .validate_authenticated_recovery(&filtered)
        .await
        .is_err());
    assert!(original
        .install_authenticated_recovery(&filtered)
        .await
        .is_err());
    assert_eq!(before, storage.load_config("client_state").await.unwrap());
    assert!(!original.has_cached_group_key(personal).await.unwrap());
}

#[tokio::test]
async fn test_saved_code_failed_persistence_keeps_unverified_keys_and_retry_is_idempotent() {
    let storage = Arc::new(MockStorage::new());
    let original = client(storage.clone());
    original.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    original
        .import_recovery_capsule(&RecoveryCapsulePlain {
            group_id: group,
            generated_at: Utc::now(),
            epochs: vec![RecoveryEpochSecret {
                epoch_number: 2,
                epoch_uuid: EpochIdMapper::u64_to_uuid(2, group.as_bytes()),
                created_at: Utc::now(),
                is_active: true,
                file_count: 0,
                encryption_key_b64: general_purpose::STANDARD.encode([7; 32]),
            }],
        })
        .await
        .unwrap();
    let before = storage.load_config("client_state").await.unwrap();
    let recovery = plan(group, 2, &[recovered(group, 1, 3), recovered(group, 2, 4)]);
    storage.fail_next_config_write();
    assert!(original
        .install_authenticated_recovery(&recovery)
        .await
        .is_err());
    assert_eq!(before, storage.load_config("client_state").await.unwrap());
    assert!(!original
        .has_cached_group_epoch_key(group, EpochIdMapper::u64_to_uuid(2, group.as_bytes()))
        .await
        .unwrap());
    let unchanged = original.export_recovery_capsule(group).await.unwrap();
    assert_eq!(unchanged.epochs.len(), 1);
    assert_eq!(
        unchanged.epochs[0].encryption_key_b64,
        general_purpose::STANDARD.encode([7; 32])
    );
    original
        .install_authenticated_recovery(&recovery)
        .await
        .unwrap();
    original
        .install_authenticated_recovery(&recovery)
        .await
        .unwrap();
    assert_eq!(
        original
            .export_recovery_capsule(group)
            .await
            .unwrap()
            .epochs
            .len(),
        2
    );
    assert!(client(storage)
        .has_cached_group_epoch_key(group, EpochIdMapper::u64_to_uuid(2, group.as_bytes()))
        .await
        .unwrap());
}

#[tokio::test]
async fn test_saved_code_exact_epoch_activation_reconciles_stale_membership() {
    let storage = Arc::new(MockStorage::new());
    let original = client(storage.clone());
    let group = Uuid::new_v4();
    original
        .install_authenticated_recovery(&plan(
            group,
            2,
            &[recovered(group, 1, 3), recovered(group, 2, 4)],
        ))
        .await
        .unwrap();
    original
        .state
        .write()
        .await
        .group_memberships
        .get_mut(&group)
        .unwrap()
        .current_epoch_id = Some(1);
    let current = EpochIdMapper::u64_to_uuid(2, group.as_bytes());
    original.use_group_at_epoch(group, current).await.unwrap();
    assert_eq!(original.state.read().await.current_epoch, 2);
    assert_eq!(original.active_group_id_opt().await, Some(group));
    let restarted = client(storage);
    assert!(restarted
        .has_cached_group_epoch_key(group, current)
        .await
        .unwrap());
    assert_eq!(restarted.state.read().await.current_epoch, 2);
    assert!(original
        .use_group_at_epoch(group, Uuid::new_v4())
        .await
        .is_err());
    assert_eq!(original.state.read().await.current_epoch, 2);
}

#[tokio::test]
async fn test_saved_code_exact_verified_key_can_activate_before_membership_metadata_is_cached() {
    let original = client(Arc::new(MockStorage::new()));
    let group = Uuid::new_v4();
    original
        .install_authenticated_recovery(&plan(group, 2, &[recovered(group, 2, 4)]))
        .await
        .unwrap();
    original
        .state
        .write()
        .await
        .group_memberships
        .remove(&group);
    let current = EpochIdMapper::u64_to_uuid(2, group.as_bytes());
    original.use_group_at_epoch(group, current).await.unwrap();
    let state = original.state.read().await;
    assert_eq!(state.current_epoch, 2);
    assert_eq!(state.active_group_id, Some(group));
    assert_eq!(state.group_memberships[&group].user_role, GroupRole::Member);
    assert_eq!(state.group_memberships[&group].current_epoch_id, Some(2));
}
