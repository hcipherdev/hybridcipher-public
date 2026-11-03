// Tests needs_key_migration(), Client::leftover_key_files(), Client::migrate_leftover_key_files() and its progress variant (migrate_leftover_key_files_with_progress) in crates/client/src/state/client/leftover_key_files.rs, and the rotation queue (populate_migration_queue): files a device left on an older key after a cutover are counted and moved to the current key, including across a version a cancelled rotation used, files another device encrypted ([adopt]) and folder records.
use super::*;
use crate::ipc::coverage_workflows::enroll_and_hydrate;
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

fn entry(state: FileCoverageState, orphan_kind: Option<FileOrphanKind>, last_epoch: u64) -> FileIndexEntry {
    FileIndexEntry {
        file_uuid: Uuid::new_v4(),
        file_id: None,
        root_id: Uuid::new_v4(),
        relative_path: "a.txt".into(),
        size: 1,
        last_epoch,
        checksum_hint: None,
        last_seen: Utc::now(),
        state,
        orphan_kind,
    }
}

#[test]
fn only_files_on_another_key_need_moving() {
    use FileCoverageState::*;
    let tracked = |epoch| entry(Tracked, None, epoch);
    // No rotation running: only older keys (a newer one means the index is ahead of this device).
    assert!(needs_key_migration(&tracked(1), 2, false));
    assert!(!needs_key_migration(&tracked(2), 2, false));
    assert!(!needs_key_migration(&tracked(3), 2, false));
    assert!(!needs_key_migration(&tracked(0), 2, false));
    // During a rotation every other key moves to the target.
    assert!(needs_key_migration(&tracked(3), 2, true));
    assert!(needs_key_migration(&tracked(0), 2, true));
    assert!(needs_key_migration(&entry(Orphaned, Some(FileOrphanKind::WrongEpoch), 1), 2, false));
    assert!(!needs_key_migration(&entry(Orphaned, Some(FileOrphanKind::Outcast), 1), 2, false));
    assert!(!needs_key_migration(&entry(Tombstoned, None, 1), 2, false));
    // Encrypted by another device ([adopt]): the key its header named at scan time decides.
    let adopt = |epoch| entry(Orphaned, Some(FileOrphanKind::MissingMetadata), epoch);
    assert!(needs_key_migration(&adopt(1), 2, false));
    assert!(!needs_key_migration(&adopt(2), 2, false));
    assert!(needs_key_migration(&adopt(3), 2, true));
    assert!(!needs_key_migration(&adopt(0), 2, true));
}

fn epoch(group: Uuid, epoch_id: u64, key: u8) -> EpochState {
    EpochState {
        group_id: Some(group),
        epoch_id,
        encryption_key: [key; 32],
        key_source: EpochKeySource::Welcome,
        members: vec![],
        created_at: Utc::now(),
        is_active: epoch_id == 1,
        file_count: 0,
        marked_for_removal: false,
        removal_eligible_at: None,
    }
}

#[tokio::test]
async fn files_left_on_the_old_key_after_a_missed_cutover_are_moved_to_the_current_key() {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let storage = Arc::new(LocalFsStorage::new(dir.path().join("account")));
    storage
        .store_config(
            "client_state",
            &serde_json::json!({
                "epochs":{"1":[epoch(group, 1, 11)],"2":[epoch(group, 2, 22)]}, "current_epoch":1,
                "active_group_id":group, "migration":null,"active_rekey":null,"last_sync":Utc::now(),
                "version":1, "group_memberships":{},"auth_credentials":null,"invitation_keypair":null
            })
            .to_string(),
        )
        .await
        .unwrap();
    let client = Client::with_client_config(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
        ClientConfig {
            migration_automation_enabled: false,
            coverage_watchers_enabled: false,
            ..ClientConfig::default()
        },
    );
    client.ensure_state_loaded().await.unwrap();
    let folder = dir.path().join("protected");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("a.txt"), b"alpha").await.unwrap();
    fs::write(folder.join("b.txt"), b"bravo").await.unwrap();
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    assert_eq!(client.leftover_key_files().await.unwrap().files, 0);

    // The device installed v2 from its Welcome after the rotation had already finished.
    client.state.write().await.current_epoch = 2;
    assert_eq!(
        client.leftover_key_files().await.unwrap(),
        LeftoverKeyFiles { target_version: 2, files: 2, oldest_version: Some(1), folders: 0 }
    );

    assert_eq!(
        client.migrate_leftover_key_files().await.unwrap(),
        LeftoverKeyMigration { migrated: 2, ..Default::default() }
    );
    assert_eq!(client.leftover_key_files().await.unwrap().files, 0);
    let mut epochs = Vec::new();
    let mut entries = fs::read_dir(&folder).await.unwrap();
    while let Some(file) = entries.next_entry().await.unwrap() {
        if let Some(header) = Client::<LocalFsStorage, MockNetwork>::parse_encrypted_file_metadata(&file.path()) {
            epochs.push(header.epoch_id);
        }
    }
    assert_eq!(epochs, vec![2, 2]);
    // Nothing left to do on the next pass.
    assert_eq!(client.migrate_leftover_key_files().await.unwrap(), LeftoverKeyMigration::default());
}

#[tokio::test]
async fn files_jump_over_a_cancelled_version_to_the_current_key() {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let storage = Arc::new(LocalFsStorage::new(dir.path().join("account")));
    // v3 belonged to a cancelled rotation, so the next rotation became v4.
    storage
        .store_config(
            "client_state",
            &serde_json::json!({
                "epochs":{"2":[epoch(group, 2, 22)],"3":[epoch(group, 3, 33)],"4":[epoch(group, 4, 44)]}, "current_epoch":2,
                "active_group_id":group, "migration":null,"active_rekey":null,"last_sync":Utc::now(),
                "version":1, "group_memberships":{},"auth_credentials":null,"invitation_keypair":null
            })
            .to_string(),
        )
        .await
        .unwrap();
    let client = Client::with_client_config(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
        ClientConfig {
            migration_automation_enabled: false,
            coverage_watchers_enabled: false,
            ..ClientConfig::default()
        },
    );
    client.ensure_state_loaded().await.unwrap();
    let folder = dir.path().join("protected");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("a.txt"), b"alpha").await.unwrap();
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();

    client.state.write().await.current_epoch = 4;
    assert_eq!(
        client.leftover_key_files().await.unwrap(),
        LeftoverKeyFiles { target_version: 4, files: 1, oldest_version: Some(2), folders: 0 }
    );
    assert_eq!(
        client.migrate_leftover_key_files().await.unwrap(),
        LeftoverKeyMigration { migrated: 1, ..Default::default() }
    );
    let mut epochs = Vec::new();
    let mut entries = fs::read_dir(&folder).await.unwrap();
    while let Some(file) = entries.next_entry().await.unwrap() {
        if let Some(header) = Client::<LocalFsStorage, MockNetwork>::parse_encrypted_file_metadata(&file.path()) {
            epochs.push(header.epoch_id);
        }
    }
    assert_eq!(epochs, vec![4]);
}

/// A device for `group` holding keys v1 and v2, on `current`, with its own local records.
async fn device_with_keys(dir: &Path, group: Uuid, current: u64) -> Client<LocalFsStorage, MockNetwork> {
    let storage = Arc::new(LocalFsStorage::new(dir.to_path_buf()));
    storage
        .store_config(
            "client_state",
            &serde_json::json!({
                "epochs":{"1":[epoch(group, 1, 11)],"2":[epoch(group, 2, 22)]}, "current_epoch":current,
                "active_group_id":group, "migration":null,"active_rekey":null,"last_sync":Utc::now(),
                "version":1, "group_memberships":{},"auth_credentials":null,"invitation_keypair":null
            })
            .to_string(),
        )
        .await
        .unwrap();
    let client = Client::with_client_config(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
        ClientConfig {
            migration_automation_enabled: false,
            coverage_watchers_enabled: false,
            ..ClientConfig::default()
        },
    );
    client.ensure_state_loaded().await.unwrap();
    client
}

#[tokio::test]
async fn moving_files_reports_progress_up_to_the_total() {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let client = device_with_keys(&dir.path().join("account"), group, 1).await;
    let folder = dir.path().join("protected");
    fs::create_dir(&folder).await.unwrap();
    for name in ["a.txt", "b.txt", "c.txt"] {
        fs::write(folder.join(name), name.as_bytes()).await.unwrap();
    }
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    client.state.write().await.current_epoch = 2;

    let mut seen = Vec::new();
    let outcome = client
        .migrate_leftover_key_files_with_progress(false, |progress| {
            seen.push((progress.migrated_files, progress.total_files))
        })
        .await
        .unwrap();
    assert_eq!(outcome, LeftoverKeyMigration { migrated: 3, ..Default::default() });
    // Counts only grow, and the last report covers every file.
    assert!(seen.windows(2).all(|pair| pair[0].0 <= pair[1].0), "{seen:?}");
    assert_eq!(seen.last(), Some(&(3, 3)));
    assert_eq!(header_epochs(&folder).await.iter().filter(|(_, epoch)| *epoch == 2).count(), 3);
}

async fn header_epochs(folder: &Path) -> Vec<(String, u64)> {
    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(folder).into_iter().filter_map(Result::ok) {
        if let Some(header) = Client::<LocalFsStorage, MockNetwork>::parse_encrypted_file_metadata(entry.path()) {
            // `/` on every platform, so expectations read the same on Windows.
            let name = entry.path().strip_prefix(folder).unwrap().display().to_string().replace('\\', "/");
            found.push((name, header.epoch_id));
        }
    }
    found.sort();
    found
}

#[tokio::test]
async fn files_from_another_device_and_folder_records_move_with_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();

    // The other device (the XPS) encrypts a file under v1 in its own copy of the folder.
    let other = device_with_keys(&dir.path().join("xps"), group, 1).await;
    let xps_folder = dir.path().join("xps-protected");
    fs::create_dir(&xps_folder).await.unwrap();
    fs::write(xps_folder.join("fromxps.txt"), b"from the xps").await.unwrap();
    fs::write(xps_folder.join("folder-record.txt"), b"").await.unwrap();
    enroll_and_hydrate(&other, xps_folder.clone()).await.unwrap();

    // This device has its own file, and receives the XPS file plus a folder record
    // through the sync service. It has no local record for either.
    let client = device_with_keys(&dir.path().join("mac"), group, 1).await;
    let folder = dir.path().join("protected");
    fs::create_dir_all(folder.join("sub")).await.unwrap();
    fs::write(folder.join("mine.txt"), b"mine").await.unwrap();
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    fs::copy(xps_folder.join("fromxps.txt.encrypted"), folder.join("fromxps.txt.encrypted")).await.unwrap();
    fs::copy(
        xps_folder.join("folder-record.txt.encrypted"),
        folder.join("sub").join(".hybridcipher_dir.encrypted"),
    )
    .await
    .unwrap();
    client.coverage_rescan(None).await.unwrap();
    let adopt = client
        .list_file_index_entries_for_root(client.active_group_roots_map().await.unwrap().2.keys().copied().next().unwrap())
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.relative_path.starts_with("fromxps"))
        .expect("indexed");
    assert_eq!(adopt.orphan_kind, Some(FileOrphanKind::MissingMetadata), "the XPS file starts as [adopt]");

    // The group rotates to v2.
    client.state.write().await.current_epoch = 2;
    assert_eq!(
        client.leftover_key_files().await.unwrap(),
        LeftoverKeyFiles { target_version: 2, files: 2, oldest_version: Some(1), folders: 1 }
    );
    assert_eq!(
        client.migrate_leftover_key_files().await.unwrap(),
        LeftoverKeyMigration { migrated: 3, ..Default::default() }
    );
    assert_eq!(
        header_epochs(&folder).await,
        vec![
            ("fromxps.txt.encrypted".to_string(), 2),
            ("mine.txt.encrypted".to_string(), 2),
            ("sub/.hybridcipher_dir.encrypted".to_string(), 2),
        ]
    );
    // Both still open on this device after the move.
    for (path, plaintext) in [
        (folder.join("fromxps.txt.encrypted"), b"from the xps".as_slice()),
        (folder.join("sub").join(".hybridcipher_dir.encrypted"), b"".as_slice()),
    ] {
        let header = Client::<LocalFsStorage, MockNetwork>::parse_encrypted_file_metadata(&path).unwrap();
        assert_eq!(client.decrypt_file(&header).await.unwrap(), plaintext, "{}", path.display());
    }
    let leftovers = client.leftover_key_files().await.unwrap();
    assert_eq!((leftovers.files, leftovers.folders), (0, 0));
}

#[tokio::test]
async fn a_rotation_queues_files_another_device_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let other = device_with_keys(&dir.path().join("xps"), group, 1).await;
    let xps_folder = dir.path().join("xps-protected");
    fs::create_dir(&xps_folder).await.unwrap();
    fs::write(xps_folder.join("fromxps.txt"), b"from the xps").await.unwrap();
    enroll_and_hydrate(&other, xps_folder.clone()).await.unwrap();

    let mut client = device_with_keys(&dir.path().join("mac"), group, 1).await;
    let folder = dir.path().join("protected");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("mine.txt"), b"mine").await.unwrap();
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    fs::copy(xps_folder.join("fromxps.txt.encrypted"), folder.join("fromxps.txt.encrypted")).await.unwrap();
    client.coverage_rescan(None).await.unwrap();

    // A rotation from v1 to v2 starts on this device.
    client.config.migration_automation_enabled = true;
    client.state.write().await.migration = Some(MigrationState {
        from_epoch: 1,
        to_epoch: 2,
        phase: MigrationPhase::Migrating,
        migrated_files: Vec::new(),
        migrated_files_set: Default::default(),
        failed_files: Vec::new(),
        total_files: 0,
        started_at: Utc::now(),
        estimated_completion: None,
    });
    client.populate_migration_queue().await.unwrap();
    let mut queued: Vec<String> = client
        .state
        .read()
        .await
        .pending_rewraps
        .iter()
        .map(|task| Path::new(&task.path).file_name().unwrap().to_string_lossy().to_string())
        .collect();
    queued.sort();
    assert_eq!(queued, vec!["fromxps.txt.encrypted", "mine.txt.encrypted"]);
}

#[tokio::test]
async fn files_that_cannot_be_moved_are_reported_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let storage = Arc::new(LocalFsStorage::new(dir.path().join("account")));
    storage
        .store_config(
            "client_state",
            &serde_json::json!({
                "epochs":{"1":[epoch(group, 1, 11)],"2":[epoch(group, 2, 22)]}, "current_epoch":1,
                "active_group_id":group, "migration":null,"active_rekey":null,"last_sync":Utc::now(),
                "version":1, "group_memberships":{},"auth_credentials":null,"invitation_keypair":null
            })
            .to_string(),
        )
        .await
        .unwrap();
    let client = Client::with_client_config(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
        ClientConfig {
            migration_automation_enabled: false,
            coverage_watchers_enabled: false,
            ..ClientConfig::default()
        },
    );
    client.ensure_state_loaded().await.unwrap();
    let folder = dir.path().join("protected");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("a.txt"), b"alpha").await.unwrap();
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();

    // On v2 now, but the key the file is still under is gone from this device.
    {
        let mut state = client.state.write().await;
        state.current_epoch = 2;
        state.epochs.remove(&1);
    }

    let outcome = client.migrate_leftover_key_files_with(true).await.unwrap();
    assert_eq!((outcome.migrated, outcome.failed), (0, 1));
    assert_eq!(outcome.failures.len(), 1);
    assert!(outcome.failures[0].path.ends_with("a.txt.encrypted"));
    assert_eq!(outcome.failures[0].from_version, Some(1));
    assert!(!outcome.failures[0].reason.is_empty());
    assert!(!outcome.rotation_running);
}

#[test]
fn files_move_only_once_the_rotation_is_over_and_the_keys_agree() {
    let view = |rotation_running, current_version| ServerKeyView {
        rotation_running,
        current_version,
    };
    // Still rolling out: wait, even on a device that already holds the new key.
    assert_eq!(
        leftover_move_decision(view(true, Some(6)), 7),
        LeftoverMoveDecision::WaitForRotation
    );
    // Finished and this device is on the server's current key.
    assert_eq!(
        leftover_move_decision(view(false, Some(7)), 7),
        LeftoverMoveDecision::Proceed
    );
    // A cancelled rotation's key kept on this device: nothing moves, and the device's key is
    // left alone (the server alone cannot switch it back).
    assert_eq!(
        leftover_move_decision(view(false, Some(6)), 7),
        LeftoverMoveDecision::KeysDisagree { server: 6 }
    );
    // An older server that does not report its current key.
    assert_eq!(
        leftover_move_decision(view(false, None), 7),
        LeftoverMoveDecision::Proceed
    );
}

#[tokio::test]
async fn coverage_stats_say_which_key_the_files_are_on() {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let storage = Arc::new(LocalFsStorage::new(dir.path().join("account")));
    storage
        .store_config(
            "client_state",
            &serde_json::json!({
                "epochs":{"1":[epoch(group, 1, 11)],"2":[epoch(group, 2, 22)]}, "current_epoch":1,
                "active_group_id":group, "migration":null,"active_rekey":null,"last_sync":Utc::now(),
                "version":1, "group_memberships":{},"auth_credentials":null,"invitation_keypair":null
            })
            .to_string(),
        )
        .await
        .unwrap();
    let client = Client::with_client_config(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
        ClientConfig {
            migration_automation_enabled: false,
            coverage_watchers_enabled: false,
            ..ClientConfig::default()
        },
    );
    client.ensure_state_loaded().await.unwrap();
    let folder = dir.path().join("protected");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("a.txt"), b"alpha").await.unwrap();
    fs::write(folder.join("b.txt"), b"bravo").await.unwrap();
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();

    let keys = |stats: Vec<CoverageRootStats>| stats[0].keys;
    assert_eq!(
        keys(client.coverage_root_stats().await.unwrap()),
        CoverageKeyCounts { target_version: 1, on_target: 2, on_other: 0 }
    );

    // After a rotation to v2 every file is still protected, but on the old key.
    client.state.write().await.current_epoch = 2;
    let stats = client.coverage_root_stats().await.unwrap();
    assert_eq!(stats[0].coverage_ratio, 1.0);
    assert_eq!(
        stats[0].keys,
        CoverageKeyCounts { target_version: 2, on_target: 0, on_other: 2 }
    );

    client.migrate_leftover_key_files().await.unwrap();
    assert_eq!(
        keys(client.coverage_root_stats().await.unwrap()),
        CoverageKeyCounts { target_version: 2, on_target: 2, on_other: 0 }
    );

    // The support report says the same, by key version and without naming files.
    let report = client.key_state_report().await.unwrap();
    assert_eq!(report.group_id, Some(group));
    assert_eq!(report.current_version, 2);
    assert_eq!(report.held_versions, vec![1, 2]);
    assert_eq!(report.folders.len(), 1);
    assert_eq!(report.folders[0].by_version.get(&2), Some(&2));
    assert_eq!(report.leftovers.files, 0);
    assert!(!serde_json::to_string(&report).unwrap().contains("a.txt"));
}
