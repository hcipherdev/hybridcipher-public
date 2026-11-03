// Tests coverage_moved_root_for_path() and coverage_relocate_root() for protected folders renamed or moved outside the app.
use super::*;
use crate::ipc::coverage_workflows::{enroll_and_hydrate, unenroll_and_decrypt};
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

type TestClient = Client<LocalFsStorage, MockNetwork>;

async fn fixture() -> (tempfile::TempDir, TestClient, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let storage = Arc::new(LocalFsStorage::new(dir.path().join("account")));
    let epoch = EpochState {
        group_id: Some(group),
        epoch_id: 1,
        encryption_key: [42; 32],
        key_source: EpochKeySource::Welcome,
        members: vec![],
        created_at: Utc::now(),
        is_active: true,
        file_count: 0,
        marked_for_removal: false,
        removal_eligible_at: None,
    };
    storage
        .store_config(
            "client_state",
            &serde_json::json!({
                "epochs":{"1":[epoch]}, "current_epoch":1, "active_group_id":group,
                "migration":null,"active_rekey":null,"last_sync":Utc::now(),"version":1,
                "group_memberships":{},"auth_credentials":null,"invitation_keypair":null
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

    let parent = std::fs::canonicalize(dir.path()).unwrap();
    let folder = parent.join("protected");
    fs::create_dir_all(folder.join("sub")).await.unwrap();
    fs::write(folder.join("a.txt"), b"alpha").await.unwrap();
    fs::write(folder.join("sub/b.txt"), b"bravo").await.unwrap();
    (dir, client, folder)
}

async fn tracked_files(client: &TestClient, root_id: Uuid) -> usize {
    client
        .coverage_root_stats()
        .await
        .unwrap()
        .into_iter()
        .find(|stats| stats.root.root_id == root_id)
        .unwrap()
        .tracked_files
}

#[tokio::test]
async fn renamed_folder_is_relinked_with_its_records_and_still_decrypts() {
    let (_dir, client, folder) = fixture().await;
    let root = enroll_and_hydrate(&client, folder.clone())
        .await
        .unwrap()
        .root;
    let tracked = tracked_files(&client, root.root_id).await;
    assert_eq!(tracked, 2);

    let renamed = folder.with_file_name("renamed");
    fs::rename(&folder, &renamed).await.unwrap();

    // The stale root is skipped by a full rescan and keeps its records.
    client.coverage_rescan(None).await.unwrap();
    assert_eq!(tracked_files(&client, root.root_id).await, tracked);
    let moved = client.coverage_moved_root_for_path(&renamed).await.unwrap();
    assert_eq!(moved.map(|root| root.root_id), Some(root.root_id));

    let relocated = client
        .coverage_relocate_root(root.root_id, &renamed)
        .await
        .unwrap();
    assert_eq!(relocated.root_id, root.root_id);
    assert_eq!(relocated.path, renamed);
    assert_eq!(tracked_files(&client, root.root_id).await, tracked);
    let moved_record = renamed.join("sub/b.txt.encrypted");
    assert!(client
        .coverage_has_metadata_for_path(&moved_record)
        .await
        .unwrap());
    let old_key = folder.join("sub/b.txt.encrypted").display().to_string();
    assert!(client
        .storage
        .load_file_metadata(&old_key)
        .await
        .unwrap()
        .is_none());
    assert!(client
        .coverage_moved_root_for_path(&renamed)
        .await
        .unwrap()
        .is_none());

    let removed = unenroll_and_decrypt(&client, renamed.clone())
        .await
        .unwrap();
    assert_eq!(removed.root.root_id, root.root_id);
    assert_eq!(removed.decrypted_files, 2);
    assert_eq!(fs::read(renamed.join("a.txt")).await.unwrap(), b"alpha");
    assert_eq!(fs::read(renamed.join("sub/b.txt")).await.unwrap(), b"bravo");
}

#[tokio::test]
async fn moved_folder_is_not_enrolled_twice() {
    let (_dir, client, folder) = fixture().await;
    let root = enroll_and_hydrate(&client, folder.clone())
        .await
        .unwrap()
        .root;

    let elsewhere = folder.parent().unwrap().join("elsewhere");
    fs::create_dir(&elsewhere).await.unwrap();
    let moved = elsewhere.join("protected");
    fs::rename(&folder, &moved).await.unwrap();

    let err = client.coverage_enroll_root(&moved).await.unwrap_err();
    assert!(err.to_string().contains("before it moved"), "{err}");
    let found = client.coverage_moved_root_for_path(&moved).await.unwrap();
    assert_eq!(found.map(|root| root.root_id), Some(root.root_id));
}

#[tokio::test]
async fn relocation_refuses_a_copy_or_an_unrelated_folder() {
    let (_dir, client, folder) = fixture().await;
    let root = enroll_and_hydrate(&client, folder.clone())
        .await
        .unwrap()
        .root;
    let marker_name = format!(
        "{}{}{}",
        COVERAGE_MARKER_PREFIX, root.root_id, COVERAGE_MARKER_SUFFIX
    );

    // A copy carries the marker, but the original is still in place.
    let copy = folder.with_file_name("copy");
    fs::create_dir(&copy).await.unwrap();
    fs::copy(folder.join(&marker_name), copy.join(&marker_name))
        .await
        .unwrap();
    let err = client
        .coverage_relocate_root(root.root_id, &copy)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("still at its saved location"),
        "{err}"
    );
    assert!(client
        .coverage_moved_root_for_path(&copy)
        .await
        .unwrap()
        .is_none());

    // Once the original is gone, a folder without its marker is still refused.
    let unrelated = folder.with_file_name("unrelated");
    fs::create_dir(&unrelated).await.unwrap();
    fs::rename(&folder, folder.with_file_name("gone"))
        .await
        .unwrap();
    fs::remove_dir_all(folder.with_file_name("gone"))
        .await
        .unwrap();
    let err = client
        .coverage_relocate_root(root.root_id, &unrelated)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("doesn't look like"), "{err}");

    let roots = client.coverage_roots().await.unwrap();
    let kept = roots.iter().find(|r| r.root_id == root.root_id).unwrap();
    assert_eq!(kept.path, folder);
}
