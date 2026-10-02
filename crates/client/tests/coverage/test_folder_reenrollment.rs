// Verify safe folder reenrollment across workspaces and preservation of historical ownership.
use super::*;
use crate::ipc::coverage_workflows::{enroll_and_hydrate, unenroll_and_decrypt};
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

type TestClient = Client<LocalFsStorage, MockNetwork>;

async fn fixture() -> (tempfile::TempDir, TestClient, Uuid, Uuid, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let personal = Uuid::new_v4();
    let team = Uuid::new_v4();
    let storage = Arc::new(LocalFsStorage::new(dir.path().join("account")));
    let epochs: Vec<_> = [(personal, [42; 32]), (team, [73; 32])]
        .into_iter()
        .map(|(group, key)| EpochState {
            group_id: Some(group),
            epoch_id: 1,
            encryption_key: key,
            key_source: EpochKeySource::Welcome,
            members: vec![],
            created_at: Utc::now(),
            is_active: true,
            file_count: 0,
            marked_for_removal: false,
            removal_eligible_at: None,
        })
        .collect();
    storage
        .store_config(
            "client_state",
            &serde_json::json!({
                "epochs":{"1":epochs}, "current_epoch":1, "active_group_id":personal,
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
    let folder = dir.path().join("protected");
    fs::create_dir(&folder).await.unwrap();
    (dir, client, personal, team, folder)
}

async fn root_by_id(client: &TestClient, root_id: Uuid) -> CoverageRoot {
    client
        .coverage_roots()
        .await
        .unwrap()
        .into_iter()
        .find(|root| root.root_id == root_id)
        .unwrap()
}

#[tokio::test]
async fn removed_personal_folder_supports_team_encryption_edit_and_decryption() {
    let (_dir, client, personal, team, folder) = fixture().await;
    let source = folder.join("document.txt");
    let encrypted = folder.join("document.txt.encrypted");
    fs::write(&source, b"Personal data").await.unwrap();
    let personal_root = enroll_and_hydrate(&client, folder.clone())
        .await
        .unwrap()
        .root;
    assert!(encrypted.exists());
    assert!(!source.exists());
    let removed = unenroll_and_decrypt(&client, folder.clone()).await.unwrap();
    assert_eq!(removed.decrypted_files, 1);
    assert_eq!(fs::read(&source).await.unwrap(), b"Personal data");

    let team_client = client.for_local_group(team);
    let team_root = enroll_and_hydrate(&team_client, folder.clone())
        .await
        .unwrap()
        .root;
    assert_ne!(team_root.root_id, personal_root.root_id);
    assert_eq!(team_root.group_id, Some(team));
    let old = root_by_id(&client, personal_root.root_id).await;
    assert_eq!(old.group_id, Some(personal));
    assert_eq!(old.state, CoverageRootState::Unenrolled);
    assert_eq!(old.created_at, personal_root.created_at);
    assert!(encrypted.exists());
    assert!(!source.exists());

    // Publish a real edit using the selected Team key, then exercise the same
    // removal/decryption workflow used by the desktop with both root records.
    let edit = folder.join("edit.txt");
    fs::write(&edit, b"Edited in Team").await.unwrap();
    team_client
        .encrypt_file_streaming_with_id_to_path(
            "document.txt",
            &edit,
            &encrypted,
            Some("document.txt"),
            None,
            "team-edit",
            4,
        )
        .await
        .unwrap();
    fs::remove_file(&edit).await.unwrap();
    team_client.coverage_unenroll_root(&folder).await.unwrap();
    let retained_ciphertext = fs::read(&encrypted).await.unwrap();
    let recovered = team_client.coverage_enroll_root(&folder).await.unwrap();
    assert_eq!(recovered.root_id, team_root.root_id);
    assert_eq!(fs::read(&encrypted).await.unwrap(), retained_ciphertext);
    let removed = unenroll_and_decrypt(&team_client, folder.clone())
        .await
        .unwrap();
    assert_eq!(removed.root.root_id, team_root.root_id);
    assert_eq!(removed.decrypted_files, 1);
    assert_eq!(fs::read(&source).await.unwrap(), b"Edited in Team");
    assert!(!encrypted.exists());
    assert_eq!(
        root_by_id(&client, personal_root.root_id).await.state,
        CoverageRootState::Unenrolled
    );
}

#[tokio::test]
async fn same_workspace_reuses_its_own_identity_among_multiple_history_records() {
    let (_dir, client, personal, team, folder) = fixture().await;
    let old = client.coverage_enroll_root(&folder).await.unwrap();
    client.coverage_unenroll_root(&folder).await.unwrap();
    let team_client = client.for_local_group(team);
    let new = team_client.coverage_enroll_root(&folder).await.unwrap();
    team_client.coverage_unenroll_root(&folder).await.unwrap();
    for _ in 0..8 {
        let enrolled = team_client.coverage_enroll_root(&folder).await.unwrap();
        assert_eq!(enrolled.root_id, new.root_id);
        let removed = team_client.coverage_unenroll_root(&folder).await.unwrap();
        assert_eq!(removed.root_id, new.root_id);
    }
    let restored = client.coverage_enroll_root(&folder).await.unwrap();
    assert_eq!(restored.root_id, old.root_id);
    assert_eq!(restored.group_id, Some(personal));
    assert_eq!(client.coverage_roots().await.unwrap().len(), 2);
    assert_eq!(
        root_by_id(&client, new.root_id).await.state,
        CoverageRootState::Unenrolled
    );
}

#[tokio::test]
async fn active_foreign_roots_and_overlaps_remain_blocked_if_registry_is_lost() {
    let (_dir, client, personal, team, folder) = fixture().await;
    let root = client.coverage_enroll_root(&folder).await.unwrap();
    client
        .storage
        .store_config(
            COVERAGE_ROOT_REGISTRY_KEY,
            &serde_json::json!({"entries":{}}).to_string(),
        )
        .await
        .unwrap();
    let nested = folder.join("nested");
    fs::create_dir(&nested).await.unwrap();
    let team_client = client.for_local_group(team);
    for path in [&folder, &nested] {
        let error = team_client.coverage_enroll_root(path).await.unwrap_err();
        assert!(
            error.to_string().contains("active protected folder"),
            "{error}"
        );
    }
    assert!(team_client.coverage_unenroll_root(&folder).await.is_err());
    let unchanged = root_by_id(&client, root.root_id).await;
    assert_eq!(unchanged.group_id, Some(personal));
    assert_eq!(unchanged.state, CoverageRootState::Active);
    assert_eq!(client.coverage_roots().await.unwrap().len(), 1);
}

#[tokio::test]
async fn keep_encrypted_removal_blocks_transfer_even_when_ciphertext_is_renamed() {
    let (_dir, client, personal, team, folder) = fixture().await;
    let source = folder.join("document.txt");
    fs::write(&source, b"Must remain Personal").await.unwrap();
    let old = enroll_and_hydrate(&client, folder.clone())
        .await
        .unwrap()
        .root;
    client.coverage_unenroll_root(&folder).await.unwrap();
    let encrypted = folder.join("document.txt.encrypted");
    let bytes = fs::read(&encrypted).await.unwrap();
    let renamed = folder.join("renamed.dat");
    fs::rename(&encrypted, &renamed).await.unwrap();
    let error = client
        .for_local_group(team)
        .coverage_enroll_root(&folder)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("remove protection with decryption first"),
        "{error}"
    );
    assert_eq!(fs::read(&renamed).await.unwrap(), bytes);
    assert!(!source.exists());
    assert_eq!(client.coverage_roots().await.unwrap().len(), 1);
    let unchanged = root_by_id(&client, old.root_id).await;
    assert_eq!(unchanged.group_id, Some(personal));
    assert_eq!(unchanged.state, CoverageRootState::Unenrolled);
    // The original workspace may still recover its own removed enrollment.
    assert_eq!(
        client.coverage_enroll_root(&folder).await.unwrap().root_id,
        old.root_id
    );
}

#[tokio::test]
async fn unknown_ciphertext_blocks_transfer_without_mutating_history() {
    let (_dir, client, _personal, team, folder) = fixture().await;
    let root = client.coverage_enroll_root(&folder).await.unwrap();
    client.coverage_unenroll_root(&folder).await.unwrap();
    let encrypted = folder.join("unknown.ENCRYPTED");
    let bytes = b"Unrecognized encrypted file";
    fs::write(&encrypted, bytes).await.unwrap();
    let error = client
        .for_local_group(team)
        .coverage_enroll_root(&folder)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("unknown workspace"), "{error}");
    assert_eq!(fs::read(&encrypted).await.unwrap(), bytes);
    assert_eq!(
        root_by_id(&client, root.root_id).await.state,
        CoverageRootState::Unenrolled
    );
    assert_eq!(client.coverage_roots().await.unwrap().len(), 1);
}

#[tokio::test]
async fn concurrent_team_reenrollments_cannot_create_duplicate_active_roots() {
    let (_dir, client, _personal, team, folder) = fixture().await;
    let old = client.coverage_enroll_root(&folder).await.unwrap();
    client.coverage_unenroll_root(&folder).await.unwrap();
    let team_client = client.for_local_group(team);
    let (first, second) = tokio::join!(
        team_client.coverage_enroll_root(&folder),
        team_client.coverage_enroll_root(&folder)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let roots = client.coverage_roots().await.unwrap();
    assert_eq!(roots.len(), 2);
    assert_eq!(
        roots
            .iter()
            .filter(|root| root.state == CoverageRootState::Active)
            .count(),
        1
    );
    assert_eq!(
        root_by_id(&client, old.root_id).await.state,
        CoverageRootState::Unenrolled
    );
}
