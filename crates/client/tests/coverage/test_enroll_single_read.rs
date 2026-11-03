// Tests that enroll_and_hydrate() reads each file once yet still detects existing HybridCipher content and counts exactly.
use super::*;
use crate::ipc::coverage_workflows::enroll_and_hydrate;
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

async fn fixture() -> (tempfile::TempDir, Client<LocalFsStorage, MockNetwork>) {
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
    (dir, client)
}

#[tokio::test]
async fn ciphertext_under_a_plain_name_is_detected_while_hydrating() {
    let (dir, client) = fixture().await;
    let base = std::fs::canonicalize(dir.path()).unwrap();

    // Produce real ciphertext, then copy it under a plain name into a second folder.
    let first = base.join("first");
    fs::create_dir(&first).await.unwrap();
    fs::write(first.join("note.txt"), b"secret").await.unwrap();
    enroll_and_hydrate(&client, first.clone()).await.unwrap();
    let ciphertext = fs::read(first.join("note.txt.encrypted")).await.unwrap();

    let second = base.join("second");
    fs::create_dir(&second).await.unwrap();
    fs::write(second.join("copied.txt"), &ciphertext)
        .await
        .unwrap();
    for index in 0..20 {
        fs::write(
            second.join(format!("plain{index}.txt")),
            format!("plain {index}"),
        )
        .await
        .unwrap();
    }

    let outcome = enroll_and_hydrate(&client, second.clone()).await.unwrap();
    assert_eq!(outcome.hydration.already_encrypted_without_metadata, 1);
    assert_eq!(outcome.hydration.newly_encrypted, 20);
}

// A folder this large makes a live listing return the new `.encrypted` files too.
#[tokio::test]
async fn each_file_is_scanned_once_even_as_ciphertext_appears_beside_it() {
    let (dir, client) = fixture().await;
    let folder = std::fs::canonicalize(dir.path()).unwrap().join("many");
    fs::create_dir_all(folder.join("nested")).await.unwrap();
    for index in 0..2_000 {
        let sub = if index % 2 == 0 {
            folder.clone()
        } else {
            folder.join("nested")
        };
        fs::write(sub.join(format!("{index}.txt")), format!("file {index}"))
            .await
            .unwrap();
    }

    let outcome = enroll_and_hydrate(&client, folder).await.unwrap();
    assert!(
        outcome.hydration.errors.is_empty(),
        "{:?}",
        outcome.hydration.errors
    );
    assert_eq!(outcome.hydration.newly_encrypted, 2_000);
    assert_eq!(outcome.hydration.scanned_files, 2_000);
    assert_eq!(outcome.hydration.already_tracked, 0);
}
