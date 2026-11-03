// Tests that enroll_and_hydrate, coverage_rescan, export_encrypted_file and unenroll_and_decrypt in src/ipc/coverage_workflows.rs handle folder records (.hybridcipher_dir.encrypted) as folder data, not files.
use super::*;
use crate::ipc::coverage_workflows::{enroll_and_hydrate, export_encrypted_file, unenroll_and_decrypt};
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

type TestClient = Client<LocalFsStorage, MockNetwork>;

async fn client_at(storage_dir: PathBuf, group: Uuid) -> TestClient {
    let storage = Arc::new(LocalFsStorage::new(storage_dir));
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
    client
}

/// The folder from the original bug report: `.code-butler/` holds a real empty
/// file named `.code-butler`, and its folder record names the folder itself.
struct Fixture {
    dir: tempfile::TempDir,
    client: TestClient,
    folder: PathBuf,
    nested: PathBuf,
    record: PathBuf,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let client = client_at(dir.path().join("account"), Uuid::new_v4()).await;
    let folder = dir.path().join("protected");
    let nested = folder.join(".code-butler");
    fs::create_dir_all(&nested).await.unwrap();
    fs::write(nested.join(".code-butler"), b"").await.unwrap();
    fs::write(nested.join("notes.txt"), b"notes").await.unwrap();
    let record = nested.join(ciphertext::FOLDER_RECORD_FILE_NAME);
    Fixture {
        dir,
        client,
        folder,
        nested,
        record,
    }
}

async fn write_folder_record(fixture: &Fixture) {
    let empty = fixture.dir.path().join("empty");
    fs::write(&empty, b"").await.unwrap();
    fixture
        .client
        .encrypt_file_streaming_with_id_to_path(
            ".code-butler",
            &empty,
            &fixture.record,
            Some(".code-butler"),
            None,
            "folder-record",
            4,
        )
        .await
        .unwrap();
}

async fn file_names(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    let mut entries = fs::read_dir(dir).await.unwrap();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        if entry.file_type().await.unwrap().is_file() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    names
}

#[tokio::test]
async fn enrolling_and_rescanning_leave_a_folder_record_alone() {
    let fixture = fixture().await;
    // A record left from an earlier "keep files encrypted" removal.
    write_folder_record(&fixture).await;
    let record_bytes = fs::read(&fixture.record).await.unwrap();

    let outcome = enroll_and_hydrate(&fixture.client, fixture.folder.clone())
        .await
        .unwrap();
    assert_eq!(outcome.hydration.scanned_files, 2);
    assert_eq!(outcome.hydration.newly_encrypted, 2);
    assert_eq!(outcome.hydration.already_encrypted_without_metadata, 0);
    assert!(
        outcome
            .hydration
            .warnings
            .iter()
            .all(|warning| !warning.contains(ciphertext::FOLDER_RECORD_FILE_NAME)),
        "{:?}",
        outcome.hydration.warnings
    );
    assert_eq!(fs::read(&fixture.record).await.unwrap(), record_bytes);

    let canonical = fixture.folder.canonicalize().unwrap();
    let rescan = fixture.client.coverage_rescan(Some(canonical)).await.unwrap();
    assert_eq!(rescan.files_indexed, 2);
    assert_eq!(rescan.orphaned_files, 0);
    assert_eq!(rescan.unmanaged_files, 0);
}

#[tokio::test]
async fn exporting_a_folder_record_is_refused() {
    let fixture = fixture().await;
    enroll_and_hydrate(&fixture.client, fixture.folder.clone())
        .await
        .unwrap();
    write_folder_record(&fixture).await;
    let output = fixture.dir.path().join("exported");
    let error = export_encrypted_file(&fixture.client, &fixture.record, &output)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Expected a .encrypted file"), "{error}");
    assert!(!output.exists());
}

#[tokio::test]
async fn folder_record_named_like_a_file_in_its_folder_does_not_block_removal() {
    let fixture = fixture().await;
    enroll_and_hydrate(&fixture.client, fixture.folder.clone())
        .await
        .unwrap();
    write_folder_record(&fixture).await;

    let removed = unenroll_and_decrypt(&fixture.client, fixture.folder.clone())
        .await
        .unwrap();
    assert_eq!(removed.decrypted_files, 2);
    assert!(!fixture.record.exists());
    assert_eq!(fs::read(fixture.nested.join(".code-butler")).await.unwrap(), b"");
    assert_eq!(fs::read(fixture.nested.join("notes.txt")).await.unwrap(), b"notes");
    assert_eq!(file_names(&fixture.nested).await, [".code-butler", "notes.txt"]);
}
