// Tests unenroll_and_decrypt_with_progress() batched folder removal in ipc/coverage_workflows.rs: output, resume after an interruption, and failures that keep ciphertext.
use super::*;
use crate::ipc::coverage_workflows::{
    enroll_and_hydrate, export_encrypted_file, unenroll_and_decrypt_with_progress,
};
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;
use std::path::{Path, PathBuf};

/// More than one restore batch in the first folder, plus a nested folder.
const TOP_FILES: usize = 150;
const NESTED_FILES: usize = 20;

async fn protected_folder() -> (
    tempfile::TempDir,
    Client<LocalFsStorage, MockNetwork>,
    PathBuf,
) {
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

    let folder = std::fs::canonicalize(dir.path()).unwrap().join("protected");
    std::fs::create_dir_all(folder.join("nested")).unwrap();
    for index in 0..TOP_FILES {
        std::fs::write(folder.join(format!("{index}.txt")), contents(index)).unwrap();
    }
    for index in 0..NESTED_FILES {
        std::fs::write(
            folder.join("nested").join(format!("{index}.txt")),
            contents(1000 + index),
        )
        .unwrap();
    }
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    (dir, client, folder)
}

fn contents(index: usize) -> String {
    format!("review {index}: {}", "plain words. ".repeat(index % 7 + 1))
}

fn ciphertext(folder: &Path, name: &str) -> PathBuf {
    let path = folder.join(format!("{name}.encrypted"));
    assert!(path.exists(), "{} should be protected", path.display());
    path
}

fn encrypted_count(folder: &Path) -> usize {
    let mut count = 0;
    let mut stack = vec![folder.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(current).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "encrypted") {
                count += 1;
            }
        }
    }
    count
}

#[tokio::test(flavor = "multi_thread")]
async fn every_file_comes_back_across_batches_and_folders() {
    let (_dir, client, folder) = protected_folder().await;
    let mut reports = Vec::new();

    let outcome = unenroll_and_decrypt_with_progress(&client, folder.clone(), &mut |progress| {
        reports.push((progress.decrypted_files, progress.total_files))
    })
    .await
    .unwrap();

    assert_eq!(outcome.decrypted_files, TOP_FILES + NESTED_FILES);
    assert_eq!(encrypted_count(&folder), 0);
    for index in 0..TOP_FILES {
        let restored = std::fs::read_to_string(folder.join(format!("{index}.txt"))).unwrap();
        assert_eq!(restored, contents(index));
    }
    for index in 0..NESTED_FILES {
        let restored =
            std::fs::read_to_string(folder.join("nested").join(format!("{index}.txt"))).unwrap();
        assert_eq!(restored, contents(1000 + index));
    }
    let total = TOP_FILES + NESTED_FILES;
    assert_eq!(reports.first(), Some(&(0, total)));
    assert_eq!(reports.last(), Some(&(total, total)));
    assert!(reports.windows(2).all(|pair| pair[0].0 <= pair[1].0));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_interrupted_removal_finishes_when_run_again() {
    let (_dir, client, folder) = protected_folder().await;
    // A removal stopped after publishing these plaintexts and before deleting
    // their ciphertexts leaves both copies.
    for index in [3, 70, 140] {
        let name = format!("{index}.txt");
        export_encrypted_file(&client, &ciphertext(&folder, &name), &folder.join(&name))
            .await
            .unwrap();
    }

    let outcome = unenroll_and_decrypt_with_progress(&client, folder.clone(), &mut |_| {})
        .await
        .unwrap();

    assert_eq!(outcome.decrypted_files, TOP_FILES + NESTED_FILES);
    assert_eq!(encrypted_count(&folder), 0);
    assert_eq!(
        std::fs::read_to_string(folder.join("70.txt")).unwrap(),
        contents(70)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_file_in_the_way_keeps_its_ciphertext() {
    let (_dir, client, folder) = protected_folder().await;
    let encrypted = ciphertext(&folder, "5.txt");
    std::fs::write(folder.join("5.txt"), "someone else's file").unwrap();

    let result = unenroll_and_decrypt_with_progress(&client, folder.clone(), &mut |_| {}).await;

    assert!(result.is_err());
    assert!(encrypted.exists());
    assert_eq!(
        std::fs::read_to_string(folder.join("5.txt")).unwrap(),
        "someone else's file"
    );
    assert_eq!(encrypted_count(&folder), 1);
    assert_eq!(
        std::fs::read_to_string(folder.join("6.txt")).unwrap(),
        contents(6)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_file_keeps_its_ciphertext_while_the_rest_are_restored() {
    let (_dir, client, folder) = protected_folder().await;
    let encrypted = ciphertext(&folder, "9.txt");
    let mut damaged = std::fs::read(&encrypted).unwrap();
    damaged.truncate(damaged.len() - 8);
    std::fs::write(&encrypted, &damaged).unwrap();

    let result = unenroll_and_decrypt_with_progress(&client, folder.clone(), &mut |_| {}).await;

    let message = result.unwrap_err().to_string();
    assert!(
        message.contains(&format!(
            "Restored {} protected file(s)",
            TOP_FILES + NESTED_FILES - 1
        )),
        "{message}"
    );
    assert_eq!(std::fs::read(&encrypted).unwrap(), damaged);
    assert!(!folder.join("9.txt").exists());
    assert_eq!(encrypted_count(&folder), 1);
}
