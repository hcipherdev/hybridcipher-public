// Measures enroll_and_hydrate() and unenroll_and_decrypt() throughput on many small files; run with --ignored --nocapture.
use super::*;
use crate::ipc::coverage_workflows::{enroll_and_hydrate, unenroll_and_decrypt};
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

/// Override with HC_ENROLL_BENCH_FILES, e.g. 100000 for the aclImdb-sized case.
const DEFAULT_FILES: usize = 10_000;
const PER_FOLDER: usize = 12_500;

struct Bench {
    _dir: tempfile::TempDir,
    client: Client<LocalFsStorage, MockNetwork>,
    folder: std::path::PathBuf,
    files: usize,
}

async fn bench_folder() -> Bench {
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

    let files: usize = std::env::var("HC_ENROLL_BENCH_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_FILES);
    let folder = std::fs::canonicalize(dir.path()).unwrap().join("reviews");
    for index in 0..files {
        let sub = folder.join(format!("part{}", index / PER_FOLDER));
        if index % PER_FOLDER == 0 {
            std::fs::create_dir_all(&sub).unwrap();
        }
        let text = format!(
            "Review {index}: {}",
            "a fairly ordinary movie review. ".repeat(30)
        );
        std::fs::write(sub.join(format!("{index}.txt")), text).unwrap();
    }

    Bench {
        _dir: dir,
        client,
        folder,
        files,
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "throughput measurement, not a correctness check"]
async fn enroll_throughput_on_many_small_files() {
    let Bench {
        _dir,
        client,
        folder,
        files,
    } = bench_folder().await;
    let started = std::time::Instant::now();
    let outcome = enroll_and_hydrate(&client, folder).await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(outcome.hydration.newly_encrypted, files);
    println!(
        "scanned {} files, {} already tracked",
        outcome.hydration.scanned_files, outcome.hydration.already_tracked
    );
    println!(
        "Enrolled {} files in {:.2} s ({:.0} files/s)",
        files,
        elapsed.as_secs_f64(),
        files as f64 / elapsed.as_secs_f64()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "throughput measurement, not a correctness check"]
async fn unenroll_throughput_on_many_small_files() {
    let Bench {
        _dir,
        client,
        folder,
        files,
    } = bench_folder().await;
    enroll_and_hydrate(&client, folder.clone()).await.unwrap();

    let started = std::time::Instant::now();
    let outcome = unenroll_and_decrypt(&client, folder).await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(outcome.decrypted_files, files);
    println!(
        "Restored {} files in {:.2} s ({:.0} files/s)",
        files,
        elapsed.as_secs_f64(),
        files as f64 / elapsed.as_secs_f64()
    );
}
