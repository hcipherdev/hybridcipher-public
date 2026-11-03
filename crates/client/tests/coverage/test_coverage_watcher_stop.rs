// Tests Client::stop_coverage_watchers() in crates/client/src/state/client/coverage/background.rs: a stopped watcher exits and never restarts.
use super::*;
use crate::ipc::coverage_workflows::enroll_and_hydrate;
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

async fn watched_client() -> (tempfile::TempDir, Client<LocalFsStorage, MockNetwork>, PathBuf) {
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
            coverage_watchers_enabled: true,
            ..ClientConfig::default()
        },
    );
    client.ensure_state_loaded().await.unwrap();
    let folder = dir.path().join("protected");
    fs::create_dir(&folder).await.unwrap();
    (dir, client, folder)
}

async fn watcher_running(client: &Client<LocalFsStorage, MockNetwork>) -> bool {
    client.coverage_watcher.lock().await.running
}

#[tokio::test]
async fn a_stopped_watcher_exits_and_never_restarts() {
    let (_dir, client, folder) = watched_client().await;
    enroll_and_hydrate(&client, folder).await.unwrap();
    assert!(watcher_running(&client).await, "enrolling a folder starts the watcher");

    client.stop_coverage_watchers().await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while watcher_running(&client).await {
        assert!(std::time::Instant::now() < deadline, "the watcher stops promptly");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    client.coverage_roots().await.unwrap();
    assert!(
        !watcher_running(&client).await,
        "listing folders no longer restarts it"
    );
}
