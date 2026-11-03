// Tests the short-lived success cache in Client::require_local_write_for_group() (state/client/local_write_access.rs).
use super::*;
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

type TestClient = Client<LocalFsStorage, MockNetwork>;

async fn client_with_access() -> (tempfile::TempDir, TestClient, Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let client = Client::with_client_config(
        Ed25519KeyPair::generate(),
        Arc::new(LocalFsStorage::new(dir.path().join("account"))),
        Arc::new(MockNetwork::new()),
        ClientConfig {
            migration_automation_enabled: false,
            coverage_watchers_enabled: false,
            ..ClientConfig::default()
        },
    );
    client
        .configure_local_write_access(LocalWriteAccess {
            issuer: "https://test.invalid".into(),
            user_id: "user".into(),
            entitlement: None,
            revoked: false,
        })
        .await
        .unwrap();
    (dir, client, Uuid::new_v4())
}

/// Writes the group list the way another process (the CLI) would: straight to storage.
async fn store_role(client: &TestClient, group_id: Uuid, role: &str) {
    let cache = serde_json::json!({ "by_id": { group_id.to_string(): {
        "organization_id": null, "organization_known": true, "role": role,
    } } });
    client
        .storage
        .store_config("group_metadata_cache", &cache.to_string())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_passed_check_is_reused_until_an_input_changes_in_this_process() {
    let (_dir, client, group) = client_with_access().await;
    store_role(&client, group, "member").await;
    client.require_local_write_for_group(group).await.unwrap();

    // Another process demotes the account: the recent pass still stands for now…
    store_role(&client, group, "viewer").await;
    client.require_local_write_for_group(group).await.unwrap();

    // …until this process records new access, which clears what it remembered.
    client
        .configure_local_write_access(LocalWriteAccess {
            issuer: "https://test.invalid".into(),
            user_id: "user".into(),
            entitlement: None,
            revoked: false,
        })
        .await
        .unwrap();
    assert!(client.require_local_write_for_group(group).await.is_err());
}

#[tokio::test]
async fn a_refusal_is_never_remembered() {
    let (_dir, client, group) = client_with_access().await;
    store_role(&client, group, "viewer").await;
    assert!(client.require_local_write_for_group(group).await.is_err());

    store_role(&client, group, "member").await;
    client.require_local_write_for_group(group).await.unwrap();
}

#[tokio::test]
async fn a_pass_covers_only_its_own_group() {
    let (_dir, client, group) = client_with_access().await;
    store_role(&client, group, "member").await;
    client.require_local_write_for_group(group).await.unwrap();

    let other = Uuid::new_v4();
    let cache = serde_json::json!({ "by_id": {
        group.to_string(): { "organization_id": null, "organization_known": true, "role": "member" },
        other.to_string(): { "organization_id": null, "organization_known": true, "role": "viewer" },
    } });
    client
        .storage
        .store_config("group_metadata_cache", &cache.to_string())
        .await
        .unwrap();
    assert!(client.require_local_write_for_group(other).await.is_err());
}
