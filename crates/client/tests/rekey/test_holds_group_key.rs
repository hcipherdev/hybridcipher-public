// Tests Client::holds_group_key() in crates/client/src/state/client/key_receipts.rs: true only for a usable key of that group and version.
use super::*;
use crate::network::MockNetwork;
use crate::storage::MockStorage;

type TestClient = Client<MockStorage, MockNetwork>;

fn epoch(group_id: Uuid, version: u64, key_source: EpochKeySource) -> EpochState {
    EpochState {
        group_id: Some(group_id),
        epoch_id: version,
        encryption_key: [version as u8; 32],
        key_source,
        members: Vec::new(),
        created_at: Utc::now(),
        is_active: true,
        file_count: 0,
        marked_for_removal: false,
        removal_eligible_at: None,
    }
}

#[tokio::test]
async fn a_key_counts_only_for_its_own_group_and_version() {
    let client: TestClient = Client::new(
        Ed25519KeyPair::generate(),
        Arc::new(MockStorage::new()),
        Arc::new(MockNetwork::new()),
    );
    client.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    let other_group = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        TestClient::upsert_epoch_state(&mut state, group, epoch(group, 8, EpochKeySource::Welcome));
        TestClient::upsert_epoch_state(
            &mut state,
            other_group,
            epoch(other_group, 9, EpochKeySource::Welcome),
        );
    }
    assert!(client.holds_group_key(group, 8).await);
    // The new version, and another group's copy of it, do not count.
    assert!(!client.holds_group_key(group, 9).await);
    assert!(!client.holds_group_key(other_group, 8).await);
}
