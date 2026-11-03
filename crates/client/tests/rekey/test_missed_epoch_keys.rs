// Tests Client::missed_epoch_versions() and Client::install_missed_epoch_welcome() in crates/client/src/state/client/welcome.rs: a device offline across several rotations installs the key versions in between as readable keys, without changing its current key.
use super::*;
use crate::network::MockNetwork;
use crate::storage::MockStorage;

type TestClient = Client<MockStorage, MockNetwork>;

fn client() -> TestClient {
    Client::new(
        Ed25519KeyPair::generate(),
        Arc::new(MockStorage::new()),
        Arc::new(MockNetwork::new()),
    )
}

fn held_epoch(group_id: Uuid, version: u64, key: u8, key_source: EpochKeySource) -> EpochState {
    EpochState {
        group_id: Some(group_id),
        epoch_id: version,
        encryption_key: [key; 32],
        key_source,
        members: Vec::new(),
        created_at: Utc::now(),
        is_active: true,
        file_count: 0,
        marked_for_removal: false,
        removal_eligible_at: None,
    }
}

/// A Welcome for `version`, encrypted to this client's device and signed the way the server's
/// stored Welcome messages are.
async fn signed_welcome(
    client: &TestClient,
    group_id: Uuid,
    version: u64,
    user_id: Uuid,
    key: [u8; 32],
    expires_at: Option<DateTime<Utc>>,
) -> WelcomeMessagePayload {
    let invitation = client.ensure_invitation_keypair().await.unwrap();
    let manager = WelcomeManager::new(client.storage.clone(), invitation.clone());
    let encrypted = manager
        .encrypt_epoch_key_for_device(&key, &invitation.invitation_public_key().unwrap())
        .unwrap();
    let epoch_uuid = EpochIdMapper::u64_to_uuid(version, group_id.as_bytes());
    let created_at = Utc::now();
    let signable = ServerWelcomeSignable::new(
        group_id,
        epoch_uuid,
        &invitation.device_id,
        &encrypted,
        created_at,
        expires_at,
    );
    let signature = client
        .device_identity
        .sign(&signable.to_bytes().unwrap())
        .to_vec();
    WelcomeMessagePayload {
        message_id: Uuid::new_v4(),
        epoch_id: epoch_uuid,
        group_id,
        recipient_user_id: user_id,
        recipient_device_id: invitation.device_id,
        encrypted_epoch_key: encrypted,
        signature,
        signing_public_key: client.device_identity.public_key_bytes().to_vec(),
        created_at,
        expires_at,
    }
}

#[tokio::test]
async fn only_versions_between_the_oldest_held_and_the_current_key_are_missed() {
    let client = client();
    client.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        // Joined at v3, then missed v4 and v5 while offline; v7 is current and v6 arrived.
        for version in [3, 6] {
            TestClient::upsert_epoch_state(
                &mut state,
                group,
                held_epoch(group, version, 1, EpochKeySource::Welcome),
            );
        }
    }
    let state = client.state.read().await;
    assert_eq!(
        TestClient::missed_epoch_versions(&state, group, 7),
        vec![4, 5]
    );
    // Another group's keys do not count, and a device without keys asks for nothing.
    assert!(TestClient::missed_epoch_versions(&state, Uuid::new_v4(), 7).is_empty());
}

#[tokio::test]
async fn a_long_gap_asks_for_the_newest_versions_only() {
    let client = client();
    client.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        TestClient::upsert_epoch_state(
            &mut state,
            group,
            held_epoch(group, 1, 1, EpochKeySource::Welcome),
        );
    }
    let state = client.state.read().await;
    let missed = TestClient::missed_epoch_versions(&state, group, 100);
    assert_eq!(missed.len(), TestClient::MISSED_EPOCH_FETCH_LIMIT);
    assert_eq!(missed.last(), Some(&99));
}

#[tokio::test]
async fn a_missed_version_is_installed_readable_without_changing_the_current_key() {
    let client = client();
    client.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    let user = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        TestClient::upsert_epoch_state(
            &mut state,
            group,
            held_epoch(group, 1, 1, EpochKeySource::Welcome),
        );
        TestClient::upsert_epoch_state(
            &mut state,
            group,
            held_epoch(group, 3, 3, EpochKeySource::Welcome),
        );
        state.current_epoch = 3;
    }

    let welcome = signed_welcome(&client, group, 2, user, [2; 32], None).await;
    assert!(client
        .install_missed_epoch_welcome(group, 2, welcome, user)
        .await
        .unwrap());
    {
        let state = client.state.read().await;
        let installed = TestClient::get_epoch_state(&state, group, 2).expect("v2 installed");
        assert_eq!(installed.encryption_key, [2; 32]);
        assert!(!installed.is_active);
        assert_eq!(state.current_epoch, 3);
    }

    // A second copy changes nothing: the held key is kept.
    let again = signed_welcome(&client, group, 2, user, [9; 32], None).await;
    assert!(!client
        .install_missed_epoch_welcome(group, 2, again, user)
        .await
        .unwrap());
    let state = client.state.read().await;
    assert_eq!(
        TestClient::get_epoch_state(&state, group, 2)
            .unwrap()
            .encryption_key,
        [2; 32]
    );
}

#[tokio::test]
async fn welcomes_for_another_user_version_or_past_their_expiry_are_ignored() {
    let client = client();
    client.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    let user = Uuid::new_v4();

    let someone_else = signed_welcome(&client, group, 2, Uuid::new_v4(), [2; 32], None).await;
    assert!(!client
        .install_missed_epoch_welcome(group, 2, someone_else, user)
        .await
        .unwrap());
    // A Welcome for v2 handed back when v3 was asked for.
    let wrong_version = signed_welcome(&client, group, 2, user, [2; 32], None).await;
    assert!(!client
        .install_missed_epoch_welcome(group, 3, wrong_version, user)
        .await
        .unwrap());
    let expired = signed_welcome(
        &client,
        group,
        2,
        user,
        [2; 32],
        Some(Utc::now() - chrono::Duration::minutes(1)),
    )
    .await;
    assert!(!client
        .install_missed_epoch_welcome(group, 2, expired, user)
        .await
        .unwrap());
    let mut tampered = signed_welcome(&client, group, 2, user, [2; 32], None).await;
    tampered.encrypted_epoch_key[0] ^= 1;
    assert!(!client
        .install_missed_epoch_welcome(group, 2, tampered, user)
        .await
        .unwrap());

    let state = client.state.read().await;
    assert!(TestClient::get_epoch_state(&state, group, 2).is_none());
    assert!(TestClient::get_epoch_state(&state, group, 3).is_none());
}
