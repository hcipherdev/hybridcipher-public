use hybridcipher_client::{
    auth::{LoginFlow, RegistrationFlow},
    network::{MockNetwork, Network},
    state::client::{GroupMember, MemberCapabilities},
    storage::{MockStorage, Storage},
    Client,
};
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use hybridcipher_messages::transparency::TransparencyConfig;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_client_creation_and_basic_operations() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());

    let client = Client::new(device_identity, storage, network);

    // Test basic state queries
    assert_eq!(client.current_epoch().await, 0);
    assert!(!client.is_migrating().await);
    assert!(client.migration_progress().await.is_none());

    // Test state validation
    client.validate_state().await.unwrap();
}

#[tokio::test]
async fn test_epoch_transition() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());

    let client = Client::new(device_identity, storage, network);

    // Create test group members
    let members = vec![
        GroupMember {
            member_id: [1u8; 32],
            public_key: [2u8; 32],
            capabilities: MemberCapabilities::default(),
            joined_at: chrono::Utc::now(),
        },
        GroupMember {
            member_id: [3u8; 32],
            public_key: [4u8; 32],
            capabilities: MemberCapabilities {
                can_read: true,
                can_write: true,
                can_invite: true,
                can_rekey: true,
                can_remove: false,
            },
            joined_at: chrono::Utc::now(),
        },
    ];

    // Start epoch transition
    client.start_epoch_transition(members).await.unwrap();

    // Verify migration state
    assert!(client.is_migrating().await);
    assert_eq!(client.migration_progress().await, Some(0.0));

    // State should still be valid during migration
    client.validate_state().await.unwrap();
}

#[tokio::test]
async fn test_registration_and_login_flow() {
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());
    let transparency_config = TransparencyConfig::default();

    // Test registration
    let mut registration = RegistrationFlow::new(
        "test-device-123".to_string(),
        storage.clone(),
        network.clone(),
        transparency_config.clone(),
    );
    let invitation_key = [0x42u8; 32];

    let registration_result = registration
        .register("test-user", "secure-password-123", invitation_key) // lgtm[rust/hard-coded-cryptographic-value] non-secret test credential
        .await
        .unwrap();

    // Verify registration result
    assert_ne!(registration_result.device_public_key, [0u8; 32]);
    assert_eq!(
        registration_result.join_card.invitation_public,
        invitation_key
    );
    assert!(!registration_result.registration_record.is_empty());
    assert_ne!(registration_result.session_key, [0u8; 32]);

    // Test login with registered credentials
    let login = LoginFlow::new(
        "test-device-123".to_string(),
        storage.clone(),
        network,
        transparency_config,
    );
    let login_result = login
        .login(
            "secure-password-123", // lgtm[rust/hard-coded-cryptographic-value] non-secret test credential
            &registration_result.registration_record,
        )
        .await
        .unwrap();

    // Verify login result
    assert_eq!(
        login_result.device_public_key,
        registration_result.device_public_key
    );
    assert_ne!(login_result.session_key, [0u8; 32]);
    assert_eq!(login_result.current_epoch, 0);
    assert_eq!(login_result.file_count, 0);
}

#[tokio::test]
async fn test_storage_operations() {
    let storage = Arc::new(MockStorage::new());

    // Test identity key storage
    let device_id = "test-device";
    let identity_key = b"test-identity-key-32-bytes-long!";

    storage
        .store_identity_key(device_id, identity_key)
        .await
        .unwrap();
    let loaded_key = storage.load_identity_key(device_id).await.unwrap().unwrap();
    assert_eq!(loaded_key, identity_key);

    // Test epoch state storage
    let epoch_data = hybridcipher_client::EpochStateData {
        epoch_id: 42,
        encrypted_key: vec![1u8; 32],
        members: vec![],
        created_at: chrono::Utc::now(),
        is_active: true,
        file_count: 0,
        version: 1,
    };

    storage
        .store_epoch_state_data(42, &epoch_data)
        .await
        .unwrap();
    let loaded_epoch = storage.load_epoch_state(42).await.unwrap();
    assert_eq!(loaded_epoch.epoch_id, 42);
    assert_eq!(loaded_epoch.encryption_key, [1u8; 32]);

    // Test epoch listing
    let epochs = storage.list_epochs().await.unwrap();
    assert!(epochs.contains(&42));
}

#[tokio::test]
async fn test_network_operations() {
    let network = Arc::new(MockNetwork::new());

    // Test network status
    let status = network.get_network_status().await.unwrap();
    assert!(status.is_connected);
    assert_eq!(status.connected_peers, 0);

    // Test peer management
    let peer_key = [0x99u8; 32];
    network
        .connect_peer("127.0.0.1:8080", &peer_key)
        .await
        .unwrap();

    let peers = network.list_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].public_key, peer_key);

    // Test message simulation
    let message = hybridcipher_client::NetworkMessage {
        message_type: hybridcipher_client::MessageType::Heartbeat,
        encrypted_payload: vec![1, 2, 3],
        sender_public_key: [0x11u8; 32],
        signature: [0u8; 64],
        timestamp: chrono::Utc::now(),
        sequence_number: 1,
        priority: hybridcipher_client::MessagePriority::Normal,
    };

    // Test message sending
    network.send_message(&peer_key, &message).await.unwrap();

    // Test message receiving (should be empty initially)
    let received = network.receive_message().await.unwrap();
    assert!(received.is_none());
}

#[tokio::test]
async fn test_concurrent_client_access() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());

    let client = Arc::new(Client::new(device_identity, storage, network));

    // Spawn multiple tasks accessing client concurrently
    let mut handles = Vec::new();

    for i in 0..20 {
        let client_clone = client.clone();
        let handle = tokio::spawn(async move {
            // Perform various operations concurrently
            let epoch = client_clone.current_epoch().await;
            let migrating = client_clone.is_migrating().await;
            let progress = client_clone.migration_progress().await;
            let public_key = client_clone.device_public_key();

            // Validate state multiple times
            for _ in 0..5 {
                client_clone.validate_state().await.unwrap();
            }

            (
                i,
                epoch,
                migrating,
                progress.is_none(),
                public_key != [0u8; 32],
            )
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        let (task_id, epoch, migrating, no_progress, valid_key) = handle.await.unwrap();
        assert_eq!(epoch, 0);
        assert!(!migrating);
        assert!(no_progress);
        assert!(valid_key);
        println!("Task {} completed successfully", task_id);
    }
}

#[tokio::test]
async fn test_storage_transaction() {
    let storage = Arc::new(MockStorage::new());

    // Begin transaction
    let tx = storage.begin_transaction().await.unwrap();

    // Perform operations within transaction
    let epoch_data = hybridcipher_client::EpochStateData {
        epoch_id: 100,
        encrypted_key: vec![5u8; 32],
        members: vec![],
        created_at: chrono::Utc::now(),
        is_active: false,
        file_count: 42,
        version: 1,
    };

    tx.store_epoch_state(100, &epoch_data).await.unwrap();

    let coverage_data = hybridcipher_client::CoverageLogData {
        root_hash: [0x42u8; 32],
        tree_nodes: vec![1, 2, 3, 4, 5],
        file_epochs: std::collections::HashMap::new(),
        sequence: 1,
        updated_at: chrono::Utc::now(),
        version: 1,
    };

    tx.store_coverage_log(Uuid::nil(), &coverage_data)
        .await
        .unwrap();

    // Commit transaction
    tx.commit().await.unwrap();

    // Verify data was stored
    let loaded_epoch = storage.load_epoch_state(100).await.unwrap();
    assert_eq!(loaded_epoch.epoch_id, 100);
    assert_eq!(loaded_epoch.file_count, 42);

    let loaded_coverage = storage.load_coverage_log(uuid::Uuid::nil()).await.unwrap();
    assert_eq!(loaded_coverage.root_hash, [0x42u8; 32]);
    assert_eq!(loaded_coverage.sequence, 1);
}
