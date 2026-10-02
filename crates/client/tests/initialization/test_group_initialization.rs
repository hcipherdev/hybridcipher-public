// Purpose: verify protected genesis retry persistence, concurrent setup, canonical readiness, and typed API failures.
use super::*;
use crate::network::MockNetwork;
use crate::storage::{LocalFsStorage, MockStorage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn client(storage: Arc<MockStorage>) -> Client<MockStorage, MockNetwork> {
    Client::new(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
    )
}

async fn signed_welcome_response(
    client: &Client<MockStorage, MockNetwork>,
    group: Uuid,
    epoch: u64,
    plaintext: &[u8],
) -> WelcomeMessagesResponse {
    let invitation = client.ensure_invitation_keypair().await.unwrap();
    let mut manager = WelcomeManager::new(client.storage.clone(), invitation.clone());
    let encrypted = if plaintext.len() == 32 {
        manager
            .encrypt_epoch_key_for_device(plaintext, &invitation.invitation_public_key().unwrap())
            .unwrap()
    } else {
        let secrets = serde_json::from_slice(plaintext).unwrap();
        let join_card = invitation.create_join_card(Uuid::new_v4()).unwrap();
        manager
            .create_welcome_messages(group, &secrets, &[join_card], &client.device_identity)
            .await
            .unwrap()
            .remove(0)
            .encrypted_payload
    };
    let epoch_uuid = EpochIdMapper::u64_to_uuid(epoch, group.as_bytes());
    let created_at = Utc::now();
    let signable = ServerWelcomeSignable::new(
        group,
        epoch_uuid,
        &invitation.device_id,
        &encrypted,
        created_at,
        None,
    );
    let signature = client
        .device_identity
        .sign(&signable.to_bytes().unwrap())
        .to_vec();
    WelcomeMessagesResponse {
        group_id: group,
        epoch_uuid,
        epoch_id: epoch,
        legacy_mapping: false,
        messages: vec![WelcomeMessagePayload {
            message_id: Uuid::new_v4(),
            epoch_id: epoch_uuid,
            group_id: group,
            recipient_user_id: Uuid::new_v4(),
            recipient_device_id: invitation.device_id,
            encrypted_epoch_key: encrypted,
            signature,
            signing_public_key: client.device_identity.public_key_bytes().to_vec(),
            created_at,
            expires_at: None,
        }],
        expires_at: created_at + chrono::Duration::minutes(30),
    }
}

#[tokio::test]
async fn test_welcome_cannot_replace_a_verified_canonical_key() {
    let client = client(Arc::new(MockStorage::new()));
    client.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    let original = signed_welcome_response(&client, group, 1, &[17; 32]).await;
    client
        .process_welcome_messages_inner(original, group)
        .await
        .unwrap();
    let conflicting = signed_welcome_response(&client, group, 1, &[18; 32]).await;
    let error = client
        .process_welcome_messages_inner(conflicting, group)
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::SecurityTampering));
    let state = client.state.read().await;
    assert_eq!(
        Client::<MockStorage, MockNetwork>::get_epoch_state(&state, group, 1)
            .unwrap()
            .encryption_key,
        [17; 32]
    );
}

#[tokio::test]
async fn test_mixed_welcome_response_installs_only_the_canonical_epoch() {
    let client = client(Arc::new(MockStorage::new()));
    client.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    let mut canonical = signed_welcome_response(&client, group, 2, &[19; 32]).await;
    let mut stale = signed_welcome_response(&client, group, 1, &[17; 32]).await;
    canonical.messages.insert(0, stale.messages.remove(0));
    client
        .process_welcome_messages_inner(canonical, group)
        .await
        .unwrap();
    let state = client.state.read().await;
    assert_eq!(
        Client::<MockStorage, MockNetwork>::get_epoch_state(&state, group, 2)
            .unwrap()
            .encryption_key,
        [19; 32]
    );
}

#[tokio::test]
async fn test_signed_welcome_with_wrong_decrypted_epoch_is_rejected() {
    let client = client(Arc::new(MockStorage::new()));
    client.ensure_state_loaded().await.unwrap();
    let group = Uuid::new_v4();
    let plaintext = serde_json::to_vec(&crate::welcome_manager::EpochSecrets {
        epoch_key: [17; 32],
        epoch_id: 1,
        group_members: Vec::new(),
        active_at: Utc::now(),
    })
    .unwrap();
    let response = signed_welcome_response(&client, group, 2, &plaintext).await;
    let error = client
        .process_welcome_messages_inner(response, group)
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::SecurityTampering));
    let state = client.state.read().await;
    assert!(Client::<MockStorage, MockNetwork>::get_epoch_state(&state, group, 2).is_none());
}

#[test]
fn test_no_active_epoch_uses_typed_code_and_exact_legacy_messages() {
    for body in [
        r#"{"code":"group_not_initialized","error":"Localized message"}"#,
        r#"{"error":"Group has no current epoch"}"#,
        r#"{"error":"Group has no active epoch"}"#,
    ] {
        assert_eq!(
            group_api_error_code(StatusCode::BAD_REQUEST, body),
            Some(ErrorCode::GroupNotInitialized)
        );
    }
    assert_eq!(
        group_api_error_code(StatusCode::FORBIDDEN, r#"{"code":"group_not_initialized"}"#),
        None
    );
    assert_eq!(
        group_api_error_code(
            StatusCode::BAD_REQUEST,
            r#"{"error":"Unrelated operation: Group has no active epoch"}"#
        ),
        None
    );
    assert_eq!(
        group_api_error_code(
            StatusCode::BAD_REQUEST,
            r#"{"code":"genesis_already_initialized"}"#
        ),
        Some(ErrorCode::GroupGenesisConflict)
    );
    assert_eq!(
        setup_error(ErrorCode::GroupDeviceApprovalRequired, "Approval").error_code(),
        Some(ErrorCode::GroupDeviceApprovalRequired)
    );
}

#[test]
fn test_pending_setup_scope_separates_account_device_server_and_group() {
    let user = Uuid::new_v4();
    let group = Uuid::new_v4();
    let original = pending_key("https://one.test", user, "device", group);
    for different in [
        pending_key("https://two.test", user, "device", group),
        pending_key("https://one.test", Uuid::new_v4(), "device", group),
        pending_key("https://one.test", user, "other", group),
        pending_key("https://one.test", user, "device", Uuid::new_v4()),
    ] {
        assert_ne!(original, different);
    }
}

#[tokio::test]
async fn test_concurrent_genesis_preparation_reuses_one_signed_payload() {
    let storage = Arc::new(MockStorage::new());
    let first = client(storage.clone());
    let second = client(storage.clone());
    let invitation = InvitationKeyPair::generate("test-device".into()).unwrap();
    let user = Uuid::new_v4();
    let group = Uuid::new_v4();
    let (left, right) = tokio::join!(
        first.load_or_create_pending_genesis(group, user, "https://one.test", &invitation),
        second.load_or_create_pending_genesis(group, user, "https://one.test", &invitation),
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert!(left.request.welcome_messages[0].expires_at.is_none());
    assert_eq!(
        serde_json::to_value(&left.request).unwrap(),
        serde_json::to_value(&right.request).unwrap()
    );
    assert_eq!(left.epoch_key, right.epoch_key);
    assert_eq!(
        first
            .ready_group_epoch(group)
            .await
            .unwrap_err()
            .error_code(),
        Some(ErrorCode::GroupDeviceApprovalRequired)
    );
}

#[tokio::test]
async fn test_protected_pending_payload_survives_restart_and_never_overwrites() {
    let temporary = tempfile::tempdir().unwrap();
    let invitation = InvitationKeyPair::generate("persisted-device".into()).unwrap();
    let user = Uuid::new_v4();
    let group = Uuid::new_v4();
    let key = pending_key("https://one.test", user, &invitation.device_id, group);
    let storage = Arc::new(LocalFsStorage::new(temporary.path()));
    storage.enable_account_encryption([23; 32]);
    let first = Client::new(
        Ed25519KeyPair::generate(),
        storage.clone(),
        Arc::new(MockNetwork::new()),
    );
    let pending = first
        .load_or_create_pending_genesis(group, user, "https://one.test", &invitation)
        .await
        .unwrap();
    let stored = std::fs::read_to_string(temporary.path().join(format!("{key}.json"))).unwrap();
    assert!(!stored.contains("epoch_key"));
    assert!(!stored.contains(&invitation.device_id));
    assert!(!storage
        .create_protected_config_if_absent(&key, "replacement")
        .await
        .unwrap());
    drop(first);
    drop(storage);
    let storage = Arc::new(LocalFsStorage::new(temporary.path()));
    storage.enable_account_encryption([23; 32]);
    let restarted = Client::new(
        Ed25519KeyPair::generate(),
        storage.clone(),
        Arc::new(MockNetwork::new()),
    );
    let restored = restarted
        .load_or_create_pending_genesis(group, user, "https://one.test", &invitation)
        .await
        .unwrap();
    assert_eq!(restored.epoch_key, pending.epoch_key);
    assert_eq!(
        serde_json::to_value(&restored.request).unwrap(),
        serde_json::to_value(&pending.request).unwrap()
    );
    let locked = LocalFsStorage::new(temporary.path().join("locked"));
    assert!(locked
        .create_protected_config_if_absent("pending", "private")
        .await
        .is_err());
    assert!(!temporary.path().join("locked/pending.json").exists());
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut all = Vec::new();
    loop {
        let mut buffer = [0u8; 4096];
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        all.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = all.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&all[..header_end]);
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            if all.len() >= header_end + 4 + length {
                return all[header_end + 4..header_end + 4 + length].to_vec();
            }
        }
    }
}

#[tokio::test]
async fn test_lost_response_retry_sends_identical_genesis_body() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut bodies = Vec::new();
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            bodies.push(read_request(&mut socket).await);
            if attempt == 1 {
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .await
                    .unwrap();
            }
        }
        bodies
    });
    let storage = Arc::new(MockStorage::new());
    let invitation = InvitationKeyPair::generate("retry-device".into()).unwrap();
    let group = Uuid::new_v4();
    let user = Uuid::new_v4();
    let first = client(storage.clone());
    let pending = first
        .load_or_create_pending_genesis(group, user, &server_url, &invitation)
        .await
        .unwrap();
    assert!(Client::<MockStorage, MockNetwork>::submit_pending_genesis(
        &pending,
        "test-token",
        std::time::Duration::from_secs(2)
    )
    .await
    .is_err());
    drop(first);
    let restarted = client(storage.clone());
    let restored = restarted
        .load_or_create_pending_genesis(group, user, &server_url, &invitation)
        .await
        .unwrap();
    Client::<MockStorage, MockNetwork>::submit_pending_genesis(
        &restored,
        "test-token",
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    let bodies = server.await.unwrap();
    assert_eq!(bodies[0], bodies[1]);
    assert!(storage
        .load_config_fresh(&pending_key(
            &server_url,
            user,
            &invitation.device_id,
            group
        ))
        .await
        .unwrap()
        .is_some());
    assert!(
        restarted.ready_group_epoch(group).await.is_err(),
        "HTTP success alone must never mark group ready"
    );
}

#[tokio::test]
async fn test_setup_timeout_preserves_pending_keys() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut socket).await;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });
    let storage = Arc::new(MockStorage::new());
    let client = client(storage.clone());
    let invitation = InvitationKeyPair::generate("timeout-device".into()).unwrap();
    let user = Uuid::new_v4();
    let group = Uuid::new_v4();
    let pending = client
        .load_or_create_pending_genesis(group, user, &server_url, &invitation)
        .await
        .unwrap();
    let error = Client::<MockStorage, MockNetwork>::submit_pending_genesis(
        &pending,
        "test-token",
        std::time::Duration::from_millis(25),
    )
    .await
    .unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::NetworkTimeout));
    let restored = client
        .load_or_create_pending_genesis(group, user, &server_url, &invitation)
        .await
        .unwrap();
    assert_eq!(restored.epoch_key, pending.epoch_key);
    server.abort();
}

#[tokio::test]
async fn test_ready_requires_authenticated_local_keys_and_durable_save() {
    let storage = Arc::new(MockStorage::new());
    let client = client(storage.clone());
    let group = Uuid::new_v4();
    storage
        .store_config(&format!("committed_group_epoch_{group}"), "1")
        .await
        .unwrap();
    assert!(
        !client.has_cached_group_key(group).await.unwrap(),
        "an epoch identifier is not a key"
    );
    let epoch = EpochState {
        group_id: Some(group),
        epoch_id: 1,
        encryption_key: [31; 32],
        key_source: EpochKeySource::LocalInit,
        members: Vec::new(),
        created_at: Utc::now(),
        is_active: true,
        file_count: 0,
        marked_for_removal: false,
        removal_eligible_at: None,
    };
    {
        let mut state = client.state.write().await;
        Client::<MockStorage, MockNetwork>::upsert_epoch_state(&mut state, group, epoch.clone());
    }
    assert!(client.ready_group_epoch(group).await.is_err());
    assert!(
        !client.has_cached_group_key(group).await.unwrap(),
        "a proposed key is not authenticated"
    );
    {
        let mut state = client.state.write().await;
        let mut authenticated = epoch;
        authenticated.key_source = EpochKeySource::Welcome;
        Client::<MockStorage, MockNetwork>::upsert_epoch_state(&mut state, group, authenticated);
    }
    client.save_client_state_now().await.unwrap();
    let restarted = self::client(storage);
    restarted.load_client_state().await.unwrap();
    assert_eq!(restarted.ready_group_epoch(group).await.unwrap(), 1);
    assert!(restarted.has_cached_group_key(group).await.unwrap());
    assert!(!restarted
        .has_cached_group_key(Uuid::new_v4())
        .await
        .unwrap());
    restarted
        .storage
        .store_config(&format!("committed_group_epoch_{group}"), "2")
        .await
        .unwrap();
    assert!(
        !restarted.has_cached_group_key(group).await.unwrap(),
        "a saved older key cannot stand in for current keys"
    );
}

#[tokio::test]
async fn test_protected_filesystem_concurrent_creation_publishes_one_complete_record() {
    let temporary = tempfile::tempdir().unwrap();
    let storage = Arc::new(LocalFsStorage::new(temporary.path()));
    storage.enable_account_encryption([21; 32]);
    let (left, right) = tokio::join!(
        storage.create_protected_config_if_absent("pending_race", "first"),
        storage.create_protected_config_if_absent("pending_race", "second"),
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_ne!(left, right);
    assert_eq!(
        storage
            .load_config_fresh("pending_race")
            .await
            .unwrap()
            .unwrap(),
        if left { "first" } else { "second" }
    );
}

#[tokio::test]
async fn test_genesis_conflict_preserves_existing_canonical_key() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut socket).await;
        let body = r#"{"code":"genesis_already_initialized","epoch_id":"canonical"}"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    let storage = Arc::new(MockStorage::new());
    let client = client(storage.clone());
    let invitation = InvitationKeyPair::generate("losing-device".into()).unwrap();
    let group = Uuid::new_v4();
    let pending = client
        .load_or_create_pending_genesis(group, Uuid::new_v4(), &server_url, &invitation)
        .await
        .unwrap();
    {
        let mut state = client.state.write().await;
        Client::<MockStorage, MockNetwork>::upsert_epoch_state(
            &mut state,
            group,
            EpochState {
                group_id: Some(group),
                epoch_id: 1,
                encryption_key: [17; 32],
                key_source: EpochKeySource::Welcome,
                members: Vec::new(),
                created_at: Utc::now(),
                is_active: true,
                file_count: 0,
                marked_for_removal: false,
                removal_eligible_at: None,
            },
        );
    }
    Client::<MockStorage, MockNetwork>::submit_pending_genesis(
        &pending,
        "test-token",
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    server.await.unwrap();
    let state = client.state.read().await;
    assert_eq!(
        Client::<MockStorage, MockNetwork>::get_epoch_state(&state, group, 1)
            .unwrap()
            .encryption_key,
        [17; 32]
    );
    assert!(storage
        .load_config_fresh(&pending_key(
            &server_url,
            pending.user_id,
            &invitation.device_id,
            group
        ))
        .await
        .unwrap()
        .is_some());
}
