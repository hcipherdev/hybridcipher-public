use super::coverage_filesystem::PendingIndexEntry;
use super::*;
use crate::network::MockNetwork;
use crate::pinning::PinningMethod;
use crate::storage::{AccessControlData, LocalFsStorage, MockStorage, Storage};
use hybridcipher_crypto::signatures::VerifyingKey;
use tempfile::TempDir;

fn write_placeholder_encrypted_file(path: &Path) {
    let metadata = serde_json::json!({
        "file_id": "placeholder",
        "epoch_id": 1,
        "original_size": 1,
        "file_size": 1,
        "group_id": Uuid::nil().to_string(),
        "encrypted_at": Utc::now().to_rfc3339(),
        "file_path": "/placeholder",
    });
    let mut payload = serde_json::to_vec(&metadata).expect("serialize metadata");
    payload.extend_from_slice(ENCRYPTED_FILE_SEPARATOR);
    payload.extend_from_slice(b"x");
    std::fs::create_dir_all(path.parent().unwrap()).expect("create parent");
    std::fs::write(path, payload).expect("write encrypted file");
}

#[test]
fn file_exclusion_list_matches_obsidian_absolute_directory_and_file() {
    let exclusions = FileExclusionList::from_patterns(&[
        ".obsidian".to_string(),
        ".obsidian/**".to_string(),
        "**/.obsidian".to_string(),
        "**/.obsidian/**".to_string(),
    ]);

    let obsidian_dir = PathBuf::from(
        "/Users/test/Library/CloudStorage/Dropbox/Hybridcipher_development/.obsidian",
    );
    let obsidian_file = obsidian_dir.join("appearance.json");

    assert!(exclusions.matches(&obsidian_dir));
    assert!(exclusions.matches(&obsidian_file));
}

#[test]
fn file_exclusion_list_matches_target_absolute_file() {
    let exclusions =
        FileExclusionList::from_patterns(&["target/**".to_string(), "**/target/**".to_string()]);

    let target_file = PathBuf::from("/Users/test/project/target/debug/app");
    assert!(exclusions.matches(&target_file));
}

async fn set_active_epoch<S: Storage, N: Network>(
    client: &Client<S, N>,
    group_id: Uuid,
    epoch_id: u64,
) {
    let mut state = client.state.write().await;
    state.active_group_id = Some(group_id);
    state.current_epoch = epoch_id;
    let epoch_state = EpochState {
        group_id: Some(group_id),
        epoch_id,
        encryption_key: [0u8; 32],
        key_source: EpochKeySource::Placeholder,
        members: Vec::new(),
        created_at: Utc::now(),
        is_active: true,
        file_count: 0,
        marked_for_removal: false,
        removal_eligible_at: None,
    };
    state.epochs.insert(epoch_id, vec![epoch_state]);
}

#[tokio::test]
async fn test_client_creation() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());

    let client = Client::new(device_identity, storage.clone(), network);

    assert_eq!(client.current_epoch().await, 0);
    assert!(!client.is_migrating().await);
    assert!(client.migration_progress().await.is_none());
}

#[tokio::test]
async fn test_epoch_transition() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());

    let client = Client::new(device_identity, storage.clone(), network);

    let members = vec![GroupMember {
        member_id: [1u8; 32],
        public_key: [2u8; 32],
        capabilities: MemberCapabilities::default(),
        joined_at: Utc::now(),
    }];

    client.start_epoch_transition(members).await.unwrap();

    assert!(client.is_migrating().await);
    assert_eq!(client.migration_progress().await, Some(0.0));
}

#[tokio::test]
async fn save_client_state_persists_group_memberships() {
    let temp_dir = TempDir::new().expect("temp dir");
    let original_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", temp_dir.path());

    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    let membership = GroupMembership {
        group_id,
        group_name: "integration-test".to_string(),
        group_description: Some("state persistence".to_string()),
        user_role: GroupRole::Admin,
        joined_at: Utc::now(),
        current_epoch_id: None,
        last_sync: Utc::now(),
        members: vec![],
    };

    {
        let mut state = client.state.write().await;
        state.group_memberships.insert(group_id, membership);
    }

    client
        .save_client_state()
        .await
        .expect("client state saved");

    let client_state_path = temp_dir.path().join("client_state.json");
    assert!(
        client_state_path.exists(),
        "client_state.json should be written"
    );

    let contents = std::fs::read_to_string(&client_state_path).expect("read client state");
    let state_json: serde_json::Value = serde_json::from_str(&contents).expect("parse json");
    let groups = state_json["group_memberships"]
        .as_object()
        .expect("group memberships object");
    assert!(
        groups.contains_key(&group_id.to_string()),
        "client_state.json must include persisted membership"
    );

    if let Some(original) = original_home {
        std::env::set_var("HOME", original);
    } else {
        std::env::remove_var("HOME");
    }
}

#[tokio::test]
async fn recovery_self_welcome_uses_local_epoch_state() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let epoch_number = 1u64;
    let epoch_uuid = EpochIdMapper::u64_to_uuid(epoch_number, group_id.as_bytes());
    let encryption_key = [0xAAu8; 32];

    let capsule = RecoveryCapsulePlain {
        group_id,
        generated_at: Utc::now(),
        epochs: vec![RecoveryEpochSecret {
            epoch_number,
            epoch_uuid,
            created_at: Utc::now(),
            is_active: true,
            file_count: 0,
            encryption_key_b64: general_purpose::STANDARD.encode(encryption_key),
        }],
    };

    client
        .import_recovery_capsule(&capsule)
        .await
        .expect("import recovery capsule");

    let generated = client
        .generate_self_welcome_after_recovery(group_id, user_id)
        .await
        .expect("generate self welcome");

    assert_eq!(generated.recipient_user_id, user_id);
    assert_eq!(generated.device_id, client.local_device_id());
    assert!(!generated.encrypted_epoch_key.is_empty());
    assert!(!generated.signature.is_empty());
    assert!(
        generated
            .expires_at
            .map(|expires| expires > generated.created_at)
            .unwrap_or(false),
        "generated welcome should have a future expiration"
    );
}

#[tokio::test]
async fn single_group_membership_becomes_active() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    let group_info = ServerGroupInfo {
        id: group_id,
        name: "solo-group".to_string(),
        description: Some("only group".to_string()),
        current_epoch: None,
        user_role: ServerGroupRole::Member,
    };

    client
        .upsert_group_membership(&group_info, Some(99))
        .await
        .expect("membership inserted");

    {
        let state = client.state.read().await;
        assert_eq!(state.active_group_id, Some(group_id));
        assert_eq!(state.current_epoch, 99);
    }

    let cached_group = storage
        .load_config("group_id")
        .await
        .expect("load cached group");
    assert_eq!(cached_group, Some(group_id.to_string()));
}

#[tokio::test]
async fn test_state_validation() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());

    let client = Client::new(device_identity, storage, network);

    client.validate_state().await.unwrap();

    let members = vec![GroupMember {
        member_id: [1u8; 32],
        public_key: [2u8; 32],
        capabilities: MemberCapabilities::default(),
        joined_at: Utc::now(),
    }];

    client.start_epoch_transition(members).await.unwrap();
    client.validate_state().await.unwrap();
}

#[tokio::test]
async fn test_concurrent_access() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());

    let client = Arc::new(Client::new(device_identity, storage, network));

    let mut handles = Vec::new();

    for i in 0..10 {
        let client_clone = client.clone();
        let handle = tokio::spawn(async move {
            let epoch = client_clone.current_epoch().await;
            let migrating = client_clone.is_migrating().await;
            (i, epoch, migrating)
        });
        handles.push(handle);
    }

    for handle in handles {
        let (i, epoch, migrating) = handle.await.unwrap();
        assert_eq!(epoch, 0);
        assert!(!migrating);
        println!(
            "Task {} completed: epoch={}, migrating={}",
            i, epoch, migrating
        );
    }
}

#[tokio::test]
async fn verify_join_card_requires_pinning_before_welcome() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());
    let client = Client::new(device_identity, storage.clone(), network);

    let invitation = InvitationKeyPair::generate("device-a".to_string()).unwrap();
    let user_id = Uuid::new_v4();
    let join_card = invitation.create_join_card(user_id).unwrap();

    let result = client
        .verify_join_card_with_pinning(&join_card)
        .await
        .expect("pinning check");
    assert!(
        matches!(
            result,
            PinningVerificationResult::RequiresVerification { .. }
        ),
        "expected join card to require manual verification"
    );

    let verifying_key =
        VerifyingKey::from_bytes(&join_card.identity_public).expect("valid verifying key");
    client
        .pinning_manager
        .pin_key(
            &join_card.user_id.to_string(),
            &join_card.device_id,
            &verifying_key,
            PinningMethod::Manual,
            Some("test pin".to_string()),
        )
        .await
        .expect("pin key");

    let result = client
        .verify_join_card_with_pinning(&join_card)
        .await
        .expect("pinning check after pin");
    assert!(
        matches!(result, PinningVerificationResult::Verified),
        "expected join card to verify after pinning"
    );
}

#[tokio::test]
async fn verify_join_card_detects_key_mismatch() {
    let device_identity = Ed25519KeyPair::generate();
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());
    let client = Client::new(device_identity, storage.clone(), network);

    let invitation_one = InvitationKeyPair::generate("device-b".to_string()).unwrap();
    let invitation_two = InvitationKeyPair::generate("device-b".to_string()).unwrap();
    let user_id = Uuid::new_v4();
    let original_card = invitation_one.create_join_card(user_id).unwrap();
    let tampered_card = invitation_two.create_join_card(user_id).unwrap();

    let verifying_key =
        VerifyingKey::from_bytes(&original_card.identity_public).expect("valid verifying key");
    client
        .pinning_manager
        .pin_key(
            &original_card.user_id.to_string(),
            &original_card.device_id,
            &verifying_key,
            PinningMethod::Manual,
            None,
        )
        .await
        .expect("pin original key");

    let result = client
        .verify_join_card_with_pinning(&tampered_card)
        .await
        .expect("pinning check mismatch");

    assert!(
        matches!(result, PinningVerificationResult::KeyMismatch { .. }),
        "expected key mismatch when join card identity differs from pinned"
    );
}

#[tokio::test]
async fn coverage_rescan_populates_file_index() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    set_active_epoch(&client, group_id, 5).await;

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let file_path = root_path.join("report.txt");
    std::fs::write(&file_path, b"coverage").expect("write file");

    let canonical_root = root_path.canonicalize().expect("canonical root");
    let canonical_file = file_path.canonicalize().expect("canonical file");

    let metadata = FileMetadataData {
        file_path: canonical_file.to_string_lossy().to_string(),
        file_id: Some(canonical_file.to_string_lossy().to_string()),
        group_id: Some(group_id),
        epoch_id: 5,
        header_version: Some(1),
        wrapped_file_key: None,
        key_wrap_nonce: None,
        key_wrap_aad_hash: None,
        content_nonce: None,
        content_chunk_size: None,
        algorithm: "aes-gcm".to_string(),
        file_size: 8,
        modified_at: Utc::now(),
        integrity_hash: [0xAAu8; 32],
        permissions: AccessControlData {
            readers: vec![],
            writers: vec![],
            is_public: true,
        },
        version: 1,
        chunks: Vec::new(),
        encrypted_size: 8,
        encrypted_at: Utc::now(),
    };

    storage
        .store_file_metadata(&metadata.file_path, &metadata)
        .await
        .expect("store metadata");

    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    let summary = client.coverage_rescan(None).await.expect("rescan");
    assert_eq!(summary.roots_scanned, 1);
    assert_eq!(summary.files_indexed, 1);
    assert_eq!(summary.orphaned_files, 0);
    assert_eq!(summary.unmanaged_files, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert_eq!(entries.len(), 1);
    let indexed = entries.first().expect("indexed entry present");
    assert_eq!(indexed.last_epoch, metadata.epoch_id);
    assert_eq!(indexed.state, FileCoverageState::Tracked);
}

#[tokio::test]
async fn coverage_adopt_path_tracks_unmanaged_file() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    set_active_epoch(&client, group_id, 7).await;

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let file_path = root_path.join("notes.txt");
    std::fs::write(&file_path, b"notes").expect("write file");

    let canonical_root = root_path.canonicalize().expect("canonical root");
    let canonical_file = file_path.canonicalize().expect("canonical file");

    let metadata = FileMetadataData {
        file_path: canonical_file.to_string_lossy().to_string(),
        file_id: Some(canonical_file.to_string_lossy().to_string()),
        group_id: Some(group_id),
        epoch_id: 7,
        header_version: Some(1),
        wrapped_file_key: None,
        key_wrap_nonce: None,
        key_wrap_aad_hash: None,
        content_nonce: None,
        content_chunk_size: None,
        algorithm: "aes-gcm".to_string(),
        file_size: 5,
        modified_at: Utc::now(),
        integrity_hash: [0xBBu8; 32],
        permissions: AccessControlData {
            readers: vec![],
            writers: vec![],
            is_public: false,
        },
        version: 1,
        chunks: Vec::new(),
        encrypted_size: 5,
        encrypted_at: Utc::now(),
    };

    storage
        .store_file_metadata(&metadata.file_path, &metadata)
        .await
        .expect("store metadata");

    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    let result = client
        .coverage_adopt_path(&canonical_file)
        .await
        .expect("coverage adopt");

    assert_eq!(result.entry.last_epoch, metadata.epoch_id);
    assert_eq!(result.entry.size, metadata.file_size);
    assert_eq!(result.entry.state, FileCoverageState::Tracked);
    assert_eq!(result.root.path, canonical_root);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn coverage_rescan_marks_unmanaged_files_without_metadata() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    set_active_epoch(&client, group_id, 1).await;

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let file_path = root_path.join("draft.txt");
    std::fs::write(&file_path, b"in-flight draft").expect("write file");

    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    let summary = client.coverage_rescan(None).await.expect("rescan");
    assert_eq!(summary.roots_scanned, 1);
    assert_eq!(summary.files_indexed, 1);
    assert_eq!(summary.orphaned_files, 0);
    assert_eq!(summary.unmanaged_files, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    let entry = entries.first().expect("indexed entry present");
    assert_eq!(entry.state, FileCoverageState::Tracked);
    assert!(entry.orphan_kind.is_none());
}

#[tokio::test]
async fn coverage_rescan_marks_mismatched_metadata_as_orphaned() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    set_active_epoch(&client, group_id, 42).await;

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let file_path = root_path.join("stale.txt.encrypted");
    std::fs::write(&file_path, b"ciphertext placeholder").expect("write file");

    let canonical_root = root_path.canonicalize().expect("canonical root");
    let canonical_file = file_path.canonicalize().expect("canonical file");

    let metadata = FileMetadataData {
        file_path: canonical_file.to_string_lossy().to_string(),
        file_id: Some(canonical_file.to_string_lossy().to_string()),
        group_id: Some(group_id),
        epoch_id: 7,
        header_version: Some(1),
        wrapped_file_key: None,
        key_wrap_nonce: None,
        key_wrap_aad_hash: None,
        content_nonce: None,
        content_chunk_size: None,
        algorithm: "aes-gcm".to_string(),
        file_size: 20,
        modified_at: Utc::now(),
        integrity_hash: [0xCCu8; 32],
        permissions: AccessControlData {
            readers: vec![],
            writers: vec![],
            is_public: false,
        },
        version: 1,
        chunks: Vec::new(),
        encrypted_size: 20,
        encrypted_at: Utc::now(),
    };

    storage
        .store_file_metadata(&metadata.file_path, &metadata)
        .await
        .expect("store metadata");

    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    client.coverage_rescan(None).await.expect("rescan");

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    let entry = entries.first().expect("entry present");
    assert_eq!(entry.state, FileCoverageState::Orphaned);
    assert_eq!(entry.last_epoch, metadata.epoch_id);
}

#[tokio::test]
async fn coverage_rescan_preserves_tracked_encrypted_entries_without_metadata() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        state.active_group_id = Some(group_id);
    }

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let file_path = root_path.join("historical.txt.encrypted");
    std::fs::write(&file_path, b"ciphertext placeholder").expect("write file");

    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    let file_uuid = Uuid::new_v4();
    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid,
            file_id: None,
            root_id: root.root_id,
            relative_path: "historical.txt.encrypted".to_string(),
            size: 24,
            last_epoch: 42,
            checksum_hint: Some("abc123".to_string()),
            last_seen: Utc::now(),
            state: FileCoverageState::Tracked,
            orphan_kind: None,
        })
        .await
        .expect("store file index entry");

    let summary = client
        .coverage_rescan(Some(canonical_root.clone()))
        .await
        .expect("rescan");
    assert_eq!(summary.files_indexed, 1);
    assert_eq!(summary.unmanaged_files, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    let entry = entries
        .iter()
        .find(|entry| entry.relative_path == "historical.txt.encrypted")
        .expect("tracked entry");
    assert_eq!(entry.state, FileCoverageState::Tracked);
    assert_eq!(entry.last_epoch, 42);
}

#[tokio::test]
async fn coverage_rescan_ignores_directory_metadata_sidecars() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);
    let group_id = Uuid::new_v4();
    set_active_epoch(&client, group_id, 1).await;

    let root_path = temp_dir.path().join("workspace");
    let nested = root_path.join("folder").join("subfolder");
    std::fs::create_dir_all(&nested).expect("create nested folders");
    let sidecar_path = nested.join(".hybridcipher_dir.encrypted");
    write_placeholder_encrypted_file(&sidecar_path);

    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    let summary = client
        .coverage_rescan(Some(canonical_root.clone()))
        .await
        .expect("rescan");
    assert_eq!(summary.files_indexed, 0);
    assert_eq!(summary.orphaned_files, 0);
    assert_eq!(summary.unmanaged_files, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert!(entries.is_empty());
}

#[tokio::test]
async fn coverage_rescan_removes_stale_directory_metadata_sidecars_from_index() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);
    let group_id = Uuid::new_v4();
    set_active_epoch(&client, group_id, 1).await;

    let root_path = temp_dir.path().join("workspace");
    let nested = root_path.join("folder");
    std::fs::create_dir_all(&nested).expect("create nested folder");
    let sidecar_path = nested.join(".hybridcipher_dir.encrypted");
    write_placeholder_encrypted_file(&sidecar_path);

    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid: Uuid::new_v4(),
            file_id: Some("sidecar".to_string()),
            root_id: root.root_id,
            relative_path: "folder/.hybridcipher_dir.encrypted".to_string(),
            size: 748,
            last_epoch: 1,
            checksum_hint: None,
            last_seen: Utc::now(),
            state: FileCoverageState::Tracked,
            orphan_kind: None,
        })
        .await
        .expect("store stale sidecar entry");

    let summary = client
        .coverage_rescan(Some(canonical_root.clone()))
        .await
        .expect("rescan");
    assert_eq!(summary.files_indexed, 0);
    assert_eq!(summary.orphaned_files, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert!(entries.is_empty());
}

#[tokio::test]
async fn coverage_prune_orphans_removes_missing_entries() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        state.active_group_id = Some(group_id);
    }

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let placeholder = root_path.join("gone.txt.encrypted");
    write_placeholder_encrypted_file(&placeholder);
    std::fs::remove_file(&placeholder).expect("remove placeholder");
    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    let file_uuid = Uuid::new_v4();
    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid,
            file_id: None,
            root_id: root.root_id,
            relative_path: "gone.txt".to_string(),
            size: 10,
            last_epoch: 1,
            checksum_hint: None,
            last_seen: Utc::now(),
            state: FileCoverageState::Orphaned,
            orphan_kind: Some(FileOrphanKind::MissingFile),
        })
        .await
        .expect("store file index entry");

    let removed = client
        .coverage_prune_orphans(Some(canonical_root.clone()), false)
        .await
        .expect("prune orphans");
    assert_eq!(removed, 1);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert!(entries.is_empty());
}

#[tokio::test]
async fn coverage_prune_orphans_removes_directory_metadata_sidecars() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    set_active_epoch(&client, group_id, 1).await;

    let root_path = temp_dir.path().join("workspace");
    let nested = root_path.join("folder");
    std::fs::create_dir_all(&nested).expect("create folder");
    let sidecar_path = nested.join(".hybridcipher_dir.encrypted");
    write_placeholder_encrypted_file(&sidecar_path);
    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid: Uuid::new_v4(),
            file_id: Some("sidecar".to_string()),
            root_id: root.root_id,
            relative_path: "folder/.hybridcipher_dir.encrypted".to_string(),
            size: 748,
            last_epoch: 1,
            checksum_hint: None,
            last_seen: Utc::now(),
            state: FileCoverageState::Orphaned,
            orphan_kind: Some(FileOrphanKind::MissingFile),
        })
        .await
        .expect("store orphan sidecar entry");

    let removed = client
        .coverage_prune_orphans(Some(canonical_root.clone()), false)
        .await
        .expect("prune sidecar");
    assert_eq!(removed, 1);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert!(entries.is_empty());
}

#[tokio::test]
async fn ensure_state_loaded_refreshes_when_generation_changes() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage_a = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let storage_b = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network_a = Arc::new(MockNetwork::new());
    let network_b = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();

    let client_a = Client::new(device_identity.clone(), storage_a, network_a);
    let client_b = Client::new(device_identity, storage_b, network_b);

    let group_id = Uuid::new_v4();
    {
        let mut state = client_a.state.write().await;
        state.current_epoch = 1;
        state.active_group_id = Some(group_id);
    }
    client_a
        .save_client_state()
        .await
        .expect("save initial state");

    client_b
        .ensure_state_loaded()
        .await
        .expect("load shared state");

    let initial_generation = {
        let state = client_b.state.read().await;
        assert_eq!(state.active_group_id, Some(group_id));
        state.state_generation
    };
    assert!(initial_generation > 0);

    let updated_group_id = Uuid::new_v4();
    {
        let mut state = client_a.state.write().await;
        state.active_group_id = Some(updated_group_id);
    }
    client_a
        .save_client_state()
        .await
        .expect("persist pruned entries");

    client_b
        .ensure_state_loaded()
        .await
        .expect("reload stale client state");

    let state = client_b.state.read().await;
    assert_eq!(state.active_group_id, Some(updated_group_id));
    assert!(
        state.state_generation > initial_generation,
        "generation counter should advance after reload"
    );
}

#[tokio::test]
async fn coverage_prune_orphans_skips_existing_files() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        state.active_group_id = Some(group_id);
    }

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let encrypted_file = root_path.join("still_here.txt.encrypted");
    write_placeholder_encrypted_file(&encrypted_file);
    assert!(
        encrypted_file.exists(),
        "placeholder ciphertext should exist"
    );
    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    let file_uuid = Uuid::new_v4();
    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid,
            file_id: None,
            root_id: root.root_id,
            relative_path: "still_here.txt".to_string(),
            size: 5,
            last_epoch: 1,
            checksum_hint: None,
            last_seen: Utc::now(),
            state: FileCoverageState::Orphaned,
            orphan_kind: Some(FileOrphanKind::MissingFile),
        })
        .await
        .expect("store file index entry");

    let removed = client
        .coverage_prune_orphans(None, true)
        .await
        .expect("prune orphans");
    println!("removed {}", removed);
    assert_eq!(removed, 0, "removed {}", removed);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn coverage_prune_orphans_skips_excluded_paths() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let mut config = ClientConfig::default();
    config.excluded_file_patterns = vec!["skip-me.txt".to_string()];
    let client = Client::with_client_config(device_identity, storage.clone(), network, config);

    let group_id = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        state.active_group_id = Some(group_id);
    }

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid: Uuid::new_v4(),
            file_id: None,
            root_id: root.root_id,
            relative_path: "skip-me.txt".to_string(),
            size: 10,
            last_epoch: 1,
            checksum_hint: None,
            last_seen: Utc::now(),
            state: FileCoverageState::Orphaned,
            orphan_kind: Some(FileOrphanKind::MissingFile),
        })
        .await
        .expect("store file index entry");

    let removed = client
        .coverage_prune_orphans(None, true)
        .await
        .expect("prune excluded orphan");
    assert_eq!(removed, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn coverage_purge_outcasts_skips_excluded_paths() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let mut config = ClientConfig::default();
    config.excluded_file_patterns = vec!["skip-outcast.txt".to_string()];
    let client = Client::with_client_config(device_identity, storage.clone(), network, config);

    let group_id = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        state.active_group_id = Some(group_id);
    }

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid: Uuid::new_v4(),
            file_id: None,
            root_id: root.root_id,
            relative_path: "skip-outcast.txt".to_string(),
            size: 5,
            last_epoch: 1,
            checksum_hint: None,
            last_seen: Utc::now(),
            state: FileCoverageState::Orphaned,
            orphan_kind: Some(FileOrphanKind::Outcast),
        })
        .await
        .expect("store file index entry");

    let removed = client
        .coverage_purge_outcasts(None, None, true)
        .await
        .expect("purge outcasts");
    assert_eq!(removed, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn coverage_migrate_orphans_skips_excluded_paths() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let mut config = ClientConfig::default();
    config.excluded_file_patterns = vec!["skip-migrate.txt.encrypted".to_string()];
    let client = Client::with_client_config(device_identity, storage.clone(), network, config);

    let group_id = Uuid::new_v4();
    set_active_epoch(&client, group_id, 5).await;

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");
    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid: Uuid::new_v4(),
            file_id: None,
            root_id: root.root_id,
            relative_path: "skip-migrate.txt.encrypted".to_string(),
            size: 5,
            last_epoch: 1,
            checksum_hint: None,
            last_seen: Utc::now(),
            state: FileCoverageState::Orphaned,
            orphan_kind: Some(FileOrphanKind::WrongEpoch),
        })
        .await
        .expect("store file index entry");

    let migrated = client
        .coverage_migrate_orphans(None, None, true)
        .await
        .expect("migrate orphans");
    assert_eq!(migrated, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].state, FileCoverageState::Orphaned);
    assert_eq!(entries[0].orphan_kind, Some(FileOrphanKind::WrongEpoch));
}

#[tokio::test]
async fn rewrap_file_internal_rejects_excluded_paths() {
    let storage = Arc::new(MockStorage::new());
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let mut config = ClientConfig::default();
    config.excluded_file_patterns = vec!["skip-me.encrypted".to_string()];
    let client = Client::with_client_config(device_identity, storage, network, config);

    let result = client.rewrap_file_internal("skip-me.encrypted", 1, 2).await;
    assert!(matches!(result, Err(ClientError::PathExcluded(path)) if path == "skip-me.encrypted"));
}

#[test]
fn validate_encrypt_path_label_rejects_file_id_like_value() {
    let file_id_like = "d559b892864ac07562de8c25fb769f347229c5e3843052a6aca5e29c2b9762b6";
    let result = Client::<MockStorage, MockNetwork>::validate_encrypt_path_label(file_id_like);
    assert!(matches!(result, Err(ClientError::InvalidInput(_))));
}

#[test]
fn validate_encrypt_path_label_accepts_regular_path_label() {
    let result = Client::<MockStorage, MockNetwork>::validate_encrypt_path_label("folder/file.txt");
    assert!(result.is_ok());
}

#[tokio::test]
async fn persist_index_entries_treats_encrypted_suffix_as_same_file() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(LocalFsStorage::new(temp_dir.path()));
    let network = Arc::new(MockNetwork::new());
    let device_identity = Ed25519KeyPair::generate();
    let client = Client::new(device_identity, storage.clone(), network);

    let group_id = Uuid::new_v4();
    {
        let mut state = client.state.write().await;
        state.active_group_id = Some(group_id);
    }

    let root_path = temp_dir.path().join("workspace");
    std::fs::create_dir_all(&root_path).expect("create root");

    let canonical_root = root_path.canonicalize().expect("canonical root");
    let root = client
        .coverage_enroll_root(&canonical_root)
        .await
        .expect("enroll root");

    let file_uuid = Uuid::new_v4();
    storage
        .store_file_index_entry(&FileIndexEntry {
            file_uuid,
            file_id: None,
            root_id: root.root_id,
            relative_path: "notes.txt".to_string(),
            size: 1024,
            last_epoch: 5,
            checksum_hint: None,
            last_seen: Utc::now(),
            state: FileCoverageState::Tracked,
            orphan_kind: None,
        })
        .await
        .expect("store file index entry");

    let pending_entries = vec![PendingIndexEntry {
        relative_path: "notes.txt.encrypted".to_string(),
        size: 1024,
        last_epoch: 5,
        checksum_hint: Some("deadbeef".to_string()),
        last_seen: Utc::now(),
        state: FileCoverageState::Tracked,
        orphan_kind: None,
        file_id: None,
    }];

    let stats = client
        .persist_index_entries_for_root(root.clone(), pending_entries)
        .await
        .expect("persist");

    assert_eq!(stats.tracked, 1);
    assert_eq!(stats.orphaned, 0);

    let entries = storage
        .list_file_index_entries_by_root(root.root_id)
        .await
        .expect("list file index entries");
    assert_eq!(entries.len(), 1);
    let entry = entries.first().expect("entry");
    assert_eq!(entry.relative_path, "notes.txt.encrypted");
    assert_eq!(entry.state, FileCoverageState::Tracked);
    assert_eq!(entry.root_id, root.root_id);
}
