//! Synthetic ciphertext and isolated credentials for opt-in native verification.
use super::*;
use hybridcipher_client::{
    epoch_key_source::EpochKeySource,
    file::{content_manifest, encrypt::*},
    state::client::EpochState,
    storage::Storage,
    ClientConfig,
};
use hybridcipher_crypto::{
    kdf::{hkdf_expand, HkdfContext},
    signatures::Ed25519KeyPair,
    AeadKey,
};

pub async fn client(account: &Path, group: Uuid) -> Arc<LocalProviderClient> {
    let storage = Arc::new(LocalFsStorage::new(account));
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
    storage.store_config("client_state", &serde_json::json!({"epochs":{"1":[epoch]},"current_epoch":1,"active_group_id":group,"migration":null,"active_rekey":null,"last_sync":Utc::now(),"version":1,"group_memberships":{},"auth_credentials":null,"invitation_keypair":null}).to_string()).await.unwrap();
    let mut config = ClientConfig::default();
    config.migration_automation_enabled = false;
    let client = Arc::new(Client::with_client_config(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
        config,
    ));
    client.ensure_state_loaded().await.unwrap();
    client
}

pub fn fixture(
    root: &Path,
    name: &str,
    size: usize,
    version: u32,
    sparse: bool,
    group: Uuid,
) -> PathBuf {
    let id = format!("fixture-{}", Uuid::new_v4());
    let key = AeadKey::from_bytes(&[17; 32]).unwrap();
    let kek = AeadKey::from_bytes(&hkdf_expand(&[42; 32], HkdfContext::KeyWrapping, 32).unwrap())
        .unwrap();
    let nonce = [9; 12];
    let chunk = 128;
    let mut ciphertext = Vec::new();
    encrypt_content_chunked(
        &vec![42; size][..],
        &mut ciphertext,
        &key,
        &id,
        &nonce,
        chunk,
    )
    .unwrap();
    let logical_size = if sparse {
        size as u64 + 64
    } else {
        size as u64
    };
    let sparse_metadata = sparse.then(|| SparseFileMetadata {
        logical_size,
        extents: vec![SparseExtent {
            offset: 0,
            length: size as u64,
        }],
    });
    let aad = build_wrap_aad(&id, name, Some(group), 1, version);
    let (wrapped, wrap_nonce) = if version == 3 {
        content_manifest::wrap(
            &key,
            &kek,
            &aad,
            &content_manifest::digest(
                logical_size,
                ciphertext.len() as u64,
                Some(chunk as u64),
                &nonce,
                sparse_metadata.as_ref(),
            ),
        )
        .unwrap()
    } else {
        wrap_file_key(&key, &kek, &aad).unwrap()
    };
    let path =
        hybridcipher_mount_sync::encrypted_path_for(root, Path::new(""), Path::new(name)).unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    write_encrypted_file(
        &path,
        &SerializedEncryptedHeader {
            file_id: &id,
            file_path: name,
            group_id: Some(group),
            epoch_id: 1,
            header_version: version,
            wrapped_file_key: &wrapped,
            key_wrap_nonce: &wrap_nonce,
            key_wrap_aad_hash: &hash_wrap_aad(&aad),
            content_nonce: &nonce,
            content_chunk_size: Some(chunk as u64),
            original_size: logical_size,
            encrypted_size: ciphertext.len() as u64,
            encrypted_at: Utc::now(),
            original_name: Path::new(name).file_name().and_then(|s| s.to_str()),
            platform_metadata: None,
            sparse_metadata: sparse_metadata.as_ref(),
        },
        &ciphertext,
    )
    .unwrap();
    path
}
