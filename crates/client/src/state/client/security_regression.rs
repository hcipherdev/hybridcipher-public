use super::*;
use crate::file::{
    content_manifest,
    encrypt::{encrypt_content_chunked, SparseExtent, SparseFileMetadata},
};
use hybridcipher_crypto::{
    kdf::{hkdf_expand, HkdfContext},
    AeadKey,
};

#[tokio::test]
async fn legacy_streaming_is_explicit_atomic_and_does_not_change_ciphertext() {
    use content_manifest::LegacyReadPolicy::{AllowLegacyUnverified, Strict};
    for (name, size) in [
        (
            "API_keys/claude  setting.json file using aws platform api.md",
            398,
        ),
        ("API_keys/github backup codes.md", 272),
    ] {
        for sparse in [false, true] {
            let plaintext = vec![42; size];
            let (client, metadata) = sized_fixture(2, sparse, name, &plaintext).await;
            let dir = tempfile::tempdir().unwrap();
            let encrypted = dir.path().join("fixture.encrypted");
            let output = dir.path().join("plaintext");
            let mut bytes = b"{}\n---ENCRYPTED_DATA---\n".to_vec();
            bytes.extend_from_slice(&metadata.encrypted_content);
            std::fs::write(&encrypted, &bytes).unwrap();
            let result = client
                .decrypt_file_streaming_to_path_with_policy(&encrypted, &metadata, &output, Strict)
                .await;
            assert!(matches!(
                result,
                Err(ClientError::LegacyCompatibilityRequired)
            ));
            assert!(!output.exists());
            client
                .decrypt_file_streaming_to_path_with_policy(
                    &encrypted,
                    &metadata,
                    &output,
                    AllowLegacyUnverified,
                )
                .await
                .unwrap();
            let mut expected = plaintext;
            if sparse {
                expected.resize(size * 2, 0);
            }
            assert_eq!(std::fs::read(&output).unwrap(), expected);
            assert_eq!(std::fs::read(&encrypted).unwrap(), bytes);
            *bytes.last_mut().unwrap() ^= 1;
            std::fs::write(&encrypted, &bytes).unwrap();
            assert!(matches!(
                client
                    .decrypt_file_streaming_to_path_with_policy(
                        &encrypted,
                        &metadata,
                        &output,
                        AllowLegacyUnverified
                    )
                    .await,
                Err(ClientError::FileIntegrity(_))
            ));
            assert_eq!(std::fs::read(&output).unwrap(), expected);
            assert_eq!(
                std::fs::read_dir(dir.path()).unwrap().count(),
                2,
                "failed temporary output must be removed"
            );
        }
    }
}

#[tokio::test]
async fn compatibility_never_bypasses_current_integrity_or_bad_legacy_wraps_and_layouts() {
    use content_manifest::LegacyReadPolicy::AllowLegacyUnverified;
    for version in [2, 3] {
        let (client, metadata) = fixture(version, true).await;
        let dir = tempfile::tempdir().unwrap();
        let encrypted = dir.path().join("fixture.encrypted");
        let output = dir.path().join("output");
        let mut bytes = b"{}\n---ENCRYPTED_DATA---\n".to_vec();
        bytes.extend_from_slice(&metadata.encrypted_content);
        std::fs::write(&encrypted, bytes).unwrap();
        let mut variants = Vec::new();
        let mut bad = metadata.clone();
        bad.wrapped_file_key.as_mut().unwrap()[0] ^= 1;
        variants.push(bad);
        let mut bad = metadata.clone();
        bad.sparse_metadata.as_mut().unwrap().extents[0].offset = u64::MAX;
        variants.push(bad);
        let mut bad = metadata.clone();
        bad.encrypted_size += 1;
        variants.push(bad);
        if version == 3 {
            let mut bad = metadata.clone();
            bad.header_version = Some(2);
            bad.key_wrap_aad_hash = None;
            variants.push(bad);
        }
        for bad in variants {
            assert!(client
                .decrypt_file_streaming_to_path_with_policy(
                    &encrypted,
                    &bad,
                    &output,
                    AllowLegacyUnverified
                )
                .await
                .is_err());
            assert!(!output.exists());
        }
    }
}

async fn fixture(
    version: u32,
    sparse: bool,
) -> (Client<MockStorage, MockNetwork>, EncryptedFileMetadata) {
    sized_fixture(version, sparse, "file.txt", b"ABCDEFGH").await
}

async fn sized_fixture(
    version: u32,
    sparse: bool,
    name: &str,
    plaintext: &[u8],
) -> (Client<MockStorage, MockNetwork>, EncryptedFileMetadata) {
    let mut config = ClientConfig::default();
    config.migration_automation_enabled = false;
    let client = Client::with_client_config(
        Ed25519KeyPair::generate(),
        Arc::new(MockStorage::new()),
        Arc::new(MockNetwork::new()),
        config,
    );
    let group = Uuid::new_v4();
    set_active_epoch(&client, group, 1).await;
    {
        let mut state = client.state.write().await;
        let epoch = &mut state.epochs.get_mut(&1).unwrap()[0];
        epoch.encryption_key = [42; 32];
        epoch.key_source = EpochKeySource::Welcome;
    }
    let key = AeadKey::from_bytes(&[17; 32]).unwrap();
    let kek = AeadKey::from_bytes(&hkdf_expand(&[42; 32], HkdfContext::KeyWrapping, 32).unwrap())
        .unwrap();
    let aad = client.build_wrap_aad("security-file", name, group, 1, version);
    let mut encrypted = Vec::new();
    encrypt_content_chunked(
        plaintext,
        &mut encrypted,
        &key,
        "security-file",
        &[9; 12],
        4,
    )
    .unwrap();
    let sparse_metadata = sparse.then(|| SparseFileMetadata {
        logical_size: plaintext.len() as u64 * 2,
        extents: vec![SparseExtent {
            offset: 0,
            length: plaintext.len() as u64,
        }],
    });
    let size = plaintext.len() as u64 * if sparse { 2 } else { 1 };
    let (wrapped, wrap_nonce) = if version == 3 {
        content_manifest::wrap(
            &key,
            &kek,
            &aad,
            &content_manifest::digest(
                size,
                encrypted.len() as u64,
                Some(4),
                &[9; 12],
                sparse_metadata.as_ref(),
            ),
        )
        .unwrap()
    } else {
        crate::file::encrypt::wrap_file_key(&key, &kek, &aad).unwrap()
    };
    let metadata = EncryptedFileMetadata {
        file_id: "security-file".into(),
        file_path: name.into(),
        group_id: Some(group),
        epoch_id: 1,
        header_version: Some(version),
        wrapped_file_key: Some(wrapped),
        key_wrap_nonce: Some(wrap_nonce),
        key_wrap_aad_hash: Some(hash_wrap_aad(&aad)),
        content_nonce: Some(vec![9; 12]),
        content_chunk_size: Some(4),
        content_size: size,
        encrypted_size: encrypted.len() as u64,
        created_at: Utc::now(),
        platform_metadata: None,
        sparse_metadata,
        encrypted_content: encrypted,
    };
    (client, metadata)
}

#[tokio::test]
async fn manifest_rejects_truncation_empty_payload_and_downgrade() {
    let (client, metadata) = fixture(3, false).await;
    assert_eq!(client.decrypt_file(&metadata).await.unwrap(), b"ABCDEFGH");
    for size in [0, 4] {
        let mut changed = metadata.clone();
        changed.content_size = size;
        changed.encrypted_size = if size == 0 { 0 } else { 20 };
        changed
            .encrypted_content
            .truncate(changed.encrypted_size as usize);
        assert!(client.decrypt_file(&changed).await.is_err());
        assert!(client
            .recover_legacy_file_unverified(&changed)
            .await
            .is_err());
    }
    let mut changed = metadata.clone();
    changed.header_version = Some(1);
    changed.content_chunk_size = None;
    changed.key_wrap_aad_hash = None;
    assert!(client.decrypt_file(&changed).await.is_err());
    let mut corrupt = metadata.clone();
    corrupt.encrypted_content[0] ^= 1;
    assert!(client.decrypt_file(&corrupt).await.is_err());
}

#[tokio::test]
async fn manifest_rejects_sparse_relocation_and_chunk_size_change() {
    let (client, mut metadata) = fixture(3, true).await;
    assert_eq!(
        &client.decrypt_file(&metadata).await.unwrap()[..8],
        b"ABCDEFGH"
    );
    metadata.sparse_metadata.as_mut().unwrap().extents[0].offset = 8;
    assert!(client.decrypt_file(&metadata).await.is_err());
    let (client, mut metadata) = fixture(3, false).await;
    metadata.content_chunk_size = Some(u64::MAX);
    assert!(client.decrypt_file(&metadata).await.is_err());
}

#[tokio::test]
async fn legacy_chunked_requires_explicit_recovery() {
    let (client, metadata) = fixture(2, false).await;
    assert!(client.decrypt_file(&metadata).await.is_err());
    assert_eq!(
        client
            .recover_legacy_file_unverified(&metadata)
            .await
            .unwrap(),
        b"ABCDEFGH"
    );
}

#[tokio::test]
async fn rewrapping_preserves_manifest_and_single_record_files_round_trip() {
    let (client, metadata) = fixture(3, false).await;
    let encrypted = client.encrypt_file("ordinary.txt", b"hello").await.unwrap();
    assert_eq!(encrypted.header_version, Some(3));
    assert_eq!(client.decrypt_file(&encrypted).await.unwrap(), b"hello");
    let key = AeadKey::from_bytes(&hkdf_expand(&[42; 32], HkdfContext::KeyWrapping, 32).unwrap())
        .unwrap();
    let aad = client.build_wrap_aad(
        &metadata.file_id,
        &metadata.file_path,
        metadata.group_id.unwrap(),
        1,
        3,
    );
    let nonce =
        hybridcipher_crypto::AeadNonce::from_bytes(metadata.key_wrap_nonce.as_ref().unwrap())
            .unwrap();
    let envelope = hybridcipher_crypto::open(
        &key,
        &nonce,
        hybridcipher_crypto::AeadContext::FileData,
        &aad,
        metadata.wrapped_file_key.as_ref().unwrap(),
    )
    .unwrap();
    let next = AeadKey::from_bytes(&[99; 32]).unwrap();
    let (wrapped, nonce) = content_manifest::rewrap(&envelope, &next, b"new epoch AAD").unwrap();
    let recovered = hybridcipher_crypto::open(
        &next,
        &hybridcipher_crypto::AeadNonce::from_bytes(&nonce).unwrap(),
        hybridcipher_crypto::AeadContext::FileData,
        b"new epoch AAD",
        &wrapped,
    )
    .unwrap();
    assert_eq!(envelope, recovered);
    assert!(content_manifest::verify(&metadata, &recovered, false).is_ok());
}

#[tokio::test]
async fn new_streamed_files_round_trip_and_failed_restore_keeps_output() {
    let (client, template) = fixture(3, false).await;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source.txt");
    let encrypted = root.path().join("source.encrypted");
    let output = root.path().join("restored.txt");
    for plaintext in [&b""[..], &b"ABCDEFGH"[..]] {
        std::fs::write(&source, plaintext).unwrap();
        let (metadata, _) = client
            .encrypt_file_streaming_with_id_to_path(
                "source.txt",
                &source,
                &encrypted,
                Some("source.txt"),
                None,
                &template.file_id,
                4,
            )
            .await
            .unwrap();
        client
            .decrypt_file_streaming_to_path(&encrypted, &metadata, &output)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), plaintext);
        let mut modified = metadata.clone();
        modified.content_size += 1;
        assert!(client
            .decrypt_file_streaming_to_path(&encrypted, &modified, &output)
            .await
            .is_err());
        assert_eq!(std::fs::read(&output).unwrap(), plaintext);
    }
}

#[tokio::test]
async fn current_chunked_files_decrypt_exact_authenticated_ranges() {
    let (client, template) = fixture(content_manifest::VERSION, false).await;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("range-source.bin");
    let encrypted = root.path().join("range-source.encrypted");
    const CHUNK_SIZE: usize = 4 * 1024 * 1024;
    let plaintext = (0..(CHUNK_SIZE * 2 + 4097))
        .map(|index| ((index * 31 + 17) % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &plaintext).unwrap();
    let (metadata, _) = client
        .encrypt_file_streaming_with_id_to_path(
            "range-source.bin",
            &source,
            &encrypted,
            Some("range-source.bin"),
            None,
            &template.file_id,
            CHUNK_SIZE,
        )
        .await
        .unwrap();

    let ranges = [
        (0usize, 1usize),
        (0, 4095),
        (0, 4096),
        (0, 4097),
        (CHUNK_SIZE - 1, 2),
        (CHUNK_SIZE, 4097),
        (CHUNK_SIZE * 2 - 2048, 4096),
        (plaintext.len() - 17, 17),
    ];
    for (offset, length) in ranges {
        let decrypted = client
            .decrypt_file_range(&encrypted, &metadata, offset as u64, length)
            .await
            .unwrap();
        assert_eq!(&decrypted[..], &plaintext[offset..offset + length]);
    }

    let mut corrupt = std::fs::read(&encrypted).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&encrypted, corrupt).unwrap();
    assert!(client
        .decrypt_file_range(&encrypted, &metadata, (plaintext.len() - 17) as u64, 17,)
        .await
        .is_err());
}
