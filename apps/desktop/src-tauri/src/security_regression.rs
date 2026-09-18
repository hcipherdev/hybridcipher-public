//! Regression coverage for the decoder boundary used by the Windows provider.
use hybridcipher_client::file::{write_encrypted_file, SerializedEncryptedHeader};

#[test]
fn version_three_single_record_payload_is_read_and_restore_names_are_confined() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("fixture.encrypted");
    let header = SerializedEncryptedHeader {
        file_id: "fixture",
        file_path: "fixture.txt",
        group_id: None,
        epoch_id: 1,
        header_version: 3,
        wrapped_file_key: &[1; 80],
        key_wrap_nonce: &[2; 12],
        key_wrap_aad_hash: &[3; 32],
        content_nonce: &[4; 12],
        content_chunk_size: None,
        original_size: 4,
        encrypted_size: 4,
        encrypted_at: chrono::Utc::now(),
        original_name: Some("fixture.txt"),
        platform_metadata: None,
        sparse_metadata: None,
    };
    // Parser-only fixture: encryption/authentication is covered by client tests.
    write_encrypted_file(&path, &header, b"test").unwrap();
    let mut parsed = hybridcipher_mount_sync::parse_encrypted_file(&path).unwrap();
    assert_eq!(parsed.metadata.encrypted_content, b"test");
    assert_eq!(parsed.metadata.header_version, Some(3));
    assert!(hybridcipher_mount_sync::decrypted_target_path(
        root.path(),
        &path,
        root.path(),
        &parsed
    )
    .is_ok());
    parsed.original_name = Some("../escaped.txt".into());
    assert!(hybridcipher_mount_sync::decrypted_target_path(
        root.path(),
        &path,
        root.path(),
        &parsed
    )
    .is_err());
}
