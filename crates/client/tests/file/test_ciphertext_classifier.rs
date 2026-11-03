// Tests classify(), classify_relative(), classify_name(), strip_encrypted_suffix(), inspect_bytes() and inspect_path() in src/file/ciphertext.rs.
use super::*;
use crate::file::encrypt::ENCRYPTED_FILE_SEPARATOR;

#[test]
fn folder_records_are_told_apart_from_files() {
    assert_eq!(
        classify(Path::new("/p/.code-butler/.hybridcipher_dir.encrypted")),
        CiphertextKind::FolderRecord
    );
    assert_eq!(
        classify_name(".HYBRIDCIPHER_DIR.encrypted"),
        CiphertextKind::FolderRecord
    );
    assert_eq!(
        classify(Path::new("/p/notes.txt.encrypted")),
        CiphertextKind::File
    );
    assert_eq!(
        classify(Path::new("/p/.code-butler")),
        CiphertextKind::NotEncrypted
    );
    // A file merely named like the record's folder name is ciphertext of a file.
    assert_eq!(
        classify_name(".hybridcipher_dir.txt.encrypted"),
        CiphertextKind::File
    );
}

#[test]
fn suffix_ignores_case_but_needs_a_name() {
    assert_eq!(classify_name("unknown.ENCRYPTED"), CiphertextKind::File);
    assert_eq!(classify_name(".encrypted"), CiphertextKind::NotEncrypted);
    assert_eq!(classify_name("encrypted"), CiphertextKind::NotEncrypted);
    assert_eq!(classify(Path::new("/")), CiphertextKind::NotEncrypted);
}

#[test]
fn relative_paths_use_their_last_component() {
    assert_eq!(
        classify_relative("a/b/.hybridcipher_dir.encrypted"),
        CiphertextKind::FolderRecord
    );
    assert_eq!(
        classify_relative("a\\b\\.hybridcipher_dir.encrypted"),
        CiphertextKind::FolderRecord
    );
    assert_eq!(
        classify_relative("a/b.encrypted/c.txt"),
        CiphertextKind::NotEncrypted
    );
    assert_eq!(classify_relative("doc.txt.encrypted"), CiphertextKind::File);
}

#[test]
fn strip_removes_exactly_one_suffix() {
    assert_eq!(strip_encrypted_suffix("a/b.txt.encrypted"), Some("a/b.txt"));
    assert_eq!(strip_encrypted_suffix("b.Encrypted"), Some("b"));
    assert_eq!(
        strip_encrypted_suffix("b.encrypted.encrypted"),
        Some("b.encrypted")
    );
    assert_eq!(strip_encrypted_suffix("b.txt"), None);
    assert_eq!(strip_encrypted_suffix(".encrypted"), None);
    // Multi-byte names never split inside a character.
    assert_eq!(strip_encrypted_suffix("éééééa"), None);
    assert_eq!(strip_encrypted_suffix("résumé.encrypted"), Some("résumé"));
}

fn header(file_size: u64) -> Value {
    serde_json::json!({
        "file_id": "f1",
        "epoch_id": 1,
        "group_id": "6f1c1f6e-2f63-4b8e-9d4a-1f2b3c4d5e6f",
        "header_version": 3,
        "file_size": file_size,
        "file_path": "note.txt",
        "wrapped_file_key": "AAAA",
        "key_wrap_nonce": "AAAA",
        "key_wrap_aad_hash": "AAAA",
        "content_nonce": "AAAA",
    })
}

fn file_with(header: &Value, body: &[u8]) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(header).unwrap();
    bytes.extend_from_slice(ENCRYPTED_FILE_SEPARATOR);
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn a_complete_header_with_matching_sizes_is_ciphertext() {
    // A single-record body is the content plus a 12-byte nonce and 16-byte tag.
    let bytes = file_with(&header(4), &[0; 32]);
    let ContentKind::Ciphertext(metadata) = inspect_bytes(&bytes) else {
        panic!("expected ciphertext");
    };
    assert_eq!(metadata.file_id, "f1");
    assert_eq!(metadata.encrypted_size, 32);
    assert!(metadata.encrypted_content.is_empty());

    // Pretty-printed headers, as rekeying writes them, are read the same way.
    let mut pretty = serde_json::to_vec_pretty(&header(4)).unwrap();
    pretty.extend_from_slice(ENCRYPTED_FILE_SEPARATOR);
    pretty.extend_from_slice(&[0; 32]);
    assert!(matches!(inspect_bytes(&pretty), ContentKind::Ciphertext(_)));
}

#[test]
fn a_header_whose_sizes_do_not_hold_up_is_damaged() {
    let truncated = file_with(&header(4), &[0; 31]);
    let ContentKind::Damaged(identity) = inspect_bytes(&truncated) else {
        panic!("expected damaged");
    };
    assert_eq!(identity.file_id, "f1");
    assert_eq!(identity.epoch_id, 1);
    assert!(identity.group_id.is_some());

    let mut missing_key = header(4);
    missing_key
        .as_object_mut()
        .unwrap()
        .remove("wrapped_file_key");
    assert!(matches!(
        inspect_bytes(&file_with(&missing_key, &[0; 32])),
        ContentKind::Damaged(_)
    ));
}

#[test]
fn anything_else_is_plaintext() {
    assert!(matches!(inspect_bytes(b""), ContentKind::NotCiphertext));
    assert!(matches!(
        inspect_bytes(b"hello"),
        ContentKind::NotCiphertext
    ));
    // JSON that is not a HybridCipher header.
    let other = file_with(&serde_json::json!({"name": "x"}), b"data");
    assert!(matches!(inspect_bytes(&other), ContentKind::NotCiphertext));
    // A separator later in a document does not make it ciphertext.
    let mut quoted = b"notes about files\n".to_vec();
    quoted.extend_from_slice(&file_with(&header(4), &[0; 32]));
    assert!(matches!(inspect_bytes(&quoted), ContentKind::NotCiphertext));
    // A header with no separator after it.
    let unterminated = serde_json::to_vec(&header(4)).unwrap();
    assert!(matches!(
        inspect_bytes(&unterminated),
        ContentKind::NotCiphertext
    ));
}

#[test]
fn inspecting_a_path_reads_the_same_answer_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.txt");
    std::fs::write(&real, file_with(&header(4), &[0; 32])).unwrap();
    assert!(matches!(
        inspect_path(&real).unwrap(),
        ContentKind::Ciphertext(_)
    ));

    let fake = dir.path().join("fake.txt.encrypted");
    std::fs::write(&fake, b"plain words").unwrap();
    assert!(matches!(
        inspect_path(&fake).unwrap(),
        ContentKind::NotCiphertext
    ));

    assert!(inspect_path(&dir.path().join("missing")).is_err());
}
