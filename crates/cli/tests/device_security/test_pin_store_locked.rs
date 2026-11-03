// Tests load_all_pinned_keys(), find_expired_pins() and prune_expired_pins() in src/commands/pin.rs: encrypted pins read without the account key are reported as locked and never deleted, and unreadable entries are kept.
use super::*;
use hybridcipher_client::storage::LocalFsStorage;
use hybridcipher_crypto::signatures::{Ed25519KeyPair, VerifyingKey};

const ACCOUNT_KEY: [u8; 32] = [5; 32];

async fn storage_with_one_pin(dir: &std::path::Path) -> UserStorage {
    let storage: UserStorage = Arc::new(LocalFsStorage::new(dir));
    storage.enable_account_encryption(ACCOUNT_KEY);
    let key = VerifyingKey::from_bytes(&Ed25519KeyPair::generate().public_key_bytes()).unwrap();
    PinningStore::new(storage.clone(), PinningConfig::default())
        .pin_key("user-xing", "device_97209c", &key, PinningMethod::Manual, None)
        .await
        .unwrap();
    storage
}

fn pin_files(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(PINNED_KEY_PREFIX))
        .count()
}

#[tokio::test]
async fn pins_read_without_the_key_are_locked_not_deleted() {
    let dir = tempfile::tempdir().unwrap();
    storage_with_one_pin(dir.path()).await;
    assert_eq!(pin_files(dir.path()), 1);

    // A process that never unlocked local state (as when the desktop starts the CLI).
    let locked: UserStorage = Arc::new(LocalFsStorage::new(dir.path()));
    let expiring = PinningConfig {
        max_pin_age_days: Some(1),
        ..PinningConfig::default()
    };
    assert!(matches!(
        load_all_pinned_keys(&locked, &PinningConfig::default()).await,
        Err(CliError::Decryption { .. })
    ));
    assert!(find_expired_pins(&locked, &expiring).await.is_err());
    assert!(prune_expired_pins(&locked, &expiring).await.is_err());
    assert_eq!(pin_files(dir.path()), 1, "the pin must still be on disk");

    // Once unlocked, the same pin reads normally.
    let unlocked: UserStorage = Arc::new(LocalFsStorage::new(dir.path()));
    unlocked.enable_account_encryption(ACCOUNT_KEY);
    let pins = load_all_pinned_keys(&unlocked, &PinningConfig::default())
        .await
        .unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].device_id, "device_97209c");
}

#[tokio::test]
async fn unreadable_entries_are_skipped_and_kept() {
    let dir = tempfile::tempdir().unwrap();
    let storage = storage_with_one_pin(dir.path()).await;
    std::fs::write(dir.path().join(format!("{PINNED_KEY_PREFIX}garbage.json")), "not json").unwrap();
    std::fs::write(dir.path().join(format!("{PINNED_KEY_PREFIX}empty.json")), "").unwrap();

    let pins = load_all_pinned_keys(&storage, &PinningConfig::default())
        .await
        .unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pin_files(dir.path()), 3, "nothing is deleted while reading");
}
