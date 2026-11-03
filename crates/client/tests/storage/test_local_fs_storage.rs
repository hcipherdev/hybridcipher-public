// Tests LocalFsStorage in crates/client/src/storage/local_fs.rs: the shared per-folder file index (open_shared_file_index) and Windows-safe config file names (config_file_name, legacy reads).
use super::*;
use crate::coverage::{FileCoverageState, FileIndexEntry};
use chrono::Utc;
use tempfile::TempDir;

fn index_entry(root_id: Uuid, relative_path: &str) -> FileIndexEntry {
    FileIndexEntry {
        file_uuid: Uuid::new_v4(),
        file_id: None,
        root_id,
        relative_path: relative_path.to_string(),
        size: 1,
        last_epoch: 6,
        checksum_hint: None,
        last_seen: Utc::now(),
        state: FileCoverageState::Tracked,
        orphan_kind: None,
    }
}

#[tokio::test]
async fn storages_for_one_folder_share_its_file_index() {
    let temp_dir = TempDir::new().expect("temp dir");
    let first = LocalFsStorage::new(temp_dir.path());
    let second = LocalFsStorage::new(temp_dir.path());
    let root_id = Uuid::new_v4();

    first
        .store_file_index_entry(&index_entry(root_id, "a.txt.encrypted"))
        .await
        .expect("store through the first storage");

    let seen = second
        .list_file_index_entries_by_root(root_id)
        .await
        .expect("list through the second storage");
    assert_eq!(seen.len(), 1, "both storages must see the same index");
}

#[tokio::test]
async fn file_index_reopens_after_every_storage_is_dropped() {
    let temp_dir = TempDir::new().expect("temp dir");
    let root_id = Uuid::new_v4();
    {
        let storage = LocalFsStorage::new(temp_dir.path());
        storage
            .store_file_index_entries(&[index_entry(root_id, "a.txt.encrypted")])
            .await
            .expect("store entry");
    }

    let reopened = LocalFsStorage::new(temp_dir.path());
    let seen = reopened
        .list_file_index_entries_by_root(root_id)
        .await
        .expect("list after reopening");
    assert_eq!(seen.len(), 1, "entries must survive closing the index");
}

#[tokio::test]
async fn a_file_index_held_elsewhere_is_reported_not_replaced_by_an_empty_one() {
    let temp_dir = TempDir::new().expect("temp dir");
    // Another holder of the folder's lock, as the desktop app is for the CLI.
    let _holder = sled::Config::new()
        .path(temp_dir.path().join("file_index_db"))
        .open()
        .expect("hold the file index");

    let storage = LocalFsStorage::new(temp_dir.path());
    let result = storage
        .list_file_index_entries_by_root(Uuid::new_v4())
        .await;
    assert!(
        matches!(result, Err(StorageError::FileIndexUnavailable(_))),
        "expected FileIndexUnavailable, got {result:?}"
    );

    // Everything that is not the file index keeps working.
    storage
        .store_config("plain_key", "value")
        .await
        .expect("config writes still work");
}

#[tokio::test]
async fn config_keys_with_colons_use_windows_safe_file_names() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = LocalFsStorage::new(temp_dir.path());
    let key = "group_members_cache:0faad012-bc76-4383-ab76-a971ae88d17f";

    storage
        .store_config(key, "members")
        .await
        .expect("store config");

    assert!(temp_dir
        .path()
        .join("group_members_cache_0faad012-bc76-4383-ab76-a971ae88d17f.json")
        .is_file());
    let fresh = LocalFsStorage::new(temp_dir.path());
    assert_eq!(
        fresh
            .load_config(key)
            .await
            .expect("load config")
            .as_deref(),
        Some("members")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn config_written_under_a_legacy_name_still_loads_and_is_renamed_on_write() {
    let temp_dir = TempDir::new().expect("temp dir");
    let key = "group_members_cache:legacy";
    let legacy = temp_dir.path().join(format!("{key}.json"));
    std::fs::write(&legacy, "old members").expect("write legacy file");

    let storage = LocalFsStorage::new(temp_dir.path());
    assert_eq!(
        storage
            .load_config(key)
            .await
            .expect("load legacy")
            .as_deref(),
        Some("old members")
    );

    storage
        .store_config(key, "new members")
        .await
        .expect("rewrite");
    assert!(
        !legacy.exists(),
        "the legacy file is removed once rewritten"
    );
    assert!(temp_dir
        .path()
        .join("group_members_cache_legacy.json")
        .is_file());
}
