// Tests merge_folder_list, merge_allowed, merge_belongs_to, status_of and MergeProgress::next_folder for moving a vault into an existing account (apps/desktop/src-tauri/src/commands/local_vault.rs).
use super::*;

fn record() -> LocalVaultRecord {
    LocalVaultRecord {
        storage_id: "local-0011223344556677".into(),
        group_id: Uuid::new_v4(),
        created_at: chrono::Utc::now(),
        kit_saved: true,
        upgrade: None,
        merge: None,
    }
}

fn progress(steps: &[MergeStep]) -> MergeProgress {
    MergeProgress {
        user_id: "user-1".into(),
        email: "owner@example.test".into(),
        server_url: "https://api.example.test".into(),
        target_group_id: Uuid::new_v4(),
        folders: steps
            .iter()
            .enumerate()
            .map(|(index, step)| MergeFolder {
                path: PathBuf::from(format!("/folders/{index}")),
                protected: true,
                step: *step,
            })
            .collect(),
    }
}

#[test]
fn a_move_in_progress_survives_a_restart() {
    let config = tempfile::tempdir().unwrap();
    let mut saved = record();
    saved.merge = Some(progress(&[MergeStep::Done, MergeStep::Moved]));
    vault::save_record(config.path(), &saved).unwrap();
    let loaded = vault::load_record(config.path()).unwrap().unwrap();
    let merge = loaded.merge.unwrap();
    assert_eq!(merge.folders, saved.merge.unwrap().folders);
    assert_eq!(merge.email, "owner@example.test");

    // Records written before moves existed still load.
    let older = serde_json::json!({
        "storage_id": "local-0011223344556677",
        "group_id": Uuid::new_v4(),
        "created_at": chrono::Utc::now(),
        "kit_saved": true,
    });
    std::fs::write(
        config.path().join("global/local_vault.json"),
        older.to_string(),
    )
    .unwrap();
    assert!(vault::load_record(config.path())
        .unwrap()
        .unwrap()
        .merge
        .is_none());
}

#[test]
fn a_resumed_move_continues_with_the_first_unfinished_folder() {
    assert_eq!(progress(&[]).next_folder(), None);
    assert_eq!(
        progress(&[MergeStep::Done, MergeStep::Moved, MergeStep::Pending]).next_folder(),
        Some(1)
    );
    assert_eq!(
        progress(&[MergeStep::Done, MergeStep::Done]).next_folder(),
        None
    );
    assert_eq!(
        progress(&[MergeStep::Pending, MergeStep::Done]).next_folder(),
        Some(0)
    );
}

#[test]
fn each_folder_is_listed_once_and_stays_protected_if_any_record_was() {
    let folders = merge_folder_list([
        (PathBuf::from("/a"), false),
        (PathBuf::from("/b"), false),
        (PathBuf::from("/a"), true),
    ]);
    assert_eq!(folders.len(), 2);
    assert_eq!(folders[0].path, PathBuf::from("/a"));
    assert!(folders[0].protected);
    assert!(
        !folders[1].protected,
        "a removed folder only moves its files"
    );
    assert!(folders
        .iter()
        .all(|folder| folder.step == MergeStep::Pending));
}

#[test]
fn only_a_present_vault_that_isnt_becoming_an_account_can_move() {
    let mut saved = record();
    assert!(merge_allowed(&saved, true));
    assert!(!merge_allowed(&saved, false), "its files are missing");
    saved.kit_saved = false;
    assert!(
        !merge_allowed(&saved, true),
        "without a saved kit it never protected anything"
    );
    saved.kit_saved = true;
    saved.upgrade = Some(UpgradeProgress {
        email: "new@example.test".into(),
        server_url: "https://api.example.test".into(),
        account_storage_id: "a1b2c3d4e5f60718".into(),
        phase: UpgradePhase::Registered,
    });
    assert!(
        !merge_allowed(&saved, true),
        "a new account is being created from it"
    );
}

#[test]
fn a_move_continues_only_under_the_account_that_started_it() {
    let merge = progress(&[MergeStep::Pending]);
    assert!(merge_belongs_to(
        &merge,
        "user-1",
        "https://api.example.test"
    ));
    assert!(!merge_belongs_to(
        &merge,
        "user-2",
        "https://api.example.test"
    ));
    assert!(!merge_belongs_to(
        &merge,
        "user-1",
        "https://other.example.test"
    ));
    assert!(merge_pending_message(&merge).contains("owner@example.test"));
}

#[test]
fn status_names_the_account_a_vault_is_moving_into() {
    let mut saved = record();
    assert_eq!(status_of(Some(&saved), false).merge_email, None);
    saved.merge = Some(progress(&[MergeStep::Pending]));
    let status = status_of(Some(&saved), false);
    assert_eq!(status.merge_email.as_deref(), Some("owner@example.test"));
    assert!(!status.active);
    assert!(!status.can_merge, "only a signed-in status offers the move");
}
