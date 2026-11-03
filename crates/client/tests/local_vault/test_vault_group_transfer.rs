// Tests Client::transfer_folder_to_group, current_group_transfer_key and file::group_transfer::transfer_file_to_group, which move a local vault's files into an account group, and Client::local_vault_folders_in_use, which decides whether a vault can be replaced.
use super::*;
use crate::ipc::coverage_workflows::{enroll_and_hydrate, unenroll_and_decrypt};
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

type TestClient = Client<LocalFsStorage, MockNetwork>;
const ACCOUNT_EPOCH: u64 = 3;
const SEPARATOR: &[u8] = b"\n---ENCRYPTED_DATA---\n";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: TestClient,
    account: TestClient,
    vault_group: Uuid,
    personal: Uuid,
    folder: PathBuf,
}

fn new_client(storage: PathBuf) -> TestClient {
    let mut config = ClientConfig {
        migration_automation_enabled: false,
        coverage_watchers_enabled: false,
        ..ClientConfig::default()
    };
    // Keep the defaults, which exclude the folder's own coverage marker.
    config.excluded_file_patterns.push("*.skip".into());
    Client::with_client_config(
        Ed25519KeyPair::generate(),
        Arc::new(LocalFsStorage::new(storage)),
        Arc::new(MockNetwork::new()),
        config,
    )
}

/// A vault that protected `files`, and an account whose Personal group is at a
/// later epoch with an account-confirmed key.
async fn fixture(files: &[(&str, Vec<u8>)]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_client(dir.path().join("vault"));
    vault.set_local_only(true);
    let vault_group = vault.create_local_vault().await.unwrap().group_id;

    let account = new_client(dir.path().join("account"));
    account.ensure_state_loaded().await.unwrap();
    let personal = Uuid::new_v4();
    {
        let mut state = account.state.write().await;
        TestClient::upsert_epoch_state(
            &mut state,
            personal,
            EpochState {
                group_id: Some(personal),
                epoch_id: ACCOUNT_EPOCH,
                encryption_key: [42; 32],
                key_source: EpochKeySource::Welcome,
                members: vec![],
                created_at: Utc::now(),
                is_active: true,
                file_count: 0,
                marked_for_removal: false,
                removal_eligible_at: None,
            },
        );
        state.group_memberships.insert(
            personal,
            GroupMembership {
                group_id: personal,
                group_name: "Personal".into(),
                group_description: None,
                user_role: GroupRole::Admin,
                joined_at: Utc::now(),
                current_epoch_id: Some(ACCOUNT_EPOCH),
                last_sync: Utc::now(),
                members: Vec::new(),
            },
        );
        state.active_group_id = Some(personal);
        state.current_epoch = ACCOUNT_EPOCH;
    }

    let folder = dir.path().join("protected");
    tokio::fs::create_dir_all(&folder).await.unwrap();
    for (name, contents) in files {
        let path = folder.join(name);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, contents).await.unwrap();
    }
    enroll_and_hydrate(&vault, folder.clone()).await.unwrap();
    Fixture {
        _dir: dir,
        vault,
        account,
        vault_group,
        personal,
        folder,
    }
}

async fn keys(fx: &Fixture) -> (GroupEpochKey, GroupEpochKey) {
    (
        fx.vault
            .local_vault_transfer_key(fx.vault_group)
            .await
            .unwrap(),
        fx.account
            .current_group_transfer_key(fx.personal)
            .await
            .unwrap(),
    )
}

fn split(path: &Path) -> (serde_json::Value, Vec<u8>) {
    let bytes = std::fs::read(path).unwrap();
    let at = bytes
        .windows(SEPARATOR.len())
        .position(|window| window == SEPARATOR)
        .unwrap();
    (
        serde_json::from_slice(&bytes[..at]).unwrap(),
        bytes[at + SEPARATOR.len()..].to_vec(),
    )
}

/// Hand a moved folder from the vault to the account, in the merge's order: the
/// folder registry is shared by every storage on the machine, so the vault must
/// give the folder up before the account can protect it.
async fn enroll_in_account(fx: &Fixture) -> TestClient {
    fx.vault.coverage_unenroll_root(&fx.folder).await.unwrap();
    let account = fx.account.for_local_group(fx.personal);
    enroll_and_hydrate(&account, fx.folder.clone())
        .await
        .unwrap();
    account
}

/// Readable test data that differs across a large file.
fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index * 31 % 251) as u8).collect()
}

#[tokio::test]
async fn vault_files_open_in_the_account_after_moving() {
    let fx = fixture(&[
        ("notes.txt", b"private notes".to_vec()),
        ("sub/photo.bin", patterned(4096)),
    ])
    .await;
    let notes = fx.folder.join("notes.txt.encrypted");
    let (header_before, body_before) = split(&notes);
    assert_eq!(header_before["group_id"], fx.vault_group.to_string());
    let modified_before = std::fs::metadata(&notes).unwrap().modified().unwrap();

    let (from, to) = keys(&fx).await;
    assert_eq!(to.epoch_id, ACCOUNT_EPOCH);
    let progress = fx
        .account
        .transfer_folder_to_group(&fx.folder, from, to, |_| {})
        .await
        .unwrap();
    assert_eq!(progress.moved_files, 2);
    assert_eq!(progress.processed_files, progress.total_files);

    let (header_after, body_after) = split(&notes);
    assert_eq!(header_after["group_id"], fx.personal.to_string());
    assert_eq!(header_after["epoch_id"], ACCOUNT_EPOCH);
    assert_eq!(header_after["file_id"], header_before["file_id"]);
    assert_eq!(body_after, body_before, "contents must not be re-encrypted");
    assert_eq!(
        std::fs::metadata(&notes).unwrap().modified().unwrap(),
        modified_before
    );

    fx.account
        .coverage_assert_folder_owned_by(&fx.folder, fx.personal)
        .await
        .unwrap();
    let account = enroll_in_account(&fx).await;
    let removed = unenroll_and_decrypt(&account, fx.folder.clone())
        .await
        .unwrap();
    assert_eq!(removed.decrypted_files, 2);
    assert_eq!(
        tokio::fs::read(fx.folder.join("notes.txt")).await.unwrap(),
        b"private notes"
    );
    assert_eq!(
        tokio::fs::read(fx.folder.join("sub/photo.bin"))
            .await
            .unwrap(),
        patterned(4096)
    );
}

#[tokio::test]
async fn a_file_larger_than_the_copy_buffer_moves_intact() {
    let large = patterned(3 * 1024 * 1024 + 17);
    let fx = fixture(&[("large.bin", large.clone())]).await;
    let (from, to) = keys(&fx).await;
    let (_, body_before) = split(&fx.folder.join("large.bin.encrypted"));
    fx.account
        .transfer_folder_to_group(&fx.folder, from, to, |_| {})
        .await
        .unwrap();
    let (_, body_after) = split(&fx.folder.join("large.bin.encrypted"));
    assert_eq!(body_after, body_before);

    let account = enroll_in_account(&fx).await;
    unenroll_and_decrypt(&account, fx.folder.clone())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(fx.folder.join("large.bin")).await.unwrap(),
        large
    );
}

#[tokio::test]
async fn a_second_run_moves_nothing_and_removes_unfinished_copies() {
    let fx = fixture(&[("a.txt", b"one".to_vec())]).await;
    let (from, to) = keys(&fx).await;
    let encrypted = fx.folder.join("a.txt.encrypted");
    fx.account
        .transfer_folder_to_group(&fx.folder, from.clone(), to.clone(), |_| {})
        .await
        .unwrap();
    let moved = std::fs::read(&encrypted).unwrap();
    let unfinished = fx
        .folder
        .join(format!(".a.txt.encrypted{TRANSFER_TEMP_SUFFIX}"));
    tokio::fs::write(&unfinished, b"half written")
        .await
        .unwrap();

    let again = fx
        .account
        .transfer_folder_to_group(&fx.folder, from.clone(), to.clone(), |_| {})
        .await
        .unwrap();
    assert_eq!(again.moved_files, 0);
    assert!(!unfinished.exists());
    assert_eq!(std::fs::read(&encrypted).unwrap(), moved);
    assert_eq!(
        transfer_file_to_group(&encrypted, &from, &to).unwrap(),
        GroupTransferOutcome::AlreadyInTarget
    );
}

#[tokio::test]
async fn a_file_from_another_workspace_stops_the_move_untouched() {
    let fx = fixture(&[("a.txt", b"one".to_vec())]).await;
    let (_, to) = keys(&fx).await;
    let encrypted = fx.folder.join("a.txt.encrypted");
    let before = std::fs::read(&encrypted).unwrap();
    // The file belongs to the vault, which is neither side of this move.
    let elsewhere = GroupEpochKey {
        group_id: Uuid::new_v4(),
        epoch_id: 1,
        key: Zeroizing::new([9; 32]),
    };
    let error = fx
        .account
        .transfer_folder_to_group(&fx.folder, elsewhere, to, |_| {})
        .await
        .unwrap_err();
    assert!(error.to_string().contains("another workspace"), "{error}");
    assert_eq!(std::fs::read(&encrypted).unwrap(), before);
}

#[tokio::test]
async fn a_changed_header_or_wrong_key_is_refused_untouched() {
    let fx = fixture(&[("a.txt", b"one".to_vec()), ("b.txt", b"two".to_vec())]).await;
    let (from, to) = keys(&fx).await;

    let tampered = fx.folder.join("a.txt.encrypted");
    let (mut header, body) = split(&tampered);
    header["file_path"] = "renamed.txt".into();
    let mut bytes = serde_json::to_vec(&header).unwrap();
    bytes.extend_from_slice(SEPARATOR);
    bytes.extend_from_slice(&body);
    std::fs::write(&tampered, &bytes).unwrap();
    let error = transfer_file_to_group(&tampered, &from, &to).unwrap_err();
    assert!(matches!(error, ClientError::FileIntegrity(_)), "{error}");
    assert_eq!(std::fs::read(&tampered).unwrap(), bytes);

    let other = fx.folder.join("b.txt.encrypted");
    let before = std::fs::read(&other).unwrap();
    let wrong = GroupEpochKey {
        key: Zeroizing::new([1; 32]),
        ..from
    };
    let error = transfer_file_to_group(&other, &wrong, &to).unwrap_err();
    assert!(matches!(error, ClientError::DecryptionError(_)), "{error}");
    assert_eq!(std::fs::read(&other).unwrap(), before);
}

#[tokio::test]
async fn the_ownership_check_fails_while_one_vault_file_remains() {
    let fx = fixture(&[("a.txt", b"one".to_vec()), ("b.txt", b"two".to_vec())]).await;
    let (from, to) = keys(&fx).await;
    transfer_file_to_group(&fx.folder.join("a.txt.encrypted"), &from, &to).unwrap();
    let error = fx
        .account
        .coverage_assert_folder_owned_by(&fx.folder, fx.personal)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("b.txt.encrypted"), "{error}");

    fx.account
        .transfer_folder_to_group(&fx.folder, from, to, |_| {})
        .await
        .unwrap();
    fx.account
        .coverage_assert_folder_owned_by(&fx.folder, fx.personal)
        .await
        .unwrap();
}

#[tokio::test]
async fn excluded_paths_are_left_alone() {
    let fx = fixture(&[("a.txt", b"one".to_vec())]).await;
    let (from, to) = keys(&fx).await;
    let excluded = fx.folder.join("copy.skip");
    std::fs::copy(fx.folder.join("a.txt.encrypted"), &excluded).unwrap();
    let progress = fx
        .account
        .transfer_folder_to_group(&fx.folder, from, to, |_| {})
        .await
        .unwrap();
    assert_eq!(progress.moved_files, 1);
    assert_eq!(split(&excluded).0["group_id"], fx.vault_group.to_string());
}

#[tokio::test]
async fn only_an_account_confirmed_current_key_can_be_a_target() {
    let fx = fixture(&[]).await;
    assert!(fx
        .vault
        .current_group_transfer_key(fx.vault_group)
        .await
        .is_err());
    assert!(fx
        .account
        .current_group_transfer_key(Uuid::new_v4())
        .await
        .is_err());
    fx.account.state.write().await.active_rekey = Some(ActiveRekeyOperation {
        rekey_id: Uuid::new_v4(),
        group_id: fx.personal,
        new_epoch_id: None,
        new_epoch_label: String::new(),
        status: RekeyStatus::InProgress,
        started_at: Utc::now(),
        last_updated: Utc::now(),
        estimated_completion: None,
        can_cutover: false,
        progress: RekeyProgress {
            total_files: 0,
            migrated_files: 0,
            total_members: 1,
            confirmed_members: 0,
            reporting_members: 0,
            estimated_time_remaining_minutes: None,
        },
        policy: None,
        errors: Vec::new(),
        descriptor_commitment: None,
        suppress_local_override: false,
    });
    let error = fx
        .account
        .current_group_transfer_key(fx.personal)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("changing its keys"), "{error}");
}

#[tokio::test]
async fn a_vault_that_never_protected_a_folder_has_none_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_client(dir.path().join("vault"));
    vault.set_local_only(true);
    let group = vault.create_local_vault().await.unwrap().group_id;
    assert!(vault.local_vault_folders_in_use(group).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_folder_is_in_use_until_its_vault_files_are_decrypted() {
    let fx = fixture(&[("a.txt", b"one".to_vec())]).await;
    let folder = tokio::fs::canonicalize(&fx.folder).await.unwrap();
    let in_use = fx.vault.local_vault_folders_in_use(fx.vault_group).await.unwrap();
    assert_eq!(in_use, vec![folder.clone()], "a protected folder");

    // Unprotected but still encrypted: the files still need the vault's key.
    fx.vault.coverage_unenroll_root(&fx.folder).await.unwrap();
    let in_use = fx.vault.local_vault_folders_in_use(fx.vault_group).await.unwrap();
    assert_eq!(in_use, vec![folder.clone()], "files left encrypted");

    enroll_and_hydrate(&fx.vault, fx.folder.clone()).await.unwrap();
    unenroll_and_decrypt(&fx.vault, fx.folder.clone()).await.unwrap();
    assert!(fx.vault.local_vault_folders_in_use(fx.vault_group).await.unwrap().is_empty());
}

#[tokio::test]
async fn files_moved_to_another_group_do_not_keep_the_vault_in_use() {
    let fx = fixture(&[("a.txt", b"one".to_vec())]).await;
    let (from, to) = keys(&fx).await;
    fx.vault
        .transfer_folder_to_group(&fx.folder, from, to, |_| {})
        .await
        .unwrap();
    fx.vault.coverage_unenroll_root(&fx.folder).await.unwrap();
    assert!(fx.vault.local_vault_folders_in_use(fx.vault_group).await.unwrap().is_empty());
}
