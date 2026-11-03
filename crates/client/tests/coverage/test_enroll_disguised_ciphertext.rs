// Tests that enroll_and_hydrate() and handle_new_file_event() judge files by their contents, not their `.encrypted` name, and never encrypt ciphertext twice.
use super::*;
use crate::file::encrypt::ENCRYPTED_FILE_SEPARATOR;
use crate::ipc::coverage_workflows::{enroll_and_hydrate, export_encrypted_file};
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;

async fn fixture() -> (tempfile::TempDir, Client<LocalFsStorage, MockNetwork>) {
    let dir = tempfile::tempdir().unwrap();
    let group = Uuid::new_v4();
    let storage = Arc::new(LocalFsStorage::new(dir.path().join("account")));
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
    storage
        .store_config(
            "client_state",
            &serde_json::json!({
                "epochs":{"1":[epoch]}, "current_epoch":1, "active_group_id":group,
                "migration":null,"active_rekey":null,"last_sync":Utc::now(),"version":1,
                "group_memberships":{},"auth_credentials":null,"invitation_keypair":null
            })
            .to_string(),
        )
        .await
        .unwrap();
    let client = Client::with_client_config(
        Ed25519KeyPair::generate(),
        storage,
        Arc::new(MockNetwork::new()),
        ClientConfig {
            migration_automation_enabled: false,
            coverage_watchers_enabled: false,
            ..ClientConfig::default()
        },
    );
    client.ensure_state_loaded().await.unwrap();
    (dir, client)
}

/// This group's ciphertext of `plaintext`, made by protecting a scratch folder.
async fn real_ciphertext(
    client: &Client<LocalFsStorage, MockNetwork>,
    base: &Path,
    plaintext: &[u8],
) -> Vec<u8> {
    let scratch = base.join(format!("scratch-{}", Uuid::new_v4()));
    fs::create_dir(&scratch).await.unwrap();
    fs::write(scratch.join("source.txt"), plaintext)
        .await
        .unwrap();
    enroll_and_hydrate(client, scratch.clone()).await.unwrap();
    fs::read(scratch.join("source.txt.encrypted"))
        .await
        .unwrap()
}

/// `bytes` with its JSON header changed by `edit`.
fn edit_header(bytes: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let split = bytes
        .windows(ENCRYPTED_FILE_SEPARATOR.len())
        .position(|window| window == ENCRYPTED_FILE_SEPARATOR)
        .unwrap();
    let mut header: Value = serde_json::from_slice(&bytes[..split]).unwrap();
    edit(&mut header);
    let mut edited = serde_json::to_vec(&header).unwrap();
    edited.extend_from_slice(&bytes[split..]);
    edited
}

async fn decrypts_to(
    client: &Client<LocalFsStorage, MockNetwork>,
    encrypted: &Path,
    expected: &[u8],
) {
    let output = encrypted.with_file_name(format!("check-{}", Uuid::new_v4()));
    export_encrypted_file(client, encrypted, &output)
        .await
        .unwrap();
    assert_eq!(fs::read(&output).await.unwrap(), expected);
    fs::remove_file(&output).await.unwrap();
}

/// The user's files in `folder`, without the client's own hidden root marker and temp folder.
fn names_in(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn ciphertext_under_a_plain_name_gets_its_name_back_instead_of_a_second_layer() {
    let (dir, client) = fixture().await;
    let base = std::fs::canonicalize(dir.path()).unwrap();
    let ciphertext = real_ciphertext(&client, &base, b"secret").await;

    let folder = base.join("folder");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("report.pdf"), &ciphertext)
        .await
        .unwrap();

    let outcome = enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    assert_eq!(outcome.hydration.already_encrypted_without_metadata, 1);
    assert_eq!(outcome.hydration.newly_encrypted, 0);
    // The rescan after hydration must agree and leave it alone.
    assert_eq!(names_in(&folder), ["report.pdf.encrypted"]);
    let adopted = folder.join("report.pdf.encrypted");
    assert_eq!(fs::read(&adopted).await.unwrap(), ciphertext);
    decrypts_to(&client, &adopted, b"secret").await;
}

#[tokio::test]
async fn plaintext_named_encrypted_is_protected() {
    let (dir, client) = fixture().await;
    let folder = std::fs::canonicalize(dir.path()).unwrap().join("folder");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("notes.txt.encrypted"), b"not secret at all")
        .await
        .unwrap();

    let outcome = enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    assert_eq!(outcome.hydration.newly_encrypted, 1);
    assert_eq!(outcome.hydration.already_encrypted_without_metadata, 0);
    assert_eq!(names_in(&folder), ["notes.txt.encrypted.encrypted"]);
    decrypts_to(
        &client,
        &folder.join("notes.txt.encrypted.encrypted"),
        b"not secret at all",
    )
    .await;
}

#[tokio::test]
async fn headers_that_cannot_be_checked_are_encrypted_anyway() {
    let (dir, client) = fixture().await;
    let base = std::fs::canonicalize(dir.path()).unwrap();
    let ciphertext = real_ciphertext(&client, &base, b"secret").await;

    // A forged key, another group's header, and a bare header over plaintext.
    let forged = edit_header(&ciphertext, |header| {
        let key = header["wrapped_file_key"].as_str().unwrap().to_string();
        header["wrapped_file_key"] = Value::from(key.replace(|c: char| c != '=', "A"));
    });
    let foreign = edit_header(&ciphertext, |header| {
        header["group_id"] = Value::from(Uuid::new_v4().to_string());
    });
    let mut bare = br#"{"file_id":"x","epoch_id":1}"#.to_vec();
    bare.extend_from_slice(ENCRYPTED_FILE_SEPARATOR);
    bare.extend_from_slice(b"plain words");

    let folder = base.join("folder");
    fs::create_dir(&folder).await.unwrap();
    for (name, bytes) in [
        ("forged.txt", &forged),
        ("foreign.txt", &foreign),
        ("bare.txt", &bare),
    ] {
        fs::write(folder.join(name), bytes).await.unwrap();
    }

    let outcome = enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    assert_eq!(outcome.hydration.newly_encrypted, 3);
    assert_eq!(outcome.hydration.already_encrypted_without_metadata, 0);
    let unchecked = outcome
        .hydration
        .warnings
        .iter()
        .filter(|warning| warning.contains("cannot be checked"))
        .count();
    assert_eq!(unchecked, 3, "{:?}", outcome.hydration.warnings);
    assert_eq!(
        names_in(&folder),
        [
            "bare.txt.encrypted",
            "foreign.txt.encrypted",
            "forged.txt.encrypted"
        ]
    );
    decrypts_to(&client, &folder.join("forged.txt.encrypted"), &forged).await;
    decrypts_to(&client, &folder.join("foreign.txt.encrypted"), &foreign).await;
    decrypts_to(&client, &folder.join("bare.txt.encrypted"), &bare).await;
}

#[tokio::test]
async fn adopting_never_replaces_an_existing_encrypted_name() {
    let (dir, client) = fixture().await;
    let base = std::fs::canonicalize(dir.path()).unwrap();
    let first = real_ciphertext(&client, &base, b"first").await;
    let second = real_ciphertext(&client, &base, b"second").await;

    let folder = base.join("folder");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("dup.txt"), &first).await.unwrap();
    fs::write(folder.join("dup.txt.encrypted"), &second)
        .await
        .unwrap();

    let outcome = enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    assert_eq!(outcome.hydration.newly_encrypted, 0);
    assert_eq!(outcome.hydration.already_encrypted_without_metadata, 2);
    assert!(
        outcome
            .hydration
            .warnings
            .iter()
            .any(|warning| warning.contains("exists, so it was left unchanged")),
        "{:?}",
        outcome.hydration.warnings
    );
    assert_eq!(names_in(&folder), ["dup.txt", "dup.txt.encrypted"]);
    assert_eq!(fs::read(folder.join("dup.txt")).await.unwrap(), first);
    assert_eq!(
        fs::read(folder.join("dup.txt.encrypted")).await.unwrap(),
        second
    );
}

#[tokio::test]
async fn the_watcher_renames_ciphertext_back_instead_of_encrypting_it() {
    let (dir, client) = fixture().await;
    let folder = std::fs::canonicalize(dir.path()).unwrap().join("folder");
    fs::create_dir(&folder).await.unwrap();
    fs::write(folder.join("note.txt"), b"secret").await.unwrap();
    let outcome = enroll_and_hydrate(&client, folder.clone()).await.unwrap();
    let encrypted = folder.join("note.txt.encrypted");
    let ciphertext = fs::read(&encrypted).await.unwrap();

    // Someone drops the suffix by hand.
    fs::rename(&encrypted, folder.join("note.txt"))
        .await
        .unwrap();
    client
        .handle_new_file_event(
            outcome.root.root_id,
            outcome.root.path.clone(),
            folder.join("note.txt"),
        )
        .await
        .unwrap();

    assert_eq!(names_in(&folder), ["note.txt.encrypted"]);
    assert_eq!(fs::read(&encrypted).await.unwrap(), ciphertext);

    // A new `.encrypted` file holding plaintext is protected all the same.
    let fake = folder.join("draft.txt.encrypted");
    fs::write(&fake, b"draft").await.unwrap();
    client
        .handle_new_file_event(outcome.root.root_id, outcome.root.path.clone(), fake)
        .await
        .unwrap();
    assert_eq!(
        names_in(&folder),
        ["draft.txt.encrypted.encrypted", "note.txt.encrypted"]
    );
    decrypts_to(
        &client,
        &folder.join("draft.txt.encrypted.encrypted"),
        b"draft",
    )
    .await;
}
