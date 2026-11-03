// Tests load_or_create_device_keys_in(), load_saved_device_keys_in() and move_device_identity_aside() in src/client.rs: saved identities are reused, never silently replaced, and only moved aside on request.
use super::*;

fn file_bytes(dir: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(dir.join(INVITATION_KEYPAIR_FILE)).unwrap(),
        fs::read(dir.join(DEVICE_KEYPAIR_FILE)).unwrap(),
    )
}

fn no_keystore() -> Option<[u8; 32]> {
    None
}

fn message(err: DeviceIdentityError) -> (bool, String) {
    let unreadable = matches!(err, DeviceIdentityError::Unreadable(_));
    (unreadable, err.into())
}

#[test]
fn creates_identity_once_and_reuses_it() {
    let root = tempfile::tempdir().unwrap();
    let user_dir = root.path().join("user");
    let state_key = [7u8; 32];

    let Ok((created, _)) =
        load_or_create_device_keys_in(&user_dir, None, Some(&state_key), no_keystore)
    else {
        panic!("first sign-in must create an identity");
    };
    let Ok((reloaded, keystore_key)) =
        load_or_create_device_keys_in(&user_dir, None, Some(&state_key), no_keystore)
    else {
        panic!("saved identity must reload");
    };

    assert_eq!(created.device_id, reloaded.device_id);
    assert_eq!(created.identity_public, reloaded.identity_public);
    assert!(keystore_key.is_none());
}

#[test]
fn unreadable_identity_is_reported_and_left_untouched() {
    let root = tempfile::tempdir().unwrap();
    let user_dir = root.path().join("user");
    let Ok((original, _)) =
        load_or_create_device_keys_in(&user_dir, None, Some(&[7u8; 32]), no_keystore)
    else {
        panic!("identity must be created");
    };
    let before = file_bytes(&user_dir);

    let Err(err) = load_or_create_device_keys_in(
        &user_dir,
        Some(&[8u8; 32]),
        Some(&[9u8; 32]),
        || Some([10u8; 32]),
    ) else {
        panic!("unreadable identity must not be replaced");
    };

    let (unreadable, text) = message(err);
    assert!(unreadable);
    assert!(text.contains("could not be unlocked"), "{text}");
    assert_eq!(file_bytes(&user_dir), before);
    let Ok((recovered, _)) =
        load_or_create_device_keys_in(&user_dir, None, Some(&[7u8; 32]), no_keystore)
    else {
        panic!("the right key must still open the identity");
    };
    assert_eq!(recovered.device_id, original.device_id);
}

#[test]
fn keystore_state_key_opens_identity_the_folder_key_cannot() {
    let root = tempfile::tempdir().unwrap();
    let user_dir = root.path().join("user");
    let keystore_key = [7u8; 32];
    let Ok((original, _)) =
        load_or_create_device_keys_in(&user_dir, None, Some(&keystore_key), no_keystore)
    else {
        panic!("identity must be created");
    };

    let Ok(Some((loaded, used))) =
        load_saved_device_keys_in(&user_dir, None, Some(&[9u8; 32]), || Some(keystore_key))
    else {
        panic!("keystore key must open the identity");
    };

    assert_eq!(loaded.device_id, original.device_id);
    assert_eq!(used, Some(keystore_key));
}

#[test]
fn unsaved_new_identity_is_never_returned() {
    let root = tempfile::tempdir().unwrap();
    let blocked_dir = root.path().join("not-a-directory");
    fs::write(&blocked_dir, b"file in the way").unwrap();

    let Err(err) = load_or_create_device_keys_in(
        &blocked_dir.join("user"),
        None,
        Some(&[7u8; 32]),
        no_keystore,
    ) else {
        panic!("unsaved identity must not be returned");
    };

    let (unreadable, text) = message(err);
    assert!(!unreadable);
    assert!(text.contains("could not be saved"), "{text}");
}

#[test]
fn identity_is_moved_out_of_users_with_its_files() {
    let root = tempfile::tempdir().unwrap();
    let user_dir = root.path().join(USERS_DIR).join("70f3e0a9a9467a87");
    assert!(load_or_create_device_keys_in(&user_dir, None, Some(&[7u8; 32]), no_keystore).is_ok());
    let before = file_bytes(&user_dir);
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-14T12:30:05Z")
        .unwrap()
        .with_timezone(&Utc);

    let moved = move_device_identity_aside(&user_dir, now).unwrap();

    assert_eq!(
        moved,
        root.path()
            .join(REPLACED_IDENTITIES_DIR)
            .join("70f3e0a9a9467a87-20261014-123005")
    );
    assert!(!user_dir.exists());
    assert_eq!(file_bytes(&moved), before);
    assert!(load_or_create_device_keys_in(&user_dir, None, Some(&[7u8; 32]), no_keystore).is_ok());
    assert!(move_device_identity_aside(&user_dir, now).is_err());
}
