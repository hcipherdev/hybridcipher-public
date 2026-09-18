use super::*;
use crate::compatibility_fixtures::{client, fixture};

fn backup_path(policy: &VaultCompatibility, entry: &ProviderEntry, original: &[u8]) -> PathBuf {
    policy
        .status()
        .encrypted_backup_directory
        .join(format!(
            "{:x}",
            Sha256::digest(entry.identity.file_id.as_ref().unwrap().as_bytes())
        ))
        .join(format!("{:x}.encrypted", Sha256::digest(original)))
}

#[tokio::test]
async fn production_bridge_mixed_vault_consent_reads_and_saved_upgrades() {
    let dir = tempfile::tempdir().unwrap();
    let account = dir.path().join("account");
    let encrypted = dir.path().join("encrypted");
    fs::create_dir_all(&encrypted).unwrap();
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let client = client(&account, group).await;
    let policy = Arc::new(VaultCompatibility::load(&account, root).unwrap());
    let bridge = local_provider_bridge_with_compatibility(client.clone(), policy.clone());
    bridge
        .create_directory(root, &encrypted, "API_keys")
        .await
        .unwrap();
    for (name, size, version, sparse) in [
        (
            "API_keys/claude  setting.json file using aws platform api.md",
            398,
            2,
            false,
        ),
        ("API_keys/github backup codes.md", 272, 2, false),
        ("sparse.md", 80, 2, true),
        ("current.md", 192, 3, false),
    ] {
        fixture(&encrypted, name, size, version, sparse, group);
    }
    let entries = bridge.inventory(root, &encrypted).await.unwrap();
    assert_eq!(policy.status().legacy_file_count, 3);
    let output = dir.path().join("output");
    for entry in entries.iter().filter(|e| e.kind == ProviderEntryKind::File) {
        let original = fs::read(&entry.encrypted_path).unwrap();
        if entry.metadata.as_ref().unwrap().header_version == Some(2) {
            assert!(bridge
                .hydrate_file_to_path(entry, &output)
                .await
                .unwrap_err()
                .is_legacy_consent_required());
        } else {
            bridge.hydrate_file_to_path(entry, &output).await.unwrap();
        }
        assert_eq!(fs::read(&entry.encrypted_path).unwrap(), original);
    }
    assert!(!policy.status().encrypted_backup_directory.exists());
    assert_eq!(
        policy.status().last_read_error,
        Some(ProviderFileErrorCode::LegacyConsentRequired)
    );
    bridge.set_legacy_compatibility(true).unwrap();
    let restarted_policy = Arc::new(VaultCompatibility::load(&account, root).unwrap());
    assert!(restarted_policy.status().enabled);
    let bridge = local_provider_bridge_with_compatibility(client, restarted_policy.clone());
    for entry in entries.iter().filter(|e| e.kind == ProviderEntryKind::File) {
        let original = fs::read(&entry.encrypted_path).unwrap();
        bridge.hydrate_file_to_path(entry, &output).await.unwrap();
        let restored = fs::read(&output).unwrap();
        assert_eq!(
            restored.len() as u64,
            entry.metadata.as_ref().unwrap().content_size
        );
        assert_eq!(fs::read(&entry.encrypted_path).unwrap(), original);
    }
    assert!(
        !policy.status().encrypted_backup_directory.exists(),
        "read-only access never creates a backup or upgrade"
    );
    for (index, entry) in entries
        .iter()
        .filter(|e| {
            e.kind == ProviderEntryKind::File
                && e.metadata.as_ref().unwrap().header_version == Some(2)
        })
        .enumerate()
    {
        let original = fs::read(&entry.encrypted_path).unwrap();
        // A separately named editor temp file exercises the same checked replacement.
        let edited = dir.path().join(format!(".editor-save-{index}.tmp"));
        fs::write(&edited, b"intentional edit").unwrap();
        let expected = ExpectedProviderVersion::Exact(entry.content_version().unwrap());
        let changed = bridge
            .writeback_file_checked(
                root,
                &encrypted,
                &entry.relative_path,
                &edited,
                Some(&entry.identity),
                &expected,
            )
            .await
            .unwrap();
        assert_eq!(changed.metadata.as_ref().unwrap().header_version, Some(3));
        assert_eq!(
            fs::read(backup_path(&policy, entry, &original)).unwrap(),
            original
        );
        bridge
            .hydrate_file_to_path(&changed, &output)
            .await
            .unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"intentional edit");
        assert!(
            bridge
                .writeback_file_checked(
                    root,
                    &encrypted,
                    &entry.relative_path,
                    &edited,
                    Some(&entry.identity),
                    &expected
                )
                .await
                .is_err(),
            "stale content versions cannot overwrite a newer save"
        );
    }
    assert!(
        !VaultCompatibility::load(&account, Uuid::new_v4())
            .unwrap()
            .status()
            .enabled
    );
}

#[tokio::test]
async fn backup_failure_and_restart_after_backup_preserve_legacy_original() {
    let dir = tempfile::tempdir().unwrap();
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let account = dir.path().join("account");
    let encrypted = dir.path().join("encrypted");
    let client = client(&account, group).await;
    let policy = Arc::new(VaultCompatibility::load(&account, root).unwrap());
    policy.set_enabled(true).unwrap();
    let path = fixture(&encrypted, "legacy.md", 272, 2, false, group);
    let bridge = local_provider_bridge_with_compatibility(client.clone(), policy.clone());
    let entry = bridge
        .inventory(root, &encrypted)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.relative_path == "legacy.md")
        .unwrap();
    let original = fs::read(&path).unwrap();
    let backup = backup_path(&policy, &entry, &original);
    fs::create_dir_all(backup.parent().unwrap().parent().unwrap()).unwrap();
    fs::write(backup.parent().unwrap(), b"unavailable recovery directory").unwrap();
    let edit = dir.path().join("edit");
    fs::write(&edit, b"edit").unwrap();
    let expected = ExpectedProviderVersion::Exact(entry.content_version().unwrap());
    assert!(bridge
        .writeback_file_checked(
            root,
            &encrypted,
            &entry.relative_path,
            &edit,
            Some(&entry.identity),
            &expected
        )
        .await
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read(&edit).unwrap(), b"edit");
    fs::remove_file(backup.parent().unwrap()).unwrap();
    policy.preserve(root, &path).unwrap(); // Simulate a crash after backup, before replacement.
    drop(bridge);
    let reopened = Arc::new(VaultCompatibility::load(&account, root).unwrap());
    let bridge = local_provider_bridge_with_compatibility(client, reopened);
    bridge
        .writeback_file_checked(
            root,
            &encrypted,
            &entry.relative_path,
            &edit,
            Some(&entry.identity),
            &expected,
        )
        .await
        .unwrap();
    assert_eq!(fs::read(&backup).unwrap(), original);
    assert_eq!(fs::read_dir(backup.parent().unwrap()).unwrap().count(), 1);
}

#[tokio::test]
async fn rename_upgrade_preserves_ciphertext_and_rejects_conflicting_destination() {
    let dir = tempfile::tempdir().unwrap();
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let account = dir.path().join("account");
    let encrypted = dir.path().join("encrypted");
    let client = client(&account, group).await;
    let policy = Arc::new(VaultCompatibility::load(&account, root).unwrap());
    policy.set_enabled(true).unwrap();
    let path = fixture(&encrypted, "original.md", 272, 2, false, group);
    let original = fs::read(&path).unwrap();
    let bridge = local_provider_bridge_with_compatibility(client, policy.clone());
    let entry = bridge.inventory(root, &encrypted).await.unwrap().remove(0);
    let temporary = dir.path().join("authorized-plaintext");
    bridge
        .hydrate_file_to_path(&entry, &temporary)
        .await
        .unwrap();
    let expected = ExpectedProviderVersion::Exact(entry.content_version().unwrap());
    fixture(&encrypted, "occupied.md", 4, 3, false, group);
    assert!(bridge
        .rename_entry_checked(
            root,
            &encrypted,
            &entry.identity,
            "occupied.md",
            Some(&temporary),
            &expected
        )
        .await
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    let renamed = bridge
        .rename_entry_checked(
            root,
            &encrypted,
            &entry.identity,
            "renamed.md",
            Some(&temporary),
            &expected,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!path.exists());
    assert_eq!(renamed.metadata.as_ref().unwrap().header_version, Some(3));
    assert_eq!(
        fs::read(backup_path(&policy, &entry, &original)).unwrap(),
        original
    );
}

#[test]
fn partial_backup_disk_full_and_concurrent_change_never_publish_an_upgrade() {
    use std::io::{Read, Write};
    let dir = tempfile::tempdir().unwrap();
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let policy = VaultCompatibility::load(&dir.path().join("account"), root).unwrap();
    let path = fixture(
        &dir.path().join("encrypted"),
        "legacy.md",
        272,
        2,
        false,
        group,
    );
    let original = fs::read(&path).unwrap();
    let failure = policy.preserve_with_copy(root, &path, |input, output| {
        let mut first = [0; 64];
        input.read_exact(&mut first)?;
        output.write_all(&first)?;
        Err(std::io::Error::from_raw_os_error(112))
    });
    assert!(failure.is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    let object_dirs = fs::read_dir(policy.status().encrypted_backup_directory).unwrap();
    for object in object_dirs {
        assert_eq!(
            fs::read_dir(object.unwrap().path()).unwrap().count(),
            0,
            "partial backups must not be retained as complete archives"
        );
    }
    let preserved = policy.preserve(root, &path).unwrap().unwrap();
    let mut concurrent = original.clone();
    *concurrent.last_mut().unwrap() ^= 1;
    fs::write(&path, &concurrent).unwrap();
    assert!(preserved.verify_current().is_err());
    assert_eq!(
        fs::read(&path).unwrap(),
        concurrent,
        "concurrent source is never replaced"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn production_bridge_handles_long_protected_paths_and_backups() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("long-account-location".repeat(7));
    let account = nested.join("account");
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let client = client(&account, group).await;
    let encrypted = dir.path().join("encrypted");
    let path = fixture(&encrypted, "legacy.md", 398, 2, false, group);
    let original = fs::read(&path).unwrap();
    let policy = Arc::new(VaultCompatibility::load(&account, root).unwrap());
    policy.set_enabled(true).unwrap();
    let bridge = local_provider_bridge_with_compatibility(client, policy.clone());
    let entry = bridge.inventory(root, &encrypted).await.unwrap().remove(0);
    let output = nested.join("protected-cache").join(format!(
        ".hydrate-{}-{}.plain.tmp",
        root,
        Uuid::new_v4()
    ));
    assert!(output.as_os_str().len() > 260);
    bridge.hydrate_file_to_path(&entry, &output).await.unwrap();
    assert_eq!(fs::read(&output).unwrap(), vec![42; 398]);
    assert_eq!(fs::read(&path).unwrap(), original);
    let archived = policy.preserve(root, &path).unwrap().unwrap();
    archived.verify_current().unwrap();
    let backup = backup_path(&policy, &entry, &original);
    assert!(backup.as_os_str().len() > 260);
    assert_eq!(fs::read(backup).unwrap(), original);
}
