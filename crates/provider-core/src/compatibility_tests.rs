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

#[tokio::test]
async fn provider_hydration_rejects_truncation_forged_sizes_and_sparse_relocation() {
    let dir = tempfile::tempdir().unwrap();
    let account = dir.path().join("account");
    let encrypted = dir.path().join("encrypted");
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let client = client(&account, group).await;
    let bridge = local_provider_bridge(client);
    let path = fixture(&encrypted, "current.md", 256, 3, false, group);
    let original = fs::read(&path).unwrap();
    let entry = bridge.inventory(root, &encrypted).await.unwrap().remove(0);
    let output = dir.path().join("hydrated.txt");
    bridge.hydrate_file_to_path(&entry, &output).await.unwrap();
    assert_eq!(fs::read(&output).unwrap(), vec![42; 256]);

    let mut truncated = original.clone();
    truncated.truncate(truncated.len() - 144);
    fs::write(&path, &truncated).unwrap();
    assert!(bridge.hydrate_file_to_path(&entry, &output).await.is_err());
    assert_eq!(fs::read(&output).unwrap(), vec![42; 256]);
    fs::write(&path, &original).unwrap();

    let mut forged = entry.clone();
    forged.metadata.as_mut().unwrap().content_size = 128;
    forged.metadata.as_mut().unwrap().encrypted_size = 144;
    assert!(bridge.hydrate_file_to_path(&forged, &output).await.is_err());
    assert_eq!(fs::read(&output).unwrap(), vec![42; 256]);

    let mut huge_chunk = entry.clone();
    huge_chunk.metadata.as_mut().unwrap().content_chunk_size =
        Some(hybridcipher_client::file::encrypt::MAX_CONTENT_CHUNK_SIZE as u64 + 1);
    assert!(bridge
        .hydrate_file_to_path(&huge_chunk, &output)
        .await
        .is_err());
    assert_eq!(fs::read(&output).unwrap(), vec![42; 256]);

    let sparse_path = fixture(&encrypted, "sparse.md", 128, 3, true, group);
    let mut sparse = bridge
        .inventory(root, &encrypted)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.encrypted_path == sparse_path)
        .unwrap();
    sparse
        .metadata
        .as_mut()
        .unwrap()
        .sparse_metadata
        .as_mut()
        .unwrap()
        .extents[0]
        .offset = 64;
    assert!(bridge.hydrate_file_to_path(&sparse, &output).await.is_err());
    assert_eq!(fs::read(&output).unwrap(), vec![42; 256]);
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[tokio::test]
async fn compatibility_consent_does_not_bypass_current_format_integrity_checks() {
    let dir = tempfile::tempdir().unwrap();
    let account = dir.path().join("account");
    let encrypted = dir.path().join("encrypted");
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let client = client(&account, group).await;
    let policy = Arc::new(VaultCompatibility::load(&account, root).unwrap());
    policy.set_enabled(true).unwrap();
    let bridge = local_provider_bridge_with_compatibility(client, policy.clone());
    let path = fixture(&encrypted, "current.md", 256, 3, false, group);
    let entry = bridge.inventory(root, &encrypted).await.unwrap().remove(0);
    let original = fs::read(&path).unwrap();
    let mut corrupted = original.clone();
    *corrupted.last_mut().unwrap() ^= 0x01;
    fs::write(&path, corrupted).unwrap();

    let output = dir.path().join("hydrated.txt");
    let error = bridge
        .hydrate_file_to_path(&entry, &output)
        .await
        .unwrap_err();
    assert!(error.is_integrity_failure());
    assert_eq!(
        policy.status().last_read_error,
        Some(ProviderFileErrorCode::IntegrityFailure)
    );
    assert!(
        !output.exists(),
        "failed integrity verification writes no plaintext"
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

#[tokio::test]
async fn files_on_a_key_version_this_device_lacks_report_key_unavailable_until_readable() {
    let dir = tempfile::tempdir().unwrap();
    let account = dir.path().join("account");
    let encrypted = dir.path().join("encrypted");
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let client = client(&account, group).await;
    let policy = Arc::new(VaultCompatibility::load(&account, root).unwrap());
    let bridge = local_provider_bridge_with_compatibility(client, policy.clone());
    let readable = fixture(&encrypted, "readable.md", 64, 3, false, group);
    let missing = fixture(&encrypted, "missing.md", 64, 3, false, group);
    // The client holds only key version 1; claim version 7, as after rotations this device missed.
    let original = fs::read(&missing).unwrap();
    let text = String::from_utf8_lossy(&original);
    let marker = ["\"epoch_id\":1,", "\"epoch_id\": 1,"]
        .into_iter()
        .find(|marker| text.contains(marker))
        .expect("fixture header records its key version");
    let header_end = original
        .windows(marker.len())
        .position(|window| window == marker.as_bytes())
        .unwrap();
    let mut rewritten = original[..header_end].to_vec();
    rewritten.extend_from_slice(marker.replace('1', "7").as_bytes());
    rewritten.extend_from_slice(&original[header_end + marker.len()..]);
    fs::write(&missing, rewritten).unwrap();

    let entries = bridge.inventory(root, &encrypted).await.unwrap();
    let entry = |name: &str| {
        entries
            .iter()
            .find(|entry| entry.relative_path == name)
            .unwrap()
            .clone()
    };
    let output = dir.path().join("hydrated.md");
    let error = bridge
        .hydrate_file_to_path(&entry("missing.md"), &output)
        .await
        .unwrap_err();
    assert!(error.is_key_unavailable(), "{error}");
    assert!(error.is_file_unavailable());
    assert_eq!(
        policy.status().last_read_error,
        Some(ProviderFileErrorCode::KeyUnavailable)
    );
    assert!(!output.exists(), "an unreadable file writes no plaintext");

    // A file that opens again (key restored or file moved) clears the notice.
    bridge
        .hydrate_file_to_path(&entry("readable.md"), &output)
        .await
        .unwrap();
    assert_eq!(policy.status().last_read_error, None);
}
