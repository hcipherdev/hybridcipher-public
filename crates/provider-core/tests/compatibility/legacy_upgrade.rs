// Tests legacy_file_summaries(), upgrade_legacy_entries(), upgrade_legacy_file() and LocalProviderBridge::upgrade_legacy_files() in crates/provider-core/src/legacy_upgrade.rs
use hybridcipher_provider_core::{
    compatibility_fixtures::{client, fixture},
    legacy_file_summaries, local_provider_bridge_with_compatibility, upgrade_legacy_entries,
    upgrade_legacy_file, ClientMountCrypto, LegacyFileSummary, LegacyUpgradeContext, ProviderEntry,
    VaultCompatibility,
};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

struct Vault {
    _dir: tempfile::TempDir,
    account: PathBuf,
    encrypted: PathBuf,
    staging: PathBuf,
    root: Uuid,
    group: Uuid,
}

fn vault() -> Vault {
    let dir = tempfile::tempdir().unwrap();
    let account = dir.path().join("account");
    let encrypted = dir.path().join("encrypted");
    let staging = dir.path().join("staging");
    fs::create_dir_all(&encrypted).unwrap();
    Vault {
        account,
        encrypted,
        staging,
        root: Uuid::new_v4(),
        group: Uuid::new_v4(),
        _dir: dir,
    }
}

fn header_version(path: &Path) -> Option<u32> {
    hybridcipher_mount_sync::parse_encrypted_file(path)
        .unwrap()
        .metadata
        .header_version
}

fn backups(policy: &VaultCompatibility) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    let directory = policy.status().encrypted_backup_directory;
    if !directory.exists() {
        return found;
    }
    for object in fs::read_dir(directory).unwrap() {
        for copy in fs::read_dir(object.unwrap().path()).unwrap() {
            found.push(fs::read(copy.unwrap().path()).unwrap());
        }
    }
    found
}

fn entry<'a>(entries: &'a [ProviderEntry], relative_path: &str) -> &'a ProviderEntry {
    entries
        .iter()
        .find(|entry| entry.relative_path == relative_path)
        .unwrap()
}

#[tokio::test]
async fn bridge_upgrades_only_consented_older_files_and_keeps_encrypted_originals() {
    let vault = vault();
    let client = client(&vault.account, vault.group).await;
    let policy = Arc::new(VaultCompatibility::load(&vault.account, vault.root).unwrap());
    let bridge = local_provider_bridge_with_compatibility(client, policy.clone());
    fixture(&vault.encrypted, "notes.md", 300, 2, false, vault.group);
    fixture(&vault.encrypted, "sparse.md", 80, 2, true, vault.group);
    fixture(&vault.encrypted, "current.md", 192, 3, false, vault.group);

    let entries = bridge
        .inventory(vault.root, &vault.encrypted)
        .await
        .unwrap();
    assert_eq!(
        legacy_file_summaries(&entries),
        vec![
            LegacyFileSummary {
                relative_path: "notes.md".into(),
                content_size: 300
            },
            LegacyFileSummary {
                relative_path: "sparse.md".into(),
                content_size: 144
            },
        ]
    );
    let notes_original = fs::read(&entry(&entries, "notes.md").encrypted_path).unwrap();
    let sparse_original = fs::read(&entry(&entries, "sparse.md").encrypted_path).unwrap();

    let refused = bridge
        .upgrade_legacy_files(vault.root, &vault.encrypted, None, &vault.staging)
        .await
        .unwrap_err();
    assert!(refused.is_legacy_consent_required());
    assert_eq!(
        fs::read(&entry(&entries, "notes.md").encrypted_path).unwrap(),
        notes_original,
        "an upgrade without consent never touches the original"
    );

    bridge.set_legacy_compatibility(true).unwrap();
    let requested = vec![
        "notes.md".to_string(),
        "current.md".into(),
        "missing.md".into(),
    ];
    let report = bridge
        .upgrade_legacy_files(
            vault.root,
            &vault.encrypted,
            Some(&requested),
            &vault.staging,
        )
        .await
        .unwrap();
    assert_eq!(report.upgraded, vec!["notes.md".to_string()]);
    let failed: Vec<_> = report
        .failed
        .iter()
        .map(|f| f.relative_path.as_str())
        .collect();
    assert_eq!(failed, vec!["current.md", "missing.md"]);
    assert_eq!(policy.status().legacy_file_count, 1);
    assert_eq!(backups(&policy), vec![notes_original]);

    let report = bridge
        .upgrade_legacy_files(vault.root, &vault.encrypted, None, &vault.staging)
        .await
        .unwrap();
    assert_eq!(report.upgraded, vec!["sparse.md".to_string()]);
    assert!(report.failed.is_empty());
    assert_eq!(policy.status().legacy_file_count, 0);
    assert!(backups(&policy).contains(&sparse_original));

    let output = vault.staging.join("check");
    let entries = bridge
        .inventory(vault.root, &vault.encrypted)
        .await
        .unwrap();
    assert!(legacy_file_summaries(&entries).is_empty());
    for (path, expected) in [
        ("notes.md", vec![42u8; 300]),
        ("sparse.md", [vec![42u8; 80], vec![0u8; 64]].concat()),
    ] {
        let upgraded = entry(&entries, path);
        assert_eq!(header_version(&upgraded.encrypted_path), Some(3));
        bridge
            .hydrate_file_to_path(upgraded, &output)
            .await
            .unwrap();
        assert_eq!(
            fs::read(&output).unwrap(),
            expected,
            "{path} plaintext is unchanged"
        );
    }
    let staged: Vec<_> = fs::read_dir(&vault.staging)
        .unwrap()
        .map(|item| item.unwrap().file_name())
        .filter(|name| name != "check")
        .collect();
    assert!(
        staged.is_empty(),
        "no transient plaintext is left behind: {staged:?}"
    );
}

#[tokio::test]
async fn upgrade_skips_busy_files_and_never_replaces_a_changed_original() {
    let vault = vault();
    let client = client(&vault.account, vault.group).await;
    let policy = Arc::new(VaultCompatibility::load(&vault.account, vault.root).unwrap());
    policy.set_enabled(true).unwrap();
    let bridge = local_provider_bridge_with_compatibility(client.clone(), policy.clone());
    let crypto = ClientMountCrypto::for_root_with_compatibility(client, vault.root, policy.clone())
        .await
        .unwrap();
    let busy_path = fixture(&vault.encrypted, "busy.md", 64, 2, false, vault.group);
    fixture(&vault.encrypted, "stale.md", 64, 2, false, vault.group);
    let entries = bridge
        .inventory(vault.root, &vault.encrypted)
        .await
        .unwrap();
    let context = LegacyUpgradeContext {
        crypto: &crypto,
        compatibility: &policy,
        root_id: vault.root,
        encrypted_root: &vault.encrypted,
        plaintext_staging_dir: &vault.staging,
    };

    let busy = HashSet::from(["busy.md".to_string()]);
    let report = upgrade_legacy_entries(&context, &entries, Some(&["busy.md".into()]), &busy)
        .await
        .unwrap();
    assert!(report.upgraded.is_empty());
    assert_eq!(report.failed[0].relative_path, "busy.md");
    assert_eq!(header_version(&busy_path), Some(2));

    // Another device replaced the file after it was listed.
    let stale = entry(&entries, "stale.md").clone();
    let replacement = fixture(&vault.encrypted, "stale.md", 96, 2, false, vault.group);
    let newer = fs::read(&replacement).unwrap();
    assert!(upgrade_legacy_file(&context, &stale).await.is_err());
    assert_eq!(fs::read(&replacement).unwrap(), newer);
}
