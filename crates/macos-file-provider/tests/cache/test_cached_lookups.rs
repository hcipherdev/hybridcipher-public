// Tests that MacFileProviderCacheBridge's cached inventory and provider state follow syncs and deletes (lib.rs).

#[tokio::test]
async fn cached_lookups_follow_syncs_and_deletes() {
    use hybridcipher_provider_core::compatibility_fixtures::{client, fixture};

    let temp = tempfile::tempdir().unwrap();
    let root_id = Uuid::new_v4();
    let group = Uuid::new_v4();
    let account = temp.path().join("account");
    let encrypted_root = temp.path().join("encrypted");
    let state = temp.path().join("state");
    fs::create_dir_all(&encrypted_root).unwrap();
    let runtime_paths = ProviderRuntimePaths {
        status_path: state.join("status.json"),
        journal_path: state.join("journal.json"),
        provider_state_path: state.join("provider_state.json"),
        provider_changes_path: state.join("provider_changes.json"),
        socket_path: state.join("provider.sock"),
        cache_dir: state.join("cache"),
    };
    let client = client(&account, group).await;
    let compatibility = Arc::new(VaultCompatibility::load(&account, root_id).unwrap());
    let crypto = Arc::new(
        ClientMountCrypto::for_root_with_compatibility(client, root_id, compatibility.clone())
            .await
            .unwrap(),
    );
    fixture(&encrypted_root, "a.md", 64, 3, false, group);
    fixture(&encrypted_root, "b.md", 64, 3, false, group);
    let bridge = MacFileProviderCacheBridge::new(
        root_id,
        "test-domain".into(),
        encrypted_root.clone(),
        runtime_paths,
        account,
        Vec::new(),
        crypto,
        Some(compatibility),
    )
    .unwrap();
    bridge.sync_once().await.unwrap();

    assert_eq!(listed_names(&bridge).await, vec!["a.md", "b.md"]);
    assert!(bridge.entry_for_relative_path("a.md").unwrap().is_some());

    // A file arriving from elsewhere appears once the regular sync runs.
    fixture(&encrypted_root, "c.md", 64, 3, false, group);
    bridge.sync_once().await.unwrap();
    assert_eq!(listed_names(&bridge).await, vec!["a.md", "b.md", "c.md"]);
    assert!(bridge.entry_for_relative_path("c.md").unwrap().is_some());

    // A delete through the bridge leaves lookups at once; Finder's listing follows
    // at the next sync, which rebuilds the provider state as before.
    let a = ProviderSocketBridge::list_directory(&bridge, root_id, &encrypted_root, None)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.relative_path == "a.md")
        .unwrap();
    ProviderSocketBridge::delete(&bridge, root_id, &encrypted_root, &a.provider_id)
        .await
        .unwrap();
    assert!(bridge.entry_for_relative_path("a.md").unwrap().is_none());
    bridge.sync_once().await.unwrap();
    assert_eq!(listed_names(&bridge).await, vec!["b.md", "c.md"]);
}

async fn listed_names(bridge: &MacFileProviderCacheBridge) -> Vec<String> {
    let mut names: Vec<String> =
        ProviderSocketBridge::list_directory(bridge, bridge.root_id, &bridge.encrypted_root, None)
            .await
            .unwrap()
            .into_iter()
            .map(|item| item.relative_path)
            .collect();
    names.sort();
    names
}
