// Tests MacFileProviderCacheBridge before and after its first full sync (lib.rs): reads straight from ciphertext, and changes refused with retry_later until warm.

#[tokio::test]
async fn before_the_first_sync_files_come_from_ciphertext_and_changes_wait() {
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
    let new_bridge = |crypto: Arc<ClientMountCrypto>| {
        Arc::new(
            MacFileProviderCacheBridge::new(
                root_id,
                "test-domain".into(),
                encrypted_root.clone(),
                runtime_paths.clone(),
                account.clone(),
                Vec::new(),
                crypto,
                Some(compatibility.clone()),
            )
            .unwrap(),
        )
    };
    // An earlier session filled the cache; the file was replaced elsewhere since.
    let ciphertext = fixture(&encrypted_root, "a.md", 64, 3, false, group);
    new_bridge(crypto.clone()).sync_once().await.unwrap();
    assert_eq!(
        fs::read(runtime_paths.cache_dir.join("a.md")).unwrap(),
        vec![42; 64]
    );
    fs::remove_file(&ciphertext).unwrap();
    let ciphertext = fixture(&encrypted_root, "a.md", 32, 3, false, group);
    let bridge = new_bridge(crypto);

    // What start_root does before Finder is let in.
    {
        let _operation = bridge.lock_operation().await;
        bridge.reconcile_provider_state().await.unwrap();
    }
    assert!(!bridge.accepts_changes());
    let item = ProviderSocketBridge::list_directory(&*bridge, root_id, &encrypted_root, None)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.relative_path == "a.md")
        .unwrap();
    let opened = temp.path().join("opened.md");
    ProviderSocketBridge::hydrate(
        &*bridge,
        root_id,
        &encrypted_root,
        &item.provider_id,
        &opened,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fs::read(&opened).unwrap(), vec![42; 32]);

    let host = MacFileProviderHost::new(ProviderHostConfig {
        user_config_dir: temp.path().to_path_buf(),
        socket_path: None,
        provider_identifier: None,
    });
    let registration = FileProviderDomainRegistration {
        root_id,
        domain_identifier: "test-domain".into(),
        display_name: "Test".into(),
        encrypted_root: encrypted_root.clone(),
        user_visible_url: None,
    };
    let delete = serde_json::to_string(&ProviderSocketRequest::Delete {
        root_id,
        identifier: item.provider_id.clone(),
    })
    .unwrap();
    let socket_bridge: Arc<dyn ProviderSocketBridge> = bridge.clone();
    let refused = ipc::handle_request(
        &host,
        &registration,
        socket_bridge.clone(),
        &runtime_paths,
        &delete,
    )
    .await;
    assert!(!refused.ok);
    assert_eq!(refused.retry_later, Some(true));
    assert!(ciphertext.exists());

    // Once a full sync has run, the cache is trusted again and changes go through.
    bridge.sync_once().await.unwrap();
    assert!(bridge.accepts_changes());
    let accepted =
        ipc::handle_request(&host, &registration, socket_bridge, &runtime_paths, &delete).await;
    assert!(accepted.ok, "{:?}", accepted.message);
    assert_eq!(accepted.retry_later, None);
    assert!(!ciphertext.exists());
}
