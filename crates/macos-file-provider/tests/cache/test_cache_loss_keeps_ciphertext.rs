// Tests that MacFileProviderCacheBridge (lib.rs) decrypts files lost from its cache again instead of deleting their ciphertext, while Finder's explicit deletes and renames still go through.

struct CacheLossEnv {
    temp: tempfile::TempDir,
    root_id: Uuid,
    group: Uuid,
    account: PathBuf,
    encrypted_root: PathBuf,
    runtime_paths: ProviderRuntimePaths,
    crypto: Arc<ClientMountCrypto>,
    compatibility: Arc<VaultCompatibility>,
}

impl CacheLossEnv {
    async fn new() -> Self {
        use hybridcipher_provider_core::compatibility_fixtures::client;

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
        Self {
            temp,
            root_id,
            group,
            account,
            encrypted_root,
            runtime_paths,
            crypto,
            compatibility,
        }
    }

    fn fixture(&self, name: &str) -> PathBuf {
        hybridcipher_provider_core::compatibility_fixtures::fixture(
            &self.encrypted_root,
            name,
            64,
            3,
            false,
            self.group,
        )
    }

    /// A bridge as a new mount session builds it, from whatever state is on disk.
    fn bridge(&self) -> Arc<MacFileProviderCacheBridge> {
        Arc::new(
            MacFileProviderCacheBridge::new(
                self.root_id,
                "test-domain".into(),
                self.encrypted_root.clone(),
                self.runtime_paths.clone(),
                self.account.clone(),
                Vec::new(),
                self.crypto.clone(),
                Some(self.compatibility.clone()),
            )
            .unwrap(),
        )
    }

    async fn request(
        &self,
        bridge: &Arc<MacFileProviderCacheBridge>,
        request: &ProviderSocketRequest,
    ) -> ProviderSocketResponse {
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: self.temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let registration = FileProviderDomainRegistration {
            root_id: self.root_id,
            domain_identifier: "test-domain".into(),
            display_name: "Test".into(),
            encrypted_root: self.encrypted_root.clone(),
            user_visible_url: None,
        };
        let socket_bridge: Arc<dyn ProviderSocketBridge> = bridge.clone();
        ipc::handle_request(
            &host,
            &registration,
            socket_bridge,
            &self.runtime_paths,
            &serde_json::to_string(request).unwrap(),
        )
        .await
    }

    /// The Finder identifier of a file at the top of the root.
    async fn provider_id(&self, bridge: &MacFileProviderCacheBridge, relative_path: &str) -> String {
        ProviderSocketBridge::list_directory(bridge, self.root_id, &self.encrypted_root, None)
            .await
            .unwrap()
            .into_iter()
            .find(|item| item.relative_path == relative_path)
            .unwrap_or_else(|| panic!("{relative_path} is not listed"))
            .provider_id
    }

    fn retained(&self) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(self.account.join("retention")) else {
            return Vec::new();
        };
        entries
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_file() && !path.to_string_lossy().ends_with(".meta.json"))
            .collect()
    }
}

#[tokio::test]
async fn a_cache_lost_between_sessions_is_decrypted_again_not_deleted() {
    let env = CacheLossEnv::new().await;
    // More files than the startup delete threshold, in and out of a folder.
    let ciphertexts: Vec<PathBuf> = (0..25)
        .map(|i| match i % 2 {
            0 => env.fixture(&format!("note-{i}.md")),
            _ => env.fixture(&format!("docs/note-{i}.md")),
        })
        .collect();
    env.bridge().sync_once().await.unwrap();
    assert!(env.runtime_paths.cache_dir.join("docs/note-1.md").is_file());

    // The incident: the saved sync state outlives the cache it describes.
    fs::remove_dir_all(&env.runtime_paths.cache_dir).unwrap();
    env.bridge().sync_once().await.unwrap();

    for ciphertext in &ciphertexts {
        assert!(ciphertext.exists(), "{} was deleted", ciphertext.display());
    }
    assert!(env.retained().is_empty(), "retired: {:?}", env.retained());
    assert_eq!(
        fs::read(env.runtime_paths.cache_dir.join("docs/note-1.md")).unwrap(),
        vec![42; 64]
    );
    assert_eq!(
        fs::read(env.runtime_paths.cache_dir.join("note-24.md")).unwrap(),
        vec![42; 64]
    );
}

#[tokio::test]
async fn files_lost_from_a_running_cache_are_restored() {
    let env = CacheLossEnv::new().await;
    let kept = env.fixture("kept.md");
    let lost = env.fixture("lost.md");
    let bridge = env.bridge();
    bridge.sync_once().await.unwrap();

    fs::remove_file(env.runtime_paths.cache_dir.join("lost.md")).unwrap();
    bridge.sync_once().await.unwrap();
    bridge.sync_once().await.unwrap();

    assert!(kept.exists());
    assert!(lost.exists(), "a file only missing from the cache was deleted");
    assert!(env.retained().is_empty(), "retired: {:?}", env.retained());
    assert_eq!(
        fs::read(env.runtime_paths.cache_dir.join("lost.md")).unwrap(),
        vec![42; 64]
    );
}

#[tokio::test]
async fn a_finder_delete_retires_only_that_file_and_records_where_it_was() {
    let env = CacheLossEnv::new().await;
    let kept = env.fixture("kept.md");
    let deleted = env.fixture("deleted.md");
    let bridge = env.bridge();
    bridge.sync_once().await.unwrap();

    let identifier = env.provider_id(&bridge, "deleted.md").await;
    let response = env
        .request(
            &bridge,
            &ProviderSocketRequest::Delete {
                root_id: env.root_id,
                identifier,
            },
        )
        .await;
    assert!(response.ok, "{:?}", response.message);
    bridge.sync_once().await.unwrap();

    assert!(kept.exists());
    assert!(!deleted.exists());
    assert!(!env.runtime_paths.cache_dir.join("deleted.md").exists());
    let retained = env.retained();
    assert_eq!(retained.len(), 1, "retired: {retained:?}");
    let meta: serde_json::Value = serde_json::from_slice(
        &fs::read(format!("{}.meta.json", retained[0].display())).unwrap(),
    )
    .unwrap();
    assert_eq!(
        meta["original_path"].as_str(),
        Some(deleted.to_str().unwrap())
    );
}

#[tokio::test]
async fn a_finder_rename_moves_the_ciphertext_without_a_copy_left_behind() {
    let env = CacheLossEnv::new().await;
    let source = env.fixture("before.md");
    let bridge = env.bridge();
    bridge.sync_once().await.unwrap();

    let identifier = env.provider_id(&bridge, "before.md").await;
    let response = env
        .request(
            &bridge,
            &ProviderSocketRequest::Rename {
                root_id: env.root_id,
                identifier,
                target_relative_path: "after.md".into(),
                target_plaintext_path: None,
            },
        )
        .await;
    assert!(response.ok, "{:?}", response.message);
    bridge.sync_once().await.unwrap();
    bridge.sync_once().await.unwrap();

    let target = hybridcipher_mount_sync::encrypted_path_for(
        &env.encrypted_root,
        Path::new(""),
        Path::new("after.md"),
    )
    .unwrap();
    assert!(target.exists(), "the renamed file has no ciphertext");
    assert!(!source.exists(), "the old ciphertext was left behind");
    assert!(!env.runtime_paths.cache_dir.join("before.md").exists());
    assert_eq!(
        fs::read(env.runtime_paths.cache_dir.join("after.md")).unwrap(),
        vec![42; 64]
    );
}
