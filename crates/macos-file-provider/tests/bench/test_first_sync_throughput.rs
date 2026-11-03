// Measures a first mount of many small files with MacFileProviderCacheBridge: time to the listing Finder opens with, then the full sync; run with --ignored --nocapture.

/// Override with HC_MOUNT_BENCH_FILES, e.g. 100000 for the aclImdb-sized case.
const DEFAULT_MOUNT_BENCH_FILES: usize = 2_000;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "throughput measurement, not a correctness check"]
async fn first_sync_throughput_on_many_small_files() {
    use hybridcipher_provider_core::compatibility_fixtures::{client, fixture};

    let files: usize = std::env::var("HC_MOUNT_BENCH_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MOUNT_BENCH_FILES);
    // The home volume, like a real mount; the system temp folder can be elsewhere.
    let temp = tempfile::tempdir_in(std::env::var("HOME").unwrap()).unwrap();
    let root_id = Uuid::new_v4();
    let group = Uuid::new_v4();
    let account = temp.path().join("account");
    let encrypted_root = temp.path().join("encrypted");
    let state = temp.path().join("state");
    fs::create_dir_all(encrypted_root.join("part")).unwrap();
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
    for index in 0..files {
        fixture(
            &encrypted_root.join("part"),
            &format!("{index}.txt"),
            1000,
            3,
            false,
            group,
        );
    }
    let bridge = MacFileProviderCacheBridge::new(
        root_id,
        "bench-domain".into(),
        encrypted_root.clone(),
        runtime_paths,
        account,
        Vec::new(),
        crypto,
        Some(compatibility),
    )
    .unwrap();

    let started = std::time::Instant::now();
    {
        let _operation = bridge.lock_operation().await;
        bridge.reconcile_provider_state().await.unwrap();
    }
    println!(
        "Listing of {files} files ready in {:.2} s",
        started.elapsed().as_secs_f64()
    );

    let started = std::time::Instant::now();
    bridge.sync_once().await.unwrap();
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "First sync of {files} files in {elapsed:.1} s ({:.0} files/s)",
        files as f64 / elapsed
    );
}
