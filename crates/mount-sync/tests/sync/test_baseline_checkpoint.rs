// Tests that SyncTracker::sync_with_progress() checkpoints the sync baseline during a long first sync.

/// Six encrypted files under `<temp>/encrypted`, made through a throwaway view.
async fn six_encrypted_files(temp: &TempDir, crypto: &RoundTripMetadataCrypto) -> PathBuf {
    let encrypted_root = temp.path().join("encrypted");
    let seed_mount = temp.path().join("seed");
    fs::create_dir_all(&encrypted_root).unwrap();
    fs::create_dir_all(&seed_mount).unwrap();
    for index in 0..6 {
        fs::write(seed_mount.join(format!("{index}.txt")), format!("file {index}")).unwrap();
    }
    let mut seed = mock_tracker();
    for _ in 0..2 {
        seed.sync(crypto, &encrypted_root, &seed_mount).await.unwrap();
    }
    assert_eq!(count_encrypted_files(&encrypted_root), 6);
    encrypted_root
}

/// Encrypted files the saved baseline records, or `None` when none is saved yet.
fn saved_encrypted_signatures(baseline: &Path) -> Option<usize> {
    let data = fs::read(baseline).ok()?;
    let record: SyncBaselineRecord = serde_json::from_slice(&data).unwrap();
    Some(record.encrypted_signatures.len())
}

#[tokio::test]
async fn a_long_first_sync_saves_the_files_it_has_done_as_it_goes() {
    let temp = TempDir::new().unwrap();
    let crypto = RoundTripMetadataCrypto {
        plaintext: b"file".to_vec(),
    };
    let encrypted_root = six_encrypted_files(&temp, &crypto).await;
    let mount_root = temp.path().join("mount");
    fs::create_dir_all(&mount_root).unwrap();
    let baseline = temp.path().join("baseline.json");

    let mut tracker = mock_tracker();
    tracker.set_sync_baseline_path(baseline.clone());
    tracker.set_sync_baseline_checkpoint_interval(Duration::ZERO);
    // What a quit at each point would leave behind.
    let saved = std::sync::Mutex::new(Vec::new());
    let report = |done: usize, _total: usize| {
        if done > 0 {
            saved.lock().unwrap().push(saved_encrypted_signatures(&baseline));
        }
    };
    tracker
        .sync_with_progress(&crypto, &encrypted_root, &mount_root, Some(&report))
        .await
        .unwrap();

    let saved = saved.into_inner().unwrap();
    assert_eq!(
        saved,
        (1..=6).map(Some).collect::<Vec<_>>(),
        "each checkpoint records every file done so far"
    );

    // A restart from the checkpoint alone keeps the files already brought in:
    // every rewrite replaces the file, so their inodes stay the same.
    let inodes = || {
        use std::os::unix::fs::MetadataExt;
        let mut inodes: Vec<(PathBuf, u64)> = fs::read_dir(&mount_root)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_type().unwrap().is_file())
            .map(|entry| (entry.path(), entry.metadata().unwrap().ino()))
            .collect();
        inodes.sort();
        inodes
    };
    let before = inodes();
    assert!(!before.is_empty());
    let mut restarted = mock_tracker();
    restarted.set_sync_baseline_path(baseline.clone());
    restarted
        .sync(&crypto, &encrypted_root, &mount_root)
        .await
        .unwrap();
    assert_eq!(inodes(), before, "files were decrypted again after a restart");
}

#[tokio::test]
async fn a_short_sync_does_not_save_before_the_interval_passes() {
    let temp = TempDir::new().unwrap();
    let crypto = RoundTripMetadataCrypto {
        plaintext: b"file".to_vec(),
    };
    let encrypted_root = six_encrypted_files(&temp, &crypto).await;
    let mount_root = temp.path().join("mount");
    fs::create_dir_all(&mount_root).unwrap();
    let baseline = temp.path().join("baseline.json");

    let mut tracker = mock_tracker();
    tracker.set_sync_baseline_path(baseline.clone());
    tracker
        .sync_with_progress(&crypto, &encrypted_root, &mount_root, None)
        .await
        .unwrap();

    assert_eq!(saved_encrypted_signatures(&baseline), None);
}
