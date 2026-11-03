// Tests SyncTracker::sync_with_progress() counts on a first sync into an empty mounted view.

#[tokio::test]
async fn first_sync_reports_every_encrypted_file_against_the_counted_total() {
    let temp = TempDir::new().unwrap();
    let encrypted_root = temp.path().join("encrypted");
    let seed_mount = temp.path().join("seed");
    fs::create_dir_all(&encrypted_root).unwrap();
    fs::create_dir_all(seed_mount.join("nested")).unwrap();
    for index in 0..6 {
        let dir = if index % 2 == 0 {
            seed_mount.clone()
        } else {
            seed_mount.join("nested")
        };
        fs::write(dir.join(format!("{index}.txt")), format!("file {index}")).unwrap();
    }
    // Encrypt through one view (its second sync writes the ciphertext), then bring
    // everything into a fresh, empty one.
    // This crypto names every file the same, so only the counts are checked.
    let crypto = RoundTripMetadataCrypto {
        plaintext: b"file".to_vec(),
    };
    let mut seed = mock_tracker();
    for _ in 0..2 {
        seed.sync(&crypto, &encrypted_root, &seed_mount)
            .await
            .unwrap();
    }
    assert_eq!(count_encrypted_files(&encrypted_root), 6);

    let mount_root = temp.path().join("mount");
    fs::create_dir_all(&mount_root).unwrap();
    let reports = std::sync::Mutex::new(Vec::new());
    let report = |done: usize, total: usize| reports.lock().unwrap().push((done, total));
    mock_tracker()
        .sync_with_progress(&crypto, &encrypted_root, &mount_root, Some(&report))
        .await
        .unwrap();

    let reports = reports.into_inner().unwrap();
    assert_eq!(reports.first(), Some(&(0, 6)));
    assert_eq!(reports.last(), Some(&(6, 6)));
    assert!(reports.windows(2).all(|pair| pair[0].0 <= pair[1].0));
}
