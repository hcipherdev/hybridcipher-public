// Tests SyncTracker::check_mount_health() holding back deletions from a mount that lost every file, and process_pending_deletions() still retiring ordinary deletes.

/// A tracker that has decrypted `count` files into `mount_root`.
async fn tracker_with_decrypted_files(
    temp: &TempDir,
    count: usize,
) -> (SyncTracker, PathBuf, PathBuf, Vec<PathBuf>) {
    let encrypted_root = temp.path().join("encrypted");
    let mount_root = temp.path().join("mount");
    fs::create_dir_all(&encrypted_root).unwrap();
    fs::create_dir_all(&mount_root).unwrap();
    let ciphertexts: Vec<PathBuf> = (0..count)
        .map(|i| {
            let name = format!("note-{i}.txt");
            let path = encrypted_root.join(format!("{name}.encrypted"));
            write_test_encrypted_file(&path, &format!("health-{i}"), &name).unwrap();
            path
        })
        .collect();

    let mut tracker = mock_tracker();
    // Two verification scans confirm a delete, well inside the time allowed.
    tracker.set_deletion_config(DeletionConfig {
        min_consecutive_missing_scans: 2,
        rapid_scan_total_duration_ms: 1_000,
        ..DeletionConfig::default()
    });
    tracker.set_retention_folder(&temp.path().join("config"));
    let crypto = RoundTripMetadataCrypto {
        plaintext: b"decrypted".to_vec(),
    };
    tracker
        .sync(&crypto, &encrypted_root, &mount_root)
        .await
        .unwrap();
    assert!(mount_root.join("note-0.txt").exists());
    (tracker, encrypted_root, mount_root, ciphertexts)
}

fn retained_files(temp: &TempDir) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(temp.path().join("config").join("retention")) else {
        return Vec::new();
    };
    entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file() && !path.to_string_lossy().ends_with(".meta.json"))
        .collect()
}

#[tokio::test]
async fn a_mount_that_lost_every_file_keeps_all_ciphertext() {
    let temp = TempDir::new().unwrap();
    let (mut tracker, encrypted_root, mount_root, ciphertexts) =
        tracker_with_decrypted_files(&temp, STARTUP_LOCAL_DELETE_MAX_ACTIONS + 5).await;
    let crypto = RoundTripMetadataCrypto {
        plaintext: b"decrypted".to_vec(),
    };

    fs::remove_dir_all(&mount_root).unwrap();
    fs::create_dir_all(&mount_root).unwrap();
    for _ in 0..3 {
        tracker
            .sync(&crypto, &encrypted_root, &mount_root)
            .await
            .unwrap();
    }

    assert!(matches!(tracker.scan_health, ScanHealth::Unhealthy { .. }));
    for ciphertext in &ciphertexts {
        assert!(ciphertext.exists(), "{} was deleted", ciphertext.display());
    }
    assert!(retained_files(&temp).is_empty());
}

#[tokio::test]
async fn deleting_a_few_files_from_a_mount_still_retires_their_ciphertext() {
    let temp = TempDir::new().unwrap();
    let (mut tracker, encrypted_root, mount_root, ciphertexts) =
        tracker_with_decrypted_files(&temp, 3).await;
    let crypto = RoundTripMetadataCrypto {
        plaintext: b"decrypted".to_vec(),
    };

    fs::remove_file(mount_root.join("note-1.txt")).unwrap();
    tracker
        .sync(&crypto, &encrypted_root, &mount_root)
        .await
        .unwrap();

    assert!(matches!(tracker.scan_health, ScanHealth::Healthy));
    assert!(ciphertexts[0].exists());
    assert!(!ciphertexts[1].exists());
    assert!(ciphertexts[2].exists());
    let retained = retained_files(&temp);
    assert_eq!(retained.len(), 1, "retired: {retained:?}");
    let meta: RetentionMetadata = serde_json::from_slice(
        &fs::read(format!("{}.meta.json", retained[0].display())).unwrap(),
    )
    .unwrap();
    assert_eq!(meta.original_path.as_deref(), Some(ciphertexts[1].as_path()));
}
