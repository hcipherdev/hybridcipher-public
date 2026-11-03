// Tests SpaceProbe::available() reuse of a volume listing, and SyncTracker::persist_sync_baseline() flushing deferred cache writes first.

fn probe_with(available: u64) -> (TempDir, SpaceProbe) {
    let temp = TempDir::new().unwrap();
    let probe = SpaceProbe {
        // A pretend volume at the folder itself, which no real mount point can match.
        volumes: vec![(fs::canonicalize(temp.path()).unwrap(), available)],
        measured_at: Some(Instant::now()),
        requested_since: 0,
    };
    (temp, probe)
}

#[test]
fn space_checks_reuse_a_recent_listing_and_subtract_what_they_granted() {
    let gib = 1024 * 1024 * 1024;
    let (temp, mut probe) = probe_with(10 * gib);

    assert_eq!(probe.available(temp.path(), gib, 3 * gib), Some(10 * gib));
    assert_eq!(probe.available(temp.path(), gib, 3 * gib), Some(7 * gib));
    assert_eq!(probe.available(temp.path(), gib, 3 * gib), Some(4 * gib));
    // One more grant would leave less than twice the budget, so the volumes are
    // listed again and the pretend one is gone.
    probe.available(temp.path(), gib, 3 * gib);
    assert!(probe.volumes.len() != 1 || probe.volumes[0].1 != 10 * gib);
    assert_eq!(probe.requested_since, 3 * gib);
}

#[test]
fn an_old_listing_is_taken_again() {
    let (temp, mut probe) = probe_with(u64::MAX / 4);
    probe.measured_at = Some(Instant::now() - SPACE_PROBE_INTERVAL);

    assert_ne!(probe.available(temp.path(), 1, 1), Some(u64::MAX / 4));
    assert!(probe.measured_at.unwrap().elapsed() < SPACE_PROBE_INTERVAL);
}

#[tokio::test]
async fn deferred_cache_writes_are_flushed_before_the_baseline_is_saved() {
    let temp = TempDir::new().unwrap();
    let encrypted_root = temp.path().join("encrypted");
    let mount_root = temp.path().join("mount");
    fs::create_dir_all(&encrypted_root).unwrap();
    fs::create_dir_all(&mount_root).unwrap();
    write_test_encrypted_file(
        &encrypted_root.join("good.txt.encrypted"),
        "good-id",
        "good.txt",
    )
    .unwrap();

    let mut tracker = mock_tracker();
    tracker.set_sync_baseline_path(temp.path().join("baseline.json"));
    tracker
        .sync(&MixedDecryptCrypto, &encrypted_root, &mount_root)
        .await
        .unwrap();
    assert!(mount_root.join("good.txt").exists());
    assert!(tracker.deferred_cache_write.lock().unwrap().is_some());

    tracker.persist_sync_baseline().unwrap();

    assert!(tracker.deferred_cache_write.lock().unwrap().is_none());
    assert!(temp.path().join("baseline.json").exists());
}
