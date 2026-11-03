// Verify malformed/in-flight mount records and unknown, stale, or unsafe health block self-revocation.
use super::*;
use tempfile::TempDir;

fn mount_state() -> MountRuntimeState {
    MountRuntimeState {
        root_id: Uuid::new_v4(),
        mountpoint: PathBuf::from("/test/mount"),
        encrypted_dir: PathBuf::from("/test/encrypted"),
        platform: "test".into(),
        backend: Some(MountBackend::Sync),
        host_pid: Some(123),
        fallback_reason: None,
        ready: true,
        requested_unmount: false,
    }
}

#[test]
fn strict_removal_scan_keeps_inflight_unmounts_and_rejects_corrupt_state() {
    let temp = TempDir::new().unwrap();
    let legacy = temp.path().join("legacy.json");
    let record = temp.path().join("mount_state_device.json");
    let mut state = mount_state();
    state.requested_unmount = true;
    write_runtime_state(&record, &state).unwrap();
    fs::write(temp.path().join("mount_sync_status_device.json"), "{}").unwrap();
    let records = read_mount_records_for_device_removal(temp.path(), &legacy).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].1.requested_unmount);
    fs::write(&record, "invalid state").unwrap();
    assert!(read_mount_records_for_device_removal(temp.path(), &legacy).is_err());
}

#[test]
fn strict_inventory_never_treats_an_invalid_directory_or_symlink_as_no_mounts() {
    let temp = TempDir::new().unwrap();
    let invalid_dir = temp.path().join("inventory-file");
    fs::write(&invalid_dir, "not a directory").unwrap();
    assert!(
        read_mount_records_for_device_removal(&invalid_dir, &temp.path().join("missing")).is_err()
    );
    #[cfg(unix)]
    {
        let link = temp.path().join("mount_state_link.json");
        std::os::unix::fs::symlink(temp.path().join("missing"), &link).unwrap();
        assert!(
            read_mount_records_for_device_removal(temp.path(), &temp.path().join("legacy"))
                .is_err()
        );
    }
}

#[test]
fn self_removal_requires_fresh_consistent_and_safe_mount_health() {
    let state = mount_state();
    let now = chrono::Utc::now();
    assert!(validate_device_removal_mount_health(&state, None, now).is_err());
    let mut health = MountSyncRuntimeStatus::default();
    health.updated_at = now;
    assert!(validate_device_removal_mount_health(&state, Some(&health), now).is_err());
    health.safe_to_unmount = true;
    assert!(validate_device_removal_mount_health(&state, Some(&health), now).is_ok());
    health.updated_at = now - chrono::Duration::seconds(16);
    assert!(validate_device_removal_mount_health(&state, Some(&health), now).is_err());
    health.updated_at = now + chrono::Duration::seconds(2);
    assert!(validate_device_removal_mount_health(&state, Some(&health), now).is_err());
    health.updated_at = now;
    health.pending_writeback_count = 1;
    assert!(validate_device_removal_mount_health(&state, Some(&health), now).is_err());
}

#[test]
fn stopped_views_with_recovery_files_cannot_be_treated_as_successful_cleanup() {
    let temp = TempDir::new().unwrap();
    assert!(ensure_device_removal_view_is_empty(temp.path()).is_ok());
    fs::write(temp.path().join("pending.txt"), "pending work").unwrap();
    assert!(ensure_device_removal_view_is_empty(temp.path()).is_err());
    assert!(ensure_device_removal_view_is_empty(&temp.path().join("pending.txt")).is_err());
}

#[test]
fn failed_poststop_validation_remains_blocked_on_a_second_inventory_scan() {
    let temp = TempDir::new().unwrap();
    let view = temp.path().join("view");
    fs::create_dir(&view).unwrap();
    fs::write(view.join("pending.txt"), "unsynced work").unwrap();
    let mut state = mount_state();
    state.mountpoint = view.clone();
    let record = temp
        .path()
        .join(format!("mount_state_{}.json", state.root_id));
    write_runtime_state(&record, &state).unwrap();
    write_device_removal_mount_tracker(temp.path(), &[(record.clone(), state.clone())]).unwrap();
    // Simulate the mount host deleting its ordinary record before retained-view
    // validation rejects the first removal attempt.
    clear_runtime_state(&record).unwrap();
    assert!(ensure_device_removal_view_is_empty(&view).is_err());
    let retry =
        read_mount_records_for_device_removal(temp.path(), &temp.path().join("legacy")).unwrap();
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].1.mountpoint, view);
    assert!(ensure_device_removal_view_is_empty(&retry[0].1.mountpoint).is_err());
    // Ordinary MountRuntimeState parsing cannot consume or clean the tracker.
    assert!(read_runtime_state(&temp.path().join(DEVICE_REMOVAL_MOUNT_TRACKER)).is_err());
    // Reusing the root ID cannot overwrite the pending original view.
    state.mountpoint = temp.path().join("different-view");
    write_runtime_state(&record, &state).unwrap();
    assert!(
        read_mount_records_for_device_removal(temp.path(), &temp.path().join("legacy")).is_err()
    );
}

#[test]
fn unreadable_or_malformed_removal_tracking_never_becomes_an_empty_inventory() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join(DEVICE_REMOVAL_MOUNT_TRACKER),
        "malformed tracking",
    )
    .unwrap();
    assert!(
        read_mount_records_for_device_removal(temp.path(), &temp.path().join("legacy")).is_err()
    );
}

#[tokio::test]
async fn empty_stopped_views_complete_tracking_without_requesting_missing_live_health() {
    let temp = TempDir::new().unwrap();
    let mut state = mount_state();
    state.host_pid = Some(i32::MAX as u32);
    state.mountpoint = dirs::home_dir()
        .unwrap()
        .join(hybridcipher_client::config_loader::account_data_location())
        .join(format!("nonexistent_test_{}_mount", Uuid::new_v4()));
    let record = temp
        .path()
        .join(format!("mount_state_{}.json", state.root_id));
    write_device_removal_mount_tracker(temp.path(), &[(record, state.clone())]).unwrap();
    validate_device_removal_mount_before_stop(&state, async {
        Err(CliError::mount(
            "Live health is unavailable after the host stopped",
        ))
    })
    .await
    .unwrap();
    validate_stopped_device_removal_mount(&state).await.unwrap();
    assert!(read_remaining_mount_records_for_device_removal(
        temp.path(),
        &temp.path().join("legacy")
    )
    .unwrap()
    .is_empty());
    complete_device_removal_mount_tracking(temp.path()).unwrap();
    assert!(
        read_mount_records_for_device_removal(temp.path(), &temp.path().join("legacy"))
            .unwrap()
            .is_empty()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn native_desktop_provider_registration_blocks_cli_device_removal() {
    let temp = TempDir::new().unwrap();
    assert!(ensure_no_native_provider_registrations(temp.path()).is_ok());
    let host = hybridcipher_macos_file_provider::MacFileProviderHost::new(
        hybridcipher_macos_file_provider::ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        },
    );
    let registration = hybridcipher_macos_file_provider::FileProviderDomainRegistration {
        root_id: Uuid::new_v4(),
        domain_identifier: "test.device-removal".into(),
        display_name: "Test".into(),
        encrypted_root: temp.path().join("encrypted"),
        user_visible_url: Some(temp.path().join("visible")),
    };
    host.register_domain(&registration).unwrap();
    assert!(ensure_no_native_provider_registrations(temp.path()).is_err());
    host.unregister_domain_state(registration.root_id).unwrap();
    #[cfg(unix)]
    {
        let unknown = temp.path().join("macos-file-provider/domains/unknown.json");
        std::os::unix::fs::symlink(temp.path().join("missing"), unknown).unwrap();
        assert!(ensure_no_native_provider_registrations(temp.path()).is_err());
    }
}
