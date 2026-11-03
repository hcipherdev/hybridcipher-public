// Tests reconnected_mount_state() and record_reconnected_mounts() in apps/desktop/src-tauri/src/commands.rs: a mount the last run left behind shows as mounted once this run reconnects it.
use super::*;
use crate::cloud_provider::{ReconnectFailure, ReconnectReport, ReconnectedRoot};

fn reconnected_root() -> ReconnectedRoot {
    ReconnectedRoot {
        root_id: Uuid::new_v4(),
        mountpoint: PathBuf::from("/mount/Docs"),
        encrypted_root: PathBuf::from("/encrypted/Docs"),
    }
}

/// What a killed run leaves: its own pid, and on a quit macOS did not let us
/// stop safely, the unmount mark set on exit.
fn left_state(root: &ReconnectedRoot) -> MountRuntimeState {
    MountRuntimeState {
        root_id: root.root_id.to_string(),
        mountpoint: PathBuf::from("/mount/Docs (named by last run)"),
        encrypted_dir: root.encrypted_root.clone(),
        platform: std::env::consts::OS.to_string(),
        backend: Some(MountBackend::WindowsCloudFiles),
        host_pid: Some(u32::MAX),
        fallback_reason: Some("old".into()),
        ready: true,
        requested_unmount: true,
        display_name: Some("Docs".into()),
    }
}

#[test]
fn a_left_mount_state_is_taken_over_by_this_process() {
    let root = reconnected_root();
    let state = reconnected_mount_state(
        Some(left_state(&root)),
        &root,
        MountBackend::WindowsCloudFiles,
    );

    assert_eq!(state.host_pid, Some(std::process::id()));
    assert!(state.ready);
    assert!(!state.requested_unmount);
    assert_eq!(state.fallback_reason, None);
    assert!(mount_state_host_is_active(&state));
    assert_eq!(state.display_name.as_deref(), Some("Docs"), "the name Finder shows is kept");
    assert_eq!(
        state.mountpoint,
        PathBuf::from("/mount/Docs (named by last run)"),
        "the mountpoint the last run chose is kept"
    );
}

#[test]
fn a_missing_mount_state_is_rebuilt_from_the_registration() {
    let root = reconnected_root();
    let state = reconnected_mount_state(None, &root, MountBackend::MacOsFileProvider);

    assert_eq!(state.root_id, root.root_id.to_string());
    assert_eq!(state.mountpoint, root.mountpoint);
    assert_eq!(state.encrypted_dir, root.encrypted_root);
    assert!(matches!(state.backend, Some(MountBackend::MacOsFileProvider)));
    assert!(state.ready && !state.requested_unmount);
    assert!(mount_state_host_is_active(&state));
}

#[tokio::test]
async fn reconnected_mounts_are_recorded_and_failed_ones_left_alone() {
    let temp = tempfile::tempdir().unwrap();
    let user_dir = temp.path();
    let root = reconnected_root();
    let failed_id = Uuid::new_v4();
    let states_dir = user_dir.join("mount_states");
    write_mount_runtime_state(
        &states_dir.join(format!("mount_state_{}.json", root.root_id)),
        &left_state(&root),
    )
    .await
    .unwrap();

    let report = ReconnectReport {
        reconnected: vec![root.clone()],
        failed: vec![ReconnectFailure {
            root_id: failed_id.to_string(),
            name: "Other".into(),
            error: "provider did not start".into(),
        }],
    };
    record_reconnected_mounts(user_dir, &report).await;

    let written: MountRuntimeState = serde_json::from_slice(
        &fs::read(states_dir.join(format!("mount_state_{}.json", root.root_id)))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(written.host_pid, Some(std::process::id()));
    assert!(!written.requested_unmount);
    assert_eq!(written.display_name.as_deref(), Some("Docs"));
    assert!(
        !states_dir
            .join(format!("mount_state_{failed_id}.json"))
            .exists(),
        "a mount that was not reconnected gets no state"
    );
}
