// Tests mount_availability in apps/desktop/src-tauri/src/commands.rs: a macOS File Provider mount whose extension never connected is degraded, and Cloud Files health still decides on Windows.
use super::*;

#[test]
fn a_file_provider_mount_finder_never_reached_is_degraded() {
    let unreached = serde_json::json!({
        "extension_connected": false,
        "waiting_secs": 25,
        "error": MACOS_EXTENSION_UNREACHED_MESSAGE,
    });
    assert_eq!(
        mount_availability(MountBackend::MacOsFileProvider, Some(&unreached)),
        "degraded"
    );
    assert_eq!(
        mount_availability(MountBackend::MacOsFileProvider, None),
        "usable",
        "connected, or still within the grace period"
    );
}

#[test]
fn other_backends_ignore_the_file_provider_signal() {
    let unreached = serde_json::json!({ "extension_connected": false });
    assert_eq!(mount_availability(MountBackend::Sync, Some(&unreached)), "usable");
    assert_eq!(
        mount_availability(MountBackend::WindowsCloudFiles, None),
        "degraded",
        "Cloud Files without health stays degraded, as before"
    );
}
