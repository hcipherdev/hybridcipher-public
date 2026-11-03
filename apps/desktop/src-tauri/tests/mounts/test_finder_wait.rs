// Tests finder_wait_steps, finder_location_state and finder_mount_failed_message in apps/desktop/src-tauri/src/commands.rs: when a Finder wait re-asks the location and wakes the domain, how it describes an unreadable or privacy-blocked folder, and the error shown instead of the CLI fallback.
use super::*;

const fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

#[test]
fn the_location_is_asked_at_once_and_every_five_seconds() {
    assert!(finder_wait_steps(secs(0), None, None).resolve);
    assert!(!finder_wait_steps(secs(4), Some(secs(0)), None).resolve);
    assert!(finder_wait_steps(secs(5), Some(secs(0)), None).resolve);
    assert!(!finder_wait_steps(secs(9), Some(secs(5)), None).resolve);
}

#[test]
fn an_unreadable_folder_is_woken_after_three_seconds_then_every_ten() {
    assert!(!finder_wait_steps(secs(2), Some(secs(0)), None).wake);
    assert!(finder_wait_steps(secs(3), Some(secs(0)), None).wake);
    assert!(!finder_wait_steps(secs(12), Some(secs(10)), Some(secs(3))).wake);
    assert!(finder_wait_steps(secs(13), Some(secs(10)), Some(secs(3))).wake);
}

#[tokio::test]
async fn the_folder_state_says_why_it_is_not_ready() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("HybridCipher-Personal·screenshots");
    assert_eq!(
        finder_location_state(&missing).await.unwrap_err(),
        "does not exist"
    );

    let file = temp.path().join("not-a-folder");
    std::fs::write(&file, b"x").unwrap();
    assert_eq!(
        finder_location_state(&file).await.unwrap_err(),
        "is not a folder"
    );

    // A folder macOS creates while the wait runs is picked up.
    std::fs::create_dir(&missing).unwrap();
    assert_eq!(
        finder_location_state(&missing).await.unwrap(),
        FinderLocationAccess::Readable
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_folder_this_app_may_not_list_is_blocked_not_missing() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let folder = temp.path().join("HybridCipher-init-group·pqctest");
    std::fs::create_dir(&folder).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Root lists any folder, so the refusal can only be staged without it.
    let staged = std::fs::read_dir(&folder).is_err();
    let access = finder_location_state(&folder).await;
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();

    if staged {
        assert_eq!(access.unwrap(), FinderLocationAccess::Blocked);
    }
}

#[test]
fn a_finder_failure_names_the_folder_and_what_to_try() {
    let message = finder_mount_failed_message("screenshots", "the folder did not appear");

    assert!(message.starts_with("Finder couldn't open screenshots (the folder did not appear)."));
    assert!(message.contains("Try mounting it again"));
    assert!(message.contains("File Providers"));
    assert!(!message.contains("file index"));
}

#[test]
fn a_blocked_folder_says_to_reopen_the_app_not_to_retry() {
    let reason =
        format!("{FINDER_ACCESS_BLOCKED}, and the health check failed: socket unreachable");
    let message = finder_mount_failed_message("pqctest", &reason);

    assert!(message.starts_with("Finder couldn't open pqctest (macOS privacy settings blocked"));
    assert!(message.contains("Quit and reopen HybridCipher"));
    assert!(message.contains("Files & Folders"));
    assert!(!message.contains("Try mounting it again"));
}
