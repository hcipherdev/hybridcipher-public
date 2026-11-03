// Tests run_bounded, unmount_lock and unmount_in_progress in apps/desktop/src-tauri/src/commands/unmount_batch.rs, and host_process_is_running in commands.rs: every folder is attempted within the parallel limit, one folder is never unmounted twice at once or mounted mid-unmount, and the app's own mounts need no process lookup.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn every_folder_is_attempted_when_one_fails() {
    let results = unmount_batch::run_bounded(vec![1, 2, 3, 4, 5], 2, |item| async move {
        tokio::task::yield_now().await;
        if item == 2 {
            Err(format!("folder {item} refused"))
        } else {
            Ok(item)
        }
    })
    .await;

    assert_eq!(results.len(), 5);
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 4);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
}

#[tokio::test]
async fn no_more_folders_run_at_once_than_the_limit() {
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    unmount_batch::run_bounded((0..8).collect::<Vec<_>>(), 3, |_| {
        let running = running.clone();
        let peak = peak.clone();
        async move {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            running.fetch_sub(1, Ordering::SeqCst);
        }
    })
    .await;

    assert!(peak.load(Ordering::SeqCst) <= 3);
    assert!(peak.load(Ordering::SeqCst) >= 2, "folders ran side by side");
}

#[tokio::test]
async fn a_second_unmount_of_a_folder_waits_for_the_first() {
    let root_id = Uuid::new_v4();
    let first = unmount_batch::unmount_lock(root_id);
    let held = first.lock().await;
    assert!(unmount_batch::unmount_in_progress(root_id));

    let second = unmount_batch::unmount_lock(root_id);
    assert!(
        second.try_lock().is_err(),
        "the same folder shares one lock, so a second unmount waits"
    );
    assert!(
        !unmount_batch::unmount_in_progress(Uuid::new_v4()),
        "other folders are unaffected"
    );

    drop(held);
    assert!(!unmount_batch::unmount_in_progress(root_id));
    assert!(second.try_lock().is_ok());
}

#[test]
fn the_app_itself_counts_as_a_running_mount_host_without_asking_the_system() {
    assert!(host_process_is_running(std::process::id()));
}
