// Tests ProgressThrottle::should_emit() in src/commands/folder_jobs.rs, which limits folder job progress events.
use super::*;

const MS: Duration = Duration::from_millis(1);

#[test]
fn first_last_and_phase_changes_are_always_sent() {
    let start = Instant::now();
    let mut throttle = ProgressThrottle::default();
    assert!(throttle.should_emit("encrypting", 0, 100_000, start));
    assert!(!throttle.should_emit("encrypting", 1, 100_000, start + MS));
    assert!(throttle.should_emit("finalizing", 1, 100_000, start + 2 * MS));
    assert!(throttle.should_emit("finalizing", 100_000, 100_000, start + 3 * MS));
    assert!(throttle.should_emit("finalizing", 100_000, 100_000, start + 4 * MS));
}

#[test]
fn a_large_folder_sends_one_update_per_percent_while_fast() {
    let start = Instant::now();
    let mut throttle = ProgressThrottle::default();
    let total = 100_000;
    // Every file reported within the same instant: only percent steps pass.
    let sent = (0..=total)
        .filter(|processed| throttle.should_emit("encrypting", *processed, total, start))
        .count();
    assert_eq!(sent, 101);
}

#[test]
fn slow_progress_still_updates_within_the_interval() {
    let start = Instant::now();
    let mut throttle = ProgressThrottle::default();
    assert!(throttle.should_emit("encrypting", 0, 100_000, start));
    assert!(!throttle.should_emit("encrypting", 10, 100_000, start + 100 * MS));
    assert!(throttle.should_emit("encrypting", 20, 100_000, start + 160 * MS));
}

#[test]
fn an_empty_folder_reports_without_dividing_by_zero() {
    let mut throttle = ProgressThrottle::default();
    assert!(throttle.should_emit("encrypting", 0, 0, Instant::now()));
    assert!(throttle.should_emit("encrypting", 0, 0, Instant::now()));
}
