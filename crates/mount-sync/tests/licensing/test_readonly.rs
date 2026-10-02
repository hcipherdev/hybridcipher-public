// Tests reversible read-only mounted views and crash recovery in readonly.rs.
use super::*;

#[test]
fn mounted_view_denies_mutations_preserves_reads_and_recovers_original_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("view");
    fs::create_dir(&root).unwrap();
    let file = root.join("existing.txt");
    fs::write(&file, b"pending edit").unwrap();
    let original = permissions::capture(&file).unwrap();
    let journal = temp.path().join("permissions.json");
    let mut guard = ReadOnlyMount::open(&root, journal.clone()).unwrap();
    guard.set_read_only(true).unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"pending edit");
    assert!(fs::write(&file, b"blocked").is_err());
    assert!(fs::write(root.join("new.txt"), b"blocked").is_err());
    assert!(fs::remove_file(&file).is_err());
    assert!(fs::rename(&file, root.join("renamed.txt")).is_err());
    drop(guard); // Simulate a crash: durable journal remains.
    let mut recovered = ReadOnlyMount::open(&root, journal.clone()).unwrap();
    recovered.set_read_only(true).unwrap();
    recovered.restore().unwrap();
    let restored = permissions::capture(&file).unwrap();
    // Windows can recompute the auto-inherited marker without changing any ACE.
    assert_eq!(
        restored.replace("D:AI", "D:"),
        original.replace("D:AI", "D:")
    );
    assert!(!journal.exists());
    fs::write(&file, b"access restored").unwrap();
    assert_eq!(fs::read(file).unwrap(), b"access restored");
}

#[test]
fn permission_journal_cannot_restore_another_mount() {
    let temp = tempfile::tempdir().unwrap();
    let one = temp.path().join("one");
    let two = temp.path().join("two");
    fs::create_dir(&one).unwrap();
    fs::create_dir(&two).unwrap();
    let journal = temp.path().join("permissions.json");
    let mut guard = ReadOnlyMount::open(&one, journal.clone()).unwrap();
    guard.set_read_only(true).unwrap();
    assert!(ReadOnlyMount::open(&two, journal).is_err());
    guard.restore().unwrap();
}
