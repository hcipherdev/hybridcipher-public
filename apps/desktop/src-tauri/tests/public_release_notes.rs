use hybridcipher_desktop::release_notes::load_release_notes_from_dir;

fn catalog(version: &str) -> String {
    format!(r#"{{"releases":[{{"version":"{version}","published_at":"2026-09-27"}}]}}"#)
}

#[test]
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn platform_catalog_loads_without_shared_source_file() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("releases.windows.json"),
        catalog("7.8.9"),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("releases.macos.json"),
        catalog("2.3.4"),
    )
    .unwrap();
    let releases = load_release_notes_from_dir(directory.path()).unwrap();
    let expected = if cfg!(target_os = "windows") {
        "7.8.9"
    } else {
        "2.3.4"
    };
    assert_eq!(releases[0].version, expected);
}

#[test]
fn bundled_alias_keeps_precedence() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("releases.json"), catalog("9.9.9")).unwrap();
    std::fs::write(
        directory.path().join("releases.windows.json"),
        catalog("7.8.9"),
    )
    .unwrap();
    assert_eq!(
        load_release_notes_from_dir(directory.path()).unwrap()[0].version,
        "9.9.9"
    );
}

#[test]
fn malformed_alias_is_rejected_without_fallback() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("releases.json"), "invalid JSON").unwrap();
    std::fs::write(
        directory.path().join("releases.windows.json"),
        catalog("7.8.9"),
    )
    .unwrap();
    assert!(load_release_notes_from_dir(directory.path()).is_err());
}
