use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseNoteEntry {
    pub version: String,
    pub published_at: String,
    #[serde(default)]
    pub highlights: Vec<String>,
    #[serde(default)]
    pub important_changes: Vec<String>,
    #[serde(default)]
    pub fixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseNotesPayload {
    pub current_version: String,
    pub releases: Vec<ReleaseNoteEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReleaseNotesDocument {
    releases: Vec<ReleaseNoteEntry>,
}

pub fn release_notes_fallback_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("release-notes")
}

fn release_notes_fallback_file_name_for_os(os: &str) -> &'static str {
    match os {
        "macos" => "releases.macos.json",
        "windows" => "releases.windows.json",
        _ => "releases.json",
    }
}

fn release_notes_fallback_path() -> PathBuf {
    release_notes_fallback_dir().join(release_notes_fallback_file_name_for_os(
        std::env::consts::OS,
    ))
}

pub fn load_release_notes_from_dir(base_dir: &Path) -> Result<Vec<ReleaseNoteEntry>, String> {
    let bundled_alias = base_dir.join("releases.json");
    if bundled_alias.exists() {
        return load_release_notes_from_path(&bundled_alias);
    }
    load_release_notes_from_path(&base_dir.join(release_notes_fallback_file_name_for_os(
        std::env::consts::OS,
    )))
}

fn load_release_notes_from_path(path: &Path) -> Result<Vec<ReleaseNoteEntry>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read release notes {}: {}", path.display(), error))?;
    let parsed: ReleaseNotesDocument = serde_json::from_str(&content).map_err(|error| {
        format!(
            "Failed to parse release notes {}: {}",
            path.display(),
            error
        )
    })?;

    let releases = parsed
        .releases
        .into_iter()
        .filter(|entry| !entry.version.trim().is_empty())
        .collect::<Vec<_>>();

    Ok(releases)
}

pub fn load_release_notes(
    resource_dir: Option<&Path>,
    current_version: &str,
) -> Result<ReleaseNotesPayload, String> {
    let fallback_path = release_notes_fallback_path();

    // Development runs should reflect the editable catalog for the build host,
    // even when Tauri has copied the general catalog into a local resource dir.
    if cfg!(debug_assertions) && fallback_path.exists() {
        return Ok(ReleaseNotesPayload {
            current_version: current_version.to_string(),
            releases: load_release_notes_from_path(&fallback_path)?,
        });
    }

    if let Some(resource_dir) = resource_dir {
        // Resource maps use the first layout; Tauri's default ../release-notes
        // directory resource uses _up_/release-notes in unsigned bundles.
        for bundled_dir in [
            resource_dir.join("release-notes"),
            resource_dir.join("_up_").join("release-notes"),
        ] {
            if bundled_dir.exists() {
                return Ok(ReleaseNotesPayload {
                    current_version: current_version.to_string(),
                    releases: load_release_notes_from_dir(&bundled_dir)?,
                });
            }
        }
    }

    Ok(ReleaseNotesPayload {
        current_version: current_version.to_string(),
        releases: load_release_notes_from_path(&fallback_path)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn loads_release_notes_from_dir() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("releases.json"),
            r#"{
                "releases": [
                    {
                        "version": "0.1.0",
                        "published_at": "2026-03-25",
                        "highlights": ["Highlight"],
                        "important_changes": ["Important"],
                        "fixes": ["Fix"]
                    }
                ]
            }"#,
        )
        .expect("write release notes");

        let releases = load_release_notes_from_dir(temp_dir.path()).expect("load releases");

        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, "0.1.0");
        assert_eq!(releases[0].highlights, vec!["Highlight".to_string()]);
    }

    #[test]
    fn accepts_an_empty_platform_catalog() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(temp_dir.path().join("releases.json"), r#"{"releases":[]}"#)
            .expect("write empty catalog");

        let releases = load_release_notes_from_dir(temp_dir.path()).expect("load empty catalog");

        assert!(releases.is_empty());
    }

    #[test]
    fn selects_platform_catalog_for_development_fallback() {
        assert_eq!(
            release_notes_fallback_file_name_for_os("macos"),
            "releases.macos.json"
        );
        assert_eq!(
            release_notes_fallback_file_name_for_os("windows"),
            "releases.windows.json"
        );
        assert_eq!(
            release_notes_fallback_file_name_for_os("linux"),
            "releases.json"
        );

        let payload = load_release_notes(None, "7.8.9").expect("load platform fallback catalog");
        assert_eq!(payload.current_version, "7.8.9");
        assert!(release_notes_fallback_path().exists());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn development_prefers_platform_catalog_over_bundled_general_catalog() {
        let temp_dir = tempdir().expect("temp dir");
        let bundled_dir = temp_dir.path().join("release-notes");
        fs::create_dir_all(&bundled_dir).expect("create bundled release-notes dir");
        fs::write(
            bundled_dir.join("releases.json"),
            r#"{"releases":[{"version":"99.0.0","published_at":"2026-01-01"}]}"#,
        )
        .expect("write bundled general catalog");

        let payload =
            load_release_notes(Some(temp_dir.path()), "7.8.9").expect("load development catalog");
        let expected = load_release_notes_from_path(&release_notes_fallback_path())
            .expect("load platform fallback catalog");

        assert_eq!(payload.releases, expected);
    }

    #[test]
    fn falls_back_to_repo_release_notes_in_dev() {
        let payload = load_release_notes(None, "7.8.9").expect("load fallback release notes");

        assert_eq!(payload.current_version, "7.8.9");
        // The Windows catalog intentionally starts empty; other platform
        // catalogs can have a newer version than the app package.
    }
}
