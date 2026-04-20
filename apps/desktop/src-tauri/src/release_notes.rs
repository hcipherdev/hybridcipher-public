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

pub fn load_release_notes_from_dir(base_dir: &Path) -> Result<Vec<ReleaseNoteEntry>, String> {
    let path = base_dir.join("releases.json");
    let content = fs::read_to_string(&path)
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

    if releases.is_empty() {
        return Err(format!(
            "No versioned release notes were found in {}",
            path.display()
        ));
    }

    Ok(releases)
}

pub fn load_release_notes(resource_dir: Option<&Path>) -> Result<ReleaseNotesPayload, String> {
    if let Some(resource_dir) = resource_dir {
        let bundled_dir = resource_dir.join("release-notes");
        if bundled_dir.exists() {
            return Ok(ReleaseNotesPayload {
                current_version: env!("CARGO_PKG_VERSION").to_string(),
                releases: load_release_notes_from_dir(&bundled_dir)?,
            });
        }
    }

    Ok(ReleaseNotesPayload {
        current_version: env!("CARGO_PKG_VERSION").to_string(),
        releases: load_release_notes_from_dir(&release_notes_fallback_dir())?,
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
    fn falls_back_to_repo_release_notes_in_dev() {
        let payload = load_release_notes(None).expect("load fallback release notes");

        assert_eq!(payload.current_version, env!("CARGO_PKG_VERSION"));
        assert!(!payload.releases.is_empty());
        assert!(payload
            .releases
            .iter()
            .any(|entry| entry.version == env!("CARGO_PKG_VERSION")));
    }
}
