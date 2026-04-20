use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Append an audit entry as JSONL to the provided path.
pub fn append_jsonl<T: Serialize>(path: &Path, entry: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut serialized = serde_json::to_string(entry)
        .unwrap_or_else(|_| format!(r#"{{"error":"failed to serialize","ts":"{}"}}"#, Utc::now()));
    serialized.push('\n');
    file.write_all(serialized.as_bytes())
}
