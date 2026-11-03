//! Decides whether a path the UI asks to open may go to the OS launcher. Only folders
//! and allow-listed document types are opened; programs, scripts, shortcuts, bundles
//! and anything unrecognised are revealed in the file manager instead, so a synced
//! file can never be launched through `open_path_in_shell`.

use std::io;
use std::path::Path;

#[cfg(test)]
#[path = "../../tests/operations/test_path_opener.rs"]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenDecision {
    OpenFolder,
    OpenDocument,
    Reveal,
}

/// Document types that open in a viewer or editor, never as a program. Macro-capable
/// Office formats and browser-rendered types (html, svg) are intentionally absent.
const DOCUMENT_EXTENSIONS: &[&str] = &[
    "txt", "md", "markdown", "csv", "tsv", "json", "log", "rtf", "pdf", "png", "jpg", "jpeg",
    "gif", "webp", "heic", "heif", "bmp", "tif", "tiff", "docx", "xlsx", "pptx", "odt", "ods",
    "odp", "pages", "numbers", "key", "mp3", "m4a", "wav", "aac", "flac", "ogg", "mp4", "m4v",
    "mov", "avi", "mkv", "webm", "zip",
];

/// Directory extensions that macOS treats as packages and launches instead of browsing.
const BUNDLE_EXTENSIONS: &[&str] = &[
    "app",
    "bundle",
    "framework",
    "plugin",
    "appex",
    "xpc",
    "kext",
    "prefpane",
    "saver",
    "qlgenerator",
    "mdimporter",
    "systemextension",
    "workflow",
    "action",
    "scptd",
    "pkg",
    "mpkg",
];

/// Lower-case extension of the final path component, ignoring trailing dots and spaces
/// (Windows drops them, so `evil.exe.` runs as `evil.exe`).
fn normalized_extension(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let trimmed = name.trim_end_matches(['.', ' ']);
    let (stem, extension) = trimmed.rsplit_once('.')?;
    if stem.is_empty() || extension.is_empty() {
        return None;
    }
    Some(extension.to_ascii_lowercase())
}

#[cfg(unix)]
fn has_execute_bit(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn has_execute_bit(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Decide how to handle `path`. Symlinks and `..` are resolved first, so the decision
/// is about the file that would actually be opened.
pub(crate) fn decide_open(path: &Path) -> io::Result<OpenDecision> {
    let target = std::fs::canonicalize(path)?;
    let metadata = std::fs::metadata(&target)?;
    let extension = normalized_extension(&target);

    if metadata.is_dir() {
        let is_bundle = extension
            .as_deref()
            .is_some_and(|ext| BUNDLE_EXTENSIONS.contains(&ext));
        return Ok(if is_bundle {
            OpenDecision::Reveal
        } else {
            OpenDecision::OpenFolder
        });
    }

    let is_document = metadata.is_file()
        && !has_execute_bit(&metadata)
        && extension
            .as_deref()
            .is_some_and(|ext| DOCUMENT_EXTENSIONS.contains(&ext));
    Ok(if is_document {
        OpenDecision::OpenDocument
    } else {
        OpenDecision::Reveal
    })
}
