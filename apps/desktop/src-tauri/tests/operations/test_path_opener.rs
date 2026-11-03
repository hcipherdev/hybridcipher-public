// Tests decide_open() in src/commands/path_opener.rs: only folders and allow-listed documents are opened; programs, scripts, shortcuts, bundles, executables and symlinks to them are revealed.
use super::*;
use std::fs;
use std::path::PathBuf;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "hc-path-opener-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn file(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, b"content").unwrap();
        path
    }

    fn dir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(&path).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn decision(path: &Path) -> OpenDecision {
    decide_open(path).unwrap()
}

#[test]
fn allow_listed_documents_open() {
    let temp = TempDir::new("docs");
    for name in [
        "report.pdf",
        "Photo.JPG",
        "notes.txt",
        "sheet.xlsx",
        "clip.mp4",
    ] {
        assert_eq!(
            decision(&temp.file(name)),
            OpenDecision::OpenDocument,
            "{name}"
        );
    }
}

#[test]
fn programs_scripts_shortcuts_and_unknown_types_are_revealed() {
    let temp = TempDir::new("programs");
    for name in [
        "setup.exe",
        "run.bat",
        "x.lnk",
        "a.scr",
        "script.sh",
        "page.html",
        "image.svg",
        "notes.docm",
        "legacy.doc",
        "shortcut.url",
        "no-extension",
        ".hidden",
    ] {
        assert_eq!(decision(&temp.file(name)), OpenDecision::Reveal, "{name}");
    }
}

#[test]
fn trailing_dots_and_spaces_do_not_hide_the_real_extension() {
    assert_eq!(
        normalized_extension(Path::new("evil.exe.")).as_deref(),
        Some("exe")
    );
    assert_eq!(
        normalized_extension(Path::new("evil.exe ")).as_deref(),
        Some("exe")
    );
    assert_eq!(
        normalized_extension(Path::new("report.PDF")).as_deref(),
        Some("pdf")
    );
    assert_eq!(normalized_extension(Path::new(".bashrc")), None);
}

#[cfg(unix)]
#[test]
fn executable_documents_are_revealed() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new("exec");
    let path = temp.file("notes.txt");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(decision(&path), OpenDecision::Reveal);
}

#[test]
fn folders_open_but_bundles_are_revealed() {
    let temp = TempDir::new("folders");
    assert_eq!(decision(&temp.dir("Project")), OpenDecision::OpenFolder);
    assert_eq!(decision(&temp.dir("project.v2")), OpenDecision::OpenFolder);
    assert_eq!(decision(&temp.dir("Calc.app")), OpenDecision::Reveal);
    assert_eq!(decision(&temp.dir("Installer.PKG")), OpenDecision::Reveal);
}

#[cfg(unix)]
#[test]
fn symlinks_are_judged_by_their_target() {
    let temp = TempDir::new("links");
    let app = temp.dir("Calc.app");
    let exe = temp.file("setup.exe");
    let pdf = temp.file("real.pdf");

    let to_app = temp.0.join("doc.txt");
    std::os::unix::fs::symlink(&app, &to_app).unwrap();
    assert_eq!(decision(&to_app), OpenDecision::Reveal);

    let to_exe = temp.0.join("readme.txt");
    std::os::unix::fs::symlink(&exe, &to_exe).unwrap();
    assert_eq!(decision(&to_exe), OpenDecision::Reveal);

    let to_pdf = temp.0.join("link");
    std::os::unix::fs::symlink(&pdf, &to_pdf).unwrap();
    assert_eq!(decision(&to_pdf), OpenDecision::OpenDocument);
}

#[test]
fn missing_paths_are_errors() {
    let temp = TempDir::new("missing");
    assert!(decide_open(&temp.0.join("gone.pdf")).is_err());
}
