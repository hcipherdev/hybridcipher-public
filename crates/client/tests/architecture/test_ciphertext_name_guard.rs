// Tests that production Rust code outside src/file/ciphertext.rs never checks `.encrypted` names itself.
//
// Folder records share the `.encrypted` suffix, and every hand-written suffix
// check so far has forgotten them (coverage scans, key rotation, removing
// protection). Use `hybridcipher_client::file::ciphertext::classify` instead.
use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    "Some(\"encrypted\")",
    "OsStr::new(\"encrypted\")",
    "eq_ignore_ascii_case(\"encrypted\")",
    "== \"encrypted\"",
    "!= \"encrypted\"",
    "ends_with(\".encrypted\")",
    "trim_end_matches(\".encrypted\")",
    "strip_suffix(\".encrypted\")",
    "replace(\".encrypted\"",
    "= \".encrypted\";",
    "\".hybridcipher_dir.encrypted\"",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn is_test_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "tests.rs" || name.ends_with("_tests.rs") || name.starts_with("test_")
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if !matches!(
                name.to_str(),
                Some("target" | "tests" | "examples" | "node_modules")
            ) {
                collect_rust_files(&path, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") && !is_test_file(&path)
        {
            out.push(path);
        }
    }
}

/// Lines before the file's inline `#[cfg(test)] mod name {` block.
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut kept = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            let next = lines[index + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
                .unwrap_or("");
            if (next.starts_with("mod ") || next.starts_with("pub mod ")) && next.ends_with('{') {
                break;
            }
        }
        kept.push((index + 1, *line));
    }
    kept
}

fn violations_in(path: &Path, source: &str) -> Vec<String> {
    production_lines(source)
        .into_iter()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .filter(|(_, line)| FORBIDDEN.iter().any(|pattern| line.contains(pattern)))
        .map(|(number, line)| format!("{}:{number}: {}", path.display(), line.trim()))
        .collect()
}

#[test]
fn only_the_classifier_checks_encrypted_names() {
    let root = repo_root();
    let classifier = root.join("crates/client/src/file/ciphertext.rs");
    let mut files = Vec::new();
    let crates = fs::read_dir(root.join("crates")).expect("read crates");
    for krate in crates.flatten() {
        collect_rust_files(&krate.path().join("src"), &mut files);
    }
    collect_rust_files(&root.join("apps/desktop/src-tauri/src"), &mut files);
    assert!(files.len() > 50, "found only {} source files", files.len());

    let mut violations = Vec::new();
    for file in files {
        if fs::canonicalize(&file).ok() == fs::canonicalize(&classifier).ok() {
            continue;
        }
        let source = fs::read_to_string(&file).expect("read source");
        violations.extend(violations_in(file.strip_prefix(&root).unwrap_or(&file), &source));
    }
    assert!(
        violations.is_empty(),
        "Use hybridcipher_client::file::ciphertext::classify (or strip_encrypted_suffix) \
         instead of checking `.encrypted` names directly:\n{}",
        violations.join("\n")
    );
}

#[test]
fn guard_catches_a_hand_written_check_and_skips_test_modules() {
    let source = "fn a(p: &Path) -> bool {\n    p.extension() == Some(OsStr::new(\"encrypted\"))\n}\n\
                  #[cfg(test)]\nmod tests {\n    const N: &str = \".hybridcipher_dir.encrypted\";\n}\n";
    let found = violations_in(Path::new("x.rs"), source);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].starts_with("x.rs:2:"));
}
