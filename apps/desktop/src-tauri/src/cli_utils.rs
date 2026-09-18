use std::path::{Path, PathBuf};

fn push_unique(candidates: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !candidates.iter().any(|existing| existing == &candidate) {
        candidates.push(candidate);
    }
}

fn app_bundle_cli_candidates(binary_name: &str) -> Vec<PathBuf> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let Some(exe_dir) = exe.parent() else {
        return Vec::new();
    };

    let mut candidates = Vec::new();

    // Tauri Windows/Linux bundles commonly stage resources next to the executable.
    push_unique(
        &mut candidates,
        exe_dir.join("resources/bin").join(binary_name),
    );
    // Windows tauri.conf.json packages exactly resources/bin. Do not treat a
    // loose executable beside the app as a replacement for a missing bundle.
    #[cfg(not(target_os = "windows"))]
    push_unique(&mut candidates, exe_dir.join("resources").join(binary_name));

    #[cfg(target_os = "macos")]
    {
        // macOS app bundle layouts.
        push_unique(
            &mut candidates,
            exe_dir.join("../Resources/bin").join(binary_name),
        );
        push_unique(
            &mut candidates,
            exe_dir.join("../Resources/resources/bin").join(binary_name),
        );
        push_unique(
            &mut candidates,
            exe_dir.join("../Resources").join(binary_name),
        );
        push_unique(
            &mut candidates,
            exe_dir.join("../Resources/resources").join(binary_name),
        );
    }

    // Other supported package layouts.
    #[cfg(not(target_os = "windows"))]
    push_unique(&mut candidates, exe_dir.join(binary_name));

    candidates
}

#[cfg(debug_assertions)]
fn candidate_roots_for_dev_search(_current_dir: &Path) -> Vec<PathBuf> {
    // Compile-time workspace only: never search the launch working directory.
    vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")]
}

#[cfg(debug_assertions)]
fn development_cli_candidates(binary_name: &str, current_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for root in candidate_roots_for_dev_search(current_dir) {
        for profile in ["release", "debug"] {
            push_unique(
                &mut candidates,
                root.join("target").join(profile).join(binary_name),
            );
            push_unique(
                &mut candidates,
                root.join("target")
                    .join(profile)
                    .join("resources")
                    .join("bin")
                    .join(binary_name),
            );
        }
    }

    candidates
}

/// Locate a CLI binary that is bundled with the desktop application package.
pub fn locate_bundled_cli_binary() -> Option<PathBuf> {
    let binary_name = format!("hybridcipher{}", std::env::consts::EXE_SUFFIX);
    app_bundle_cli_candidates(&binary_name)
        .into_iter()
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| candidate.canonicalize().ok())
}

/// Locate the locally built `hybridcipher` CLI binary and its project root.
pub fn locate_cli_binary() -> Result<(PathBuf, PathBuf), String> {
    let fallback = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .ok_or("Application directory is unavailable")?
        .to_path_buf();
    if let Some(candidate) = locate_bundled_cli_binary() {
        return Ok((candidate, fallback));
    }
    #[cfg(debug_assertions)]
    {
        let binary_name = format!("hybridcipher{}", std::env::consts::EXE_SUFFIX);
        for candidate in development_cli_candidates(&binary_name, &fallback) {
            if candidate.is_file() {
                let candidate = candidate.canonicalize().map_err(|e| e.to_string())?;
                return Ok((candidate.clone(), infer_project_root(&candidate, &fallback)));
            }
        }
    }
    Err("The bundled HybridCipher CLI is missing. Repair or reinstall the application.".into())
}

fn infer_project_root(binary_path: &Path, fallback: &Path) -> PathBuf {
    binary_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| fallback.to_path_buf())
}

#[cfg(all(test, debug_assertions))]
mod security_regression {
    use super::*;
    #[test]
    fn development_discovery_does_not_search_working_directory() {
        let untrusted = std::env::temp_dir().join("attacker-controlled-cwd");
        let candidates = development_cli_candidates("hybridcipher.exe", &untrusted);
        assert!(!candidates.is_empty());
        assert!(candidates
            .iter()
            .all(|candidate| !candidate.starts_with(&untrusted)));
        assert_eq!(
            candidate_roots_for_dev_search(&untrusted),
            vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")]
        );
    }
}
