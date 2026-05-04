use std::path::{Path, PathBuf};

#[cfg(not(feature = "individual-edition"))]
fn is_truthy_env(var: &str) -> bool {
    std::env::var(var)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn app_bundle_cli_candidates(binary_name: &str) -> Vec<PathBuf> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let Some(macos_dir) = exe.parent() else {
        return Vec::new();
    };

    vec![
        // .../HybridCipher.app/Contents/Resources/bin/hybridcipher
        macos_dir.join("../Resources/bin").join(binary_name),
        // .../HybridCipher.app/Contents/Resources/resources/bin/hybridcipher
        macos_dir
            .join("../Resources/resources/bin")
            .join(binary_name),
        // .../HybridCipher.app/Contents/Resources/hybridcipher
        macos_dir.join("../Resources").join(binary_name),
        // .../HybridCipher.app/Contents/Resources/resources/hybridcipher
        macos_dir.join("../Resources/resources").join(binary_name),
        // Same folder as desktop executable (fallback)
        macos_dir.join(binary_name),
    ]
}

/// Locate a CLI binary that is bundled with the desktop application package.
pub fn locate_bundled_cli_binary() -> Option<PathBuf> {
    let binary_name = format!("hybridcipher{}", std::env::consts::EXE_SUFFIX);
    app_bundle_cli_candidates(&binary_name)
        .into_iter()
        .find(|candidate| candidate.exists())
}

/// Locate the locally built `hybridcipher` CLI binary and its project root.
pub fn locate_cli_binary() -> Result<(PathBuf, PathBuf), String> {
    let current_dir =
        std::env::current_dir().map_err(|e| format!("Failed to read current directory: {}", e))?;

    let exe_suffix = std::env::consts::EXE_SUFFIX;
    let binary_name = format!("hybridcipher{}", exe_suffix);

    #[cfg(feature = "individual-edition")]
    {
        if let Some(candidate) = locate_bundled_cli_binary() {
            return Ok((candidate, current_dir.clone()));
        }

        for profile in ["release", "debug"] {
            let candidate = current_dir
                .join("../../../target")
                .join(profile)
                .join(&binary_name);

            if candidate.exists() {
                let project_root = infer_project_root(&candidate, &current_dir);
                return Ok((candidate, project_root));
            }
        }

        return Err(
            "This restricted desktop build requires the bundled `hybridcipher` CLI (or a workspace-built binary in local development). Rebuild the desktop bundle with the restricted CLI included.".to_string(),
        );
    }

    #[cfg(not(feature = "individual-edition"))]
    {
        // 1) Explicit override for packaged or custom installs.
        if let Some(path) = std::env::var_os("HYBRIDCIPHER_CLI_PATH") {
            let candidate = PathBuf::from(path);
            if candidate.exists() {
                return Ok((candidate, current_dir.clone()));
            }
        }

        // 2) Common packaged-app locations relative to the running executable.
        if let Some(candidate) = locate_bundled_cli_binary() {
            return Ok((candidate, current_dir.clone()));
        }

        // 3) Development workspace build outputs.
        for profile in ["release", "debug"] {
            let candidate = current_dir
                .join("../../../target")
                .join(profile)
                .join(&binary_name);

            if candidate.exists() {
                let project_root = infer_project_root(&candidate, &current_dir);
                return Ok((candidate, project_root));
            }
        }

        // In local debug runs, avoid silently falling back to a system-installed CLI because
        // it may be stale and diverge from current workspace code.
        if cfg!(debug_assertions)
            && !is_truthy_env("HYBRIDCIPHER_ALLOW_SYSTEM_CLI_IN_DEV")
            && std::env::var_os("HYBRIDCIPHER_CLI_PATH").is_none()
        {
            return Err(
                "Desktop (debug) could not find a workspace-built `hybridcipher` binary under target/{release,debug}. Build it with `cargo build --release --bin hybridcipher` or set HYBRIDCIPHER_CLI_PATH explicitly. To allow system fallback in dev, set HYBRIDCIPHER_ALLOW_SYSTEM_CLI_IN_DEV=1.".to_string(),
            );
        }

        // 4) Standard install locations for .pkg deployments.
        let installed_candidates = [
            PathBuf::from(format!("/usr/local/bin/{}", binary_name)),
            PathBuf::from(format!("/opt/homebrew/bin/{}", binary_name)),
            PathBuf::from(format!("/opt/local/bin/{}", binary_name)),
        ];
        for candidate in installed_candidates {
            if candidate.exists() {
                return Ok((candidate, current_dir.clone()));
            }
        }

        // 5) PATH lookup for shell-launched apps/dev workflows.
        if let Ok(path) = which::which("hybridcipher") {
            return Ok((path, current_dir.clone()));
        }

        return Err(
            "Could not find the `hybridcipher` CLI binary. Install it (for example with the macOS .pkg), set HYBRIDCIPHER_CLI_PATH, or build it with `cargo build --release --bin hybridcipher`.".to_string(),
        );
    }

    #[allow(unreachable_code)]
    Err("Could not find the `hybridcipher` CLI binary.".to_string())
}

fn infer_project_root(binary_path: &Path, fallback: &Path) -> PathBuf {
    binary_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| fallback.to_path_buf())
}
