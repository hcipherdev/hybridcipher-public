//! Records the git commit the CLI is built from, so the desktop app can tell when its bundled
//! CLI comes from a different build than itself.
use std::process::Command;

fn main() {
    record_build_commit();
}

/// `HYBRIDCIPHER_BUILD_COMMIT`: the environment's value when set (builds without git),
/// otherwise the short HEAD commit, or "unknown". Re-runs whenever HEAD moves.
fn record_build_commit() {
    println!("cargo:rerun-if-env-changed=HYBRIDCIPHER_BUILD_COMMIT");
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let commit = std::env::var("HYBRIDCIPHER_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| git(&["rev-parse", "--short=12", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=HYBRIDCIPHER_BUILD_COMMIT={commit}");

    // --git-path resolves inside worktrees too.
    let mut watched = vec!["HEAD".to_string(), "packed-refs".to_string()];
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watched.push(reference);
    }
    for name in watched {
        if let Some(path) = git(&["rev-parse", "--git-path", &name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}
