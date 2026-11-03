// Tests cli_matches_app_build() in src/cli_utils.rs: the app recognises a bundled CLI from another build by the commit in its --version line.
use super::*;

#[test]
fn the_bundled_cli_matches_only_its_own_build() {
    assert!(cli_matches_app_build(&format!("hybridcipher 0.1.0 ({APP_BUILD_COMMIT})")));
    assert!(!cli_matches_app_build("hybridcipher 0.1.0 (000000000000)") || APP_BUILD_COMMIT == "unknown");
    // A CLI from before commits were recorded is from another build.
    assert!(!cli_matches_app_build("hybridcipher 0.1.0"));
    // An unknown commit on the CLI side is not called a mismatch.
    assert!(cli_matches_app_build("hybridcipher 0.1.0 (unknown)"));
}
