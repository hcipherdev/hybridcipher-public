use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("hybridcipher").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("HybridCipher"))
        .stdout(predicate::str::contains("Post-quantum"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("hybridcipher").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn test_rekey_help() {
    let mut cmd = Command::cargo_bin("hybridcipher").unwrap();
    cmd.args(&["rekey", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Rekey management"))
        .stdout(predicate::str::contains("start"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("cutover"))
        .stdout(predicate::str::contains("fallback"));
}

#[test]
fn test_coverage_help() {
    let mut cmd = Command::cargo_bin("hybridcipher").unwrap();
    cmd.args(&["coverage", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Coverage audit"))
        .stdout(predicate::str::contains("audit"))
        .stdout(predicate::str::contains("pending"))
        .stdout(predicate::str::contains("verify"));
}

#[test]
fn test_authentication_required() {
    let temp = TempDir::new().expect("temp dir");
    let config_path = temp.path().to_str().unwrap();

    let mut cmd = Command::cargo_bin("hybridcipher").unwrap();
    cmd.args(&["--config", config_path, "rekey", "status"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Not authenticated"));
}
