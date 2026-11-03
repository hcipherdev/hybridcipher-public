// Tests CoverageIpcServer::start() and CoverageIpcClient in crates/client/src/ipc/coverage.rs: requests (including the key state report) round-trip over the platform transport (a Unix socket, or on Windows a named pipe found through the marker file) and the endpoint is gone after shutdown.
use super::*;
use crate::network::MockNetwork;
use crate::storage::LocalFsStorage;
use hybridcipher_crypto::signatures::Ed25519KeyPair;

#[tokio::test]
async fn requests_round_trip_over_the_platform_transport() {
    let dir = tempfile::tempdir().unwrap();
    let client = Client::new(
        Ed25519KeyPair::generate(),
        Arc::new(LocalFsStorage::new(dir.path().join("account"))),
        Arc::new(MockNetwork::new()),
    );
    let socket_path = dir.path().join("coverage_ipc.sock");
    let server = CoverageIpcServer::start(socket_path.clone(), Arc::new(client))
        .await
        .expect("start the coverage service");
    assert!(
        socket_path.exists(),
        "the CLI discovers the service by this path"
    );

    let ipc = CoverageIpcClient::new(socket_path.clone());
    ipc.ping().await.expect("ping");
    // Several requests in a row, each on its own connection.
    for _ in 0..3 {
        assert!(ipc.coverage_roots().await.expect("list roots").is_empty());
    }
    let report = ipc.key_state_report().await.expect("key state");
    assert!(report.folders.is_empty());

    server.shutdown().await;
    assert!(!socket_path.exists(), "shutdown removes the endpoint");
    let after = ipc.ping().await;
    assert!(
        matches!(&after, Err(error) if error.is_connection_error()),
        "a stopped service reads as unavailable, got {after:?}"
    );
}

#[cfg(windows)]
#[test]
fn pipe_names_follow_the_marker_path() {
    let a = windows_pipe::pipe_name(Path::new(
        r"C:\Users\xc\.hybridcipher\users\a\coverage_ipc.sock",
    ));
    let b = windows_pipe::pipe_name(Path::new(
        r"C:\Users\xc\.hybridcipher\users\b\coverage_ipc.sock",
    ));
    assert!(a.starts_with(r"\\.\pipe\hybridcipher-coverage-"));
    assert_ne!(a, b, "each account folder gets its own pipe");
    assert_eq!(
        a,
        windows_pipe::pipe_name(Path::new(
            r"C:\Users\xc\.hybridcipher\users\a\coverage_ipc.sock"
        ))
    );
}
