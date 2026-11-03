// Tests Client::resolve_home_dir() and find_session_file_path() in crates/client/src/state/client/session.rs under test: they point at a per-test empty folder, never the real home.
use super::*;
use crate::network::MockNetwork;
use crate::storage::MockStorage;

type TestClient = Client<MockStorage, MockNetwork>;

#[test]
fn tests_never_resolve_the_real_home_folder() {
    let home = TestClient::resolve_home_dir().expect("test home");
    if let Some(real) = std::env::var_os("HOME") {
        assert_ne!(home, std::path::PathBuf::from(real));
    }
    assert!(home.starts_with(std::env::temp_dir()) || home.starts_with(std::fs::canonicalize(std::env::temp_dir()).unwrap()));
    assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0, "starts empty");

    let client = TestClient::new(Ed25519KeyPair::generate(), Arc::new(MockStorage::new()), Arc::new(MockNetwork::new()));
    // With no session in the test home there is nothing to find, whatever the real home holds.
    match client.find_session_file_path() {
        Ok(path) => assert!(path.starts_with(&home), "{path:?} is outside the test home"),
        Err(_) => {}
    }
}

#[test]
fn each_test_thread_gets_its_own_home() {
    let here = test_home::current();
    let other = std::thread::spawn(test_home::current).join().unwrap();
    assert_ne!(here, other);
}
