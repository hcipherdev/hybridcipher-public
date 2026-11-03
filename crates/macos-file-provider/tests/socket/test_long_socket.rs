// Tests bind and connect in crates/macos-file-provider/src/long_socket.rs: sockets at paths longer than the 104-byte sockaddr_un field, and the length limit.
use super::*;
use std::io::{Read, Write};

/// A folder like `~/Library/Group Containers/<team>.group.com.hybridcipher.macOS`
/// under a long user name: well past the 104-byte socket address field.
fn long_directory(root: &Path) -> std::path::PathBuf {
    let directory = root
        .join("Users")
        .join("a-person-with-a-really-long-account-name")
        .join("Library")
        .join("Group Containers")
        .join("G2L88C9692.group.com.hybridcipher.macOS");
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn a_socket_past_the_address_field_binds_and_connects() {
    let temp = tempfile::tempdir().unwrap();
    let path = long_directory(temp.path()).join("00741c18f05f45f2.sock");
    #[cfg(target_os = "macos")]
    assert!(
        path.as_os_str().len() > 104,
        "the test needs a path the plain socket address can't hold"
    );

    let listener = bind(&path).unwrap();
    assert!(path.exists(), "the socket file is created at its full path");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).unwrap();
        stream.write_all(&request).unwrap();
    });

    let mut client = connect(&path).unwrap();
    client.write_all(b"ping").unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"ping");
    server.join().unwrap();
}

#[test]
fn connecting_where_nobody_listens_fails_cleanly() {
    let temp = tempfile::tempdir().unwrap();
    let path = long_directory(temp.path()).join("nobody.sock");
    assert!(connect(&path).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn a_path_past_the_kernel_limit_is_refused_with_a_clear_error() {
    let too_long = Path::new("/").join("d".repeat(MAX_SOCKET_PATH_LEN));
    let error = bind(&too_long).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("longer than"));
}
