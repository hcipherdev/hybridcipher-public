//! Unix sockets at paths longer than `sockaddr_un.sun_path`.
//!
//! `sun_path` holds 104 bytes on macOS, and the app-group container path
//! (`~/Library/Group Containers/<team>.group.com.hybridcipher.macOS`) uses most
//! of that before the file name, so a longer user name overflowed it. The
//! sandboxed extension can only reach sockets inside that container, so a
//! shorter fallback location is no answer. The kernel limits the address by its
//! length byte (`sun_len`, up to 255), not by the struct's field, so both sides
//! pass an oversized address. The standard library refuses paths over 104 bytes,
//! hence the raw calls. The Swift extension builds the same address
//! (`ProviderBridgeClient.connectSocket`).

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

/// Longest socket path an address can carry: 255 bytes less the family and
/// length bytes and the trailing NUL.
pub(crate) const MAX_SOCKET_PATH_LEN: usize = 252;

#[cfg(target_os = "macos")]
mod imp {
    use super::MAX_SOCKET_PATH_LEN;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    const LISTEN_BACKLOG: libc::c_int = 128;
    const SUN_PATH_OFFSET: usize = std::mem::offset_of!(libc::sockaddr_un, sun_path);

    /// A `sockaddr_un` followed by room for a path past its 104-byte field.
    #[repr(C)]
    struct LongAddress {
        address: libc::sockaddr_un,
        overflow: [u8; 256 - std::mem::size_of::<libc::sockaddr_un>()],
    }

    fn address(path: &Path) -> io::Result<(LongAddress, libc::socklen_t)> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path must be non-empty and contain no NUL",
            ));
        }
        if bytes.len() > MAX_SOCKET_PATH_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "socket path is longer than {MAX_SOCKET_PATH_LEN} bytes: {}",
                    path.display()
                ),
            ));
        }
        // SAFETY: plain data; all-zero is a valid empty address.
        let mut long: LongAddress = unsafe { std::mem::zeroed() };
        let length = SUN_PATH_OFFSET + bytes.len() + 1;
        long.address.sun_len = length as u8;
        long.address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        // SAFETY: the path, its NUL included, fits in the 256-byte buffer after
        // the offset (checked above); the copy stays inside `long`.
        unsafe {
            let start = (&mut long as *mut LongAddress).cast::<u8>().add(SUN_PATH_OFFSET);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), start, bytes.len());
        }
        Ok((long, length as libc::socklen_t))
    }

    fn new_socket() -> io::Result<OwnedFd> {
        // SAFETY: plain syscalls; the descriptor is owned right after creation.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    pub fn bind(path: &Path) -> io::Result<UnixListener> {
        let (address, length) = address(path)?;
        let socket = new_socket()?;
        // SAFETY: `address` outlives the call and `length` covers its initialised prefix.
        let bound = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const LongAddress).cast(),
                length,
            )
        };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::listen(socket.as_raw_fd(), LISTEN_BACKLOG) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(UnixListener::from(socket))
    }

    pub fn connect(path: &Path) -> io::Result<UnixStream> {
        let (address, length) = address(path)?;
        let socket = new_socket()?;
        // SAFETY: as in `bind`.
        let connected = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&address as *const LongAddress).cast(),
                length,
            )
        };
        if connected < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(UnixStream::from(socket))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::io;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    // Only macOS runs the File Provider; elsewhere the standard calls serve the tests.
    pub fn bind(path: &Path) -> io::Result<UnixListener> {
        UnixListener::bind(path)
    }

    pub fn connect(path: &Path) -> io::Result<UnixStream> {
        UnixStream::connect(path)
    }
}

/// Listen on `path`, whatever its length up to [`MAX_SOCKET_PATH_LEN`].
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    imp::bind(path)
}

/// Connect to `path`, whatever its length up to [`MAX_SOCKET_PATH_LEN`].
pub fn connect(path: &Path) -> io::Result<UnixStream> {
    imp::connect(path)
}

#[cfg(test)]
#[path = "../tests/socket/test_long_socket.rs"]
mod tests;
