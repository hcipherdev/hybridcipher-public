//! How hard a write is pushed to stable storage before it counts as done.
//!
//! On macOS `File::sync_all` issues `F_FULLFSYNC`, which waits for the drive to
//! empty its cache and costs several milliseconds per call. Bulk work hands each
//! file to the drive with a plain `fsync` and runs one [`barrier`] per batch.
use std::{fs::File, io, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputDurability {
    /// Stored on disk before the call returns.
    Full,
    /// Handed to the drive; the caller runs [`barrier`] before relying on it.
    Deferred,
    /// Not synced: private output that is copied elsewhere and then discarded.
    Private,
}

impl OutputDurability {
    pub fn apply(self, file: &File) -> io::Result<()> {
        match self {
            Self::Full => file.sync_all(),
            Self::Deferred => quick_sync(file),
            Self::Private => Ok(()),
        }
    }
}

/// Hand a file's data to the drive without waiting for the drive's own cache.
pub fn quick_sync(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        file.sync_all()
    }
}

/// Make everything already handed to the drive with [`quick_sync`] durable, by
/// fully syncing one file or folder on the same volume.
pub fn barrier(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if path.is_dir() {
        // Windows cannot open a folder for flushing; every write there was already synced.
        return Ok(());
    }
    File::open(path)?.sync_all()
}
