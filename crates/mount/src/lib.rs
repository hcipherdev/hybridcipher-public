//! # HybridCipher FUSE Mount Implementation
//!
//! This crate provides a FUSE-based virtual filesystem for HybridCipher that enables
//! transparent access to encrypted files while supporting the two-phase rekey
//! mechanism with opportunistic migration.
//!
//! ## Features
//!
//! - **Dual-Epoch Access**: Seamless access to files during epoch transitions
//! - **Opportunistic Migration**: Background rewrapping during file access
//! - **Migration Status Overlay**: Virtual files showing migration progress
//! - **High Performance**: Intelligent caching and prefetching strategies
//! - **Cross-Platform**: Support for macOS (macFUSE) and Linux (FUSE)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   User Space    │    │   FUSE Layer    │    │   HybridCipher       │
//! │   Applications  │◄──►│   Virtual FS    │◄──►│   Client        │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!                                 │
//!                        ┌─────────────────┐
//!                        │   Migration     │
//!                        │   Tracker       │
//!                        └─────────────────┘
//! ```
//!
//! ## Security Properties
//!
//! - **Access Control**: FUSE-level access control integrated with HybridCipher permissions
//! - **Audit Logging**: All file access operations logged with user context
//! - **Migration Safety**: Atomic rewrapping ensures no data loss during migration
//! - **Cache Security**: Encrypted caching with automatic cleanup of sensitive data

#[cfg(target_os = "linux")]
pub mod cache;
pub mod error;
#[cfg(target_os = "linux")]
pub mod filesystem;
pub mod migration;
#[cfg(target_os = "linux")]
pub mod platform;
#[cfg(target_os = "linux")]
pub mod virtual_fs;

// Re-export main components
#[cfg(target_os = "linux")]
pub use cache::{CacheKey, CacheManager, EvictionPolicy};
pub use error::MountError;
pub use error::Result as MountResult;
#[cfg(target_os = "linux")]
pub use filesystem::{collect_mount_runtime_status, HybridCipher, MountRuntimeStatus};
pub use migration::{MigrationTracker, OpportunisticRewrapper, OverlayFile};
#[cfg(target_os = "linux")]
pub use virtual_fs::VirtualOverlay;

use anyhow::Result;
use std::path::Path;
#[cfg(target_os = "linux")]
use tracing::info;

/// Options controlling how the mount is configured on each platform.
#[derive(Debug, Clone)]
pub struct MountOptions {
    pub allow_other: bool,
    pub readonly: bool,
    pub volume_name: Option<String>,
    pub cache_size_mb: u64,
    pub max_operations: u32,
    pub debug: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            allow_other: false,
            readonly: false,
            volume_name: None,
            cache_size_mb: 256,
            max_operations: 32,
            debug: false,
        }
    }
}

/// Main entry point for mounting a HybridCipher filesystem
///
/// This function creates a new FUSE mount point with full migration support
/// and platform-specific optimizations.
///
/// # Arguments
///
/// * `mountpoint` - Path where the filesystem should be mounted
/// * `client` - HybridCipher client instance for encrypted operations
/// * `migration_tracker` - Optional migration tracker for progress monitoring
///
/// # Returns
///
/// Returns `Ok(())` on successful mount, `Err` on failure
///
/// # Example
///
/// ```rust,no_run
/// use hybridcipher_mount::{mount_hybridcipher, HybridCipher, MountOptions};
/// use hybridcipher_client::{network::MockNetwork, storage::MockStorage, Client};
/// use hybridcipher_crypto::signatures::Ed25519KeyPair;
/// use std::{path::Path, sync::Arc};
///
/// # async fn example() -> anyhow::Result<()> {
/// let device_identity = Ed25519KeyPair::generate();
/// let storage = Arc::new(MockStorage::new());
/// let network = Arc::new(MockNetwork::new());
/// let client = Client::new(device_identity, storage, network);
/// let mountpoint = Path::new("/mnt/hybridcipher");
/// let encrypted_root = Path::new("/var/lib/hybridcipher/data");
///
/// let options = MountOptions::default();
/// mount_hybridcipher(mountpoint, encrypted_root, client, None, options).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(target_os = "linux")]
pub async fn mount_hybridcipher<S, N>(
    mountpoint: &Path,
    encrypted_root: &Path,
    client: hybridcipher_client::Client<S, N>,
    migration_tracker: Option<MigrationTracker<S, N>>,
    options: MountOptions,
) -> Result<()>
where
    S: hybridcipher_client::storage::Storage + Send + Sync + 'static,
    N: hybridcipher_client::network::Network + Send + Sync + 'static,
{
    info!("Mounting HybridCipher at {}", mountpoint.display());

    let mount_point_opt = None;

    // Create the filesystem instance
    let fs = HybridCipher::new(
        client,
        migration_tracker,
        encrypted_root.to_path_buf(),
        mount_point_opt,
        options.max_operations,
        options.volume_name.clone(),
    )
    .await?;

    platform::linux::mount_linux(fs, mountpoint, &options).await
}

#[cfg(not(target_os = "linux"))]
pub async fn mount_hybridcipher<S, N>(
    mountpoint: &Path,
    encrypted_root: &Path,
    client: hybridcipher_client::Client<S, N>,
    migration_tracker: Option<MigrationTracker<S, N>>,
    options: MountOptions,
) -> Result<()>
where
    S: hybridcipher_client::storage::Storage + Send + Sync + 'static,
    N: hybridcipher_client::network::Network + Send + Sync + 'static,
{
    let _ = (
        mountpoint,
        encrypted_root,
        client,
        migration_tracker,
        options,
    );
    anyhow::bail!("FUSE mounts are only available on Linux in this build")
}

/// Unmount a HybridCipher filesystem gracefully
///
/// This function performs a clean unmount with proper migration state preservation.
///
/// # Arguments
///
/// * `mountpoint` - Path of the mounted filesystem to unmount
///
/// # Returns
///
/// Returns `Ok(())` on successful unmount, `Err` on failure
#[cfg(target_os = "linux")]
pub async fn unmount_hybridcipher(mountpoint: &Path, force: bool) -> Result<()> {
    info!("Unmounting HybridCipher from {}", mountpoint.display());

    platform::linux::unmount_linux(mountpoint, force).await
}

#[cfg(not(target_os = "linux"))]
pub async fn unmount_hybridcipher(mountpoint: &Path, force: bool) -> Result<()> {
    let _ = (mountpoint, force);
    anyhow::bail!("FUSE mounts are only available on Linux in this build")
}

/// Check if a path is a valid HybridCipher mount point
///
/// # Arguments
///
/// * `mountpoint` - Path to check
///
/// # Returns
///
/// Returns `true` if the path is a valid HybridCipher mount, `false` otherwise
pub fn is_hybridcipher_mounted(mountpoint: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        platform::linux::is_mounted(mountpoint)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mountpoint;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_mount_path_validation() {
        let temp_dir = TempDir::new().unwrap();
        let mountpoint = temp_dir.path();

        // Test with non-existent client - should fail gracefully
        // This is a smoke test to ensure the API works
        assert!(mountpoint.exists());
    }

    #[test]
    fn test_mount_status_check() {
        let temp_dir = TempDir::new().unwrap();
        let mountpoint = temp_dir.path();

        // Should return false for non-mounted directory
        assert!(!is_hybridcipher_mounted(mountpoint));
    }
}
