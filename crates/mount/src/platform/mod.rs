//! Platform-specific FUSE mounting with comprehensive migration support
//!
//! This module provides a unified cross-platform interface for mounting HybridCipher
//! with migration status notifications, platform-specific optimizations, and
//! desktop environment integration.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

use crate::{filesystem::HybridCipher, MountOptions};
use anyhow::Result;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use tracing::info;

/// Unified cross-platform mount interface with migration support
///
/// This function provides a platform-agnostic way to mount HybridCipher with
/// automatic migration status detection, desktop notifications, and
/// platform-specific optimizations.
///
/// # Arguments
///
/// * `fs` - HybridCipher filesystem instance
/// * `mountpoint` - Path where the filesystem should be mounted
///
/// # Returns
///
/// Returns `Ok(())` on successful mount, `Err` on failure
pub async fn mount_with_migration_support<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
>(
    fs: HybridCipher<S, N>,
    mountpoint: &Path,
    options: &MountOptions,
) -> Result<()> {
    info!(
        "Mounting HybridCipher with migration support at {}",
        mountpoint.display()
    );

    // Detect migration status for unified handling
    let migration_active = fs.is_migration_active().await;
    if migration_active {
        info!("Migration detected - enabling enhanced monitoring and notifications");
    }

    // Platform-specific mounting with migration support
    #[cfg(target_os = "macos")]
    {
        macos::mount_macos(fs, mountpoint, options).await
    }

    #[cfg(target_os = "linux")]
    {
        linux::mount_linux(fs, mountpoint, options).await
    }

    #[cfg(target_os = "windows")]
    {
        let _ = (fs, mountpoint, options);
        anyhow::bail!(
            "Windows live filesystem mounts are not supported; use Cloud Files or sync mount"
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        compile_error!("Unsupported operating system")
    }
}

// Re-export legacy platform functions for backward compatibility
#[cfg(target_os = "macos")]
pub use macos::mount_macos as mount_filesystem;

#[cfg(target_os = "linux")]
pub use linux::mount_linux as mount_filesystem;

/// Unified cross-platform unmount interface with migration state preservation
///
/// This function provides a platform-agnostic way to unmount HybridCipher while
/// preserving migration state and sending appropriate notifications.
///
/// # Arguments
///
/// * `mountpoint` - Path of the mounted filesystem to unmount
///
/// # Returns
///
/// Returns `Ok(())` on successful unmount, `Err` on failure
pub async fn unmount_filesystem(mountpoint: &Path, force: bool) -> Result<()> {
    info!("Unmounting HybridCipher from {}", mountpoint.display());

    // Platform-specific unmounting with migration state preservation
    #[cfg(target_os = "macos")]
    {
        macos::unmount_macos(mountpoint, force).await
    }

    #[cfg(target_os = "linux")]
    {
        linux::unmount_linux(mountpoint, force).await
    }

    #[cfg(target_os = "windows")]
    {
        let _ = (mountpoint, force);
        anyhow::bail!(
            "Windows live filesystem mounts are not supported; use Cloud Files or sync mount"
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        compile_error!("Unsupported operating system")
    }
}

/// Check if a path is currently mounted as HybridCipher
///
/// # Arguments
///
/// * `mountpoint` - Path to check for mount status
///
/// # Returns
///
/// Returns `Ok(true)` if mounted, `Ok(false)` if not mounted, `Err` on error
pub async fn is_mounted(mountpoint: &Path) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        macos::is_mounted(mountpoint).await
    }

    #[cfg(target_os = "linux")]
    {
        linux::is_mounted_linux(mountpoint).await
    }

    #[cfg(target_os = "windows")]
    {
        let _ = mountpoint;
        Ok(false)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        compile_error!("Unsupported operating system")
    }
}

/// Platform capabilities for migration notification support
pub struct PlatformCapabilities {
    /// Desktop notifications are supported
    pub desktop_notifications: bool,
    /// System tray integration is available
    pub system_tray: bool,
    /// Volume name updates are supported
    pub volume_name_updates: bool,
    /// Systemd integration is available (Linux only)
    pub systemd_integration: bool,
    /// Force unmount is supported
    pub force_unmount: bool,
}

/// Get platform-specific capabilities
pub fn get_platform_capabilities() -> PlatformCapabilities {
    #[cfg(target_os = "macos")]
    {
        PlatformCapabilities {
            desktop_notifications: true,
            system_tray: true,
            volume_name_updates: true,
            systemd_integration: false,
            force_unmount: true,
        }
    }

    #[cfg(target_os = "linux")]
    {
        PlatformCapabilities {
            desktop_notifications: true,
            system_tray: true,
            volume_name_updates: false,
            systemd_integration: std::env::var("NOTIFY_SOCKET").is_ok(),
            force_unmount: true,
        }
    }

    #[cfg(target_os = "windows")]
    {
        PlatformCapabilities {
            desktop_notifications: false,
            system_tray: false,
            volume_name_updates: false,
            systemd_integration: false,
            force_unmount: true,
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        compile_error!("Unsupported operating system")
    }
}

/// Migration notification manager trait for cross-platform notifications
pub type NotificationFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

pub trait MigrationNotificationManager {
    fn notify_migration_start(&self) -> NotificationFuture<'_>;
    fn notify_migration_progress(
        &self,
        progress: f64,
        files_remaining: u64,
    ) -> NotificationFuture<'_>;
    fn notify_migration_complete(&self) -> NotificationFuture<'_>;
    fn notify_migration_error<'a>(&'a self, error: &'a str) -> NotificationFuture<'a>;
    fn send_mount_notification<'a>(&'a self, mountpoint: &'a Path) -> NotificationFuture<'a>;
    fn send_unmount_notification<'a>(&'a self, mountpoint: &'a Path) -> NotificationFuture<'a>;
}
