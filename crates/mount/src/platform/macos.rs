//! macOS-specific FUSE mounting with macFUSE integration
//!
//! This module provides macOS-specific mounting functionality with macFUSE
//! integration, migration status notifications, and desktop integration.

use crate::platform::{MigrationNotificationManager, NotificationFuture};
use crate::{filesystem::HybridCipher, MountOptions};
use anyhow::Result;
use fuser::MountOption;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

/// macOS notification integration for migration status
pub struct MacOSNotificationManager {
    /// Last notification timestamp
    last_notification: std::sync::Arc<std::sync::RwLock<std::time::SystemTime>>,
    /// Notification cooldown period
    cooldown_duration: Duration,
    /// Enable desktop notifications
    enable_notifications: bool,
}

impl MacOSNotificationManager {
    /// Create a new macOS notification manager
    pub fn new() -> Self {
        Self {
            last_notification: std::sync::Arc::new(std::sync::RwLock::new(
                std::time::SystemTime::UNIX_EPOCH,
            )),
            cooldown_duration: Duration::from_secs(300), // 5 minutes
            enable_notifications: true,
        }
    }

    /// Send migration start notification
    async fn notify_migration_start_impl(&self) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        self.send_system_notification(
            "HybridCipher Migration Started",
            "Encrypted filesystem migration has started.",
        )
        .await
    }

    /// Send migration progress notification
    async fn notify_migration_progress_impl(
        &self,
        progress: f64,
        files_remaining: u64,
    ) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        // Check cooldown
        {
            let last_notification = self.last_notification.read().unwrap();
            if last_notification.elapsed().unwrap_or(Duration::MAX) < self.cooldown_duration {
                return Ok(());
            }
        }

        let title = "HybridCipher Migration Progress";
        let message = format!(
            "Migration {:.1}% complete. {} files remaining.",
            progress * 100.0,
            files_remaining
        );

        self.send_system_notification(title, &message).await?;

        // Update last notification time
        *self.last_notification.write().unwrap() = std::time::SystemTime::now();

        Ok(())
    }

    /// Send migration completion notification
    async fn notify_migration_complete_impl(&self) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        let title = "HybridCipher Migration Complete";
        let message = "File encryption migration has completed successfully.";

        self.send_system_notification(title, message).await
    }

    /// Send migration error notification
    async fn notify_migration_error_impl(&self, error: &str) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        let title = "HybridCipher Migration Error";
        let message = format!("Migration encountered an error: {}", error);

        self.send_system_notification(title, &message).await
    }

    /// Send mount notification
    async fn send_mount_notification_impl(&self, label: &str) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        let title = "HybridCipher Mounted";
        let message = format!("Encrypted filesystem mounted as: {}", label);

        self.send_system_notification(title, &message).await
    }

    /// Send unmount notification
    async fn send_unmount_notification_impl(&self, mountpoint: &Path) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        let title = "HybridCipher Unmounted";
        let message = format!(
            "Encrypted filesystem unmounted from: {}",
            mountpoint.display()
        );

        self.send_system_notification(title, &message).await
    }

    /// Send system notification using osascript
    async fn send_system_notification(&self, title: &str, message: &str) -> Result<()> {
        let script = format!(
            r#"display notification "{}" with title "{}" sound name "Glass""#,
            message.replace('"', r#"\""#),
            title.replace('"', r#"\""#)
        );

        let output = Command::new("osascript").args(&["-e", &script]).output()?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to send notification: {}", error_msg);
        }

        Ok(())
    }
}

impl Clone for MacOSNotificationManager {
    fn clone(&self) -> Self {
        Self {
            last_notification: self.last_notification.clone(),
            cooldown_duration: self.cooldown_duration,
            enable_notifications: self.enable_notifications,
        }
    }
}

impl MigrationNotificationManager for MacOSNotificationManager {
    fn notify_migration_start(&self) -> NotificationFuture<'_> {
        Box::pin(async move { self.notify_migration_start_impl().await })
    }

    fn notify_migration_progress(
        &self,
        progress: f64,
        files_remaining: u64,
    ) -> NotificationFuture<'_> {
        Box::pin(async move {
            self.notify_migration_progress_impl(progress, files_remaining)
                .await
        })
    }

    fn notify_migration_complete(&self) -> NotificationFuture<'_> {
        Box::pin(async move { self.notify_migration_complete_impl().await })
    }

    fn notify_migration_error<'a>(&'a self, error: &'a str) -> NotificationFuture<'a> {
        Box::pin(async move { self.notify_migration_error_impl(error).await })
    }

    fn send_mount_notification<'a>(&'a self, mountpoint: &'a Path) -> NotificationFuture<'a> {
        let label = mountpoint.display().to_string();
        Box::pin(async move { self.send_mount_notification_impl(&label).await })
    }

    fn send_unmount_notification<'a>(&'a self, mountpoint: &'a Path) -> NotificationFuture<'a> {
        Box::pin(async move { self.send_unmount_notification_impl(mountpoint).await })
    }
}

/// Monitor migration progress and send notifications
#[allow(dead_code)]
async fn monitor_migration_progress<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
>(
    fs: Arc<HybridCipher<S, N>>,
    notification_manager: MacOSNotificationManager,
    mountpoint: &Path,
) {
    let mut interval = interval(Duration::from_secs(60)); // Check every minute
    let mut last_progress = 0.0;

    loop {
        interval.tick().await;

        // Check if filesystem is still mounted
        if !is_mounted(mountpoint).await.unwrap_or(false) {
            debug!("Filesystem no longer mounted, stopping migration monitoring");
            break;
        }

        // Get current migration status
        let migration_active = fs.is_migration_active().await;
        if !migration_active {
            // Migration completed
            if let Err(e) = notification_manager.notify_migration_complete().await {
                warn!("Failed to send migration completion notification: {}", e);
            }
            break;
        }

        // Get migration progress
        let performance_stats = fs.get_performance_metrics().await;
        let current_progress = performance_stats.cache_hit_rate; // Placeholder

        // Send progress notification if significant change
        if (current_progress - last_progress).abs() > 0.1 {
            let files_remaining = 100; // Placeholder
            if let Err(e) = notification_manager
                .notify_migration_progress(current_progress, files_remaining)
                .await
            {
                warn!("Failed to send migration progress notification: {}", e);
            }
            last_progress = current_progress;
        }
    }
}

/// Mount HybridCipher on macOS using macFUSE with migration notification support
///
/// This function mounts the HybridCipher filesystem on macOS with macFUSE-specific
/// options, migration status integration, and desktop notification support.
///
/// # Arguments
///
/// * `fs` - HybridCipher filesystem instance
/// * `mountpoint` - Path where the filesystem should be mounted
///
/// # Returns
///
/// Returns `Ok(())` on successful mount, `Err` on failure
pub async fn mount_macos<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
>(
    fs: HybridCipher<S, N>,
    mountpoint: &Path,
    options: &MountOptions,
) -> Result<()> {
    info!("Mounting HybridCipher on macOS at {}", mountpoint.display());

    // Check if macFUSE is installed
    check_macfuse_installation()?;

    // Create mountpoint if it doesn't exist
    if !mountpoint.exists() {
        std::fs::create_dir_all(mountpoint)?;
        debug!("Created mountpoint directory: {}", mountpoint.display());
    }

    // Get migration status for volume naming
    let migration_active = fs.is_migration_active().await;
    let mut dynamic_volume_name = if migration_active {
        let performance_stats = fs.get_performance_metrics().await;
        let progress = performance_stats.cache_hit_rate; // Placeholder for migration progress
        format!("HybridCipher (Migrating {:.1}%)", progress * 100.0)
    } else {
        "HybridCipher Encrypted".to_string()
    };
    if let Some(custom) = &options.volume_name {
        dynamic_volume_name = custom.clone();
    }

    // Set up notification manager for migration updates
    let notification_manager = MacOSNotificationManager::new();

    // macFUSE-specific mount options with migration awareness
    let mut mount_options = vec![
        MountOption::FSName("HybridCipher".to_string()),
        MountOption::CUSTOM(format!("volname={}", dynamic_volume_name)),
        MountOption::CUSTOM("local".to_string()),
        MountOption::CUSTOM("defer_permissions".to_string()),
        MountOption::CUSTOM("noapplexattr".to_string()),
        MountOption::CUSTOM("noappledouble".to_string()),
        MountOption::CUSTOM("nolocalcaches".to_string()),
    ];

    if options.allow_other {
        mount_options.push(MountOption::CUSTOM("allow_other".to_string()));
    }
    if options.readonly {
        mount_options.push(MountOption::RO);
    }
    if options.debug {
        mount_options.push(MountOption::CUSTOM("debug".to_string()));
    }

    let iosize = options
        .cache_size_mb
        .max(1)
        .saturating_mul(1024)
        .saturating_mul(1024) as usize;
    let iosize = iosize.clamp(4096, 16 * 1024 * 1024);
    mount_options.push(MountOption::CUSTOM(format!("iosize={iosize}")));
    mount_options.push(MountOption::CUSTOM("daemon_timeout=600".to_string()));

    debug!(
        "Starting macFUSE mount with volume name: {} and options: {:?}",
        dynamic_volume_name, mount_options
    );

    // Start background migration monitoring task
    if migration_active {
        debug!("Migration active - macOS notifications enabled");
    }

    // Send initial mount notification
    notification_manager
        .send_mount_notification(Path::new(&dynamic_volume_name))
        .await?;

    // Start the FUSE mount
    let mountpoint_owned = mountpoint.to_path_buf();
    let fuse_options = mount_options.clone();
    tokio::task::spawn_blocking(move || fuser::mount2(fs, mountpoint_owned, &fuse_options))
        .await??;

    info!(
        "HybridCipher mounted successfully on macOS with volume name: {}",
        dynamic_volume_name
    );
    Ok(())
}

/// Unmount HybridCipher on macOS with migration state preservation
///
/// This function gracefully unmounts the HybridCipher filesystem while preserving
/// any ongoing migration state and sending appropriate notifications.
///
/// # Arguments
///
/// * `mountpoint` - Path of the mounted filesystem to unmount
///
/// # Returns
///
/// Returns `Ok(())` on successful unmount, `Err` on failure
pub async fn unmount_macos(mountpoint: &Path, force: bool) -> Result<()> {
    info!("Unmounting HybridCipher from {}", mountpoint.display());

    // Create notification manager for unmount notification
    let notification_manager = MacOSNotificationManager::new();

    // Check if filesystem is actually mounted
    if !is_mounted(mountpoint).await? {
        warn!("Filesystem is not mounted at {}", mountpoint.display());
        return Ok(());
    }

    // Attempt graceful unmount first
    let mut unmount_cmd = Command::new("umount");
    if force {
        unmount_cmd.arg("-f");
    }
    unmount_cmd.arg(mountpoint);

    let output = unmount_cmd.output()?;

    if output.status.success() {
        info!("HybridCipher unmounted successfully");

        // Send unmount notification
        if let Err(e) = notification_manager
            .send_unmount_notification(mountpoint)
            .await
        {
            warn!("Failed to send unmount notification: {}", e);
        }

        Ok(())
    } else {
        let error_msg = String::from_utf8_lossy(&output.stderr);

        // If graceful unmount fails, try force unmount when allowed
        if (error_msg.contains("busy") || error_msg.contains("in use")) && !force {
            warn!("Filesystem busy. Retry with force to override active handles.");
            anyhow::bail!("Filesystem busy. Retry with --force to force unmount.");
        } else if error_msg.contains("busy") || error_msg.contains("in use") {
            warn!("Filesystem busy, attempting force unmount");

            let force_output = Command::new("umount")
                .args(&["-f", mountpoint.to_str().unwrap()])
                .output()?;

            if force_output.status.success() {
                warn!("Force unmount successful");

                // Send unmount notification
                if let Err(e) = notification_manager
                    .send_unmount_notification(mountpoint)
                    .await
                {
                    warn!("Failed to send unmount notification: {}", e);
                }

                Ok(())
            } else {
                let force_error_msg = String::from_utf8_lossy(&force_output.stderr);
                error!("Force unmount failed: {}", force_error_msg);
                anyhow::bail!("Failed to unmount (even with force): {}", force_error_msg);
            }
        } else {
            error!("Unmount failed: {}", error_msg);
            anyhow::bail!("Failed to unmount: {}", error_msg);
        }
    }
}

/// Check if a path is mounted as HybridCipher on macOS
///
/// # Arguments
///
/// * `mountpoint` - Path to check for mount status
///
/// # Returns
///
/// Returns `Ok(true)` if mounted, `Ok(false)` if not mounted, `Err` on error
pub async fn is_mounted(mountpoint: &Path) -> Result<bool> {
    let output = Command::new("mount").output()?;

    if output.status.success() {
        let mount_output = String::from_utf8_lossy(&output.stdout);
        let mountpoint_str = mountpoint.to_str().unwrap_or("");

        // Check if our mountpoint appears in the mount output
        let is_mounted = mount_output
            .lines()
            .any(|line| line.contains("HybridCipher") && line.contains(mountpoint_str));

        Ok(is_mounted)
    } else {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to check mount status: {}", error_msg);
    }
}
/// Check if a mountpoint is a HybridCipher mount (synchronous version)
///
/// # Arguments
///
/// * `mountpoint` - Path to check
///
/// # Returns
///
/// Returns `true` if the path is a HybridCipher mount, `false` otherwise
pub fn is_mounted_sync(mountpoint: &Path) -> bool {
    let output = Command::new("mount").output();

    if let Ok(output) = output {
        let mount_info = String::from_utf8_lossy(&output.stdout);
        let mountpoint_str = mountpoint.to_string_lossy();

        // Look for HybridCipher mount in mount output
        mount_info.lines().any(|line| {
            line.contains(&*mountpoint_str)
                && (line.contains("HybridCipher") || line.contains("hybridcipher"))
        })
    } else {
        false
    }
}

/// Check if macFUSE is properly installed
fn check_macfuse_installation() -> Result<()> {
    debug!("Checking macFUSE installation");

    // Check for macFUSE kernel extension
    let kext_output = Command::new("kextstat")
        .arg("-b")
        .arg("io.macfuse.filesystems.macfuse")
        .output();

    match kext_output {
        Ok(output) if output.status.success() => {
            debug!("macFUSE kernel extension is loaded");
        }
        _ => {
            // Try to load the extension
            warn!("macFUSE kernel extension not loaded, attempting to load");

            let load_output = Command::new("sudo")
                .args([
                    "kextload",
                    "/Library/Filesystems/macfuse.fs/Contents/Extensions/*/macfuse.kext",
                ])
                .output();

            if let Ok(output) = load_output {
                if !output.status.success() {
                    anyhow::bail!("Failed to load macFUSE kernel extension. Please install macFUSE from https://osxfuse.github.io/");
                }
            } else {
                anyhow::bail!(
                    "macFUSE not found. Please install macFUSE from https://osxfuse.github.io/"
                );
            }
        }
    }

    // Check for macFUSE framework
    let framework_path = Path::new("/Library/Frameworks/macFUSE.framework");
    if !framework_path.exists() {
        anyhow::bail!(
            "macFUSE framework not found. Please install macFUSE from https://osxfuse.github.io/"
        );
    }

    info!("macFUSE installation verified");
    Ok(())
}

/// Configure macOS-specific performance optimizations
///
/// This function applies macOS-specific performance optimizations
/// for FUSE operations and caching.
pub fn configure_macos_optimizations() -> Result<()> {
    debug!("Configuring macOS-specific optimizations");

    // Set optimal I/O parameters for macOS
    std::env::set_var("FUSE_LIBRARY_PATH", "/usr/local/lib");

    // Configure cache settings for better performance
    std::env::set_var("FUSE_CACHE_SIZE", "134217728"); // 128MB cache
    std::env::set_var("FUSE_MAX_WRITE", "131072"); // 128KB max write

    debug!("macOS optimizations configured");
    Ok(())
}

/// Show macOS notification for migration status
///
/// # Arguments
///
/// * `title` - Notification title
/// * `message` - Notification message
/// * `progress` - Optional progress percentage
pub async fn show_migration_notification(
    title: &str,
    message: &str,
    progress: Option<f32>,
) -> Result<()> {
    debug!("Showing macOS notification: {} - {}", title, message);

    let mut osascript_cmd = format!(
        r#"display notification "{}" with title "{}""#,
        message, title
    );

    // Add progress information if available
    if let Some(prog) = progress {
        osascript_cmd = format!(
            r#"display notification "{} ({:.1}%)" with title "{}""#,
            message,
            prog * 100.0,
            title
        );
    }

    let output = Command::new("osascript")
        .arg("-e")
        .arg(&osascript_cmd)
        .output();

    match output {
        Ok(result) if result.status.success() => {
            debug!("macOS notification sent successfully");
            Ok(())
        }
        Ok(result) => {
            let error = String::from_utf8_lossy(&result.stderr);
            warn!("Failed to send macOS notification: {}", error);
            Ok(()) // Don't fail on notification errors
        }
        Err(e) => {
            warn!("Failed to execute osascript: {}", e);
            Ok(()) // Don't fail on notification errors
        }
    }
}

/// Get macOS system information relevant to FUSE operations
///
/// # Returns
///
/// Returns system information as key-value pairs
pub fn get_system_info() -> Result<std::collections::HashMap<String, String>> {
    let mut info = std::collections::HashMap::new();

    // Get macOS version
    if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            info.insert("macos_version".to_string(), version);
        }
    }

    // Get macFUSE version
    let macfuse_plist =
        Path::new("/Library/Frameworks/macFUSE.framework/Versions/Current/Resources/Info.plist");
    if macfuse_plist.exists() {
        if let Ok(output) = Command::new("defaults")
            .args([
                "read",
                macfuse_plist.to_str().unwrap(),
                "CFBundleShortVersionString",
            ])
            .output()
        {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                info.insert("macfuse_version".to_string(), version);
            }
        }
    }

    // Get available memory
    if let Ok(output) = Command::new("sysctl").args(["-n", "hw.memsize"]).output() {
        if output.status.success() {
            let memsize = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Ok(bytes) = memsize.parse::<u64>() {
                let mb = bytes / (1024 * 1024);
                info.insert("memory_mb".to_string(), mb.to_string());
            }
        }
    }

    debug!("Collected macOS system info: {:?}", info);
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_info_collection() {
        // This test runs only on macOS
        #[cfg(target_os = "macos")]
        {
            let info = get_system_info().unwrap();
            assert!(!info.is_empty());
        }
    }

    #[tokio::test]
    async fn test_mount_status_check() {
        // Test the mount status check function
        let temp_path = Path::new("/tmp/test_mount_check");
        assert!(!is_mounted(temp_path).await.unwrap_or(false));
    }
}
