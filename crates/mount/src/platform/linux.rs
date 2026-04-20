//! Linux-specific FUSE mounting with migration status integration
//!
//! This module provides Linux-specific mounting functionality with FUSE
//! integration, desktop environment notifications, and systemd integration.

use crate::platform::{MigrationNotificationManager, NotificationFuture};
use crate::{filesystem::HybridCipher, MountOptions};
use anyhow::{Context, Result};
use fuser::MountOption;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use which::which;

/// Linux notification integration for migration status
pub struct LinuxNotificationManager {
    /// Last notification timestamp
    last_notification: std::sync::Arc<std::sync::RwLock<std::time::SystemTime>>,
    /// Notification cooldown period
    cooldown_duration: Duration,
    /// Enable desktop notifications
    enable_notifications: bool,
    /// Desktop environment type
    desktop_environment: DesktopEnvironment,
}

/// Supported Linux desktop environments
#[derive(Debug, Clone)]
pub enum DesktopEnvironment {
    Gnome,
    KDE,
    XFCE,
    Unity,
    Unknown,
}

/// FUSE runtime variant detected on the host
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FuseFlavor {
    Fuse3,
    Fuse2,
}

impl FuseFlavor {
    fn as_str(self) -> &'static str {
        match self {
            FuseFlavor::Fuse3 => "FUSE3",
            FuseFlavor::Fuse2 => "FUSE2",
        }
    }
}

impl LinuxNotificationManager {
    /// Create a new Linux notification manager
    pub fn new() -> Self {
        Self {
            last_notification: std::sync::Arc::new(std::sync::RwLock::new(
                std::time::SystemTime::UNIX_EPOCH,
            )),
            cooldown_duration: Duration::from_secs(300), // 5 minutes
            enable_notifications: true,
            desktop_environment: Self::detect_desktop_environment(),
        }
    }

    /// Detect the current desktop environment
    fn detect_desktop_environment() -> DesktopEnvironment {
        if let Ok(session) = std::env::var("DESKTOP_SESSION") {
            match session.to_lowercase().as_str() {
                s if s.contains("gnome") => return DesktopEnvironment::Gnome,
                s if s.contains("kde") => return DesktopEnvironment::KDE,
                s if s.contains("xfce") => return DesktopEnvironment::XFCE,
                s if s.contains("unity") => return DesktopEnvironment::Unity,
                _ => {}
            }
        }

        if let Ok(current_desktop) = std::env::var("XDG_CURRENT_DESKTOP") {
            match current_desktop.to_lowercase().as_str() {
                s if s.contains("gnome") => return DesktopEnvironment::Gnome,
                s if s.contains("kde") => return DesktopEnvironment::KDE,
                s if s.contains("xfce") => return DesktopEnvironment::XFCE,
                s if s.contains("unity") => return DesktopEnvironment::Unity,
                _ => {}
            }
        }

        DesktopEnvironment::Unknown
    }

    /// Send migration start notification
    async fn notify_migration_start_impl(&self) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        self.send_desktop_notification(
            "HybridCipher Migration Started",
            "Encrypted filesystem migration has started.",
            "info",
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

        self.send_desktop_notification(title, &message, "info")
            .await?;

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

        self.send_desktop_notification(title, message, "info").await
    }

    /// Send migration error notification
    async fn notify_migration_error_impl(&self, error: &str) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        let title = "HybridCipher Migration Error";
        let message = format!("Migration encountered an error: {}", error);

        self.send_desktop_notification(title, &message, "error")
            .await
    }

    /// Send mount notification
    async fn send_mount_notification_impl(&self, mountpoint: &Path) -> Result<()> {
        if !self.enable_notifications {
            return Ok(());
        }

        let title = "HybridCipher Mounted";
        let message = format!("Encrypted filesystem mounted at: {}", mountpoint.display());

        self.send_desktop_notification(title, &message, "info")
            .await
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

        self.send_desktop_notification(title, &message, "info")
            .await
    }

    /// Send desktop notification using notify-send
    async fn send_desktop_notification(
        &self,
        title: &str,
        message: &str,
        urgency: &str,
    ) -> Result<()> {
        // Try notify-send first (most common)
        let notify_result = Command::new("notify-send")
            .args(&[
                "--urgency",
                urgency,
                "--icon",
                "drive-harddisk-encrypted",
                "--app-name",
                "HybridCipher",
                title,
                message,
            ])
            .output();

        match notify_result {
            Ok(output) if output.status.success() => {
                debug!("Desktop notification sent successfully");
                return Ok(());
            }
            Ok(output) => {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                warn!("notify-send failed: {}", error_msg);
            }
            Err(e) => {
                debug!("notify-send not available: {}", e);
            }
        }

        // Fallback to desktop-specific notification methods
        match self.desktop_environment {
            DesktopEnvironment::KDE => {
                self.send_kde_notification(title, message).await?;
            }
            DesktopEnvironment::Gnome => {
                self.send_gnome_notification(title, message).await?;
            }
            _ => {
                debug!("No desktop-specific notification method available");
            }
        }

        Ok(())
    }

    /// Send KDE-specific notification using kdialog
    async fn send_kde_notification(&self, title: &str, message: &str) -> Result<()> {
        let output = Command::new("kdialog")
            .args(&["--title", title, "--passivepopup", message, "5"])
            .output()?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            warn!("KDE notification failed: {}", error_msg);
        }

        Ok(())
    }

    /// Send GNOME-specific notification using gdbus
    async fn send_gnome_notification(&self, title: &str, message: &str) -> Result<()> {
        let output = Command::new("gdbus")
            .args(&[
                "call",
                "--session",
                "--dest",
                "org.freedesktop.Notifications",
                "--object-path",
                "/org/freedesktop/Notifications",
                "--method",
                "org.freedesktop.Notifications.Notify",
                "HybridCipher",
                "0",
                "drive-harddisk-encrypted",
                title,
                message,
                "[]",
                "{}",
                "5000",
            ])
            .output()?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            warn!("GNOME notification failed: {}", error_msg);
        }

        Ok(())
    }
}

impl MigrationNotificationManager for LinuxNotificationManager {
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
        Box::pin(async move { self.send_mount_notification_impl(mountpoint).await })
    }

    fn send_unmount_notification<'a>(&'a self, mountpoint: &'a Path) -> NotificationFuture<'a> {
        Box::pin(async move { self.send_unmount_notification_impl(mountpoint).await })
    }
}

/// Perform pre-flight checks and gather runtime information about the local FUSE setup.
fn prepare_fuse_runtime(options: &MountOptions) -> Result<FuseFlavor> {
    verify_dev_fuse_access()?;
    ensure_allow_other_supported(options)?;

    let (flavor, helper_path) = locate_fusermount()
        .context("Unable to locate the `fusermount` helper. Install the fuse3 (preferred) or fuse package for your distribution.")?;

    if !Path::new("/sys/module/fuse").exists() {
        warn!(
            "FUSE kernel module not detected in /sys/module. If mounting fails, run `sudo modprobe fuse`."
        );
    }

    debug!(
        "Using {} helper at {}",
        flavor.as_str(),
        helper_path.display()
    );

    Ok(flavor)
}

fn verify_dev_fuse_access() -> Result<()> {
    let fuse_device = Path::new("/dev/fuse");
    if !fuse_device.exists() {
        anyhow::bail!(
            "FUSE device /dev/fuse not found. Install fuse3/fuse packages and ensure the kernel module is loaded."
        );
    }

    match OpenOptions::new().read(true).write(true).open(fuse_device) {
        Ok(handle) => {
            drop(handle);
            Ok(())
        }
        Err(err) => {
            if err.kind() == ErrorKind::PermissionDenied {
                let groups_output = Command::new("id")
                    .arg("-nG")
                    .output()
                    .context("Failed to enumerate current user groups")?;
                let groups = String::from_utf8_lossy(&groups_output.stdout);
                if !groups.split_whitespace().any(|group| group == "fuse") {
                    anyhow::bail!(
                        "Access to /dev/fuse denied (user is not in the 'fuse' group). \
                         Add the user with `sudo usermod -a -G fuse $USER` and re-login."
                    );
                }

                anyhow::bail!(
                    "Access to /dev/fuse denied even though the user is in the 'fuse' group: {}",
                    err
                );
            }

            anyhow::bail!("Failed to access /dev/fuse: {}", err);
        }
    }
}

fn ensure_allow_other_supported(options: &MountOptions) -> Result<()> {
    if !options.allow_other {
        return Ok(());
    }

    let fuse_conf = Path::new("/etc/fuse.conf");
    let contents = fs::read_to_string(fuse_conf).with_context(|| {
        format!(
            "Failed to read {} while validating `allow_other`. Ensure the file exists and is readable.",
            fuse_conf.display()
        )
    })?;

    if contents
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with("user_allow_other"))
    {
        Ok(())
    } else {
        anyhow::bail!(
            "`allow_other` requested but /etc/fuse.conf does not enable `user_allow_other`. \
             Update the configuration (requires root) before retrying."
        );
    }
}

fn locate_fusermount() -> Result<(FuseFlavor, PathBuf)> {
    if let Ok(helper) = which("fusermount3") {
        return Ok((FuseFlavor::Fuse3, helper));
    }

    let helper = which("fusermount").context(
        "Neither `fusermount3` nor `fusermount` found in PATH. Install fuse3 or fuse package.",
    )?;
    let flavor = determine_fuse_flavor_for(&helper)?;
    Ok((flavor, helper))
}

fn determine_fuse_flavor_for(helper_path: &Path) -> Result<FuseFlavor> {
    let version_output = Command::new(helper_path)
        .arg("--version")
        .output()
        .with_context(|| format!("Failed to run {} --version", helper_path.display()))?;

    if version_output.status.success() {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&version_output.stdout),
            String::from_utf8_lossy(&version_output.stderr)
        );

        if combined.contains("fusermount3")
            || combined.contains("FUSE library version: 3")
            || combined.contains("version: 3.")
        {
            return Ok(FuseFlavor::Fuse3);
        }

        if combined.contains("fusermount version: 2") || combined.contains("version: 2.") {
            return Ok(FuseFlavor::Fuse2);
        }
    } else {
        debug!(
            "{} --version exited with status {}",
            helper_path.display(),
            version_output.status
        );
    }

    if helper_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.contains('3'))
        .unwrap_or(false)
    {
        return Ok(FuseFlavor::Fuse3);
    }

    Ok(FuseFlavor::Fuse2)
}

fn build_linux_mount_options(options: &MountOptions, _flavor: FuseFlavor) -> Vec<MountOption> {
    let mut mount_options = vec![
        MountOption::FSName("hybridcipher".to_string()),
        MountOption::Subtype("hybridcipher".to_string()),
        MountOption::NoExec,
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::NoAtime,
        MountOption::DefaultPermissions,
    ];

    if options.readonly {
        mount_options.push(MountOption::RO);
    }
    if options.allow_other {
        mount_options.push(MountOption::AllowOther);
    }
    if options.debug {
        mount_options.push(MountOption::CUSTOM("debug".to_string()));
    }

    // Note: Many advanced FUSE options (max_read, max_write, max_background,
    // congestion_threshold, attr_timeout, entry_timeout, etc.) are not
    // universally supported as mount options across different FUSE versions.
    // They are handled internally by the fuser library or kernel.
    // Using only the minimal, universally compatible FUSE mount options.

    mount_options
}

/// Monitor migration progress and send notifications on Linux
#[allow(dead_code)]
async fn monitor_migration_progress_linux<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
>(
    client: Arc<hybridcipher_client::Client<S, N>>,
    notification_manager: LinuxNotificationManager,
    mountpoint: PathBuf,
) {
    let mut interval = interval(Duration::from_secs(5));
    let mut last_reported_percent: Option<u32> = None;
    let mut completion_notified = false;

    loop {
        interval.tick().await;

        if !is_mounted_linux(&mountpoint).await.unwrap_or(false) {
            debug!("Filesystem no longer mounted, stopping migration monitoring");
            break;
        }

        match client.is_migrating().await {
            true => {
                completion_notified = false;

                let progress = client.migration_progress().await.unwrap_or(0.0);
                let percent = (progress * 100.0).clamp(0.0, 100.0).round() as u32;
                let snapshot = client.migration_state_snapshot().await;
                let files_remaining = snapshot
                    .as_ref()
                    .map(|state| {
                        state.total_files.saturating_sub(
                            state.migrated_files.len() as u64 + state.failed_files.len() as u64,
                        )
                    })
                    .unwrap_or(0);

                let should_notify = last_reported_percent
                    .map(|prev| percent.saturating_sub(prev) >= 5)
                    .unwrap_or(true);

                if should_notify {
                    if let Err(e) = notification_manager
                        .notify_migration_progress(progress, files_remaining)
                        .await
                    {
                        warn!("Failed to send migration progress notification: {}", e);
                    }

                    let status = format!("Migration {:.1}% complete", percent as f64);
                    update_systemd_status(&status).await;
                    last_reported_percent = Some(percent);
                }
            }
            false => {
                if !completion_notified && last_reported_percent.is_some() {
                    if let Err(e) = notification_manager.notify_migration_complete().await {
                        warn!("Failed to send migration completion notification: {}", e);
                    }
                    update_systemd_status("Migration completed").await;
                    completion_notified = true;
                }
                last_reported_percent = None;
            }
        }
    }
}

/// Update systemd service status if running under systemd
async fn update_systemd_status(status: &str) {
    if let Ok(_) = std::env::var("NOTIFY_SOCKET") {
        let output = Command::new("systemd-notify")
            .args(&["--status", status])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                debug!("Updated systemd status: {}", status);
            }
            Ok(result) => {
                let error_msg = String::from_utf8_lossy(&result.stderr);
                warn!("Failed to update systemd status: {}", error_msg);
            }
            Err(e) => {
                debug!("systemd-notify not available: {}", e);
            }
        }
    }
}

/// Check if a path is mounted as HybridCipher on Linux
pub(crate) async fn is_mounted_linux(mountpoint: &Path) -> Result<bool> {
    if let Ok(findmnt) = which("findmnt") {
        let output = Command::new(findmnt)
            .args(["-n", "-t", "fuse.hybridcipher"])
            .arg(mountpoint)
            .output();

        match output {
            Ok(result) if result.status.success() => return Ok(true),
            Ok(_) => debug!("findmnt indicates {} is not mounted", mountpoint.display()),
            Err(err) => debug!("findmnt execution failed: {}", err),
        }
    }

    Ok(is_mounted(mountpoint))
}

impl Clone for LinuxNotificationManager {
    fn clone(&self) -> Self {
        Self {
            last_notification: self.last_notification.clone(),
            cooldown_duration: self.cooldown_duration,
            enable_notifications: self.enable_notifications,
            desktop_environment: self.desktop_environment.clone(),
        }
    }
}

/// Mount HybridCipher on Linux using FUSE with migration notification support
///
/// This function mounts the HybridCipher filesystem on Linux with FUSE-specific
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
pub async fn mount_linux<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
>(
    fs: HybridCipher<S, N>,
    mountpoint: &Path,
    options: &MountOptions,
) -> Result<()> {
    info!("Mounting HybridCipher on Linux at {}", mountpoint.display());

    let fuse_flavor = prepare_fuse_runtime(options)?;

    // Create mountpoint if it doesn't exist
    if !mountpoint.exists() {
        std::fs::create_dir_all(mountpoint)?;
        debug!("Created mountpoint directory: {}", mountpoint.display());
    }

    // Set up notification manager for migration updates
    let notification_manager = LinuxNotificationManager::new();

    // Linux FUSE mount options tuned for the detected helper
    let mount_options = build_linux_mount_options(options, fuse_flavor);

    debug!(
        "Starting Linux FUSE mount using {} with options: {:?}",
        fuse_flavor.as_str(),
        mount_options
    );

    let mountpoint_owned = mountpoint.to_path_buf();

    // Start background migration monitoring task
    tokio::spawn(monitor_migration_progress_linux(
        fs.client_arc(),
        notification_manager.clone(),
        mountpoint_owned.clone(),
    ));

    // Send initial mount notification
    notification_manager
        .send_mount_notification(mountpoint)
        .await?;

    // Start the FUSE mount
    let fuse_options = mount_options.clone();
    tokio::task::spawn_blocking(move || fuser::mount2(fs, mountpoint_owned, &fuse_options))
        .await??;

    info!("HybridCipher mounted successfully on Linux");
    Ok(())
}

/// Unmount HybridCipher on Linux with migration state preservation
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
pub async fn unmount_linux(mountpoint: &Path, force: bool) -> Result<()> {
    info!("Unmounting HybridCipher from {}", mountpoint.display());

    // Create notification manager for unmount notification
    let notification_manager = LinuxNotificationManager::new();

    // Check if filesystem is actually mounted
    if !is_mounted_linux(mountpoint).await? {
        warn!("Filesystem is not mounted at {}", mountpoint.display());
        return Ok(());
    }

    // Update systemd status if available
    update_systemd_status("Unmounting filesystem").await;

    // Try fusermount first (preferred for user-space unmounting)
    match locate_fusermount() {
        Ok((_, helper_path)) => {
            let mut fusermount_cmd = Command::new(&helper_path);
            fusermount_cmd.arg("-u");
            if force {
                fusermount_cmd.arg("-z");
            }
            fusermount_cmd.arg(mountpoint);

            match fusermount_cmd.output() {
                Ok(output) if output.status.success() => {
                    info!(
                        "HybridCipher unmounted successfully using {}",
                        helper_path.display()
                    );

                    if let Err(e) = notification_manager
                        .send_unmount_notification(mountpoint)
                        .await
                    {
                        warn!("Failed to send unmount notification: {}", e);
                    }

                    update_systemd_status("Unmounted successfully").await;
                    return Ok(());
                }
                Ok(output) => {
                    warn!(
                        "{} failed: {}",
                        helper_path.display(),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Err(err) => {
                    warn!("Failed to execute {}: {}", helper_path.display(), err);
                }
            }
        }
        Err(err) => {
            warn!("Unable to locate fusermount helper: {}", err);
        }
    }

    // Fallback to umount
    let mut umount_cmd = Command::new("umount");
    if force {
        umount_cmd.arg("-f");
    }
    umount_cmd.arg(mountpoint);

    let umount_result = umount_cmd.output();

    match umount_result {
        Ok(output) if output.status.success() => {
            info!("HybridCipher unmounted successfully using umount");

            // Send unmount notification
            if let Err(e) = notification_manager
                .send_unmount_notification(mountpoint)
                .await
            {
                warn!("Failed to send unmount notification: {}", e);
            }

            // Update systemd status
            update_systemd_status("Unmounted successfully").await;

            Ok(())
        }
        Ok(output) => {
            let error_msg = String::from_utf8_lossy(&output.stderr);

            // If standard unmount fails, try force unmount
            if error_msg.contains("busy") || error_msg.contains("target is busy") {
                warn!("Filesystem busy, attempting lazy unmount");

                let lazy_result = Command::new("umount")
                    .args(&["-l", mountpoint.to_str().unwrap()])
                    .output()?;

                if lazy_result.status.success() {
                    warn!("Lazy unmount successful");

                    // Send unmount notification
                    if let Err(e) = notification_manager
                        .send_unmount_notification(mountpoint)
                        .await
                    {
                        warn!("Failed to send unmount notification: {}", e);
                    }

                    // Update systemd status
                    update_systemd_status("Unmounted (lazy)").await;

                    Ok(())
                } else {
                    let lazy_error_msg = String::from_utf8_lossy(&lazy_result.stderr);
                    error!("Lazy unmount failed: {}", lazy_error_msg);
                    anyhow::bail!(
                        "Failed to unmount (even with lazy unmount): {}",
                        lazy_error_msg
                    );
                }
            } else {
                error!("Unmount failed: {}", error_msg);
                anyhow::bail!("Failed to unmount: {}", error_msg);
            }
        }
        Err(e) => {
            error!("Unmount command failed: {}", e);
            anyhow::bail!("Failed to execute unmount: {}", e);
        }
    }
}

/// Check if a path is mounted as HybridCipher on Linux
///
/// # Arguments
///
/// * `mountpoint` - Path to check
///
/// # Returns
///
/// Returns `true` if the path is a HybridCipher mount, `false` otherwise
pub fn is_mounted(mountpoint: &Path) -> bool {
    // Check /proc/mounts for the mount
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        let mountpoint_str = mountpoint.to_string_lossy();

        mounts.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                parts[1] == mountpoint_str
                    && (parts[2] == "fuse.hybridcipher" || parts[0].contains("HybridCipher"))
            } else {
                false
            }
        })
    } else {
        false
    }
}

/// Configure Linux-specific performance optimizations
///
/// This function applies Linux-specific performance optimizations
/// for FUSE operations and caching.
pub fn configure_linux_optimizations() -> Result<()> {
    debug!("Configuring Linux-specific optimizations");

    // Set optimal I/O parameters for Linux
    std::env::set_var("FUSE_MAX_BACKGROUND", "64");
    std::env::set_var("FUSE_CONGESTION_THRESHOLD", "48");

    // Configure cache settings
    std::env::set_var("FUSE_KERNEL_CACHE", "1");
    std::env::set_var("FUSE_ATTR_TIMEOUT", "1.0");
    std::env::set_var("FUSE_ENTRY_TIMEOUT", "1.0");

    debug!("Linux optimizations configured");
    Ok(())
}

/// Show Linux desktop notification for migration status
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
    debug!("Showing Linux notification: {} - {}", title, message);

    let desktop_env = detect_desktop_environment();

    // Try different notification methods based on desktop environment
    match desktop_env.as_str() {
        "gnome" | "unity" | "xfce" | "kde" => {
            send_freedesktop_notification(title, message, progress).await?;
        }
        _ => {
            // Fallback to notify-send
            send_notify_send_notification(title, message, progress).await?;
        }
    }

    Ok(())
}

/// Detect desktop environment
fn detect_desktop_environment() -> String {
    // Check environment variables for desktop environment
    if let Ok(desktop) = std::env::var("XDG_CURRENT_DESKTOP") {
        return desktop.to_lowercase();
    }

    if let Ok(desktop) = std::env::var("DESKTOP_SESSION") {
        return desktop.to_lowercase();
    }

    if std::env::var("GNOME_DESKTOP_SESSION_ID").is_ok() {
        return "gnome".to_string();
    }

    if std::env::var("KDE_FULL_SESSION").is_ok() {
        return "kde".to_string();
    }

    "unknown".to_string()
}

/// Send notification using freedesktop.org specification
async fn send_freedesktop_notification(
    title: &str,
    message: &str,
    progress: Option<f32>,
) -> Result<()> {
    let mut full_message = message.to_string();

    if let Some(prog) = progress {
        full_message = format!("{} ({:.1}%)", message, prog * 100.0);
    }

    let output = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest=org.freedesktop.Notifications",
            "--object-path=/org/freedesktop/Notifications",
            "--method=org.freedesktop.Notifications.Notify",
            "HybridCipher",
            "0",
            "dialog-information",
            title,
            &full_message,
            "[]",
            "{}",
            "5000",
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            debug!("Freedesktop notification sent successfully");
            Ok(())
        }
        _ => {
            // Fallback to notify-send
            send_notify_send_notification(title, message, progress).await
        }
    }
}

/// Send notification using notify-send
async fn send_notify_send_notification(
    title: &str,
    message: &str,
    progress: Option<f32>,
) -> Result<()> {
    let mut full_message = message.to_string();

    if let Some(prog) = progress {
        full_message = format!("{} ({:.1}%)", message, prog * 100.0);
    }

    let output = Command::new("notify-send")
        .args([
            "--app-name=HybridCipher",
            "--urgency=normal",
            "--expire-time=5000",
            title,
            &full_message,
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            debug!("notify-send notification sent successfully");
            Ok(())
        }
        Ok(result) => {
            let error = String::from_utf8_lossy(&result.stderr);
            warn!("Failed to send notification: {}", error);
            Ok(()) // Don't fail on notification errors
        }
        Err(e) => {
            warn!("notify-send not available: {}", e);
            Ok(()) // Don't fail on notification errors
        }
    }
}

/// Get Linux system information relevant to FUSE operations
///
/// # Returns
///
/// Returns system information as key-value pairs
pub fn get_system_info() -> Result<std::collections::HashMap<String, String>> {
    let mut info = std::collections::HashMap::new();

    // Get kernel version
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        let kernel_version = version
            .split_whitespace()
            .nth(2)
            .unwrap_or("unknown")
            .to_string();
        info.insert("kernel_version".to_string(), kernel_version);
    }

    // Get distribution information
    if let Ok(os_release) = std::fs::read_to_string("/etc/os-release") {
        for line in os_release.lines() {
            if line.starts_with("NAME=") {
                let name = line.trim_start_matches("NAME=").trim_matches('"');
                info.insert("distribution".to_string(), name.to_string());
            }
            if line.starts_with("VERSION=") {
                let version = line.trim_start_matches("VERSION=").trim_matches('"');
                info.insert("distribution_version".to_string(), version.to_string());
            }
        }
    }

    // Get memory information
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        let mb = kb / 1024;
                        info.insert("memory_mb".to_string(), mb.to_string());
                    }
                }
                break;
            }
        }
    }

    // Get desktop environment
    let desktop = detect_desktop_environment();
    info.insert("desktop_environment".to_string(), desktop);

    debug!("Collected Linux system info: {:?}", info);
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_desktop_environment_detection() {
        // Test desktop environment detection
        let desktop = detect_desktop_environment();
        assert!(!desktop.is_empty());
    }

    #[test]
    fn test_system_info_collection() {
        // This test runs only on Linux
        #[cfg(target_os = "linux")]
        {
            let info = get_system_info().unwrap();
            assert!(!info.is_empty());
        }
    }

    #[test]
    fn test_mount_status_check() {
        // Test the mount status check function
        let temp_path = Path::new("/tmp/test_mount_check");
        assert!(!is_mounted(temp_path));
    }

    #[test]
    fn test_locate_fusermount_detects_fuse3_when_available() {
        if which("fusermount3").is_err() {
            // Environment does not provide fusermount3; nothing to assert.
            return;
        }

        let (flavor, helper) =
            locate_fusermount().expect("fusermount helper should be discoverable");
        assert_eq!(flavor, FuseFlavor::Fuse3);
        assert_eq!(
            helper.file_name().and_then(|name| name.to_str()),
            Some("fusermount3")
        );
    }
}
