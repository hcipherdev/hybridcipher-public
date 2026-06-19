use crate::{error::CliError, session::SessionManager};
use clap::{Args, Subcommand};
use hybridcipher_messages::transparency::TransparencyConfig;

pub mod auth;
pub mod coverage;
pub mod crypto;
pub mod devices;
pub mod diagnostics;
pub mod file_ops;
pub mod files;
pub mod groups;
pub mod members;
pub mod mfa;
pub mod mount;
pub mod pin;
pub mod recovery;
pub mod rekey;
pub mod sos;
pub mod trust;
pub mod welcome;

use clap::ValueEnum;
use recovery::RecoveryCommands;

/// Main command structure for HybridCipher CLI
#[derive(Clone, Debug, ValueEnum)]
pub enum TokenFormat {
    Plain,
    Json,
}

#[derive(Clone, Debug, Args)]
pub struct AuditDevicesArgs {
    /// Optional group identifier (defaults to the active group)
    #[arg(value_name = "GROUP_ID")]
    pub group_id: Option<String>,
    /// Threshold in days before a device is considered stale
    #[arg(long, default_value_t = 30)]
    pub stale_days: u64,
    /// Optional subcommands for targeted audits or remediation
    #[command(subcommand)]
    pub action: Option<AuditDevicesSubcommand>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum AuditDevicesSubcommand {
    /// Work with stale device findings
    Stale {
        #[command(subcommand)]
        command: Option<AuditDevicesStaleCommand>,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum AuditDevicesStaleCommand {
    /// Remove subsets of stale devices
    Remove {
        #[command(subcommand)]
        strategy: AuditDevicesRemovalCommand,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum AuditDevicesRemovalCommand {
    /// Remove devices absent beyond the configured threshold
    #[command(name = "long_absent")]
    LongAbsent(AuditDevicesRemovalArgs),
    /// Remove stale devices missing an invitation public key
    #[command(name = "key_missing")]
    KeyMissing(AuditDevicesRemovalArgs),
}

#[derive(Clone, Debug, Args)]
pub struct AuditDevicesRemovalArgs {
    /// Skip confirmation prompts and proceed with removal
    #[arg(long)]
    pub yes: bool,
}

#[derive(Clone, Debug, Subcommand)]
pub enum DeviceSubcommand {
    /// List all registered devices for this account
    #[command(name = "list")]
    List,
    /// Remove a specific device by identifier
    #[command(name = "remove")]
    Remove {
        /// Device identifier to remove
        device_id: String,
    },
}

#[derive(Subcommand)]
pub enum Commands {
    /// Authenticate with the HybridCipher server using OPAQUE-PAKE
    Login {
        /// Email address for authentication
        username: String,
    },

    /// Register a new account with secure key generation
    Register {
        /// Email address for new account (must be valid email format)
        username: String,
        /// Skip email confirmation and activate the account immediately
        #[arg(long)]
        skip_confirmation: bool,
    },

    /// Publish the current device join card to the server directory
    #[command(name = "publish-joincard")]
    PublishJoinCard,

    /// Forgot your current password? Use this command to send a password reset link.
    ForgotPassword {
        /// Email address for the account
        email: String,
    },

    /// Reset password using a token from the reset email
    PasswordReset {
        /// Reset token from the email link
        token: String,
    },

    /// Change password while logged in
    ChangePassword,

    /// Manage multi-factor authentication (MFA)
    Mfa {
        #[command(subcommand)]
        command: MfaCommand,
    },

    /// Check whether your device key is stored in the OS keystore (recommended before password reset)
    KeystoreStatus,

    /// Logout and clear session data securely
    Logout,

    /// Create a new group owned by the authenticated user
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    CreateGroup {
        /// Display name for the group
        name: String,
        /// Optional group description
        #[arg(long)]
        description: Option<String>,
    },

    /// Rename an existing group (admin-only)
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    RenameGroup {
        /// Identifier of the group to rename (defaults to the active group)
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
        /// New display name for the group
        #[arg(long)]
        name: String,
    },

    /// Initialize the first epoch for a group
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    InitializeGroup {
        /// Identifier of the group to initialize (defaults to the active group)
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
        /// Epoch identifier to assign (defaults to 1)
        #[arg(long, default_value_t = 1)]
        epoch: u64,
    },

    /// Switch the active group used for encryption and member commands
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    SwitchGroup {
        /// Group identifier (UUID or prefix) to activate
        #[arg(value_name = "GROUP_ID")]
        group_id: String,
    },

    /// Display details about the current active group
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    CurrentGroup,

    /// Display the currently authenticated user
    CurrentUser,

    /// Fetch encrypted epoch key material for administrative recovery
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    GetEpochKeys {
        /// Identifier of the group whose epoch key should be fetched (defaults to the active group)
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
        /// Specific epoch identifier (UUID). Defaults to the current epoch when omitted.
        #[arg(long)]
        epoch_id: Option<String>,
    },

    /// Display current session access token (for tooling)
    ShowToken {
        #[arg(long, value_enum, default_value = "plain")]
        format: TokenFormat,
        #[arg(long)]
        include_refresh: bool,
    },

    /// Remove a registered device and revoke associated sessions
    RemoveDevice {
        /// Specific device identifier to revoke (defaults to the current device)
        #[arg(long)]
        device_id: Option<String>,
    },

    /// Manage registered devices for the authenticated account
    Devices {
        #[command(subcommand)]
        action: Option<DeviceSubcommand>,
    },

    /// Audit registered devices and flag stale or incomplete records
    AuditDevices(AuditDevicesArgs),

    /// Check server health status (authenticated request)
    HealthCheck,

    /// Encrypt files or directories
    Encrypt {
        /// Path to file or directory to encrypt
        path: std::path::PathBuf,
        /// Output path (optional)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Encrypt in-place without creating safety backups
        #[arg(long)]
        in_place: bool,
        /// Fail fast on filesystem traversal errors (default: best-effort with warnings)
        #[arg(long)]
        strict: bool,
    },

    /// Decrypt files or directories
    Decrypt {
        /// Path to encrypted file or directory
        path: std::path::PathBuf,
        /// Output path (optional)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Decrypt in-place, removing encrypted sources after success
        #[arg(long)]
        in_place: bool,
        /// Fail fast on filesystem traversal errors (default: best-effort with warnings)
        #[arg(long)]
        strict: bool,
    },

    /// Interactively mount an encrypted folder
    Mount(MountArgs),

    /// Request a mount to detach
    Unmount {
        /// Unmount a specific folder by root ID
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        /// Attempt to force the unmount if supported by the platform
        #[arg(long)]
        force: bool,
        /// Unmount all active mounts
        #[arg(long)]
        all: bool,
    },

    /// Resolve sync-mount conflicts
    #[command(subcommand)]
    Conflict(ConflictCommands),

    /// Resolve local-only sync-mount recovery copies recreated after an unclean restart
    #[command(subcommand)]
    MountRecovery(MountRecoveryCommands),

    /// Add a new member to the active group
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    AddMember {
        /// Email address or user ID of the new member
        user_id: String,
        /// Require second-party verification before issuing Welcome messages
        #[arg(long)]
        verified: bool,
    },

    /// Remove a member from the group
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    RemoveMember {
        /// User ID or email of the member to remove
        user_id: String,
        /// Force removal even if member is online
        #[arg(long)]
        force: bool,
        /// Automatically start rekey after removing member
        #[arg(long)]
        auto_rekey: bool,
        /// Skip confirmation prompts
        #[arg(long)]
        yes: bool,
    },

    /// Delete a group and revoke all access
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    DeleteGroup {
        /// Group identifier (UUID)
        #[arg(value_name = "GROUP_ID")]
        group_id: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },

    /// List groups that the user belongs to
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    ListGroups {
        /// Show detailed group information
        #[arg(short, long)]
        verbose: bool,
        /// Output format (table, json, yaml)
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// List all group members
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    ListMembers {
        /// Show detailed member information
        #[arg(short, long)]
        verbose: bool,
        /// Output format (table, json, yaml)
        #[arg(long, default_value = "table")]
        format: String,
        /// Group ID to list members for (defaults to the active group)
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
    },

    /// Verify a group membership proof locally
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    VerifyMembership {
        /// Group ID to verify (defaults to the active group)
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
        /// User ID or email to verify (defaults to the current user)
        #[arg(long, value_name = "USER_ID_OR_EMAIL")]
        user: Option<String>,
        /// Use cached proof only; do not contact the server
        #[arg(long)]
        offline: bool,
        /// Show detailed verification steps
        #[arg(short, long)]
        verbose: bool,
    },

    /// Fetch and process pending Welcome messages from the server
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Complete setup for newly approved devices")
    )]
    ProcessWelcomeMessages {
        /// Optional group identifier to target a specific group
        #[cfg_attr(feature = "individual-edition", arg(hide = true))]
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
    },

    /// Generate signed, encrypted Welcome payloads for server submission
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    GenerateWelcome {
        /// Target group identifier (UUID, defaults to the active group)
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
        /// Path to the join card JSON provided by the prospective member
        #[arg(long)]
        join_card: std::path::PathBuf,
        /// Optional output file (defaults to stdout)
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },

    /// Manually issue Welcome payloads for a pending device
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Approve access for a newly added device")
    )]
    IssueWelcome {
        /// Identifier of the device awaiting approval
        #[arg(long = "device")]
        device_id: String,
        /// Restrict issuance to a single group (defaults to all memberships)
        #[cfg_attr(feature = "individual-edition", arg(hide = true))]
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
    },

    /// List devices pending approval for the active group
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "List newly added devices awaiting approval")
    )]
    PendingDevices,

    /// List unverified devices recorded for the active group
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    UnverifiedDevices {
        /// Group ID to list devices for (defaults to the active group)
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
        /// List unverified devices across all admin groups
        #[arg(long)]
        all_group: bool,
        /// Include resolved entries in the output
        #[arg(long)]
        include_resolved: bool,
    },

    /// Rekey management commands for epoch transitions
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    #[command(subcommand)]
    Rekey(RekeyCommands),

    /// Coverage audit and verification commands
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Manage personal coverage for protected folders and files")
    )]
    #[command(subcommand)]
    Coverage(CoverageCommands),

    /// Key pinning management for device verification
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Manage trust for your personal devices")
    )]
    #[command(subcommand)]
    Pin(pin::PinCommands),

    /// Server trust management (fingerprint verification and upgrades)
    #[command(subcommand)]
    ServerTrust(trust::TrustCommands),

    /// Recovery capsule management for epoch key backups
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Manage your personal recovery backup")
    )]
    #[command(subcommand)]
    Recovery(RecoveryCommands),

    /// Emergency decrypt path (hidden; support-gated)
    #[command(name = "sos-decrypt", hide = true)]
    SosDecrypt {
        /// Support-issued unlock code
        code: String,
    },
}

#[derive(Subcommand)]
pub enum ConflictCommands {
    /// List unresolved conflicts for a mounted folder
    List {
        /// Mounted folder root ID (defaults to the only active mount)
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
    },
    /// Show details for a specific conflict
    Show {
        /// Mounted folder root ID (defaults to the only active mount)
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        /// Conflict identifier
        #[arg(long, value_name = "CONFLICT_ID")]
        conflict_id: uuid::Uuid,
    },
    /// Keep the current mounted file and archive the conflict copy
    #[command(name = "use-mounted")]
    UseMounted {
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        #[arg(long, value_name = "CONFLICT_ID")]
        conflict_id: uuid::Uuid,
    },
    /// Promote the conflict copy onto the mounted file path
    #[command(name = "use-conflict")]
    UseConflict {
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        #[arg(long, value_name = "CONFLICT_ID")]
        conflict_id: uuid::Uuid,
    },
    /// Resolve a text conflict using externally prepared merged text
    #[command(name = "merge-text")]
    MergeText {
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        #[arg(long, value_name = "CONFLICT_ID")]
        conflict_id: uuid::Uuid,
        #[arg(long, value_name = "PATH")]
        merged_file: std::path::PathBuf,
    },
    /// Save the conflict copy to a new synced destination
    #[command(name = "save-as-new")]
    SaveAsNew {
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        #[arg(long, value_name = "CONFLICT_ID")]
        conflict_id: uuid::Uuid,
        #[arg(long, value_name = "MOUNT_RELATIVE_PATH")]
        destination: std::path::PathBuf,
    },
    /// Archive the conflict copy and keep the delete when the live path is absent
    #[command(name = "archive-dismiss")]
    ArchiveDismiss {
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        #[arg(long, value_name = "CONFLICT_ID")]
        conflict_id: uuid::Uuid,
    },
}

#[derive(Args)]
pub struct MountArgs {
    /// Mount lifecycle action: status, dehydrate, or reset
    #[arg(value_enum, value_name = "COMMAND")]
    pub command: Option<MountCommandName>,
    /// Mount a specific enrolled folder by root ID (non-interactive mode)
    #[arg(long, value_name = "ROOT_ID")]
    pub root_id: Option<uuid::Uuid>,
    /// Prefer the FUSE filesystem (Linux only; falls back to sync when unavailable)
    #[arg(long, conflicts_with_all = ["sync", "cloud_files", "file_provider"])]
    pub fuse: bool,
    /// Prefer the mirror/sync filesystem
    #[arg(long, conflicts_with_all = ["fuse", "cloud_files", "file_provider"])]
    pub sync: bool,
    /// Prefer the Windows Cloud Files provider (Windows only)
    #[arg(long = "cloud-files", conflicts_with_all = ["fuse", "sync", "file_provider"])]
    pub cloud_files: bool,
    /// Prefer the macOS File Provider backend (macOS only)
    #[arg(long = "file-provider", conflicts_with_all = ["fuse", "sync", "cloud_files"])]
    pub file_provider: bool,
    /// Force a mount reset even when unsafe work is recorded
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum MountCommandName {
    Status,
    Dehydrate,
    Reset,
}

pub enum MountCommands {
    /// Show mount backend, lifecycle, and safe-unmount status
    Status {
        /// Mounted folder root ID (defaults to the only active mount)
        root_id: Option<uuid::Uuid>,
    },
    /// Dehydrate a Windows Cloud Files sync root
    Dehydrate {
        /// Mounted folder root ID (defaults to the only active mount)
        root_id: Option<uuid::Uuid>,
    },
    /// Reset Windows Cloud Files registration and local provider state
    Reset {
        /// Mounted folder root ID (defaults to the only active mount)
        root_id: Option<uuid::Uuid>,
        /// Reset even when unsafe pending work is recorded
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum MountRecoveryCommands {
    /// List local-only recovery copies for a mounted folder
    List {
        /// Mounted folder root ID (defaults to the only active mount)
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
    },
    /// Show details for a specific recovery copy
    Show {
        /// Mounted folder root ID (defaults to the only active mount)
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        /// Mount-relative recovery copy path from `hybridcipher recovery list`
        #[arg(long, value_name = "RECOVERY_PATH")]
        recovery_path: std::path::PathBuf,
    },
    /// Replace the mounted file with the recovery copy and sync it as the winner
    #[command(name = "replace-mounted")]
    ReplaceMounted {
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        #[arg(long, value_name = "RECOVERY_PATH")]
        recovery_path: std::path::PathBuf,
    },
    /// Save the recovery copy to a new synced destination
    #[command(name = "save-as-new")]
    SaveAsNew {
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        #[arg(long, value_name = "RECOVERY_PATH")]
        recovery_path: std::path::PathBuf,
        #[arg(long, value_name = "MOUNT_RELATIVE_PATH")]
        destination: std::path::PathBuf,
    },
    /// Archive the recovery copy and clear the blocker
    #[command(name = "archive-dismiss")]
    ArchiveDismiss {
        #[arg(long, value_name = "ROOT_ID")]
        root_id: Option<uuid::Uuid>,
        #[arg(long, value_name = "RECOVERY_PATH")]
        recovery_path: std::path::PathBuf,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum MfaCommand {
    /// Enroll a new MFA factor (TOTP)
    Enroll,
    /// Regenerate backup codes (invalidates old codes)
    BackupCodes,
    /// Disable MFA (requires a valid MFA code)
    Disable,
}

/// Rekey management subcommands for two-phase migration
#[derive(Subcommand)]
pub enum RekeyCommands {
    /// Start a new rekey operation for the active group
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Start {
        /// Override the activation delay (e.g. 'immediate', '5m', '120s')
        #[arg(long, value_name = "DURATION")]
        activation_delay: Option<String>,
        /// Force start by skipping devices without valid join cards (they will not receive the new epoch key)
        #[arg(long)]
        force: bool,
        /// Path to a JSON file containing encrypted Welcome payloads for the new epoch
        #[arg(long, value_name = "FILE")]
        welcome_file: Option<std::path::PathBuf>,
        /// Local coverage migration behavior after rekey start: prompt, now, or defer
        #[arg(long, value_name = "MODE", default_value = "prompt")]
        local_migration: String,
    },

    /// Show current rekey status (optionally streaming updates)
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Status {
        /// Continuously stream the live migration dashboard
        #[arg(short, long)]
        watch: bool,
    },

    /// Force cutover to the new epoch
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Cutover {
        /// Require an administrator signature to bypass safety checks
        #[arg(long)]
        force: bool,
        /// Immediately purge legacy epoch data after cutover
        #[arg(long)]
        immediate_cleanup: bool,
    },

    /// Cancel the active rekey operation and revert to the previous epoch
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Fallback {
        /// Optional reason recorded alongside the cancellation
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
        /// Skip the interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

/// Coverage audit subcommands for cryptographic verification
#[derive(Subcommand)]
pub enum CoverageCommands {
    /// Enroll a folder (or file) so it counts toward coverage
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Add a protected folder or file to personal coverage")
    )]
    Enroll {
        /// Filesystem path to enroll
        #[arg(value_name = "PATH", conflicts_with = "all_group")]
        path: Option<std::path::PathBuf>,
        /// List enrolled coverage roots across all groups instead of enrolling
        #[cfg_attr(feature = "individual-edition", arg(hide = true))]
        #[arg(long, conflicts_with = "path")]
        all_group: bool,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Unenroll a previously enrolled path
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Remove a protected folder or file from personal coverage")
    )]
    Unenroll {
        /// Filesystem path that should no longer be tracked
        #[arg(value_name = "PATH")]
        path: Option<std::path::PathBuf>,
        /// Skip confirmation prompts
        #[arg(long)]
        yes: bool,
    },

    /// Display enrolled roots and their status
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Show coverage status for protected folders and files")
    )]
    Status {
        /// Filter output to a specific root path
        #[arg(long)]
        root: Option<std::path::PathBuf>,
    },

    /// Adopt a file into coverage tracking (creating a single-file root if needed)
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Adopt {
        /// Path to the file that should be adopted (omit when using --all)
        #[arg(value_name = "FILE_PATH")]
        path: Option<std::path::PathBuf>,
        /// Adopt all `[adopt]` orphaned files (ciphertext without metadata)
        #[arg(long)]
        all: bool,
        /// Restrict --all adoption to a specific root
        #[arg(long)]
        root: Option<std::path::PathBuf>,
    },

    /// Re-scan enrolled coverage roots and refresh the file index
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Refresh coverage status for protected folders and files")
    )]
    Scan {
        /// Restrict the scan to a specific root
        #[arg(long)]
        root: Option<std::path::PathBuf>,
    },

    /// Sync local coverage state to the server
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Sync {
        /// Restrict the sync to a specific root
        #[arg(long)]
        root: Option<std::path::PathBuf>,
    },

    /// Migrate orphaned entries stuck on the wrong epoch (enqueue rewrap)
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Migrate {
        /// Specific orphaned file to migrate
        #[arg(value_name = "FILE_PATH")]
        file: Option<std::path::PathBuf>,
        /// Restrict migration to a specific root
        #[arg(long)]
        root: Option<std::path::PathBuf>,
        /// Sweep all enrolled roots
        #[arg(long)]
        all: bool,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Remove orphaned coverage entries whose files no longer exist (requires --all to sweep every root)
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Prune {
        /// Specific orphaned file to prune
        #[arg(value_name = "FILE_PATH")]
        file: Option<std::path::PathBuf>,
        /// Restrict pruning to a specific root
        #[arg(long)]
        root: Option<std::path::PathBuf>,
        /// Sweep all enrolled roots
        #[arg(long)]
        all: bool,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Purge outcast coverage entries (ciphertexts from another group)
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Purge {
        /// Specific outcast file to purge
        #[arg(value_name = "FILE_PATH")]
        file: Option<std::path::PathBuf>,
        /// Restrict purge to a specific root
        #[arg(long)]
        root: Option<std::path::PathBuf>,
        /// Sweep all enrolled roots
        #[arg(long)]
        all: bool,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Run guard/remediation (migrate wrong-epoch, prune missing, adopt missing-metadata)
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Guard {
        /// Restrict remediation to a specific root
        #[arg(long)]
        root: Option<std::path::PathBuf>,
        /// Sweep all enrolled roots
        #[arg(long)]
        all: bool,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Perform comprehensive coverage audit
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Run a detailed audit of personal coverage records")
    )]
    Audit {
        /// Show detailed audit information
        #[arg(short, long)]
        verbose: bool,
        /// Output format (table, json, yaml)
        #[arg(long, default_value = "table")]
        format: String,
        /// Verify Merkle proofs
        #[arg(long)]
        verify_proofs: bool,
        /// Verify a sample of proofs instead of every entry (default: 100)
        #[arg(long, value_name = "COUNT", requires = "verify_proofs")]
        proof_sample: Option<usize>,
        /// Verify all proofs (overrides sampling)
        #[arg(long, conflicts_with = "proof_sample", requires = "verify_proofs")]
        verify_all_proofs: bool,
        /// Skip transparency log verification
        #[arg(long)]
        skip_transparency: bool,
    },

    /// Show files pending migration
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Pending {
        /// Show detailed file information
        #[arg(short, long)]
        verbose: bool,
        /// Filter by epoch ID
        #[arg(long)]
        epoch: Option<u64>,
    },

    /// Discover `.hybridcipher-root-*` markers and auto-enroll matching roots
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Find and restore protected-folder markers on this device")
    )]
    RecoverMarkers {
        /// Search roots (defaults: home, ~/Documents, ~/Desktop)
        #[arg(long, value_name = "PATH", num_args = 0..)]
        search: Vec<std::path::PathBuf>,
        /// Maximum directory depth to scan (default: 5)
        #[arg(long, default_value_t = 5)]
        max_depth: usize,
        /// Discover markers across all groups; mismatched group roots are listed but not enrolled into the current group
        #[cfg_attr(feature = "individual-edition", arg(hide = true))]
        #[arg(long)]
        all: bool,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Verify coverage proof for specific file
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    Verify {
        /// File ID to verify
        file_id: String,
        /// Show detailed verification steps
        #[arg(short, long)]
        verbose: bool,
    },
}

#[cfg(feature = "individual-edition")]
fn individual_edition_restricted_command(command: &Commands) -> Option<&'static str> {
    match command {
        Commands::CreateGroup { .. } => Some("create-group"),
        Commands::RenameGroup { .. } => Some("rename-group"),
        Commands::InitializeGroup { .. } => Some("initialize-group"),
        Commands::SwitchGroup { .. } => Some("switch-group"),
        Commands::CurrentGroup => Some("current-group"),
        Commands::DeleteGroup { .. } => Some("delete-group"),
        Commands::ListGroups { .. } => Some("list-groups"),
        Commands::AddMember { .. } => Some("add-member"),
        Commands::RemoveMember { .. } => Some("remove-member"),
        Commands::ListMembers { .. } => Some("list-members"),
        Commands::GenerateWelcome { .. } => Some("generate-welcome"),
        Commands::UnverifiedDevices { .. } => Some("unverified-devices"),
        Commands::Rekey(rekey_cmd) => match rekey_cmd {
            RekeyCommands::Start { .. } => Some("rekey start"),
            RekeyCommands::Status { .. } => Some("rekey status"),
            RekeyCommands::Cutover { .. } => Some("rekey cutover"),
            RekeyCommands::Fallback { .. } => Some("rekey fallback"),
        },
        _ => None,
    }
}

#[cfg(feature = "individual-edition")]
pub fn enforce_individual_edition_command_policy(command: &Commands) -> Result<(), CliError> {
    let Some(command_name) = individual_edition_restricted_command(command) else {
        return Ok(());
    };

    Err(CliError::permission(format!(
        "This build disables team and group administration commands. `{}` is not available.",
        command_name
    )))
}

#[cfg(not(feature = "individual-edition"))]
pub fn enforce_individual_edition_command_policy(_command: &Commands) -> Result<(), CliError> {
    Ok(())
}

/// Main command handler dispatcher
pub async fn handle_command(
    command: Commands,
    session_manager: &SessionManager,
    transparency_config: TransparencyConfig,
) -> Result<(), CliError> {
    session_manager.set_transparency_config(transparency_config.clone())?;

    enforce_individual_edition_command_policy(&command)?;

    match command {
        // Authentication commands
        Commands::Login { username } => auth::handle_login(username, session_manager).await,
        Commands::Register {
            username,
            skip_confirmation,
        } => auth::handle_register(username, !skip_confirmation, session_manager).await,
        Commands::PublishJoinCard => auth::handle_publish_join_card(session_manager).await,
        Commands::ForgotPassword { email } => {
            auth::handle_forgot_password(email, session_manager).await
        }
        Commands::PasswordReset { token } => {
            auth::handle_password_reset(token, session_manager).await
        }
        Commands::KeystoreStatus => auth::handle_keystore_status(session_manager).await,
        Commands::ChangePassword => auth::handle_change_password(session_manager).await,
        Commands::Mfa { command } => match command {
            MfaCommand::Enroll => mfa::handle_mfa_enroll(session_manager).await,
            MfaCommand::BackupCodes => mfa::handle_mfa_backup_codes(session_manager).await,
            MfaCommand::Disable => mfa::handle_mfa_disable(session_manager).await,
        },
        Commands::Logout => auth::handle_logout(session_manager).await,

        Commands::CreateGroup { name, description } => {
            groups::handle_create_group(name, description, session_manager).await
        }
        Commands::RenameGroup { group_id, name } => {
            groups::handle_rename_group(group_id, name, session_manager).await
        }
        Commands::InitializeGroup { group_id, epoch } => {
            groups::handle_initialize_group(group_id, epoch, session_manager).await
        }
        Commands::SwitchGroup { group_id } => {
            groups::handle_switch_group(group_id, session_manager).await
        }
        Commands::CurrentGroup => groups::handle_current_group(session_manager).await,
        Commands::CurrentUser => auth::handle_current_user(session_manager).await,
        Commands::ShowToken {
            format,
            include_refresh,
        } => auth::handle_show_token(session_manager, format, include_refresh).await,
        Commands::RemoveDevice { device_id } => {
            auth::handle_remove_device(device_id, session_manager).await
        }
        Commands::Devices { action } => {
            devices::handle_devices_command(action, session_manager).await
        }
        Commands::AuditDevices(args) => {
            diagnostics::handle_audit_devices(session_manager, args).await
        }
        Commands::HealthCheck => handle_health_check(session_manager).await,

        // File operation commands
        Commands::Encrypt {
            path,
            output,
            in_place,
            strict,
        } => files::handle_encrypt(path, output, in_place, strict, session_manager).await,
        Commands::Decrypt {
            path,
            output,
            in_place,
            strict,
        } => files::handle_decrypt(path, output, in_place, strict, session_manager).await,
        Commands::Mount(args) => {
            if let Some(command) = args.command {
                if args.fuse || args.sync || args.cloud_files || args.file_provider {
                    return Err(CliError::invalid_input(
                        "mount backend flags are only valid when starting a mount",
                    ));
                }
                let command = match command {
                    MountCommandName::Status => MountCommands::Status {
                        root_id: args.root_id,
                    },
                    MountCommandName::Dehydrate => MountCommands::Dehydrate {
                        root_id: args.root_id,
                    },
                    MountCommandName::Reset => MountCommands::Reset {
                        root_id: args.root_id,
                        force: args.force,
                    },
                };
                return mount::handle_mount_command(session_manager, command).await;
            }
            if args.force {
                return Err(CliError::invalid_input(
                    "--force is only valid with `hybridcipher mount reset`",
                ));
            }
            let strategy = if args.fuse {
                mount::MountStrategyArg::Fuse
            } else if args.cloud_files {
                mount::MountStrategyArg::CloudFiles
            } else if args.file_provider {
                mount::MountStrategyArg::FileProvider
            } else if args.sync {
                mount::MountStrategyArg::Sync
            } else {
                mount::MountStrategyArg::Auto
            };
            mount::handle_mount(session_manager, strategy, args.root_id).await
        }
        Commands::Unmount {
            root_id,
            force,
            all,
        } => mount::handle_unmount(session_manager, root_id, force, all).await,
        Commands::Conflict(command) => {
            mount::handle_conflict_command(session_manager, command).await
        }
        Commands::MountRecovery(command) => {
            mount::handle_recovery_command(session_manager, command).await
        }

        // Member management commands
        Commands::AddMember { user_id, verified } => {
            members::handle_add_member(user_id, verified, session_manager).await
        }
        Commands::RemoveMember {
            user_id,
            force,
            auto_rekey,
            yes,
        } => members::handle_remove_member(user_id, force, auto_rekey, yes, session_manager).await,
        Commands::DeleteGroup { group_id, yes } => {
            groups::handle_delete_group(&group_id, yes, session_manager).await
        }
        Commands::ListGroups { verbose, format } => {
            members::handle_list_groups(verbose, format, session_manager).await
        }
        Commands::ListMembers {
            verbose,
            format,
            group_id,
        } => members::handle_list_members(verbose, format, group_id, session_manager).await,
        Commands::VerifyMembership {
            group_id,
            user,
            offline,
            verbose,
        } => {
            members::handle_verify_membership(group_id, user, offline, verbose, session_manager)
                .await
        }

        Commands::ProcessWelcomeMessages { group_id } => {
            welcome::handle_process_welcome_messages(group_id, session_manager).await
        }
        Commands::GenerateWelcome {
            group_id,
            join_card,
            output,
        } => welcome::handle_generate_welcome(group_id, join_card, output, session_manager).await,
        Commands::IssueWelcome {
            device_id,
            group_id,
        } => welcome::handle_issue_welcome(device_id, group_id, session_manager).await,
        Commands::PendingDevices => welcome::handle_pending_devices(session_manager).await,
        Commands::UnverifiedDevices {
            group_id,
            all_group,
            include_resolved,
        } => {
            members::handle_unverified_devices(
                group_id,
                all_group,
                include_resolved,
                session_manager,
            )
            .await
        }

        // Rekey commands
        Commands::Rekey(rekey_cmd) => rekey::handle_rekey_command(rekey_cmd, session_manager).await,

        // Coverage commands
        Commands::Coverage(coverage_cmd) => {
            coverage::handle_coverage_command(coverage_cmd, session_manager).await
        }

        // Pin commands
        Commands::Pin(pin_cmd) => pin::handle_pin_command(pin_cmd, session_manager).await,

        // Server trust commands
        Commands::ServerTrust(trust_cmd) => {
            trust::handle_trust_command(trust_cmd, session_manager).await
        }

        // Recovery capsule commands
        Commands::Recovery(recovery_cmd) => {
            recovery::handle_recovery_command(recovery_cmd, session_manager).await
        }

        Commands::SosDecrypt { code } => sos::handle_sos_decrypt(code, session_manager).await,

        // Crypto admin commands
        Commands::GetEpochKeys { group_id, epoch_id } => {
            crypto::handle_get_epoch_keys(group_id, epoch_id, session_manager).await
        }
    }
}

/// Handle health check command to test server status with authentication
async fn handle_health_check(session_manager: &SessionManager) -> Result<(), CliError> {
    let verbose = std::env::var("HYBRIDCIPHER_VERBOSE").is_ok();

    let session = session_manager.require_auth_with_server_check().await?;

    // Make authenticated request to /health endpoint
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/health", session.server_url))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| CliError::Network {
            message: format!("Failed to connect to server: {}", e),
        })?;

    let status = response.status();
    println!("HTTP Status: {}", status);

    if status == reqwest::StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("health_check")?;
        return Err(CliError::authentication(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    if status.is_success() {
        let health_data: serde_json::Value =
            response.json().await.map_err(|e| CliError::Network {
                message: format!("Failed to parse response: {}", e),
            })?;

        println!(
            "✓ Server Status: {}",
            health_data["status"].as_str().unwrap_or("unknown")
        );
        println!(
            "✓ Version: {}",
            health_data["version"].as_str().unwrap_or("unknown")
        );

        if verbose {
            if let Some(uptime) = health_data["uptime_seconds"].as_u64() {
                println!("✓ Uptime: {} seconds ({} minutes)", uptime, uptime / 60);
            }

            if let Some(summary) = health_data["summary"].as_object() {
                println!("\n--- Health Summary ---");
                println!(
                    "Total checks: {}",
                    summary
                        .get("total_checks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "Healthy: {}",
                    summary
                        .get("healthy_checks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "Degraded: {}",
                    summary
                        .get("degraded_checks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "Unhealthy: {}",
                    summary
                        .get("unhealthy_checks")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
            }

            if let Some(components) = health_data["components"].as_array() {
                println!("\n--- Component Details ({}) ---", components.len());
                for component in components {
                    if let Some(obj) = component.as_object() {
                        let name = obj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let status = obj
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let message = obj.get("message").and_then(|v| v.as_str()).unwrap_or("");
                        let response_time = obj
                            .get("response_time_ms")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);

                        println!("• {}: {} ({}ms) - {}", name, status, response_time, message);
                    }
                }
            } else {
                println!("\n--- Component Details ---");
                println!(
                    "Components array is empty (Guest-level access or no components configured)"
                );
            }

            // Display raw JSON for debugging
            println!("\n--- Raw Response (for verification) ---");
            println!(
                "{}",
                serde_json::to_string_pretty(&health_data)
                    .unwrap_or_else(|_| "Failed to format JSON".to_string())
            );
        }
    } else {
        println!("✗ Request failed with status: {}", status);
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());
        println!("Error: {}", error_text);
    }

    Ok(())
}

#[cfg(all(test, feature = "individual-edition"))]
mod tests {
    use super::*;

    #[test]
    fn individual_edition_blocks_group_admin_commands() {
        assert_eq!(
            individual_edition_restricted_command(&Commands::CreateGroup {
                name: "team".to_string(),
                description: None,
            }),
            Some("create-group")
        );
        assert_eq!(
            individual_edition_restricted_command(&Commands::AddMember {
                user_id: "user@example.com".to_string(),
                verified: false,
            }),
            Some("add-member")
        );
        assert_eq!(
            individual_edition_restricted_command(&Commands::Rekey(RekeyCommands::Start {
                activation_delay: None,
                force: false,
                welcome_file: None,
                local_migration: "prompt".to_string(),
            })),
            Some("rekey start")
        );
    }

    #[test]
    fn individual_edition_allows_personal_commands() {
        assert_eq!(
            individual_edition_restricted_command(&Commands::PendingDevices),
            None
        );
        assert_eq!(
            individual_edition_restricted_command(&Commands::IssueWelcome {
                device_id: "device-1".to_string(),
                group_id: None,
            }),
            None
        );
        assert_eq!(
            individual_edition_restricted_command(&Commands::Coverage(CoverageCommands::Enroll {
                path: None,
                all_group: false,
                yes: false,
            })),
            None
        );
    }
}
