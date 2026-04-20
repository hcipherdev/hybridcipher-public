//! PIN command implementations for HybridCipher CLI
//!
//! This module provides CLI commands for managing pinned device identity keys.
//! Pin management allows users to establish secure first-contact trust through
//! out-of-band verification methods like QR codes and safety numbers.

use crate::{
    audit::{PinAuditAction, PinAuditEntry},
    commands::members,
    error::CliError,
    session::SessionManager,
    ui,
};
use base64::Engine as _;
use chrono::{Duration, Utc};
use clap::Subcommand;
use hybridcipher_client::invitation::JoinCard as ClientJoinCard;
use hybridcipher_client::pinning::{
    display_pinning_qr_code, display_pinning_qr_code_from_url, generate_fingerprint,
    generate_pinning_url, generate_safety_number, verify_fingerprint_format, PinnedKey,
    PinningConfig, PinningError, PinningMethod, PinningStore,
};
use hybridcipher_client::storage::Storage;
use hybridcipher_crypto::signatures::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_yaml;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::Duration as StdDuration;
use tokio::fs as tokio_fs;
use tokio::io::AsyncWriteExt;
use tracing::warn;
use uuid::Uuid;

/// PIN management subcommands for device identity verification
#[derive(Subcommand)]
pub enum PinCommands {
    /// Add a new pinned key for a user's device
    #[command(
        override_usage = "hybridcipher pin add --user <USER_ID_OR_EMAIL> --device <DEVICE_ID> [--join-card <PATH>] [--method manual|qr-code|safety-number] [--fingerprint <FP> | --qr | --safety-number <SN>] [--notes <TEXT>]",
        after_help = "Join card sources: --join-card <PATH>, cached join card, or server directory (if accessible).\nExamples:\n  hybridcipher pin add --user alice@example.com --device laptop --join-card ./join_card.json --fingerprint \"ABCD EFGH IJKL MNOP\"\n  hybridcipher pin add --user alice@example.com --device laptop --join-card ./join_card.json --qr\n  hybridcipher pin add --user alice@example.com --device laptop --join-card ./join_card.json --safety-number \"1234 5678 9012\"\nNotes:\n  - --qr prompts for a pin URL from the other device.\n  - pin add marks the pin verified immediately."
    )]
    Add {
        /// User ID or email to pin key for
        #[arg(long = "user", value_name = "USER_ID_OR_EMAIL", requires = "device")]
        user: Option<String>,
        /// Device ID to pin key for
        #[arg(long = "device", value_name = "DEVICE_ID", requires = "user")]
        device: Option<String>,
        /// Optional join card path to load identity key from
        #[arg(long, value_name = "PATH")]
        join_card: Option<PathBuf>,
        /// Verification method to use
        #[arg(long, value_enum, default_value = "manual")]
        method: PinMethodArg,
        /// QR code scanning mode
        #[arg(long)]
        qr: bool,
        /// Manual fingerprint verification
        #[arg(long)]
        fingerprint: Option<String>,
        /// Safety number verification
        #[arg(long)]
        safety_number: Option<String>,
        /// Notes about this pinning
        #[arg(long)]
        notes: Option<String>,
    },

    /// List pinned keys for the active group
    #[cfg_attr(
        not(feature = "individual-edition"),
        command(
            after_help = "Uses the active group to scope results. To switch groups, run `hybridcipher use-group <GROUP_ID>`. Use --all-group to include all admin groups."
        )
    )]
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "List pinned keys for your personal devices")
    )]
    List {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
        /// Output format (table, json, yaml)
        #[arg(long, default_value = "table")]
        format: String,
        /// Filter by user ID or email
        #[arg(long, value_name = "USER_ID_OR_EMAIL")]
        user: Option<String>,
        /// List pins across all admin groups
        #[cfg_attr(feature = "individual-edition", arg(hide = true))]
        #[arg(long)]
        all_group: bool,
    },

    /// Remove a pinned key
    Remove {
        /// User ID or email to remove pin for
        user_id: String,
        /// Device ID to remove pin for
        device_id: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },

    /// Verify a pinned key against current device key
    #[command(
        override_usage = "hybridcipher pin verify <USER_ID_OR_EMAIL> <DEVICE_ID> [--fingerprint <FP> | --safety-number <SN>]\n       hybridcipher pin verify",
        after_help = "Run without arguments to list unverified pins. Use --fingerprint or --safety-number to verify and promote an unverified pin."
    )]
    Verify {
        /// User ID or email to verify
        user_id: Option<String>,
        /// Device ID to verify
        device_id: Option<String>,
        /// Expected fingerprint to verify against
        #[arg(long)]
        fingerprint: Option<String>,
        /// Expected safety number to verify against
        #[arg(long)]
        safety_number: Option<String>,
    },

    /// Generate and display QR code for key pinning
    Qr {
        /// User ID or email to generate QR for
        user_id: String,
        /// Device ID to generate QR for
        device_id: String,
        /// Save QR code to file instead of displaying
        #[arg(long)]
        save: Option<std::path::PathBuf>,
    },

    /// Show the current device fingerprint (optionally as QR)
    #[command(name = "self")]
    SelfPin {
        /// Display QR code for the current device key
        #[arg(long)]
        qr: bool,
    },

    /// Generate safety number for two devices
    SafetyNumber {
        /// User ID or email for first device
        user_id1: String,
        /// Device ID for first device
        device_id1: String,
        /// User ID or email for second device
        user_id2: String,
        /// Device ID for second device
        device_id2: String,
    },

    /// Import a pinned key from QR code or URL
    Import {
        /// HybridCipher pinning URL to import
        url: String,
        /// Notes about this pinning
        #[arg(long)]
        notes: Option<String>,
    },

    /// Export pinned key information
    Export {
        /// User ID or email to export
        user_id: String,
        /// Device ID to export
        device_id: String,
        /// Export format (json, yaml, qr)
        #[arg(long, default_value = "json")]
        format: String,
    },

    /// Show pinning configuration and status
    Config {
        /// Show current configuration
        #[arg(long)]
        show: bool,
        /// Set maximum pin age in days
        #[arg(long)]
        max_age_days: Option<u32>,
        /// Set maximum signed pin URL age (days)
        #[arg(long)]
        signed_url_max_age_days: Option<u32>,
        /// Set maximum allowed future skew for signed pin URLs (seconds)
        #[arg(long, default_value_t = 600)]
        signed_url_max_future_secs: u32,
        /// Require second-party verification for device trust
        #[arg(long)]
        require_second_party: bool,
        /// Disable second-party verification requirement
        #[arg(long, conflicts_with = "require_second_party")]
        no_require_second_party: bool,
    },

    /// Run the second-party verification worker for assigned devices
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    SecondPartyWorker {
        /// Poll interval in seconds
        #[arg(long, default_value_t = 30)]
        interval_secs: u64,
        /// Exit after handling at most one assigned task
        #[arg(long)]
        once: bool,
        /// Run continuously in the background unless --verbose is set
        #[arg(long)]
        daemon: bool,
        /// Emit detailed output for debugging
        #[arg(long)]
        verbose: bool,
        #[arg(long, hide = true)]
        daemon_child: bool,
    },

    /// Enqueue a second-party verification job for a target device
    #[cfg_attr(feature = "individual-edition", command(hide = true))]
    #[command(
        override_usage = "hybridcipher pin second-party-enqueue --target-user <USER_ID_OR_EMAIL> --target-device <DEVICE_ID> (--fingerprint <FINGERPRINT> | --join-card <PATH>) [GROUP_ID]\n       hybridcipher pin second-party-enqueue --status [--all-group]\n       hybridcipher pin second-party-enqueue --status --target-user <USER_ID_OR_EMAIL> --target-device <DEVICE_ID>",
        after_help = "Required: provide either --fingerprint or --join-card unless using --status. Without --all-group, status is scoped to the current group.",
        group = clap::ArgGroup::new("expected_input")
            .required(false)
            .args(["fingerprint", "join_card"])
    )]
    SecondPartyEnqueue {
        /// Target user ID or email
        #[arg(long = "target-user", value_name = "USER_ID_OR_EMAIL")]
        target_user_id: Option<String>,
        /// Target device ID
        #[arg(long = "target-device", value_name = "DEVICE_ID")]
        target_device_id: Option<String>,
        /// Group ID for rule-based verifier selection (defaults to the active group)
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
        /// Expected fingerprint for the target device
        #[arg(long, value_name = "FINGERPRINT", conflicts_with_all = ["join_card"])]
        fingerprint: Option<String>,
        /// Join card to derive the expected fingerprint
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fingerprint"])]
        join_card: Option<PathBuf>,
        /// Verifier user IDs or emails (repeatable)
        #[arg(
            long = "verifier-user",
            value_name = "USER_ID_OR_EMAIL",
            num_args = 1..
        )]
        verifier_user_ids: Vec<String>,
        /// Show the current verification status instead of enqueueing
        #[arg(
            long,
            conflicts_with_all = ["fingerprint", "join_card", "verifier_user_ids"]
        )]
        status: bool,
        /// Show status across all groups (admins only)
        #[arg(long, requires = "status", conflicts_with_all = ["target_user_id", "target_device_id"])]
        all_group: bool,
    },
}

/// Verification method argument for CLI
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum PinMethodArg {
    Manual,
    QrCode,
    SafetyNumber,
}

impl From<PinMethodArg> for PinningMethod {
    fn from(method: PinMethodArg) -> Self {
        match method {
            PinMethodArg::Manual => PinningMethod::Manual,
            PinMethodArg::QrCode => PinningMethod::QrCode,
            PinMethodArg::SafetyNumber => PinningMethod::SafetyNumber,
        }
    }
}

/// Handle PIN command execution
pub async fn handle_pin_command(
    pin_cmd: PinCommands,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    match pin_cmd {
        PinCommands::Add {
            user,
            device,
            join_card,
            method,
            qr,
            fingerprint,
            safety_number,
            notes,
        } => {
            let (user_id, device_id) = match (user, device) {
                (Some(u), Some(d)) => (u, d),
                _ => {
                    return Err(CliError::invalid_input(
                        "Specify both --user <USER_ID_OR_EMAIL> and --device <DEVICE_ID>."
                            .to_string(),
                    ))
                }
            };

            handle_pin_add(
                user_id,
                device_id,
                join_card,
                method,
                qr,
                fingerprint,
                safety_number,
                notes,
                session_manager,
            )
            .await
        }
        PinCommands::List {
            verbose,
            format,
            user,
            all_group,
        } => handle_pin_list(verbose, format, user, all_group, session_manager).await,
        PinCommands::Remove {
            user_id,
            device_id,
            yes,
        } => handle_pin_remove(user_id, device_id, yes, session_manager).await,
        PinCommands::Verify {
            user_id,
            device_id,
            fingerprint,
            safety_number,
        } => {
            handle_pin_verify(
                user_id,
                device_id,
                fingerprint,
                safety_number,
                session_manager,
            )
            .await
        }
        PinCommands::Qr {
            user_id,
            device_id,
            save,
        } => handle_pin_qr(user_id, device_id, save, session_manager).await,
        PinCommands::SelfPin { qr } => handle_pin_self(qr, session_manager).await,
        PinCommands::SafetyNumber {
            user_id1,
            device_id1,
            user_id2,
            device_id2,
        } => {
            handle_safety_number(user_id1, device_id1, user_id2, device_id2, session_manager).await
        }
        PinCommands::Import { url, notes } => handle_pin_import(url, notes, session_manager).await,
        PinCommands::Export {
            user_id,
            device_id,
            format,
        } => handle_pin_export(user_id, device_id, format, session_manager).await,
        PinCommands::Config {
            show,
            max_age_days,
            signed_url_max_age_days,
            signed_url_max_future_secs,
            require_second_party,
            no_require_second_party,
        } => {
            handle_pin_config(
                show,
                max_age_days,
                signed_url_max_age_days,
                signed_url_max_future_secs,
                require_second_party,
                no_require_second_party,
                session_manager,
            )
            .await
        }
        PinCommands::SecondPartyWorker {
            interval_secs,
            once,
            daemon,
            verbose,
            daemon_child,
        } => {
            if daemon && once {
                return Err(CliError::invalid_input(
                    "--daemon cannot be combined with --once.".to_string(),
                ));
            }
            if daemon && !verbose && !daemon_child {
                return spawn_second_party_worker_daemon(interval_secs);
            }
            run_second_party_worker(interval_secs, once, daemon, verbose, session_manager).await
        }
        PinCommands::SecondPartyEnqueue {
            target_user_id,
            target_device_id,
            group_id,
            fingerprint,
            join_card,
            verifier_user_ids,
            status,
            all_group,
        } => {
            if status {
                handle_second_party_status(
                    target_user_id,
                    target_device_id,
                    all_group,
                    session_manager,
                )
                .await
            } else {
                let target_user_id = target_user_id.ok_or_else(|| {
                    CliError::invalid_input("Specify --target-user <USER_ID_OR_EMAIL>.".to_string())
                })?;
                let target_device_id = target_device_id.ok_or_else(|| {
                    CliError::invalid_input("Specify --target-device <DEVICE_ID>.".to_string())
                })?;
                handle_second_party_enqueue(
                    target_user_id,
                    target_device_id,
                    group_id,
                    fingerprint,
                    join_card,
                    verifier_user_ids,
                    session_manager,
                )
                .await
            }
        }
    }
}

/// Add a new pinned key
async fn handle_pin_add(
    user_id: String,
    device_id: String,
    join_card_path: Option<PathBuf>,
    method: PinMethodArg,
    qr: bool,
    fingerprint: Option<String>,
    safety_number: Option<String>,
    notes: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let user_identifier = user_id;

    println!(
        "Adding pinned key for user '{}', device '{}'",
        user_identifier, device_id
    );

    session_manager.require_auth()?;
    let (_, _, pin_config) = pinning_store_for_session(session_manager).await?;

    let mut resolved_user_id = user_identifier.clone();
    let mut join_card_override: Option<ClientJoinCard> = None;

    if resolved_user_id.contains('@') {
        match session_manager
            .resolve_user_identifier(&resolved_user_id)
            .await
        {
            Ok(resolved) => {
                resolved_user_id = resolved;
            }
            Err(err) => {
                if let Some(path) = join_card_path.as_ref() {
                    let join_card = load_join_card_file(path)?;
                    let fallback_user_id = join_card.user_id.to_string();
                    let _ = session_manager
                        .cache_user_identity(&resolved_user_id, &fallback_user_id)
                        .await;
                    resolved_user_id = fallback_user_id;
                    join_card_override = Some(join_card);
                } else {
                    return Err(err);
                }
            }
        }
    }

    let join_card = if let Some(join_card) = join_card_override {
        join_card
    } else if let Some(path) = join_card_path {
        let join_card = load_join_card_file(&path)?;
        println!("ℹ️  Loaded join card from {}", path.display());
        join_card
    } else if let Some(cached) =
        session_manager.find_cached_join_card_for_device(&resolved_user_id, &device_id)?
    {
        cached
    } else {
        let parsed_user_id = Uuid::parse_str(&resolved_user_id).map_err(|e| {
            CliError::invalid_input(format!("Invalid user ID '{}': {}", resolved_user_id, e))
        })?;
        let cards = session_manager
            .fetch_join_cards_for_user_id(&parsed_user_id)
            .await?;
        if let Some(card) = cards.into_iter().find(|card| card.device_id == device_id) {
            let canonical_json = serde_json::to_string_pretty(&card)
                .map_err(|e| CliError::format(format!("Failed to serialize join card: {}", e)))?;
            if let Err(err) = session_manager.cache_join_card(&resolved_user_id, &canonical_json) {
                ui::warning(&format!("Failed to cache join card locally: {}", err));
            }
            println!("ℹ️  Loaded join card from server directory");
            card
        } else {
            return Err(CliError::invalid_input(format!(
                "No cached join card found for user {} device {}. Supply --join-card <path> with the verified join card JSON.",
                resolved_user_id, device_id
            )));
        }
    };

    if join_card.user_id.to_string() != resolved_user_id {
        return Err(CliError::invalid_input(format!(
            "Join card user {} does not match supplied user {}",
            join_card.user_id, resolved_user_id
        )));
    }

    if join_card.device_id != device_id {
        return Err(CliError::invalid_input(format!(
            "Join card device {} does not match supplied device {}",
            join_card.device_id, device_id
        )));
    }

    join_card.verify_signature().map_err(|e| {
        CliError::invalid_input(format!("Join card signature verification failed: {}", e))
    })?;

    if !join_card.is_valid() {
        return Err(CliError::invalid_input(
            "Join card has expired. Request a fresh join card before pinning.".to_string(),
        ));
    }

    let join_card_key_bytes: [u8; 32] =
        join_card
            .identity_public
            .as_slice()
            .try_into()
            .map_err(|_| {
                CliError::invalid_input("Join card identity key is not 32 bytes".to_string())
            })?;

    let mut verifying_key = VerifyingKey::from_bytes(&join_card_key_bytes).map_err(|e| {
        CliError::invalid_input(format!("Join card identity key is invalid: {}", e))
    })?;
    let mut fingerprint_value = generate_fingerprint(&join_card_key_bytes);
    let mut pinning_method: PinningMethod = method.clone().into();

    if qr {
        println!("🔍 QR Code Verification Mode");
        println!("Please scan the QR code displayed by the other device...");
        print!("Enter the HybridCipher pinning URL from QR code: ");
        io::stdout()
            .flush()
            .map_err(|e| CliError::Io(format!("Failed to flush stdout: {}", e)))?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| CliError::Io(format!("Failed to read input: {}", e)))?;

        let url = input.trim();
        let parsed = hybridcipher_client::pinning::parse_and_verify_signed_pinning_url_with_policy(
            url,
            pin_config.clone().into(),
        )
        .map_err(|e| CliError::invalid_input(format!("Invalid or untrusted QR code URL: {}", e)))?;

        if parsed.user_id != resolved_user_id {
            return Err(CliError::invalid_input(format!(
                "QR code user {} does not match expected {}",
                parsed.user_id, resolved_user_id
            )));
        }

        if parsed.device_id != device_id {
            return Err(CliError::invalid_input(format!(
                "QR code device {} does not match expected {}",
                parsed.device_id, device_id
            )));
        }

        let parsed_key_bytes: [u8; 32] = parsed
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| CliError::invalid_input("QR code public key must be 32 bytes"))?;

        if parsed_key_bytes != join_card_key_bytes {
            return Err(CliError::PinningFailed(
                "QR code key does not match the join card identity key. Request a refreshed join card or verify the QR code."
                    .to_string(),
            ));
        }

        verifying_key = VerifyingKey::from_bytes(&parsed_key_bytes).map_err(|e| {
            CliError::invalid_input(format!("Invalid public key in QR code: {}", e))
        })?;
        fingerprint_value = generate_fingerprint(&parsed_key_bytes);
        pinning_method = PinningMethod::QrCode;
    }

    if let Some(expected_fingerprint) = fingerprint.as_ref() {
        verify_fingerprint_format(expected_fingerprint)
            .map_err(|e| CliError::invalid_input(format!("Invalid fingerprint format: {}", e)))?;

        if sanitize(expected_fingerprint) != sanitize(&fingerprint_value) {
            return Err(CliError::PinningFailed(format!(
                "Fingerprint mismatch! Expected: {}, Got: {}",
                expected_fingerprint, fingerprint_value
            )));
        }
    } else if let Some(expected_safety) = safety_number.as_ref() {
        let local_keypair = session_manager.get_or_create_device_keypair().await?;
        let local_key_bytes = local_keypair.verifying_key().to_bytes();
        let actual_safety = generate_safety_number(&local_key_bytes, &join_card_key_bytes);

        if sanitize(expected_safety) != sanitize(&actual_safety) {
            return Err(CliError::PinningFailed(format!(
                "Safety number mismatch! Expected: {}, Got: {}",
                expected_safety, actual_safety
            )));
        }

        pinning_method = PinningMethod::SafetyNumber;
    } else if !qr {
        println!("📋 Manual fingerprint verification");
        println!("Fingerprint: {}", fingerprint_value);
        print!("Does this fingerprint match the requesting device? (y/N): ");
        io::stdout()
            .flush()
            .map_err(|e| CliError::Io(format!("Failed to flush stdout: {}", e)))?;

        let mut confirm = String::new();
        io::stdin()
            .read_line(&mut confirm)
            .map_err(|e| CliError::Io(format!("Failed to read input: {}", e)))?;

        match confirm.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => {
                pinning_method = method.clone().into();
            }
            _ => {
                return Err(CliError::PinningFailed(
                    "Fingerprint verification declined".to_string(),
                ));
            }
        }
    }

    let (pinning_store, _, _) = pinning_store_for_session(session_manager).await?;

    let pinned = pinning_store
        .pin_key(
            &resolved_user_id,
            &device_id,
            &verifying_key,
            pinning_method,
            notes,
        )
        .await
        .map_err(|e| CliError::PinningFailed(format!("Failed to pin key: {}", e)))?;

    let display_user = if user_identifier.contains('@') {
        format!("{} ({})", user_identifier, resolved_user_id)
    } else {
        format_cached_user_label(session_manager, &resolved_user_id).await
    };

    println!(
        "✅ Successfully pinned key for user {} device {}",
        display_user, device_id
    );
    println!("   Fingerprint: {}", pinned.fingerprint);

    record_pin_audit(
        PinAuditAction::Add,
        &resolved_user_id,
        &device_id,
        Some(pinned.fingerprint.clone()),
        Some(pinned.verification_method.to_string()),
        pinned.notes.clone(),
        session_manager,
    )
    .await;

    Ok(())
}

/// List all pinned keys
async fn handle_pin_list(
    verbose: bool,
    format: String,
    user_filter: Option<String>,
    all_group: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    let resolved_filter = if let Some(ref filter) = user_filter {
        if filter.contains('@') {
            Some(session_manager.resolve_user_identifier(filter).await?)
        } else {
            Some(filter.clone())
        }
    } else {
        None
    };

    let (_, storage, config) = pinning_store_for_session(session_manager).await?;
    remind_expired_pins(&storage, &config).await?;
    let pins = load_all_pinned_keys(&storage, &config).await?;

    let output_format = format.to_ascii_lowercase();
    let use_email = matches!(output_format.as_str(), "table" | "text");

    if all_group && !use_email {
        let group_ids = session_manager.list_admin_group_ids_with_cache().await?;
        let mut member_ids = HashSet::new();
        for group_id in group_ids {
            if let Ok(members) = session_manager
                .list_group_members_with_cache(&group_id)
                .await
            {
                for member in members {
                    member_ids.insert(member.user_id);
                }
            }
        }
        let mut scoped = filter_pins_for_members(&pins, &member_ids);
        if let Some(ref filter) = resolved_filter {
            let normalized = filter.to_ascii_lowercase();
            scoped.retain(|pin| pin.user_id.to_ascii_lowercase() == normalized);
        }

        if scoped.is_empty() {
            println!("📋 No pinned device keys found.");
            return Ok(());
        }

        match output_format.as_str() {
            "json" => {
                let json = serde_json::to_string_pretty(&scoped).map_err(|e| CliError::Format {
                    message: format!("Failed to serialize pinned keys to JSON: {}", e),
                })?;
                println!("{}", json);
            }
            "yaml" => {
                let yaml = serde_yaml::to_string(&scoped).map_err(|e| CliError::Format {
                    message: format!("Failed to serialize pinned keys to YAML: {}", e),
                })?;
                println!("{}", yaml);
            }
            other => {
                return Err(CliError::invalid_input(format!(
                    "Unsupported format: {}",
                    other
                )));
            }
        }
        return Ok(());
    }

    if all_group && use_email {
        let group_ids = session_manager.list_admin_group_ids_with_cache().await?;
        if group_ids.is_empty() {
            println!("📋 No pinned device keys found.");
            return Ok(());
        }

        let mut total_across_groups = 0usize;
        for group_id in group_ids {
            if let Err(err) = Uuid::parse_str(&group_id) {
                ui::warning(&format!(
                    "Skipping invalid group ID '{}': {}",
                    group_id, err
                ));
                continue;
            }
            let group_label = session_manager.group_label_for_id(&group_id).await;
            ui::info(&format!("Group: {}", group_label));

            let members = match session_manager
                .list_group_members_with_cache(&group_id)
                .await
            {
                Ok(members) => members,
                Err(err) => {
                    ui::warning(&format!(
                        "Failed to fetch group members for {}: {}",
                        group_label, err
                    ));
                    continue;
                }
            };
            let member_ids: HashSet<String> = members
                .iter()
                .map(|member| member.user_id.clone())
                .collect();
            let mut scoped = filter_pins_for_members(&pins, &member_ids);
            if let Some(ref filter) = resolved_filter {
                let normalized = filter.to_ascii_lowercase();
                scoped.retain(|pin| pin.user_id.to_ascii_lowercase() == normalized);
            }

            if scoped.is_empty() {
                ui::dim("  No pinned device keys found.");
                continue;
            }

            let total = scoped.len();
            total_across_groups += total;
            let mut user_emails = user_emails_from_members(&members);
            let mut warnings: Vec<String> = Vec::new();

            let client = reqwest::Client::new();
            match fetch_user_emails_for_pins(
                &client,
                &session,
                &session.server_url,
                &scoped,
                &user_emails,
            )
            .await
            {
                Ok(map) => user_emails.extend(map),
                Err(err) => warnings.push(format!("User lookup failed: {}", err)),
            }

            if use_email && user_emails.is_empty() && !warnings.is_empty() {
                ui::warning(&format!(
                    "Unable to resolve user emails; showing IDs instead: {}",
                    warnings.join("; ")
                ));
            }

            render_pins_table(&scoped, &user_emails, verbose)?;
            render_pin_expiry_warnings(&scoped, &config, &user_emails);
            ui::info(&format!(
                "{}: {} pinned device key(s) recorded.",
                group_label, total
            ));
        }

        if total_across_groups == 0 {
            ui::success("No pinned device keys found across admin groups.");
        } else {
            ui::info(&format!(
                "{} pinned device key(s) recorded across admin groups.",
                total_across_groups
            ));
        }
        return Ok(());
    }

    let group_id = session_manager.ensure_current_group().await?.to_string();
    let group_label = session_manager.group_label_for_id(&group_id).await;
    let group_members = session_manager
        .list_group_members_with_cache(&group_id)
        .await?;
    let member_ids: HashSet<String> = group_members
        .iter()
        .map(|member| member.user_id.clone())
        .collect();
    let mut pins = filter_pins_for_members(&pins, &member_ids);

    if let Some(ref filter) = resolved_filter {
        let normalized = filter.to_ascii_lowercase();
        pins.retain(|pin| pin.user_id.to_ascii_lowercase() == normalized);
    }

    if pins.is_empty() {
        println!("📋 No pinned device keys found for group {}.", group_label);
        return Ok(());
    }

    let total = pins.len();
    let mut user_emails = user_emails_from_members(&group_members);
    let mut warnings: Vec<String> = Vec::new();

    let client = reqwest::Client::new();
    match fetch_user_emails_for_pins(&client, &session, &session.server_url, &pins, &user_emails)
        .await
    {
        Ok(map) => user_emails.extend(map),
        Err(err) => warnings.push(format!("User lookup failed: {}", err)),
    }

    if use_email && user_emails.is_empty() && !warnings.is_empty() {
        ui::warning(&format!(
            "Unable to resolve user emails; showing IDs instead: {}",
            warnings.join("; ")
        ));
    }

    if !user_emails.is_empty() {
        let cache_entries = user_emails
            .iter()
            .map(|(user_id, email)| (email.clone(), user_id.clone()))
            .collect::<Vec<_>>();
        let _ = session_manager.cache_user_identities(cache_entries).await;
    }

    let mut expiring: Vec<String> = Vec::new();
    if let Some(max_age_days) = config.max_pin_age_days {
        let warn_window = std::cmp::max(7, std::cmp::min(30, (max_age_days as i64) / 3));
        let now = Utc::now();
        for pin in &pins {
            if !pin.verified {
                continue;
            }
            let anchor = pin.verified_at.unwrap_or(pin.pinned_at);
            let age_days = (now - anchor).num_days();
            let remaining = max_age_days as i64 - age_days;
            if remaining >= 0 && remaining <= warn_window {
                let display_user = user_emails
                    .get(&pin.user_id)
                    .map(|email| format!("{} ({})", email, pin.user_id))
                    .unwrap_or_else(|| pin.user_id.clone());
                expiring.push(format!(
                    "{} ({}) expiring in {} day(s)",
                    pin.device_id, display_user, remaining
                ));
            }
        }
    }

    match output_format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&pins).map_err(|e| CliError::Format {
                message: format!("Failed to serialize pinned keys to JSON: {}", e),
            })?;
            println!("{}", json);
        }
        "yaml" => {
            let yaml = serde_yaml::to_string(&pins).map_err(|e| CliError::Format {
                message: format!("Failed to serialize pinned keys to YAML: {}", e),
            })?;
            println!("{}", yaml);
        }
        "table" | "text" => {
            ui::info(&format!("Group: {}", group_label));
            render_pins_table(&pins, &user_emails, verbose)?;
            render_pin_expiry_warnings(&pins, &config, &user_emails);
            println!("\n📊 Total pinned keys: {}", total);
        }
        other => {
            return Err(CliError::invalid_input(format!(
                "Unsupported format: {}",
                other
            )));
        }
    }

    Ok(())
}

fn filter_pins_for_members(pins: &[PinnedKey], member_ids: &HashSet<String>) -> Vec<PinnedKey> {
    pins.iter()
        .filter(|pin| member_ids.contains(&pin.user_id))
        .cloned()
        .collect()
}

fn user_emails_from_members(members: &[crate::session::MemberInfo]) -> HashMap<String, String> {
    let mut user_emails = HashMap::new();
    for member in members {
        let email = member.email.trim();
        if !email.is_empty() && !email.contains('*') {
            user_emails.insert(member.user_id.clone(), email.to_string());
        }
    }
    user_emails
}

fn render_pins_table(
    pins: &[PinnedKey],
    user_emails: &HashMap<String, String>,
    verbose: bool,
) -> Result<(), CliError> {
    println!("📋 Pinned Device Keys");
    println!(
        "{:<56} {:<20} {:<24} {:<32} {:<22} {}",
        "User (Email + UUID)", "Device", "Fingerprint", "Verified", "Method", "Pinned At"
    );
    for pin in pins {
        let display_user = user_emails
            .get(&pin.user_id)
            .map(|email| format!("{} ({})", email, pin.user_id))
            .unwrap_or_else(|| pin.user_id.clone());
        let verified_label = if pin.verified {
            if let Some(verified_at) = pin.verified_at {
                format!(
                    "yes @ {}",
                    ui::formatting::format_local_datetime(&verified_at)
                )
            } else {
                "yes".to_string()
            }
        } else {
            "no".to_string()
        };
        println!(
            "{:<56} {:<20} {:<24} {:<32} {:<22} {}",
            display_user,
            pin.device_id,
            pin.fingerprint,
            verified_label,
            pin.verification_method,
            ui::formatting::format_local_datetime(&pin.pinned_at)
        );

        if verbose {
            if pin.verified {
                if let Some(verified_at) = pin.verified_at {
                    println!(
                        "    Verified at: {}",
                        ui::formatting::format_local_datetime(&verified_at)
                    );
                }
            } else {
                println!("    Verified at: (pending)");
            }
            if let Some(notes) = &pin.notes {
                if !notes.trim().is_empty() {
                    println!("    Notes: {}", notes);
                }
            }
        }
    }
    Ok(())
}

fn render_pin_expiry_warnings(
    pins: &[PinnedKey],
    config: &PinningConfig,
    user_emails: &HashMap<String, String>,
) {
    let mut expiring: Vec<String> = Vec::new();
    if let Some(max_age_days) = config.max_pin_age_days {
        let warn_window = std::cmp::max(7, std::cmp::min(30, (max_age_days as i64) / 3));
        let now = Utc::now();
        for pin in pins {
            if !pin.verified {
                continue;
            }
            let anchor = pin.verified_at.unwrap_or(pin.pinned_at);
            let age_days = (now - anchor).num_days();
            let remaining = max_age_days as i64 - age_days;
            if remaining >= 0 && remaining <= warn_window {
                let display_user = user_emails
                    .get(&pin.user_id)
                    .map(|email| format!("{} ({})", email, pin.user_id))
                    .unwrap_or_else(|| pin.user_id.clone());
                expiring.push(format!(
                    "{} ({}) expiring in {} day(s)",
                    pin.device_id, display_user, remaining
                ));
            }
        }
    }

    if !expiring.is_empty() {
        println!("\n⚠️  Pins nearing expiration:");
        for note in expiring {
            println!("   - {}", note);
        }
    }
}

async fn fetch_user_emails_for_pins(
    client: &reqwest::Client,
    session: &crate::session::Session,
    server_url: &str,
    pins: &[PinnedKey],
    existing: &HashMap<String, String>,
) -> Result<HashMap<String, String>, CliError> {
    let mut emails = HashMap::new();
    let mut unique_user_ids = HashSet::new();
    for pin in pins {
        unique_user_ids.insert(pin.user_id.clone());
    }

    for user_id in unique_user_ids {
        if existing.contains_key(&user_id) {
            continue;
        }
        if Uuid::parse_str(&user_id).is_err() {
            continue;
        }
        let url = format!(
            "{}/api/v1/users/{}",
            server_url.trim_end_matches('/'),
            user_id
        );
        let resp = client
            .get(&url)
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to fetch user emails: {}", e)))?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if resp.status().is_success() {
            if let Ok(user_data) = resp.json::<serde_json::Value>().await {
                if let Some(email) = user_data.get("email").and_then(|e| e.as_str()) {
                    let trimmed = email.trim();
                    if !trimmed.is_empty() && !trimmed.contains('*') {
                        emails.insert(user_id, trimmed.to_string());
                    }
                }
            }
        }
    }

    Ok(emails)
}

async fn format_cached_user_label(session_manager: &SessionManager, user_id: &str) -> String {
    let trimmed = user_id.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(email) = session_manager.cached_email_for_user_id(trimmed).await {
        let email_trimmed = email.trim();
        if !email_trimmed.is_empty() && !email_trimmed.contains('*') {
            return format!("{} ({})", email_trimmed, trimmed);
        }
    }
    trimmed.to_string()
}

async fn remind_expired_pins(
    storage: &UserStorage,
    config: &PinningConfig,
) -> Result<(), CliError> {
    if EXPIRY_REMINDER_EMITTED.get().is_some() {
        return Ok(());
    }

    let expired = find_expired_pins(storage, config).await?;
    if expired.is_empty() {
        return Ok(());
    }

    let _ = EXPIRY_REMINDER_EMITTED.set(());
    ui::warning("Some pinned keys have expired. Re-pin to restore trust:");
    for pin in expired.iter().take(3) {
        let expired_at = pin.verified_at.unwrap_or(pin.pinned_at);
        ui::warning(&format!(
            " - {} ({}) expired at {}",
            pin.device_id,
            pin.user_id,
            ui::formatting::format_local_datetime(&expired_at)
        ));
        ui::dim(&format!(
            "   Re-pin: hybridcipher pin add --user {} --device {}",
            pin.user_id, pin.device_id
        ));
    }
    if expired.len() > 3 {
        ui::warning(&format!(" - ... {} more expired pins", expired.len() - 3));
    }
    Ok(())
}

/// Remove a pinned key
async fn handle_pin_remove(
    user_id: String,
    device_id: String,
    yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let _session = session_manager.require_auth()?;
    let resolved_user_id = session_manager.resolve_user_identifier(&user_id).await?;
    let display_user = if user_id.contains('@') {
        format!("{} ({})", user_id, resolved_user_id)
    } else {
        format_cached_user_label(session_manager, &resolved_user_id).await
    };

    println!(
        "🗑️  Removing pinned key for user '{}', device '{}'",
        display_user, device_id
    );

    if !yes {
        print!("⚠️  Are you sure you want to remove this pinned key? (y/N): ");
        io::stdout().flush().unwrap();

        let mut confirm = String::new();
        io::stdin()
            .read_line(&mut confirm)
            .map_err(|e| CliError::Io(format!("Failed to read input: {}", e)))?;

        if confirm.trim().to_lowercase() != "y" && confirm.trim().to_lowercase() != "yes" {
            println!("❌ Remove operation cancelled");
            return Ok(());
        }
    }

    let (pinning_store, _, _) = pinning_store_for_session(session_manager).await?;

    match pinning_store.unpin_key(&resolved_user_id, &device_id).await {
        Ok(()) => {}
        Err(PinningError::NoPinnedKey { .. }) => {
            return Err(CliError::not_found(format!(
                "No pinned key found for {} ({})",
                display_user, device_id
            )))
        }
        Err(err) => {
            return Err(CliError::PinningFailed(format!(
                "Failed to remove pin: {}",
                err
            )))
        }
    }

    println!(
        "✅ Successfully removed pinned key for {} ({})",
        display_user, device_id
    );

    record_pin_audit(
        PinAuditAction::Remove,
        &resolved_user_id,
        &device_id,
        None,
        None,
        None,
        session_manager,
    )
    .await;

    Ok(())
}

/// Verify a pinned key
async fn handle_pin_verify(
    user_id: Option<String>,
    device_id: Option<String>,
    fingerprint: Option<String>,
    safety_number: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let _session = session_manager.require_auth()?;
    if user_id.is_none() && device_id.is_none() {
        if fingerprint.is_some() || safety_number.is_some() {
            return Err(CliError::invalid_input(
                "Specify <USER_ID_OR_EMAIL> and <DEVICE_ID> when providing verification values."
                    .to_string(),
            ));
        }
        return handle_pin_verify_list_unverified(session_manager).await;
    }

    let user_id = user_id.ok_or_else(|| {
        CliError::invalid_input("Specify <USER_ID_OR_EMAIL> or run without arguments.".to_string())
    })?;
    let device_id = device_id.ok_or_else(|| {
        CliError::invalid_input("Specify <DEVICE_ID> or run without arguments.".to_string())
    })?;

    let resolved_user_id = session_manager.resolve_user_identifier(&user_id).await?;
    let display_user = if user_id.contains('@') {
        format!("{} ({})", user_id, resolved_user_id)
    } else {
        format_cached_user_label(session_manager, &resolved_user_id).await
    };

    println!(
        "🔍 Verifying pinned key for user '{}', device '{}'",
        display_user, device_id
    );

    let (pinning_store, storage, pin_config) = pinning_store_for_session(session_manager).await?;
    remind_expired_pins(&storage, &pin_config).await?;

    let mut pinned_key = match pinning_store
        .get_pinned_key(&resolved_user_id, &device_id)
        .await
    {
        Ok(Some(pin)) => pin,
        Ok(None) => {
            return Err(CliError::not_found(format!(
                "No pinned key found for {} ({})",
                display_user, device_id
            )))
        }
        Err(PinningError::ExpiredPin { pinned_at }) => {
            return Err(CliError::PinningFailed(format!(
                "Pinned key expired on {}. Re-pin the device before verification.",
                ui::formatting::format_local_datetime(&pinned_at)
            )))
        }
        Err(err) => {
            return Err(CliError::PinningFailed(format!(
                "Failed to load pinned key: {}",
                err
            )))
        }
    };

    println!("📋 Pinned key information:");
    let pinned_user_label = format_cached_user_label(session_manager, &pinned_key.user_id).await;
    println!("   User: {}", pinned_user_label);
    println!("   Device: {}", pinned_key.device_id);
    println!("   Fingerprint: {}", pinned_key.fingerprint);
    println!(
        "   Verified: {}",
        if pinned_key.verified { "yes" } else { "no" }
    );
    println!("   Method: {}", pinned_key.verification_method);
    println!(
        "   Pinned at: {}",
        ui::formatting::format_local_datetime(&pinned_key.pinned_at)
    );
    if pinned_key.verified {
        if let Some(verified_at) = pinned_key.verified_at {
            println!(
                "   Verified at: {}",
                ui::formatting::format_local_datetime(&verified_at)
            );
        }
    }

    if let Some(notes) = &pinned_key.notes {
        println!("   Notes: {}", notes);
    }

    if let Some(max_age_days) = pin_config.max_pin_age_days {
        let now = Utc::now();
        if pinned_key.verified {
            let anchor = pinned_key.verified_at.unwrap_or(pinned_key.pinned_at);
            let age_days = (now - anchor).num_days();
            let remaining = max_age_days as i64 - age_days;
            if remaining >= 0 && remaining <= 14 {
                ui::warning(&format!(
                    "Pinned key is nearing expiration ({} day(s) remaining). Re-verify soon.",
                    remaining
                ));
            }
        }
    }

    let mut verification_performed = false;
    let mut verification_method_for_update: Option<PinningMethod> = None;

    // Verify against provided fingerprint
    if let Some(ref expected_fp) = fingerprint {
        verify_fingerprint_format(&expected_fp)
            .map_err(|e| CliError::invalid_input(format!("Invalid fingerprint format: {}", e)))?;

        let normalized_expected = expected_fp.replace(' ', "").to_lowercase();
        let normalized_actual = pinned_key.fingerprint.replace(' ', "").to_lowercase();

        if normalized_expected == normalized_actual {
            println!("✅ Fingerprint verification: PASSED");
            verification_performed = true;
            verification_method_for_update = Some(PinningMethod::Manual);
        } else {
            println!("❌ Fingerprint verification: FAILED");
            println!("   Expected: {}", expected_fp);
            println!("   Actual:   {}", pinned_key.fingerprint);
            return Err(CliError::PinningFailed("Fingerprint mismatch".to_string()));
        }
    }

    // Verify against provided safety number
    if let Some(ref expected_safety) = safety_number {
        let local_keypair = session_manager.get_or_create_device_keypair().await?;
        let local_key = local_keypair.verifying_key().to_bytes();
        let actual_safety = generate_safety_number(&local_key, &pinned_key.identity_public_key);

        let normalized_expected = expected_safety.replace(' ', "");
        let normalized_actual = actual_safety.replace(' ', "");

        if normalized_expected == normalized_actual {
            println!("✅ Safety number verification: PASSED");
            verification_performed = true;
            verification_method_for_update = Some(PinningMethod::SafetyNumber);
        } else {
            println!("❌ Safety number verification: FAILED");
            println!("   Expected: {}", expected_safety);
            println!("   Actual:   {}", actual_safety);
            return Err(CliError::PinningFailed(
                "Safety number mismatch".to_string(),
            ));
        }
    }

    if fingerprint.is_none() && safety_number.is_none() {
        println!(
            "ℹ️  Use --fingerprint or --safety-number flags to verify against specific values"
        );
    }

    if verification_performed && !pinned_key.verified {
        let method = verification_method_for_update.unwrap_or(PinningMethod::Manual);
        pinned_key = pinning_store
            .mark_pin_verified(&resolved_user_id, &device_id, method)
            .await
            .map_err(|e| CliError::PinningFailed(format!("Failed to update pin: {}", e)))?;
        println!("✅ Pin marked as verified");
    } else if !verification_performed && !pinned_key.verified {
        ui::warning(
            "Pin remains unverified. Use --fingerprint or --safety-number to verify and trust it.",
        );
    }

    // If a signed pinning URL exists in notes, surface signer/timestamp if present.
    if let Some(notes) = &pinned_key.notes {
        if let Ok(parsed) =
            hybridcipher_client::pinning::parse_and_verify_signed_pinning_url_with_policy(
                notes,
                pin_config.clone().into(),
            )
        {
            if let Some(sig) = parsed.signature {
                println!(
                    "   Signed pin URL -> signer: {}, ts: {}",
                    sig.signer, sig.issued_at
                );
            } else {
                println!("   Note contains pin URL (unsigned): {}", notes);
            }
        } else if notes.contains("hybridcipher://pin") {
            println!("   Note contains pin URL (could not verify): {}", notes);
        }
    }

    if pinned_key.verified {
        let should_resolve = if pin_config.require_second_party_verification {
            match session_manager
                .get_second_party_status(&resolved_user_id, &device_id)
                .await
            {
                Ok(Some((status, _))) => status.eq_ignore_ascii_case("verified"),
                _ => false,
            }
        } else {
            true
        };

        if should_resolve {
            let reason = if pin_config.require_second_party_verification {
                "pin_and_second_party_verified"
            } else {
                "pin_verified"
            };
            match session_manager
                .resolve_unverified_device(&resolved_user_id, &device_id, None, Some(reason))
                .await
            {
                Ok(result) => {
                    if let Ok(user_uuid) = Uuid::parse_str(&resolved_user_id) {
                        for group_id in result.groups {
                            let _ = members::clear_unverified_device_cache(
                                session_manager,
                                group_id,
                                user_uuid,
                                &device_id,
                            )
                            .await;
                        }
                    }
                }
                Err(err) => {
                    ui::warning(&format!(
                        "Pinned key verified, but failed to clear unverified device entry: {}",
                        err
                    ));
                }
            }
        }
    }

    println!("✅ Pin verification completed successfully");

    record_pin_audit(
        PinAuditAction::Verify,
        &resolved_user_id,
        &device_id,
        Some(pinned_key.fingerprint.clone()),
        Some(pinned_key.verification_method.to_string()),
        pinned_key.notes.clone(),
        session_manager,
    )
    .await;

    Ok(())
}

async fn handle_pin_verify_list_unverified(
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let group_id = session_manager.ensure_current_group().await?.to_string();
    let (_, storage, config) = pinning_store_for_session(session_manager).await?;
    let mut pins = load_all_pinned_keys(&storage, &config).await?;
    let group_members = session_manager
        .list_group_members_with_cache(&group_id)
        .await?;
    let member_ids: HashSet<String> = group_members
        .iter()
        .map(|member| member.user_id.clone())
        .collect();
    pins.retain(|pin| member_ids.contains(&pin.user_id) && !pin.verified);

    if pins.is_empty() {
        println!("✅ No unverified pins found.");
        return Ok(());
    }

    println!("📋 Unverified Pinned Device Keys");
    println!(
        "{:<56} {:<20} {:<24} {}",
        "User (Email + UUID)", "Device", "Fingerprint", "Pinned At"
    );
    for pin in pins {
        let display_user = format_cached_user_label(session_manager, &pin.user_id).await;
        println!(
            "{:<56} {:<20} {:<24} {}",
            display_user,
            pin.device_id,
            pin.fingerprint,
            ui::formatting::format_local_datetime(&pin.pinned_at)
        );
    }

    println!("\nNext steps:");
    println!("  - Verify a pin: hybridcipher pin verify <USER_ID_OR_EMAIL> <DEVICE_ID> --fingerprint <FP>");
    println!("  - Or use safety numbers: hybridcipher pin verify <USER_ID_OR_EMAIL> <DEVICE_ID> --safety-number <SN>");
    Ok(())
}

/// Generate and display QR code for pinning
async fn handle_pin_qr(
    user_id: String,
    device_id: String,
    save: Option<std::path::PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    let resolved_user_id = session_manager.resolve_user_identifier(&user_id).await?;
    let display_user = if user_id.contains('@') {
        format!("{} ({})", user_id, resolved_user_id)
    } else {
        format_cached_user_label(session_manager, &resolved_user_id).await
    };

    let (pinning_store, storage, config) = pinning_store_for_session(session_manager).await?;
    remind_expired_pins(&storage, &config).await?;
    let pinned_key = match pinning_store
        .get_pinned_key(&resolved_user_id, &device_id)
        .await
    {
        Ok(Some(pin)) => pin,
        Ok(None) => {
            return Err(CliError::not_found(format!(
                "No pinned key found for {} ({})",
                display_user, device_id
            )))
        }
        Err(PinningError::ExpiredPin { pinned_at }) => {
            return Err(CliError::PinningFailed(format!(
                "Pinned key expired on {}. Re-pin the device to generate a fresh QR code.",
                ui::formatting::format_local_datetime(&pinned_at)
            )))
        }
        Err(err) => {
            return Err(CliError::PinningFailed(format!(
                "Failed to load pinned key: {}",
                err
            )))
        }
    };

    let qr_key = pinned_key.identity_public_key;
    let qr_fp = pinned_key.fingerprint.clone();

    let base_url = generate_pinning_url(&resolved_user_id, &device_id, &qr_key, &qr_fp);
    let mut signed_payload: Option<hybridcipher_client::pinning::SignedPinningPayload> = None;
    let qr_payload_url =
        if let Ok(device_keypair) = session_manager.get_or_create_device_keypair().await {
            let signer = session.username.clone();
            match hybridcipher_client::pinning::generate_signed_pinning_url(
                &resolved_user_id,
                &device_id,
                &qr_key,
                &qr_fp,
                &signer,
                &device_keypair,
            ) {
                Ok(payload) => {
                    signed_payload = Some(payload.clone());
                    payload.url
                }
                Err(_) => base_url.clone(),
            }
        } else {
            base_url.clone()
        };

    let qr_display =
        display_pinning_qr_code_from_url(&resolved_user_id, &device_id, &qr_fp, &qr_payload_url)
            .map_err(|e| CliError::PinningFailed(format!("Failed to generate QR code: {}", e)))?;

    if let Some(file_path) = save {
        // Save to file
        std::fs::write(&file_path, &qr_display).map_err(|e| {
            CliError::Io(format!(
                "Failed to save QR code to {}: {}",
                file_path.display(),
                e
            ))
        })?;

        println!("💾 QR code saved to: {}", file_path.display());
        if let Some(payload) = signed_payload.as_ref() {
            println!(
                "🔐 Signed pin URL (freshness): {} (issued {}, signer {})",
                payload.url,
                ui::formatting::format_local_datetime(&payload.issued_at),
                payload.signer
            );
        }
    } else {
        // Display to terminal
        println!("\n{}", qr_display);
        println!("\n📋 Instructions:");
        println!("   1. Scan this QR code with the other device");
        println!("   2. Or share the HybridCipher URL manually");
        println!("   3. Verify the fingerprint matches on both devices");
        if let Some(payload) = signed_payload {
            println!(
                "   4. Signed URL (freshness): {} (issued {}, signer {})",
                payload.url,
                ui::formatting::format_local_datetime(&payload.issued_at),
                payload.signer
            );
        }
    }

    Ok(())
}

async fn handle_pin_self(qr: bool, session_manager: &SessionManager) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    let user_id = session.user_id.clone();
    let device_id = session.device_id.clone();
    let invitation_keypair = session_manager
        .get_or_create_invitation_keypair()
        .await
        .map_err(|e| CliError::PinningFailed(format!("Failed to load invitation key: {}", e)))?;
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|e| CliError::invalid_input(format!("Invalid user ID '{}': {}", user_id, e)))?;
    let join_card = invitation_keypair
        .create_join_card(user_uuid)
        .map_err(|e| CliError::PinningFailed(format!("Failed to create join card: {}", e)))?;
    let public_key: [u8; 32] = join_card
        .identity_public
        .as_slice()
        .try_into()
        .map_err(|_| {
            CliError::PinningFailed("Join card identity key must be 32 bytes".to_string())
        })?;
    let fingerprint = generate_fingerprint(&public_key);

    println!("👤 User: {} ({})", session.username, user_id);
    println!("📱 Device: {}", device_id);
    println!("🔑 Fingerprint: {}", fingerprint);
    println!("ℹ️  This is the join card identity key; it is not pinned on this device.");

    if !qr {
        return Ok(());
    }

    let base_url = generate_pinning_url(&user_id, &device_id, &public_key, &fingerprint);
    let device_keypair = session_manager
        .get_or_create_device_keypair()
        .await
        .map_err(|e| CliError::PinningFailed(format!("Failed to load device key: {}", e)))?;
    let qr_payload_url = match hybridcipher_client::pinning::generate_signed_pinning_url(
        &user_id,
        &device_id,
        &public_key,
        &fingerprint,
        &session.username,
        &device_keypair,
    ) {
        Ok(payload) => payload.url,
        Err(_) => base_url,
    };

    let qr_display =
        display_pinning_qr_code_from_url(&user_id, &device_id, &fingerprint, &qr_payload_url)
            .map_err(|e| CliError::PinningFailed(format!("Failed to generate QR code: {}", e)))?;
    println!("\n{}", qr_display);

    Ok(())
}

/// Generate safety number for two devices
async fn handle_safety_number(
    user_id1: String,
    device_id1: String,
    user_id2: String,
    device_id2: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let _session = session_manager.require_auth()?;
    let resolved_user_id1 = session_manager.resolve_user_identifier(&user_id1).await?;
    let resolved_user_id2 = session_manager.resolve_user_identifier(&user_id2).await?;
    let display_user1 = if user_id1.contains('@') {
        format!("{} ({})", user_id1, resolved_user_id1)
    } else {
        format_cached_user_label(session_manager, &resolved_user_id1).await
    };
    let display_user2 = if user_id2.contains('@') {
        format!("{} ({})", user_id2, resolved_user_id2)
    } else {
        format_cached_user_label(session_manager, &resolved_user_id2).await
    };
    println!("   Device 1: {} ({})", display_user1, device_id1);
    println!("   Device 2: {} ({})", display_user2, device_id2);

    let (pinning_store, storage, config) = pinning_store_for_session(session_manager).await?;
    remind_expired_pins(&storage, &config).await?;

    let key1 = match pinning_store
        .get_pinned_key(&resolved_user_id1, &device_id1)
        .await
    {
        Ok(Some(pin)) => pin,
        Ok(None) => {
            return Err(CliError::not_found(format!(
                "No pinned key found for {} ({})",
                display_user1, device_id1
            )))
        }
        Err(PinningError::ExpiredPin { pinned_at }) => {
            return Err(CliError::PinningFailed(format!(
                "Pinned key for {} ({}) expired on {}",
                display_user1,
                device_id1,
                ui::formatting::format_local_datetime(&pinned_at)
            )))
        }
        Err(err) => {
            return Err(CliError::PinningFailed(format!(
                "Failed to load key for device 1: {}",
                err
            )))
        }
    };

    let key2 = match pinning_store
        .get_pinned_key(&resolved_user_id2, &device_id2)
        .await
    {
        Ok(Some(pin)) => pin,
        Ok(None) => {
            return Err(CliError::not_found(format!(
                "No pinned key found for {} ({})",
                display_user2, device_id2
            )))
        }
        Err(PinningError::ExpiredPin { pinned_at }) => {
            return Err(CliError::PinningFailed(format!(
                "Pinned key for {} ({}) expired on {}",
                display_user2,
                device_id2,
                ui::formatting::format_local_datetime(&pinned_at)
            )))
        }
        Err(err) => {
            return Err(CliError::PinningFailed(format!(
                "Failed to load key for device 2: {}",
                err
            )))
        }
    };

    let key1_bytes = key1.identity_public_key;
    let key2_bytes = key2.identity_public_key;

    // Generate safety number
    let safety_number = generate_safety_number(&key1_bytes, &key2_bytes);

    println!("\n🔢 Safety Number: {}", safety_number);
    println!("\n📋 Verification Instructions:");
    println!("   1. Both devices should display the same safety number");
    println!("   2. Compare the numbers on both devices");
    println!("   3. If they match, the keys are verified");
    println!("   4. If they don't match, DO NOT proceed - potential security issue");

    Ok(())
}

/// Import a pinned key from URL
async fn handle_pin_import(
    url: String,
    notes: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let _session = session_manager.require_auth()?;
    let config = session_manager
        .load_pinning_config()
        .await
        .unwrap_or_default();

    // Parse the URL
    let parsed = hybridcipher_client::pinning::parse_and_verify_signed_pinning_url_with_policy(
        &url,
        config.clone().into(),
    )
    .map_err(|e| CliError::invalid_input(format!("Invalid pinning URL: {}", e)))?;

    let parsed_user_label = format_cached_user_label(session_manager, &parsed.user_id).await;
    println!("📋 Parsed pinning URL:");
    println!("   User: {}", parsed_user_label);
    println!("   Device: {}", parsed.device_id);
    println!("   Fingerprint: {}", parsed.fingerprint);
    if let Some(sig) = &parsed.signature {
        println!(
            "   Signature: verified (signer: {}, ts: {})",
            sig.signer, sig.issued_at
        );
        println!(
            "   Acceptance window: max age {:?} day(s), max future skew {}s",
            config.signed_url_max_age_days, config.signed_url_max_future_secs
        );
    } else {
        println!("   Signature: not present (importing as unsigned; verify out-of-band)");
    }

    let public_key = VerifyingKey::from_bytes(&parsed.public_key)
        .map_err(|e| CliError::invalid_input(format!("Invalid public key in URL: {}", e)))?;

    println!("📋 Importing key for:");
    println!("   User: {}", parsed_user_label);
    println!("   Device: {}", parsed.device_id);
    println!("   Fingerprint: {}", parsed.fingerprint);

    // Verify fingerprint matches
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&parsed.public_key);
    let calculated_fp = generate_fingerprint(&key_array);
    if calculated_fp != parsed.fingerprint {
        return Err(CliError::PinningFailed(format!(
            "Fingerprint mismatch in URL: expected {}, calculated {}",
            parsed.fingerprint, calculated_fp
        )));
    }

    let (pinning_store, _, _) = pinning_store_for_session(session_manager).await?;

    let pinned = pinning_store
        .pin_key(
            &parsed.user_id,
            &parsed.device_id,
            &public_key,
            PinningMethod::QrCode,
            notes.clone(),
        )
        .await
        .map_err(|e| CliError::PinningFailed(format!("Failed to import pin: {}", e)))?;

    println!("✅ Successfully imported pinned key");
    println!("   Fingerprint: {}", pinned.fingerprint);

    record_pin_audit(
        PinAuditAction::Import,
        &parsed.user_id,
        &parsed.device_id,
        Some(pinned.fingerprint.clone()),
        Some(pinned.verification_method.to_string()),
        notes.clone(),
        session_manager,
    )
    .await;

    Ok(())
}

/// Export pinned key information
async fn handle_pin_export(
    user_id: String,
    device_id: String,
    format: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let _session = session_manager.require_auth()?;
    let resolved_user_id = session_manager.resolve_user_identifier(&user_id).await?;
    let display_user = if user_id.contains('@') {
        format!("{} ({})", user_id, resolved_user_id)
    } else {
        resolved_user_id.clone()
    };

    let (pinning_store, _, _) = pinning_store_for_session(session_manager).await?;

    let pinned_key = match pinning_store
        .get_pinned_key(&resolved_user_id, &device_id)
        .await
    {
        Ok(Some(pin)) => pin,
        Ok(None) => {
            return Err(CliError::not_found(format!(
                "No pinned key found for {} ({})",
                display_user, device_id
            )))
        }
        Err(PinningError::ExpiredPin { pinned_at }) => {
            return Err(CliError::PinningFailed(format!(
                "Pinned key expired on {}. Re-pin the device to export it.",
                ui::formatting::format_local_datetime(&pinned_at)
            )))
        }
        Err(err) => {
            return Err(CliError::PinningFailed(format!(
                "Failed to load pinned key: {}",
                err
            )))
        }
    };

    match format.to_ascii_lowercase().as_str() {
        "json" => {
            let payload = serde_json::json!({
                "user_id": pinned_key.user_id,
                "device_id": pinned_key.device_id,
                "fingerprint": pinned_key.fingerprint,
                "verified": pinned_key.verified,
                "verified_at": pinned_key.verified_at.map(|ts| ts.to_rfc3339()),
                "verification_method": pinned_key.verification_method.to_string(),
                "pinned_at": pinned_key.pinned_at.to_rfc3339(),
                "notes": pinned_key.notes,
            });

            let json = serde_json::to_string_pretty(&payload).map_err(|e| CliError::Format {
                message: format!("Failed to format JSON: {}", e),
            })?;
            println!("{}", json);
        }
        "yaml" => {
            let payload = serde_json::json!({
                "user_id": pinned_key.user_id,
                "device_id": pinned_key.device_id,
                "fingerprint": pinned_key.fingerprint,
                "verified": pinned_key.verified,
                "verified_at": pinned_key.verified_at.map(|ts| ts.to_rfc3339()),
                "verification_method": pinned_key.verification_method.to_string(),
                "pinned_at": pinned_key.pinned_at.to_rfc3339(),
                "notes": pinned_key.notes,
            });

            let yaml = serde_yaml::to_string(&payload).map_err(|e| CliError::Format {
                message: format!("Failed to format YAML: {}", e),
            })?;
            print!("{}", yaml);
        }
        "qr" => {
            let qr_display = display_pinning_qr_code(
                &pinned_key.user_id,
                &pinned_key.device_id,
                &pinned_key.identity_public_key,
                &pinned_key.fingerprint,
            )
            .map_err(|e| CliError::PinningFailed(format!("Failed to generate QR code: {}", e)))?;

            println!("{}", qr_display);
        }
        _ => {
            return Err(CliError::invalid_input(format!(
                "Unsupported export format: {}",
                format
            )));
        }
    }

    record_pin_audit(
        PinAuditAction::Export,
        &resolved_user_id,
        &device_id,
        Some(pinned_key.fingerprint.clone()),
        Some(pinned_key.verification_method.to_string()),
        pinned_key.notes.clone(),
        session_manager,
    )
    .await;

    Ok(())
}

/// Show and configure pinning settings
async fn handle_pin_config(
    show: bool,
    max_age_days: Option<u32>,
    signed_url_max_age_days: Option<u32>,
    signed_url_max_future_secs: u32,
    require_second_party: bool,
    no_require_second_party: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;
    let storage = session_manager.current_storage()?;
    let mut config = load_pinning_config_for_storage(&storage).await?;

    if show
        || (max_age_days.is_none()
            && signed_url_max_age_days.is_none()
            && !require_second_party
            && !no_require_second_party)
    {
        println!("⚙️  Pinning Configuration:");
        println!(
            "   Maximum Pin Age: {}",
            config
                .max_pin_age_days
                .map(|d| format!("{d} days"))
                .unwrap_or_else(|| "not enforced".to_string())
        );
        println!(
            "   QR Code Generation: {}",
            if config.enable_qr_codes {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "   Require Second-Party Verification: {}",
            if config.require_second_party_verification {
                "yes"
            } else {
                "no"
            }
        );
        println!(
            "   Signed URL Max Age: {}",
            config
                .signed_url_max_age_days
                .map(|d| format!("{d} days"))
                .unwrap_or_else(|| "not enforced".to_string())
        );
        println!(
            "   Signed URL Max Future Skew: {} seconds",
            config.signed_url_max_future_secs
        );
        return Ok(());
    }

    let mut updated = false;

    if let Some(max_age) = max_age_days {
        config.max_pin_age_days = Some(max_age);
        updated = true;
    }

    if let Some(max_age) = signed_url_max_age_days {
        config.signed_url_max_age_days = Some(max_age);
        updated = true;
    }

    if signed_url_max_future_secs != config.signed_url_max_future_secs {
        config.signed_url_max_future_secs = signed_url_max_future_secs;
        updated = true;
    }

    if require_second_party {
        config.require_second_party_verification = true;
        updated = true;
    }

    if no_require_second_party {
        config.require_second_party_verification = false;
        updated = true;
    }

    if !updated {
        println!("⚙️  No configuration changes requested.");
        return Ok(());
    }

    persist_pinning_config(&storage, &config).await?;

    println!("✅ Configuration updated successfully");

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct SecondPartyAssignmentToken {
    token_id: Uuid,
    target_user_id: Uuid,
    target_device_id: String,
    expected_fingerprint: String,
    verifier_user_ids: Vec<Uuid>,
    group_id: Option<Uuid>,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    admin_user_id: Uuid,
    admin_device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecondPartyRoster {
    roster_id: Uuid,
    group_id: Option<Uuid>,
    verifier_user_ids: Vec<Uuid>,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    admin_user_id: Uuid,
    admin_device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedSecondPartyRoster {
    roster: SecondPartyRoster,
    signature: String,
    signer_public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedSecondPartyAssignment {
    token: SecondPartyAssignmentToken,
    signature: String,
    signer_public_key: Vec<u8>,
    #[serde(default)]
    roster: Option<SignedSecondPartyRoster>,
}

#[derive(Serialize)]
struct SecondPartyConfirmPayload {
    token_id: Uuid,
    target_user_id: Uuid,
    target_device_id: String,
    target_fingerprint: String,
    verifier_user_id: Uuid,
    verifier_device_id: String,
    issued_at: chrono::DateTime<chrono::Utc>,
    signature: String,
    signer_public_key: Vec<u8>,
}

/// Enqueue a second-party verification job for a target device.
async fn handle_second_party_enqueue(
    target_user_id: String,
    target_device_id: String,
    group_id: Option<String>,
    fingerprint: Option<String>,
    join_card_path: Option<PathBuf>,
    verifier_user_ids: Vec<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    let target_identifier = target_user_id.clone();
    let resolved_target_user_id = session_manager
        .resolve_user_identifier(&target_identifier)
        .await?;
    let target_display = if target_identifier.contains('@') {
        format!("{} ({})", target_identifier, resolved_target_user_id)
    } else {
        resolved_target_user_id.clone()
    };
    let target_uuid = Uuid::parse_str(&resolved_target_user_id)
        .map_err(|e| CliError::invalid_input(e.to_string()))?;

    let expected_fingerprint = if let Some(fp) = fingerprint {
        normalize_fingerprint(&fp)?
    } else if let Some(path) = join_card_path {
        let join_card = load_join_card_file(&path)?;
        join_card.verify_signature().map_err(|e| {
            CliError::invalid_input(format!("Join card signature verification failed: {}", e))
        })?;
        if !join_card.is_valid() {
            return Err(CliError::invalid_input(
                "Join card has expired. Request a fresh join card before enqueueing.".to_string(),
            ));
        }
        if join_card.user_id != target_uuid {
            return Err(CliError::invalid_input(format!(
                "Join card user {} does not match target user {}",
                join_card.user_id, target_display
            )));
        }
        if join_card.device_id != target_device_id {
            return Err(CliError::invalid_input(format!(
                "Join card device {} does not match target device {}",
                join_card.device_id, target_device_id
            )));
        }
        let key_bytes: [u8; 32] =
            join_card
                .identity_public
                .as_slice()
                .try_into()
                .map_err(|_| {
                    CliError::invalid_input("Join card identity key must be 32 bytes".to_string())
                })?;
        generate_fingerprint(&key_bytes)
    } else {
        return Err(CliError::invalid_input(
            "Provide --fingerprint or --join-card to enqueue second-party verification."
                .to_string(),
        ));
    };

    let group_uuid = match group_id {
        Some(raw_id) => {
            let trimmed = raw_id.trim();
            if trimmed.is_empty() {
                return Err(CliError::invalid_input(
                    "Group identifier cannot be blank.".to_string(),
                ));
            }
            Uuid::parse_str(trimmed).map_err(|e| {
                CliError::invalid_input(format!("Invalid group identifier '{}': {}", trimmed, e))
            })?
        }
        None => session_manager.ensure_current_group().await?,
    };
    let group_id_value = group_uuid.to_string();

    let mut verifiers: Vec<Uuid> = Vec::new();
    if verifier_user_ids.is_empty() {
        let members = session_manager
            .list_group_members_http(&group_id_value)
            .await?;
        let admin_user = session.user_id.clone();
        for member in members {
            let role = member.role.to_ascii_lowercase();
            if matches!(role.as_str(), "owner" | "admin") {
                continue;
            }
            let status = member.status.to_ascii_lowercase();
            if !matches!(status.as_str(), "active" | "accepted") {
                continue;
            }
            if member.user_id == resolved_target_user_id || member.user_id == admin_user {
                continue;
            }
            let parsed = Uuid::parse_str(&member.user_id)
                .map_err(|e| CliError::invalid_input(e.to_string()))?;
            verifiers.push(parsed);
        }
    } else {
        for verifier in verifier_user_ids {
            let resolved_verifier = session_manager.resolve_user_identifier(&verifier).await?;
            let parsed = Uuid::parse_str(&resolved_verifier)
                .map_err(|e| CliError::invalid_input(e.to_string()))?;
            verifiers.push(parsed);
        }
    }

    if verifiers.is_empty() {
        return Err(CliError::invalid_input(
            "No eligible verifiers found for this request.".to_string(),
        ));
    }

    verifiers.sort();
    verifiers.dedup();

    let now = Utc::now();
    let expires_at = now + Duration::hours(24);
    let admin_user_id =
        Uuid::parse_str(&session.user_id).map_err(|e| CliError::invalid_input(e.to_string()))?;
    let roster = SecondPartyRoster {
        roster_id: Uuid::new_v4(),
        group_id: Some(group_uuid),
        verifier_user_ids: verifiers.clone(),
        issued_at: now,
        expires_at,
        admin_user_id,
        admin_device_id: session.device_id.clone(),
    };

    let token = SecondPartyAssignmentToken {
        token_id: Uuid::new_v4(),
        target_user_id: target_uuid,
        target_device_id: target_device_id.clone(),
        expected_fingerprint,
        verifier_user_ids: verifiers,
        group_id: Some(group_uuid),
        issued_at: now,
        expires_at,
        admin_user_id,
        admin_device_id: session.device_id.clone(),
    };

    let invitation_keypair = session_manager.get_or_create_invitation_keypair().await?;
    let identity_public_key = invitation_keypair
        .identity_public_key_bytes()
        .map_err(|e| CliError::PinningFailed(format!("Failed to load identity key: {}", e)))?;

    let roster_signing_bytes = serde_json::to_vec(&roster)
        .map_err(|e| CliError::invalid_input(format!("Failed to serialize roster: {}", e)))?;
    let roster_sig = invitation_keypair
        .sign_identity_message(&roster_signing_bytes)
        .map_err(|e| CliError::PinningFailed(format!("Failed to sign roster: {}", e)))?;
    let signed_roster = SignedSecondPartyRoster {
        roster,
        signature: base64::engine::general_purpose::STANDARD.encode(roster_sig.as_bytes()),
        signer_public_key: identity_public_key.to_vec(),
    };

    let signing_bytes = serde_json::to_vec(&token).map_err(|e| {
        CliError::invalid_input(format!("Failed to serialize assignment token: {}", e))
    })?;
    let sig = invitation_keypair
        .sign_identity_message(&signing_bytes)
        .map_err(|e| CliError::PinningFailed(format!("Failed to sign assignment: {}", e)))?;

    let payload = SignedSecondPartyAssignment {
        token,
        signature: base64::engine::general_purpose::STANDARD.encode(sig.as_bytes()),
        signer_public_key: identity_public_key.to_vec(),
        roster: Some(signed_roster),
    };

    let endpoint = format!(
        "{}/api/v1/pin/second-party",
        session.server_url.trim_end_matches('/')
    );
    let client = reqwest::Client::new();
    let resp = client
        .post(&endpoint)
        .bearer_auth(&session.token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to enqueue second-party job: {}", e)))?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("second_party_enqueue")?;
        return Err(CliError::NotAuthenticated(
            "Session expired. Please login again.".into(),
        ));
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::network(format!(
            "Second-party enqueue failed: status {}: {}",
            status, body
        )));
    }

    let status: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"status": "queued"}));
    ui::success(&format!(
        "Second-party verification queued for {} / {} -> {}",
        target_user_id,
        target_device_id,
        status
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("queued")
    ));

    Ok(())
}

async fn handle_second_party_status(
    target_user_id: Option<String>,
    target_device_id: Option<String>,
    all_group: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;

    match (target_user_id, target_device_id) {
        (Some(user_id), Some(device_id)) => {
            let resolved_user_id = session_manager.resolve_user_identifier(&user_id).await?;
            let display_user = if user_id.contains('@') {
                format!("{} ({})", user_id, resolved_user_id)
            } else {
                format_cached_user_label(session_manager, &resolved_user_id).await
            };

            match session_manager
                .get_second_party_status(&resolved_user_id, &device_id)
                .await?
            {
                Some((status, last_error)) => {
                    println!(
                        "📌 Second-party status for {} / {}: {}",
                        display_user, device_id, status
                    );
                    if let Some(err) = last_error {
                        println!("   Last error: {}", err);
                    }
                }
                None => {
                    println!(
                        "ℹ️  No second-party status found for {} / {} (or insufficient permissions).",
                        display_user, device_id
                    );
                }
            }
        }
        (None, None) => {
            let mut group_id: Option<String> = None;
            if !all_group {
                group_id = Some(session_manager.ensure_current_group().await?.to_string());
            }
            let statuses = session_manager
                .list_second_party_statuses(group_id.as_deref())
                .await?;
            if statuses.is_empty() {
                println!("ℹ️  No second-party verifications found.");
                return Ok(());
            }
            let mut group_labels = std::collections::HashMap::new();
            let mut user_emails = std::collections::HashMap::new();
            if all_group {
                let mut group_ids = std::collections::HashSet::new();
                for status in &statuses {
                    if let Some(group_id) = status.group_id.as_ref() {
                        if !group_id.trim().is_empty() {
                            group_ids.insert(group_id.clone());
                        }
                    }
                }
                if let Ok(groups) = session_manager.list_groups_http().await {
                    for group in groups {
                        group_labels.insert(
                            group.id.to_ascii_lowercase(),
                            format!("{} ({})", group.name.trim(), group.id),
                        );
                    }
                }
                for group_id in group_ids {
                    if let Ok(members) = session_manager.list_group_members_http(&group_id).await {
                        for member in members {
                            let email = member.email.trim();
                            if !email.is_empty() && !email.contains('*') {
                                user_emails.insert(member.user_id, email.to_string());
                            }
                        }
                    }
                }
            } else if let Some(ref group_id) = group_id {
                if let Ok(members) = session_manager.list_group_members_http(group_id).await {
                    for member in members {
                        let email = member.email.trim();
                        if !email.is_empty() && !email.contains('*') {
                            user_emails.insert(member.user_id, email.to_string());
                        }
                    }
                }
            }
            if !user_emails.is_empty() {
                let cache_entries = user_emails
                    .iter()
                    .map(|(user_id, email)| (email.clone(), user_id.clone()))
                    .collect::<Vec<_>>();
                let _ = session_manager.cache_user_identities(cache_entries).await;
            }
            println!("📌 Second-party verifications ({})", statuses.len());
            if all_group {
                println!(
                    "{:<56} {:<24} {:<36} {:<10} {}",
                    "User", "Device", "Group", "Status", "Last Error"
                );
            } else {
                println!(
                    "{:<56} {:<24} {:<10} {}",
                    "User", "Device", "Status", "Last Error"
                );
            }
            for status in statuses {
                let last_error = status.last_error.unwrap_or_default();
                let display_user = user_emails
                    .get(&status.target_user_id)
                    .map(|email| format!("{} ({})", email, status.target_user_id))
                    .unwrap_or(status.target_user_id.clone());
                if all_group {
                    let raw_group_id = status.group_id.unwrap_or_default();
                    let group_label = if raw_group_id.is_empty() {
                        raw_group_id
                    } else {
                        group_labels
                            .get(&raw_group_id.to_ascii_lowercase())
                            .cloned()
                            .unwrap_or(raw_group_id)
                    };
                    println!(
                        "{:<56} {:<24} {:<36} {:<10} {}",
                        display_user,
                        status.target_device_id,
                        group_label,
                        status.status,
                        last_error
                    );
                } else {
                    println!(
                        "{:<56} {:<24} {:<10} {}",
                        display_user, status.target_device_id, status.status, last_error
                    );
                }
            }
        }
        _ => {
            return Err(CliError::invalid_input(
                "Provide both --target-user and --target-device, or neither, when using --status."
                    .to_string(),
            ));
        }
    }

    Ok(())
}

fn spawn_second_party_worker_daemon(interval_secs: u64) -> Result<(), CliError> {
    let exe = std::env::current_exe()
        .map_err(|e| CliError::Io(format!("Failed to resolve CLI path: {}", e)))?;
    let child = Command::new(exe)
        .arg("pin")
        .arg("second-party-worker")
        .arg("--daemon")
        .arg("--daemon-child")
        .arg("--interval-secs")
        .arg(interval_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| CliError::Io(format!("Failed to start background worker: {}", e)))?;

    println!(
        "ℹ️  Second-party worker started in background (pid {}).",
        child.id()
    );
    Ok(())
}

/// Poll and process second-party verification assignments for the active user/device.
async fn run_second_party_worker(
    interval_secs: u64,
    once: bool,
    daemon: bool,
    verbose: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    let verifier_user =
        Uuid::parse_str(&session.user_id).map_err(|e| CliError::invalid_input(e.to_string()))?;
    let verifier_device = session.device_id.clone();
    let base_url = session.server_url.trim_end_matches('/').to_string();
    let poll_url = format!("{}/api/v1/pin/second-party/poll", base_url);
    let confirm_url = format!("{}/api/v1/pin/second-party/confirm", base_url);
    let client = reqwest::Client::new();
    let mut idle_notice_emitted = false;

    loop {
        if verbose {
            ui::dim("Polling second-party verifier queue...");
        }
        let resp = client
            .get(&poll_url)
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to poll verifier queue: {}", e)))?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            session_manager.invalidate_session("second_party_worker_poll")?;
            return Err(CliError::NotAuthenticated(
                "Session expired. Please login again.".into(),
            ));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::network(format!(
                "Second-party poll failed: status {}: {}",
                status, body
            )));
        }

        let assignment: Option<SignedSecondPartyAssignment> = resp
            .json()
            .await
            .map_err(|e| CliError::network(format!("Invalid poll response: {}", e)))?;

        let Some(assignment) = assignment else {
            if verbose {
                ui::info("No assigned second-party verification tasks.");
            } else if !idle_notice_emitted {
                if once {
                    ui::info("No assigned second-party verification tasks.");
                } else if daemon {
                    ui::info(&format!(
                        "No assigned second-party verification tasks. Polling every {}s.",
                        interval_secs
                    ));
                } else {
                    ui::info(&format!(
                        "No assigned second-party verification tasks. Polling every {}s; use --once to exit.",
                        interval_secs
                    ));
                }
                idle_notice_emitted = true;
            }
            if once {
                return Ok(());
            }
            tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
            continue;
        };
        idle_notice_emitted = false;

        let token = &assignment.token;
        let display_target =
            format_cached_user_label(session_manager, &token.target_user_id.to_string()).await;
        println!(
            "👀 Assigned verification for user {} device {} (expected fingerprint {})",
            display_target, token.target_device_id, token.expected_fingerprint
        );

        let (pinning_store, storage, pin_config) =
            pinning_store_for_session(session_manager).await?;
        remind_expired_pins(&storage, &pin_config).await?;

        if token.expires_at <= Utc::now() {
            ui::warning("Assignment token has expired; skipping confirmation.");
            if once {
                return Ok(());
            }
            tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
            continue;
        }

        if !token.verifier_user_ids.contains(&verifier_user) {
            ui::warning("Assignment token does not include this verifier; skipping.");
            if once {
                return Ok(());
            }
            tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
            continue;
        }

        let signing_bytes = serde_json::to_vec(token).map_err(|e| {
            CliError::PinningFailed(format!("Failed to serialize assignment token: {}", e))
        })?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&assignment.signature)
            .map_err(|e| CliError::PinningFailed(format!("Invalid assignment signature: {}", e)))?;
        let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            CliError::PinningFailed("Assignment signature must be 64 bytes".to_string())
        })?;
        let signature = hybridcipher_crypto::signatures::Signature::from_bytes(&sig_array)
            .map_err(|e| {
                CliError::PinningFailed(format!("Invalid assignment signature bytes: {}", e))
            })?;
        let signer_pk: [u8; 32] = assignment
            .signer_public_key
            .as_slice()
            .try_into()
            .map_err(|_| CliError::PinningFailed("Invalid signer key length".to_string()))?;
        let signer_vk = hybridcipher_crypto::signatures::VerifyingKey::from_bytes(&signer_pk)
            .map_err(|e| CliError::PinningFailed(format!("Invalid signer key: {}", e)))?;
        signer_vk
            .verify(&signing_bytes, &signature)
            .map_err(|e| CliError::PinningFailed(format!("Assignment signature invalid: {}", e)))?;

        let admin_pin = match pinning_store
            .get_pinned_key(&token.admin_user_id.to_string(), &token.admin_device_id)
            .await
        {
            Ok(Some(pin)) => pin,
            Ok(None) => {
                ui::warning("Admin signing key is not pinned locally; skipping confirmation.");
                if once {
                    return Ok(());
                }
                tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
                continue;
            }
            Err(PinningError::ExpiredPin { pinned_at }) => {
                ui::warning(&format!(
                    "Admin signing key expired ({}); re-pin before confirming.",
                    pinned_at
                ));
                if once {
                    return Ok(());
                }
                tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
                continue;
            }
            Err(err) => {
                return Err(CliError::PinningFailed(format!(
                    "Failed to load admin pinned key: {}",
                    err
                )))
            }
        };

        if !admin_pin.verified {
            ui::warning("Admin signing key is pinned but unverified; skipping confirmation.");
            if once {
                return Ok(());
            }
            tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
            continue;
        }

        if admin_pin.identity_public_key != signer_pk {
            ui::warning("Admin signing key does not match pinned key; skipping confirmation.");
            if once {
                return Ok(());
            }
            tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
            continue;
        }

        let observed_pin = match pinning_store
            .get_pinned_key(&token.target_user_id.to_string(), &token.target_device_id)
            .await
        {
            Ok(Some(pin)) => pin,
            Ok(None) => {
                ui::warning("No pinned key found locally for this device, please pin this device by \"hybridcipher pin add\"; skipping confirmation.");
                if once {
                    return Ok(());
                }
                tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
                continue;
            }
            Err(PinningError::ExpiredPin { pinned_at }) => {
                ui::warning(&format!(
                    "Pinned key expired ({}); re-pin before confirming.",
                    pinned_at
                ));
                if once {
                    return Ok(());
                }
                tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
                continue;
            }
            Err(err) => {
                return Err(CliError::PinningFailed(format!(
                    "Failed to load pinned key: {}",
                    err
                )))
            }
        };

        if !observed_pin.verified {
            ui::warning("Pinned key is unverified; verify before confirming second-party.");
            if once {
                return Ok(());
            }
            tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
            continue;
        }

        let observed_fp = observed_pin.fingerprint;

        let issued_at = Utc::now();
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            token.token_id,
            token.target_user_id,
            token.target_device_id,
            observed_fp,
            verifier_user,
            verifier_device,
            issued_at.to_rfc3339()
        );

        let invitation_keypair = session_manager
            .get_or_create_invitation_keypair()
            .await
            .map_err(|e| {
                CliError::PinningFailed(format!("Failed to load invitation key: {}", e))
            })?;
        let signer_public_key = invitation_keypair
            .identity_public_key_bytes()
            .map_err(|e| CliError::PinningFailed(format!("Failed to load identity key: {}", e)))?;
        let sig = invitation_keypair
            .sign_identity_message(message.as_bytes())
            .map_err(|e| CliError::PinningFailed(format!("Failed to sign confirmation: {}", e)))?;

        let payload = SecondPartyConfirmPayload {
            token_id: token.token_id,
            target_user_id: token.target_user_id,
            target_device_id: token.target_device_id.clone(),
            target_fingerprint: observed_fp,
            verifier_user_id: verifier_user,
            verifier_device_id: verifier_device.clone(),
            issued_at,
            signature: base64::engine::general_purpose::STANDARD.encode(sig.as_bytes()),
            signer_public_key: signer_public_key.to_vec(),
        };

        let resp = client
            .post(&confirm_url)
            .bearer_auth(&session.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to send confirmation: {}", e)))?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            session_manager.invalidate_session("second_party_worker_confirm")?;
            return Err(CliError::NotAuthenticated(
                "Session expired. Please login again.".into(),
            ));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            ui::warning(&format!(
                "Confirmation failed (status {}): {}",
                status, body
            ));
        } else {
            #[derive(Deserialize)]
            struct ConfirmResponse {
                status: String,
                matched: Option<bool>,
                next_verifier_index: Option<usize>,
            }

            let parsed: Option<ConfirmResponse> = resp.json().await.ok();
            let status = parsed
                .as_ref()
                .map(|resp| resp.status.as_str())
                .unwrap_or("ok");

            if let Some(resp) = parsed.as_ref() {
                if matches!(resp.matched, Some(false)) {
                    if let Some(next_idx) = resp.next_verifier_index {
                        ui::warning(&format!(
                            "Fingerprint mismatch; rotating to verifier index {}",
                            next_idx
                        ));
                    } else {
                        ui::warning("Fingerprint mismatch; rotation scheduled.");
                    }
                    ui::dim("Use /pin/second-party/status (admin token) for details.");
                }
            }

            ui::success(&format!(
                "Submitted verification as {} / {} -> {}",
                verifier_user, verifier_device, status
            ));

            if status.eq_ignore_ascii_case("verified") {
                let group_id = token.group_id.map(|id| id.to_string());
                match session_manager
                    .resolve_unverified_device(
                        &token.target_user_id.to_string(),
                        &token.target_device_id,
                        group_id.as_deref(),
                        Some("second_party_verified"),
                    )
                    .await
                {
                    Ok(result) => {
                        for group_id in result.groups {
                            let _ = members::clear_unverified_device_cache(
                                session_manager,
                                group_id,
                                token.target_user_id,
                                &token.target_device_id,
                            )
                            .await;
                        }
                    }
                    Err(err) => {
                        ui::warning(&format!(
                            "Second-party verification complete, but failed to clear unverified entry: {}",
                            err
                        ));
                    }
                }
            }
        }

        if once {
            return Ok(());
        }
        tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
    }
}

fn load_join_card_file(path: &Path) -> Result<ClientJoinCard, CliError> {
    let contents = fs::read_to_string(path).map_err(|e| {
        CliError::Io(format!(
            "Failed to read join card from '{}': {}",
            path.display(),
            e
        ))
    })?;

    serde_json::from_str::<ClientJoinCard>(&contents).map_err(|e| {
        CliError::invalid_input(format!(
            "Join card at '{}' is invalid: {}",
            path.display(),
            e
        ))
    })
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn normalize_fingerprint(value: &str) -> Result<String, CliError> {
    verify_fingerprint_format(value)
        .map_err(|e| CliError::invalid_input(format!("Invalid fingerprint format: {}", e)))?;
    let clean: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let upper = clean.to_ascii_uppercase();
    let mut formatted = String::new();
    for (idx, chunk) in upper.as_bytes().chunks(4).enumerate() {
        if idx > 0 {
            formatted.push(' ');
        }
        formatted.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    Ok(formatted)
}

type UserStorage = Arc<hybridcipher_client::storage::LocalFsStorage>;

const PINNING_CONFIG_KEY: &str = "pinning_config";
const PINNED_KEY_PREFIX: &str = "pinned_key-";
static AUDIT_REPLAY_STARTED: OnceLock<()> = OnceLock::new();
static EXPIRY_REMINDER_EMITTED: OnceLock<()> = OnceLock::new();

async fn record_pin_audit(
    action: PinAuditAction,
    user_id: &str,
    device_id: &str,
    fingerprint: Option<String>,
    method: Option<String>,
    notes: Option<String>,
    session_manager: &SessionManager,
) {
    if let Ok(session) = session_manager.require_auth() {
        #[derive(serde::Serialize)]
        struct PinAuditSigningPayload<'a> {
            action: &'a PinAuditAction,
            user_id: &'a str,
            device_id: &'a str,
            fingerprint: &'a Option<String>,
            method: &'a Option<String>,
            notes: &'a Option<String>,
            actor: &'a str,
            timestamp: &'a chrono::DateTime<chrono::Utc>,
        }

        let mut entry = PinAuditEntry {
            action,
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            fingerprint,
            method,
            notes,
            actor: session.username.clone(),
            timestamp: chrono::Utc::now(),
            signature: None,
            signer_public_key: None,
            checkpoint: None,
            log_proof: None,
            log_sequence: None,
        };

        let signing_payload = PinAuditSigningPayload {
            action: &entry.action,
            user_id,
            device_id,
            fingerprint: &entry.fingerprint,
            method: &entry.method,
            notes: &entry.notes,
            actor: &entry.actor,
            timestamp: &entry.timestamp,
        };

        // Attach the latest verified transparency checkpoint if available, refreshing if needed.
        let mut checkpoints: Vec<String> = Vec::new();
        match session_manager.transparency_cache_summary() {
            Ok(Some(summary)) => {
                checkpoints.push(format!("log:{}", summary.checkpoint_fingerprint))
            }
            Ok(None) => {
                if let Ok(Some(summary)) = session_manager
                    .refresh_transparency_cache(&session.server_url)
                    .await
                {
                    checkpoints.push(format!("log:{}", summary.checkpoint_fingerprint));
                }
            }
            Err(err) => tracing::warn!(
                "Unable to load transparency checkpoint for audit entry: {}",
                err
            ),
        }

        // Sign the audit entry with the device key if available.
        if let Ok(device_kp) = session_manager.get_or_create_device_keypair().await {
            if let Ok(serialized) = serde_json::to_vec(&signing_payload) {
                if let Ok(sig) =
                    hybridcipher_crypto::signatures::sign(device_kp.signing_key(), &serialized)
                {
                    entry.signature =
                        Some(base64::engine::general_purpose::STANDARD.encode(sig.as_bytes()));
                    entry.signer_public_key = Some(
                        base64::engine::general_purpose::STANDARD
                            .encode(device_kp.verifying_key().to_bytes()),
                    );
                }
            }
        }

        if !checkpoints.is_empty() {
            entry.checkpoint = Some(checkpoints.join(";"));
        }

        // Forward to server audit endpoint (best effort, awaited to capture checkpoint).
        let mut server_checkpoint: Option<String> = None;
        let mut forward_failures: Option<String> = None;
        let mut log_proof_hashes: Vec<String> = Vec::new();
        if entry.signature.is_some() && entry.signer_public_key.is_some() {
            let server_url = session.server_url.clone();
            let token = session.token.clone();
            let client = reqwest::Client::new();
            let endpoint = format!("{}/api/v1/audit/pin", server_url.trim_end_matches('/'));

            // Before sending the new entry, replay any pending audit writes so we don't lose history.
            if let Some(ctx) = session_manager.user_config_dir() {
                let pending_path = ctx.join("pin_audit_pending.log");
                start_background_audit_replay(
                    &client,
                    endpoint.clone(),
                    token.clone(),
                    pending_path.clone(),
                );
                if let Err(err) =
                    replay_pending_audits(&client, &endpoint, &token, &pending_path).await
                {
                    tracing::warn!("Failed to replay pending pin audits: {}", err);
                }
            }

            #[derive(serde::Deserialize)]
            struct PinAuditResponse {
                #[allow(dead_code)]
                status: String,
                checkpoint: String,
                #[serde(default)]
                log_checkpoint: Option<String>,
                #[serde(default)]
                log_proof: Option<String>,
                #[serde(default)]
                log_sequence: Option<u64>,
            }

            let mut attempt = 0;
            let mut backoff_ms = 500;
            while attempt < 3 {
                attempt += 1;
                match client
                    .post(&endpoint)
                    .bearer_auth(&token)
                    .json(&entry)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                        if let Err(err) = session_manager.invalidate_session("pin_audit_forward") {
                            tracing::warn!(
                                "Failed to invalidate session after pin audit rejection: {}",
                                err
                            );
                        }
                        forward_failures =
                            Some("Authentication token rejected. Please login again.".to_string());
                        break;
                    }
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(parsed) = resp.json::<PinAuditResponse>().await {
                            server_checkpoint = Some(parsed.checkpoint);
                            if let Some(log_cp) = parsed.log_checkpoint {
                                checkpoints.push(log_cp);
                            }
                            if let Some(proof) = parsed.log_proof {
                                log_proof_hashes.push(proof);
                            }
                            entry.log_sequence = parsed.log_sequence;
                        }
                        forward_failures = None;
                        break;
                    }
                    Ok(resp) => {
                        forward_failures = Some(format!(
                            "status {}: {}",
                            resp.status(),
                            resp.text().await.unwrap_or_default()
                        ));
                    }
                    Err(err) => {
                        forward_failures = Some(err.to_string());
                    }
                }

                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                }
            }
        } else {
            tracing::warn!("Skipping server audit forward: missing device signature");
        }

        if let Some(cp) = server_checkpoint {
            checkpoints.push(format!("server:{}", cp));
            entry.checkpoint = Some(checkpoints.join(";"));
        }
        if let Some(proof) = log_proof_hashes.first() {
            entry.log_proof = Some(proof.clone());
        }

        if let Ok(serialized) = serde_json::to_string(&entry) {
            tracing::info!("pin_audit: {}", serialized);
        }
        // Persist to a local audit log under the active user's config dir if available.
        if let Some(ctx) = session_manager.user_config_dir() {
            let log_path = ctx.join("pin_audit.log");
            let _ = crate::audit::append_jsonl(&log_path, &entry);

            if let Some(err) = forward_failures {
                let pending_path = ctx.join("pin_audit_pending.log");
                let pending = json!({
                    "entry": &entry,
                    "error": err,
                    "recorded_at": chrono::Utc::now(),
                });
                let _ = crate::audit::append_jsonl(&pending_path, &pending);
            } else if entry.log_proof.is_none() {
                let pending_path = ctx.join("pin_audit_pending.log");
                let pending = json!({
                    "entry": &entry,
                    "error": "missing transparency proof",
                    "recorded_at": chrono::Utc::now(),
                });
                let _ = crate::audit::append_jsonl(&pending_path, &pending);
                ui::warning("Transparency proof missing for pin audit; queued for retry.");
            }
        }
    }
}

/// Replay pending audit entries written to disk when a previous forward attempt failed.
async fn replay_pending_audits(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    pending_path: &std::path::Path,
) -> Result<(), String> {
    if !pending_path.exists() {
        return Ok(());
    }

    let content = tokio_fs::read_to_string(pending_path)
        .await
        .map_err(|e| format!("read pending audits: {}", e))?;
    let mut remaining = Vec::new();

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!("Skipping malformed pending audit entry: {}", err);
                continue;
            }
        };

        let Some(entry_val) = value.get("entry") else {
            tracing::warn!("Pending audit line missing 'entry' field");
            continue;
        };

        let entry: PinAuditEntry = match serde_json::from_value(entry_val.clone()) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!("Failed to parse pending audit entry: {}", err);
                continue;
            }
        };

        match client
            .post(endpoint)
            .bearer_auth(token)
            .json(&entry)
            .send()
            .await
        {
            Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                return Err("pin audit replay unauthorized; session expired".to_string());
            }
            Ok(resp) if resp.status().is_success() => {
                #[derive(serde::Deserialize)]
                struct PendingResp {
                    #[serde(rename = "checkpoint")]
                    _checkpoint: String,
                    #[serde(rename = "log_checkpoint", default)]
                    _log_checkpoint: Option<String>,
                    #[serde(default)]
                    log_proof: Option<String>,
                }
                match resp.json::<PendingResp>().await {
                    Ok(parsed) => {
                        if parsed.log_proof.is_some() {
                            // success; drop from queue
                        } else {
                            remaining.push(value);
                            tracing::warn!(
                                "Pending audit replay missing transparency proof; will retry"
                            );
                        }
                    }
                    Err(err) => {
                        remaining.push(value);
                        tracing::warn!(
                            "Pending audit replay parse failed (keeping pending): {}",
                            err
                        );
                    }
                }
            }
            Ok(resp) => {
                remaining.push(value);
                tracing::warn!(
                    "Pending audit replay failed ({}): {:?}",
                    resp.status(),
                    resp.text().await.ok()
                );
            }
            Err(err) => {
                remaining.push(value);
                tracing::warn!("Pending audit replay network error: {}", err);
            }
        }
    }

    if remaining.is_empty() {
        tokio_fs::remove_file(pending_path)
            .await
            .map_err(|e| format!("cleanup pending audits: {}", e))?;
    } else {
        let mut file = tokio_fs::File::create(pending_path)
            .await
            .map_err(|e| format!("rewrite pending audits: {}", e))?;
        for val in remaining {
            let line = serde_json::to_string(&val).map_err(|e| e.to_string())?;
            file.write_all(line.as_bytes())
                .await
                .map_err(|e| format!("write pending audits: {}", e))?;
            file.write_all(b"\n")
                .await
                .map_err(|e| format!("write pending audits newline: {}", e))?;
        }
    }

    Ok(())
}

fn start_background_audit_replay(
    client: &reqwest::Client,
    endpoint: String,
    token: String,
    pending_path: std::path::PathBuf,
) {
    if AUDIT_REPLAY_STARTED.get().is_some() {
        return;
    }
    let _ = AUDIT_REPLAY_STARTED.set(());

    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }

    let client = client.clone();
    tokio::spawn(async move {
        loop {
            if let Err(err) = replay_pending_audits(&client, &endpoint, &token, &pending_path).await
            {
                tracing::debug!("background pin-audit replay skipped: {}", err);
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
}

async fn load_pinning_config_for_storage(storage: &UserStorage) -> Result<PinningConfig, CliError> {
    match storage
        .load_config(PINNING_CONFIG_KEY)
        .await
        .map_err(|e| CliError::storage(format!("Failed to load pinning configuration: {}", e)))?
    {
        Some(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw).map_err(|e| {
            CliError::configuration(format!("Corrupted pinning configuration: {}", e))
        }),
        _ => Ok(hybridcipher_client::config_loader::load_client_config_from_files().pinning_config),
    }
}

async fn persist_pinning_config(
    storage: &UserStorage,
    config: &PinningConfig,
) -> Result<(), CliError> {
    let serialized = serde_json::to_string(config).map_err(|e| {
        CliError::configuration(format!("Failed to serialize pinning configuration: {}", e))
    })?;

    storage
        .store_config(PINNING_CONFIG_KEY, &serialized)
        .await
        .map_err(|e| CliError::storage(format!("Failed to persist pinning configuration: {}", e)))
}

async fn load_all_pinned_keys(
    storage: &UserStorage,
    config: &PinningConfig,
) -> Result<Vec<PinnedKey>, CliError> {
    let key_names = storage
        .list_config_keys_with_prefix(PINNED_KEY_PREFIX)
        .await
        .map_err(|e| CliError::storage(format!("Failed to enumerate pinned keys: {}", e)))?;

    if key_names.is_empty() {
        return Ok(Vec::new());
    }

    let pinning_store = PinningStore::new(storage.clone(), config.clone());
    let mut seen_pairs: HashSet<(String, String)> = HashSet::new();
    let mut pins = Vec::new();

    for key in key_names {
        let raw =
            match storage.load_config(&key).await.map_err(|e| {
                CliError::storage(format!("Failed to load pin entry '{}': {}", key, e))
            })? {
                Some(value) => value,
                None => continue,
            };

        if raw.trim().is_empty() {
            let _ = storage.delete_config(&key).await;
            continue;
        }

        let parsed: PinnedKey = match serde_json::from_str(&raw) {
            Ok(pin) => pin,
            Err(err) => {
                warn!("Pinned key entry '{}' is invalid JSON: {}", key, err);
                // Tombstone invalid entries so they do not repeatedly warn.
                if let Err(e) = storage.delete_config(&key).await {
                    warn!("Failed to clean invalid pin '{}': {}", key, e);
                }
                continue;
            }
        };

        let key_tuple = (parsed.user_id.clone(), parsed.device_id.clone());
        if !seen_pairs.insert(key_tuple.clone()) {
            continue;
        }

        match pinning_store
            .get_pinned_key(&key_tuple.0, &key_tuple.1)
            .await
        {
            Ok(Some(pinned)) => pins.push(pinned),
            Ok(None) => continue,
            Err(PinningError::ExpiredPin { pinned_at }) => {
                warn!(
                    "Pinned key for {} ({}) expired at {}; skipping",
                    key_tuple.0,
                    key_tuple.1,
                    ui::formatting::format_local_datetime(&pinned_at)
                );
            }
            Err(other) => {
                return Err(CliError::PinningFailed(format!(
                    "Failed to load pinned key for {} ({}): {}",
                    key_tuple.0, key_tuple.1, other
                )));
            }
        }
    }

    pins.sort_by(|a, b| b.pinned_at.cmp(&a.pinned_at));
    Ok(pins)
}

async fn find_expired_pins(
    storage: &UserStorage,
    config: &PinningConfig,
) -> Result<Vec<PinnedKey>, CliError> {
    let Some(max_age_days) = config.max_pin_age_days else {
        return Ok(Vec::new());
    };

    let key_names = storage
        .list_config_keys_with_prefix(PINNED_KEY_PREFIX)
        .await
        .map_err(|e| CliError::storage(format!("Failed to enumerate pinned keys: {}", e)))?;

    if key_names.is_empty() {
        return Ok(Vec::new());
    }

    let mut seen_pairs: HashSet<(String, String)> = HashSet::new();
    let mut expired = Vec::new();
    let now = Utc::now();
    let max_age = Duration::days(max_age_days as i64);

    for key in key_names {
        let raw =
            match storage.load_config(&key).await.map_err(|e| {
                CliError::storage(format!("Failed to load pin entry '{}': {}", key, e))
            })? {
                Some(value) => value,
                None => continue,
            };

        if raw.trim().is_empty() {
            let _ = storage.delete_config(&key).await;
            continue;
        }

        let parsed: PinnedKey = match serde_json::from_str(&raw) {
            Ok(pin) => pin,
            Err(err) => {
                warn!("Pinned key entry '{}' is invalid JSON: {}", key, err);
                let _ = storage.delete_config(&key).await;
                continue;
            }
        };

        let key_tuple = (parsed.user_id.clone(), parsed.device_id.clone());
        if !seen_pairs.insert(key_tuple) {
            continue;
        }

        if parsed.verified {
            let anchor = parsed.verified_at.unwrap_or(parsed.pinned_at);
            if now - anchor > max_age {
                expired.push(parsed);
            }
        }
    }

    expired.sort_by(|a, b| b.pinned_at.cmp(&a.pinned_at));
    Ok(expired)
}

async fn prune_expired_pins(
    storage: &UserStorage,
    config: &PinningConfig,
) -> Result<usize, CliError> {
    let expired = find_expired_pins(storage, config).await?;
    if expired.is_empty() {
        return Ok(0);
    }
    let store = PinningStore::new(storage.clone(), config.clone());
    for pin in &expired {
        let _ = store.unpin_key(&pin.user_id, &pin.device_id).await;
    }
    Ok(expired.len())
}

async fn pinning_store_for_session(
    session_manager: &SessionManager,
) -> Result<(PinningStore<UserStorage>, UserStorage, PinningConfig), CliError> {
    let storage = session_manager.current_storage()?;
    let config = load_pinning_config_for_storage(&storage).await?;
    let store = PinningStore::new(storage.clone(), config.clone());
    let _ = prune_expired_pins(&storage, &config).await?;
    Ok((store, storage, config))
}
