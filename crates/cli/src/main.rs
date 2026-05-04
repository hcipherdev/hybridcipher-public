use clap::Parser;
use color_eyre::eyre::Result;
use hybridcipher_messages::transparency::{TransparencyConfig, TransparencyTrustedKey};
use std::process;
use std::time::Instant;

mod audit;
mod commands;
mod error;
mod recovery_artifact;
mod security;
mod session;
mod ui;

use commands::{handle_command, Commands};
use error::CliError;
use security::transparency::all_known_transparency_keys;
use session::TransparencyPreferences;

const TRANSPARENCY_BYPASS_ENV: &str = "HYBRIDCIPHER_TRANSPARENCY_EXCEPTION";

/// HybridCipher - End-to-end encrypted group file sharing with post-quantum security
#[derive(Parser)]
#[command(name = "hybridcipher", version = "0.1.0")]
#[cfg_attr(
    not(feature = "individual-edition"),
    command(
        about = "Secure group file sharing with two-phase rekey and coverage audit",
        long_about = "HybridCipher provides end-to-end encrypted file sharing with advanced security features:
- Post-quantum cryptographic resistance
- Two-phase rekey migration system
- Coverage audit and verification
- Sync mounts for cloud-style local access
- Optional Linux FUSE mount support
- Member management with perfect forward secrecy

All operations maintain cryptographic security properties even against untrusted servers."
    )
)]
#[cfg_attr(
    feature = "individual-edition",
    command(
        about = "Secure personal file protection with team administration disabled",
        long_about = "HybridCipher provides encrypted file protection and device onboarding in a restricted personal build:
- Post-quantum cryptographic resistance
- Personal file encryption and decryption
- Coverage enrollment and verification
- Device approval and setup
- Recovery backup management
- Sync mounts for local access

This build disables team and group administration commands while using the same shared HybridCipher client engine."
    )
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output for debugging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<std::path::PathBuf>,

    /// Disable transparency log verification
    #[arg(long, global = true)]
    no_transparency: bool,

    /// Transparency log server URL
    #[arg(long, global = true)]
    transparency_server: Option<String>,

    /// Transparency verification timeout in seconds
    #[arg(long, global = true, default_value = "30")]
    transparency_timeout: u64,

    /// Enable fallback to key pinning if transparency log is unavailable
    #[arg(long, global = true)]
    enable_pinning_fallback: bool,

    /// Require transparency verification; fail if checkpoint cannot be validated
    #[arg(long, global = true)]
    require_transparency: bool,
}

#[tokio::main]
async fn main() {
    // Initialize enhanced error reporting with color-eyre
    if let Err(e) = color_eyre::install() {
        eprintln!("Failed to initialize error reporting: {}", e);
        process::exit(1);
    }

    // Parse command line arguments
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Enhanced error display for argument parsing
            if e.kind() == clap::error::ErrorKind::DisplayHelp
                || e.kind() == clap::error::ErrorKind::DisplayVersion
            {
                println!("{}", e);
                process::exit(0);
            }
            eprintln!("{}", e);
            ui::error::display_cli_usage_error(&e.to_string());
            process::exit(1);
        }
    };

    // Configure console output based on CLI flags
    if cli.no_color {
        console::set_colors_enabled(false);
        std::env::set_var("NO_COLOR", "1");
    }

    // Configure logging level based on verbosity
    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
        std::env::set_var("HYBRIDCIPHER_VERBOSE", "1");
    }

    // Execute the command with performance monitoring
    let start_time = Instant::now();
    let result = run_cli_with_monitoring(cli).await;
    let execution_time = start_time.elapsed();

    // Handle the result with enhanced error reporting
    match result {
        Ok(()) => {
            if std::env::var("HYBRIDCIPHER_VERBOSE").is_ok() {
                ui::info(&format!(
                    "✅ Command completed successfully in {:.2}s",
                    execution_time.as_secs_f64()
                ));
            }
        }
        Err(e) => {
            ui::error::display_error_with_context(&e, execution_time);
            process::exit(1);
        }
    }
}

async fn run_cli_with_monitoring(cli: Cli) -> Result<(), CliError> {
    let Cli {
        command,
        config,
        no_transparency,
        transparency_server,
        transparency_timeout,
        enable_pinning_fallback,
        require_transparency,
        ..
    } = cli;

    commands::enforce_individual_edition_command_policy(&command)?;

    // Initialize session management with enhanced error handling
    let show_session_banner = !matches!(command, Commands::ShowToken { .. });
    if show_session_banner {
        ui::dim("Initializing secure session management...");
    }
    let session_manager = session::SessionManager::new(config.as_deref()).map_err(|e| {
        CliError::configuration(format!("Failed to initialize session manager: {}", e))
    })?;

    if no_transparency && require_transparency {
        return Err(CliError::configuration(
            "Cannot disable transparency verification and require it simultaneously",
        ));
    }

    let mut transparency_prefs = TransparencyPreferences::default();
    let bypass_token = std::env::var(TRANSPARENCY_BYPASS_ENV).ok();

    if no_transparency {
        if bypass_token.is_none() {
            return Err(CliError::configuration(format!(
                "Transparency verification is enforced. Provide a signed exception via the {} environment variable before using --no-transparency.",
                TRANSPARENCY_BYPASS_ENV
            )));
        }
        transparency_prefs.enabled = false;
        transparency_prefs.require_transparency = false;
        transparency_prefs.fallback_to_pinning = enable_pinning_fallback;
    } else {
        transparency_prefs.enabled = true;
        transparency_prefs.require_transparency = true;
        transparency_prefs.fallback_to_pinning = false;

        if enable_pinning_fallback {
            if require_transparency {
                return Err(CliError::configuration(
                    "Cannot request both --require-transparency and --enable-pinning-fallback.",
                ));
            }
            if bypass_token.is_none() {
                return Err(CliError::configuration(format!(
                    "Transparency fallback requires a signed exception. Set {} and rerun with --enable-pinning-fallback.",
                    TRANSPARENCY_BYPASS_ENV
                )));
            }
            transparency_prefs.fallback_to_pinning = true;
            transparency_prefs.require_transparency = false;
        }
    }

    if require_transparency {
        transparency_prefs.require_transparency = true;
        transparency_prefs.fallback_to_pinning = false;
    }

    transparency_prefs.log_url_override = transparency_server.clone();
    transparency_prefs.verification_timeout_seconds = transparency_timeout;

    session_manager.set_transparency_preferences(transparency_prefs.clone())?;

    let trusted_signing_keys: Vec<TransparencyTrustedKey> = all_known_transparency_keys()
        .into_iter()
        .map(|(key_id, public_key_base64)| TransparencyTrustedKey {
            key_id,
            public_key_base64,
        })
        .collect();

    let transparency_config = TransparencyConfig {
        enabled: transparency_prefs.enabled,
        log_server_url: transparency_prefs.log_url_override.clone(),
        verification_timeout_seconds: transparency_prefs.verification_timeout_seconds,
        fallback_to_pinning: transparency_prefs.fallback_to_pinning,
        max_checkpoint_age_seconds: transparency_prefs.max_checkpoint_age_seconds,
        trusted_signing_keys,
    };

    session_manager.set_transparency_config(transparency_config.clone())?;

    // Check system prerequisites
    validate_system_requirements()?;

    // Display migration state awareness if applicable
    if show_session_banner {
        if let Some(migration_info) = session_manager.migration_info() {
            if migration_info.phase.is_active() {
                ui::subsection("Migration State Detected");
                ui::warning(&format!(
                    "🔄 Active migration in progress: {} ({:.1}% complete)",
                    migration_info.phase.description(),
                    migration_info.progress
                ));
                ui::info(
                    "Use 'hybridcipher rekey status --watch' to view the live migration dashboard",
                );
                println!();
            }
        }
    }

    // Handle the command with enhanced error context
    handle_command_with_context(command, &session_manager, transparency_config).await?;

    Ok(())
}

/// Handle command with enhanced error context and user guidance
async fn handle_command_with_context(
    command: Commands,
    session_manager: &session::SessionManager,
    transparency_config: TransparencyConfig,
) -> Result<(), CliError> {
    match handle_command(command, session_manager, transparency_config).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Provide contextual error guidance based on error type
            match &e {
                CliError::Authentication { .. } => {
                    ui::subsection("Authentication Help");
                    ui::info("💡 Try these solutions:");
                    ui::info("  1. Verify your username and password");
                    ui::info("  2. Check server connectivity with 'hybridcipher login --help'");
                    ui::info("  3. Register a new account with 'hybridcipher register <username>'");
                }
                CliError::Session { .. } => {
                    ui::subsection("Session Help");
                    ui::info("💡 Try these solutions:");
                    ui::info("  1. Login again with 'hybridcipher login <username>'");
                    ui::info("  2. Check session status and clear if needed");
                    ui::info("  3. Verify configuration file permissions");
                }
                CliError::Configuration { .. } => {
                    ui::subsection("Configuration Help");
                    ui::info("💡 Try these solutions:");
                    ui::info("  1. Check file and directory permissions");
                    ui::info("  2. Verify configuration file syntax");
                    ui::info("  3. Use --config to specify alternative config path");
                }
                _ => {
                    ui::subsection("General Help");
                    ui::info("💡 For more help:");
                    ui::info("  1. Use --verbose for detailed debugging information");
                    ui::info("  2. Check 'hybridcipher help' for command documentation");
                    ui::info("  3. Review system requirements and network connectivity");
                }
            }
            Err(e)
        }
    }
}

/// Validate system requirements and provide guidance
fn validate_system_requirements() -> Result<(), CliError> {
    // Skip validation if invoked by desktop app (it manages directories itself)
    if std::env::var("HYBRIDCIPHER_SKIP_CONFIG_CHECK").is_ok() {
        return Ok(());
    }

    // Check for required directories and permissions
    if let Some(home_dir) = directories::ProjectDirs::from("", "HybridCipher", "hybridcipher-cli") {
        let config_dir = home_dir.config_dir();

        // Check if we can create the config directory
        if !config_dir.exists() {
            std::fs::create_dir_all(config_dir).map_err(|e| {
                CliError::configuration(format!(
                    "Cannot create configuration directory {}: {}. Check file permissions.",
                    config_dir.display(),
                    e
                ))
            })?;
        }

        // Verify write permissions
        let test_file = config_dir.join(".write_test");
        std::fs::write(&test_file, "test")
            .and_then(|_| std::fs::remove_file(&test_file))
            .map_err(|e| {
                CliError::configuration(format!(
                    "Insufficient write permissions in {}: {}",
                    config_dir.display(),
                    e
                ))
            })?;
    }

    Ok(())
}
