use crate::{
    error::CliError,
    security::server_identity::{TrustDecision, TrustLevel, VerificationMethod},
    session::{SessionManager, TransparencyCacheSummary},
    ui,
};
use chrono::Utc;
use clap::Subcommand;
use qrcode::QrCode;
use serde::Deserialize;
use serde_json::json;
use std::{fs, path::PathBuf};

#[derive(Subcommand)]
pub enum TrustCommands {
    /// Display the pinned server fingerprint and safety number
    Show {
        /// Render QR code in terminal
        #[arg(long)]
        qr: bool,
    },

    /// Verify the server fingerprint using an out-of-band safety number or QR payload
    Verify {
        /// Out-of-band safety number (digits, spaces allowed)
        #[arg(long)]
        safety_number: Option<String>,
        /// Path to JSON file containing QR payload
        #[arg(long)]
        qr: Option<PathBuf>,
    },

    /// Revoke user verification status and return to TOFU state
    Revoke,

    /// Display transparency checkpoint information and optionally refresh from the server
    Checkpoint {
        /// Display cached checkpoint without hitting the server
        #[arg(long)]
        no_refresh: bool,
    },
}

pub async fn handle_trust_command(
    command: TrustCommands,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    match command {
        TrustCommands::Show { qr } => handle_show(qr, session_manager).await,
        TrustCommands::Verify { safety_number, qr } => {
            handle_verify(safety_number, qr, session_manager).await
        }
        TrustCommands::Revoke => handle_revoke(session_manager).await,
        TrustCommands::Checkpoint { no_refresh } => {
            handle_checkpoint(!no_refresh, session_manager).await
        }
    }
}

async fn handle_show(render_qr: bool, session_manager: &SessionManager) -> Result<(), CliError> {
    let (server_url, username) = resolve_context(session_manager, None)?;
    session_manager.set_user_context(&username, &server_url)?;

    let trust_decision = session_manager
        .preflight_server_identity(&server_url)
        .await?;

    let identity = session_manager
        .server_identity_manager()?
        .get_server_identity(&server_url)
        .cloned()
        .ok_or_else(|| {
            CliError::PinningFailed(format!(
                "No pinned server identity for {}. Login first to establish trust.",
                server_url
            ))
        })?;

    ui::section("Server Identity");
    ui::info(&format!("Server: {}", identity.server_url));
    ui::info(&format!(
        "Fingerprint (SHA-256): {}",
        identity.fingerprint_sha256_hex()
    ));

    if let Some(safety) = identity.safety_number() {
        ui::info(&format!("Safety number: {}", safety));
    }

    display_trust_decision(&trust_decision, &server_url);

    if render_qr {
        render_qr_payload(&identity, &server_url)?;
    }

    Ok(())
}

async fn handle_verify(
    safety_number: Option<String>,
    qr_path: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    if safety_number.is_none() && qr_path.is_none() {
        return Err(CliError::invalid_input(
            "Provide --safety-number or --qr to verify the fingerprint",
        ));
    }

    if safety_number.is_some() && qr_path.is_some() {
        return Err(CliError::invalid_input(
            "Use either --safety-number or --qr, not both",
        ));
    }

    let (server_url, username) = resolve_context(session_manager, None)?;
    session_manager.set_user_context(&username, &server_url)?;

    session_manager
        .preflight_server_identity(&server_url)
        .await?;

    let mut manager = session_manager.server_identity_manager()?;
    let identity = manager
        .get_server_identity(&server_url)
        .cloned()
        .ok_or_else(|| {
            CliError::PinningFailed(format!(
                "No pinned server identity for {}. Login first to establish trust.",
                server_url
            ))
        })?;

    if let Some(input) = safety_number {
        let provided = normalize_digits(&input);
        if provided.is_empty() {
            return Err(CliError::invalid_input(
                "Provided safety number does not contain digits",
            ));
        }

        let stored = identity.safety_number().ok_or_else(|| {
            CliError::PinningFailed(
                "Safety number is unavailable for this server. Re-run login to establish trust."
                    .to_string(),
            )
        })?;
        let expected = normalize_digits(stored);
        if expected.is_empty() {
            return Err(CliError::PinningFailed(
                "Stored safety number is unavailable. Re-run login to establish trust.".to_string(),
            ));
        }

        if provided != expected {
            return Err(CliError::PinningFailed(
                "Safety number mismatch. Possible MITM or key rotation.".to_string(),
            ));
        }

        manager.set_trust_level(
            &server_url,
            TrustLevel::UserVerified,
            VerificationMethod::SafetyNumber,
        )?;
        ui::success("✅ Server identity verified via safety number");
        return Ok(());
    }

    if let Some(path) = qr_path {
        let payload = fs::read_to_string(&path).map_err(|e| {
            CliError::Io(format!(
                "Failed to read QR payload from {}: {}",
                path.display(),
                e
            ))
        })?;
        let qr_payload: QrPayload = serde_json::from_str(&payload).map_err(|e| {
            CliError::invalid_input(format!(
                "Invalid QR JSON payload in {}: {}",
                path.display(),
                e
            ))
        })?;

        if let Some(qr_server) = qr_payload.server_url {
            if !qr_server.trim().is_empty() {
                let qr_canonical = crate::session::canonicalize_server_url(&qr_server).canonical;
                let current_canonical =
                    crate::session::canonicalize_server_url(&server_url).canonical;
                if qr_canonical != current_canonical {
                    return Err(CliError::PinningFailed(format!(
                        "QR code references server {} but current context is {}",
                        qr_server, server_url
                    )));
                }
            }
        }

        if qr_payload.sha256_hex.trim().is_empty() {
            return Err(CliError::invalid_input(
                "QR payload missing sha256_hex field",
            ));
        }

        let expected = identity.fingerprint_sha256_hex().to_string();
        if !qr_payload
            .sha256_hex
            .eq_ignore_ascii_case(expected.as_str())
        {
            return Err(CliError::PinningFailed(format!(
                "QR payload fingerprint does not match pinned key (expected {}, got {})",
                expected, qr_payload.sha256_hex
            )));
        }

        manager.set_trust_level(
            &server_url,
            TrustLevel::UserVerified,
            VerificationMethod::QRCode,
        )?;
        ui::success("✅ Server identity verified via QR code");
    }

    Ok(())
}

async fn handle_checkpoint(
    refresh: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let (server_url, username) = resolve_context(session_manager, None)?;
    session_manager.set_user_context(&username, &server_url)?;

    let cached_before = session_manager.transparency_cache_summary()?;

    let cached_after = if refresh {
        match session_manager
            .refresh_transparency_cache(&server_url)
            .await
        {
            Ok(summary) => summary,
            Err(err) => {
                ui::warning(&format!("Transparency refresh failed: {}", err));
                session_manager.transparency_cache_summary()?
            }
        }
    } else {
        cached_before.clone()
    };

    ui::section("Transparency Checkpoint");

    if cached_after.is_none() {
        ui::warning(
            "No verified transparency checkpoint cached for this server. Run a login with transparency enabled or try '--no-transparency' if the server does not publish checkpoints yet.",
        );
        return Ok(());
    }

    if let Some(snapshot) = cached_after.as_ref() {
        display_checkpoint_snapshot("Current checkpoint", snapshot);
    }

    if refresh {
        match (&cached_before, &cached_after) {
            (Some(previous), Some(current)) => display_checkpoint_diff(previous, current),
            (None, Some(_)) => {
                ui::success("First transparency checkpoint verified for this server");
            }
            _ => {}
        }
    } else {
        ui::info(
            "Run without '--no-refresh' to contact the server and fetch the latest checkpoint.",
        );
    }

    Ok(())
}

async fn handle_revoke(session_manager: &SessionManager) -> Result<(), CliError> {
    let (server_url, username) = resolve_context(session_manager, None)?;
    session_manager.set_user_context(&username, &server_url)?;

    session_manager
        .preflight_server_identity(&server_url)
        .await?;

    let mut manager = session_manager.server_identity_manager()?;
    manager.set_trust_level(
        &server_url,
        TrustLevel::FirstContact,
        VerificationMethod::ToFU,
    )?;
    ui::warning("⚠️ Server verification revoked. Future logins will require TOFU confirmation.");
    Ok(())
}

fn display_checkpoint_snapshot(label: &str, snapshot: &TransparencyCacheSummary) {
    ui::subsection(label);
    ui::info(&format!(
        "Root hash: {}",
        snapshot.root_hash_hex.chars().take(64).collect::<String>()
    ));
    ui::info(&format!("Tree size: {}", snapshot.tree_size));
    if let Some(log_url) = snapshot.log_url.as_deref() {
        ui::info(&format!("Log URL: {}", log_url));
    }
    if let Some(key_id) = snapshot.signing_key_id.as_deref() {
        ui::info(&format!("Signing key: {}", key_id));
    }
    ui::info(&format!(
        "Checkpoint fingerprint: {}",
        snapshot
            .checkpoint_fingerprint
            .chars()
            .take(32)
            .collect::<String>()
    ));
    ui::info(&format!(
        "Checkpoint generated at: {}",
        snapshot.checkpoint_generated_at
    ));
    ui::info(&format!("Verified locally at: {}", snapshot.verified_at));
}

fn display_checkpoint_diff(old: &TransparencyCacheSummary, new: &TransparencyCacheSummary) {
    if old.root_hash_hex.eq_ignore_ascii_case(&new.root_hash_hex) && old.tree_size == new.tree_size
    {
        ui::info("Checkpoint unchanged since the last verification.");
        return;
    }

    if new.tree_size > old.tree_size {
        ui::success(&format!(
            "Log grew from {} to {} leaves",
            old.tree_size, new.tree_size
        ));
    } else if new.tree_size < old.tree_size {
        ui::warning(&format!(
            "Tree size decreased ({} -> {}); investigate possible log reset",
            old.tree_size, new.tree_size
        ));
    }

    if !old.root_hash_hex.eq_ignore_ascii_case(&new.root_hash_hex) {
        ui::warning("Root hash changed; ensure the new checkpoint is expected.");
    }

    ui::info(&format!(
        "Previous checkpoint generated at: {}",
        old.checkpoint_generated_at
    ));
    ui::info(&format!(
        "Latest checkpoint generated at: {}",
        new.checkpoint_generated_at
    ));
}

fn resolve_context(
    session_manager: &SessionManager,
    username_override: Option<String>,
) -> Result<(String, String), CliError> {
    let mut username_override = username_override;

    if let Ok(session) = session_manager.require_auth() {
        let server_url = session.server_url.clone();
        let username = username_override
            .take()
            .unwrap_or_else(|| session.username.clone());
        return Ok((server_url, username));
    }

    if let Some(summary) = session_manager.active_user_summary() {
        let server_url = summary.server_url.clone();
        let username = username_override
            .take()
            .unwrap_or_else(|| summary.username.clone());
        return Ok((server_url, username));
    }

    if username_override.is_some() {
        return Err(CliError::NotAuthenticated(
            "Not authenticated. Please login first with 'hybridcipher login <username>'".into(),
        ));
    }

    Err(CliError::NotAuthenticated(
        "Not authenticated. Please login first with 'hybridcipher login <username>'".into(),
    ))
}

fn display_trust_decision(decision: &TrustDecision, server_url: &str) {
    match decision {
        TrustDecision::FirstContact(identity) => {
            ui::warning(&format!("🔒 First contact with server: {}", server_url));
            ui::info(&format!(
                "📌 Server fingerprint (short): {}",
                identity.fingerprint_preview()
            ));
            if let Some(safety) = identity.safety_number() {
                ui::info(&format!("Safety number: {}", safety));
            }
            ui::info("⚠️  Verify this fingerprint via a secure channel to upgrade trust");
        }
        TrustDecision::Trusted(level) => match level {
            TrustLevel::FirstContact => {
                ui::success("✅ Server identity matches pinned fingerprint (TOFU)")
            }
            TrustLevel::UserVerified => ui::success("✅ Server identity previously user-verified"),
            TrustLevel::TransparencyLog => {
                ui::success("✅ Server identity verified via transparency log")
            }
            TrustLevel::Unknown => ui::warning("⚠️ Stored server identity has unknown trust level"),
        },
    }
}

fn render_qr_payload(
    identity: &crate::security::server_identity::ServerIdentity,
    server_url: &str,
) -> Result<(), CliError> {
    let payload = json!({
        "server_url": server_url,
        "sha256_hex": identity.fingerprint_sha256_hex(),
        "short_hex": identity.fingerprint_preview(),
        "generated_at": Utc::now().to_rfc3339(),
    });

    let code = QrCode::new(payload.to_string().as_bytes())
        .map_err(|e| CliError::invalid_input(format!("Failed to generate QR code: {}", e)))?;
    let rendered = code
        .render::<char>()
        .dark_color('█')
        .light_color(' ')
        .build();

    println!("\n{}", rendered);
    Ok(())
}

fn normalize_digits(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
}

#[derive(Deserialize)]
struct QrPayload {
    #[serde(default)]
    server_url: Option<String>,
    sha256_hex: String,
}
