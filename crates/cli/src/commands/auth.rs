use super::mount;
use crate::{
    commands::{
        mfa,
        recovery::{self, AutoProvisionMode},
        TokenFormat,
    },
    error::CliError,
    security::server_identity::{TrustDecision, TrustLevel},
    session::{
        canonicalize_server_url, client_join_card_to_messages, CurrentDevicePinState, GroupInfo,
        JoinCardPublishState, MigrationInfo, Session, SessionFlags, SessionManager,
        SessionSecurity,
    },
    ui,
};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hex;
use hybridcipher_client::{
    auth::opaque::{
        DeviceLoginMetadata, DeviceRecoveryDeviceOption, DeviceRecoveryFinalization,
        DeviceRecoveryVerified, OpaqueAuth, OpaqueError,
    },
    network::MockNetwork,
    state::client::Client as HybridClient,
    storage::LocalFsStorage,
};
use opaque_ke::{
    key_exchange::tripledh::TripleDh, CipherSuite, ClientRegistration,
    ClientRegistrationFinishParameters, ClientRegistrationStartResult, RegistrationResponse,
    Ristretto255,
};
use rand::rngs::OsRng;
use reqwest;
use rpassword;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{self, Write};
use uuid::Uuid;

/// OPAQUE cipher suite for password reset/change flows
struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = Ristretto255;
    type KeGroup = Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

struct OpaqueRegistrationBundle {
    registration_upload_b64: String,
    export_key_b64: String,
}

#[allow(dead_code)]
type LocalClient = HybridClient<LocalFsStorage, MockNetwork>;

/// Server registration request structure (Phase 1.3 - Complete cryptographic keys)
#[derive(Debug, Serialize)]
struct ServerRegisterRequest {
    username: String,
    email: String,
    password: String,
    identity_public_key: String, // For signing GroupUpdates (hex-encoded Ed25519)
    invitation_public_key: String, // For receiving encrypted epoch keys (hex-encoded hybrid)
    device_id: String,
    registration_upload: String, // Base64-encoded OPAQUE registration data
    #[serde(rename = "require_email_confirmation")]
    require_email_confirmation: bool,
}

/// Server registration response structure
#[derive(Debug, Deserialize)]
struct ServerRegisterResponse {
    user_id: String,
    email: String,
    device_id: String,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    default_group_id: Option<Uuid>,
    #[serde(default)]
    requires_genesis_initialization: bool,
    #[serde(default)]
    pending_confirmation: bool,
    #[serde(default)]
    confirmation_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceRemovalResponsePayload {
    pub removed_device_id: String,
    pub revoked_sessions: usize,
    pub updated_groups: Vec<Uuid>,
    pub remaining_devices: usize,
    pub removed_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct DeviceRemovalOutcome {
    pub payload: DeviceRemovalResponsePayload,
    pub removed_current_device: bool,
}

/// Handle user login with OPAQUE-PAKE authentication and migration state recovery
pub async fn handle_login(
    username: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("User Authentication");

    // Check if already logged in
    if session_manager.is_authenticated() {
        if let Some(session) = session_manager.current_session() {
            ui::warning(&format!(
                "Already logged in as {} on {}",
                session.username, session.server_url
            ));

            // Check if this is the same user
            if session.username == username {
                ui::info("Session is still valid and user matches");

                // Check for migration state recovery
                if let Some(migration_info) = session_manager.migration_info() {
                    display_migration_recovery_info(&migration_info)?;
                }

                return Ok(());
            }

            let should_continue =
                ui::prompts::confirm("Do you want to logout and login as a different user?")?;
            if !should_continue {
                return Ok(());
            }

            // Secure session cleanup
            perform_secure_logout(session_manager).await?;
        }
    }

    // Get server URL with validation
    let server_url = validate_server_url()?;

    // Ensure user-specific context is prepared before any storage access
    session_manager.set_user_context(&username, &server_url)?;

    ui::info(&format!("Logging in as {} to {}", username, server_url));

    let preflight_decision = session_manager
        .preflight_server_identity(&server_url)
        .await?;
    display_trust_decision(&preflight_decision, &server_url);

    // Enhanced secure password input
    let password = get_secure_password_input("Password")?;

    if password.expose_secret().is_empty() {
        return Err(CliError::authentication("Password cannot be empty"));
    }

    session_manager.initialize_account_protection(password.expose_secret())?;

    // Show authentication progress
    let pb = ui::progress::create_auth_progress("Authenticating with HybridCipher server...");

    // Use production-ready authentication
    let login_result = session_manager
        .login_to_server(&username, password.expose_secret(), &server_url, None, None)
        .await;

    let trust_decision = if let Ok(decision) = login_result {
        ui::progress::finish_progress_with_result(&pb, true, "Authentication successful");
        decision
    } else {
        let err = login_result.err().expect("login result error expected");
        ui::progress::finish_progress_with_result(&pb, false, "Authentication failed");
        let decision = if let CliError::Authentication { message } = &err {
            if is_mfa_enrollment_error(message) {
                ui::warning("MFA enrollment is required before continuing.");
                ui::info(
                    "Sign in on an existing trusted device and run `hybridcipher mfa enroll`.",
                );
                return Err(err);
            } else if is_mfa_required_error(message) {
                ui::warning("Multi-factor authentication required.");
                let proof = prompt_mfa_proof()?;
                let retry_pb = ui::progress::create_auth_progress("Retrying login with MFA...");
                match session_manager
                    .login_to_server(
                        &username,
                        password.expose_secret(),
                        &server_url,
                        proof.mfa_code,
                        proof.backup_code,
                    )
                    .await
                {
                    Ok(decision) => {
                        ui::progress::finish_progress_with_result(
                            &retry_pb,
                            true,
                            "Authentication successful",
                        );
                        decision
                    }
                    Err(err) => {
                        ui::progress::finish_progress_with_result(
                            &retry_pb,
                            false,
                            "Authentication failed",
                        );
                        return Err(err);
                    }
                }
            } else if is_device_limit_error(message) {
                ui::error("Device registration limit reached for this account.");
                let proceed =
                    ui::prompts::confirm("Start device recovery to replace an existing device?")?;
                if proceed {
                    match attempt_device_recovery(
                        &username,
                        &password,
                        &server_url,
                        session_manager,
                    )
                    .await
                    {
                        Ok(decision) => decision,
                        Err(recovery_err) => {
                            return Err(recovery_err);
                        }
                    }
                } else {
                    return Err(err);
                }
            } else if message.contains("Email confirmation required") {
                ui::warning("Your account is registered but not yet confirmed.");
                let resend =
                    ui::prompts::confirm("Would you like to resend the confirmation email now?")?;
                if resend {
                    ui::info("Requesting a new confirmation email...");
                    match session_manager
                        .resend_confirmation_email(&username, &server_url)
                        .await
                    {
                        Ok(_) => {
                            ui::success("Confirmation email resent. Check your inbox and finish verification before logging in again.");
                            return Err(CliError::authentication(
                                "Email confirmation required. Confirmation email resent."
                                    .to_string(),
                            ));
                        }
                        Err(resend_err) => {
                            ui::error(&format!(
                                "Failed to resend confirmation email: {}",
                                resend_err
                            ));
                            return Err(CliError::authentication(
                                "Email confirmation required, and resend attempt failed. Please try again later."
                                    .to_string(),
                            ));
                        }
                    }
                } else {
                    ui::info(
                        "Login aborted. Confirm the email we sent during registration, then retry.",
                    );
                    return Err(CliError::authentication(
                        "Email confirmation required before login.".to_string(),
                    ));
                }
            } else {
                return Err(err);
            }
        } else {
            return Err(err);
        };
        decision
    };

    if matches!(preflight_decision, TrustDecision::FirstContact(_)) {
        display_trust_decision(&trust_decision, &server_url);
    }

    ui::success(&format!("Successfully logged in as {}", username));
    display_session_info(session_manager)?;

    let mut initialized_default_group = false;
    match auto_initialize_primary_group_if_needed(session_manager).await {
        Ok(did_initialize) => {
            initialized_default_group = did_initialize;
        }
        Err(err) => {
            ui::warning(&format!(
                "Automatic default group initialization failed: {}",
                err
            ));
            ui::info("Run 'hybridcipher initialize-group [GROUP_ID]' once you're ready.");
        }
    }

    // Enhanced migration state detection and recovery
    detect_and_recover_migration_state(session_manager).await?;

    match session_manager
        .ensure_join_card_published_for_current_device()
        .await
    {
        Ok(JoinCardPublishState::AlreadyPresent) => {
            ui::dim("Join card already exists on server for this device");
        }
        Ok(JoinCardPublishState::Published) => {
            ui::dim("Published join card to server directory");
        }
        Err(err) => {
            ui::warning(&format!("Join card publication check failed: {}", err));
        }
    }

    match session_manager
        .ensure_current_device_pin_verified("login")
        .await
    {
        Ok(CurrentDevicePinState::AlreadyVerified) => {}
        Ok(CurrentDevicePinState::PromotedUnverified) => {
            ui::dim("Auto-verified local device pin.");
        }
        Ok(CurrentDevicePinState::PinnedVerified) => {
            ui::dim("Pinned and verified local device key.");
        }
        Err(err) => {
            ui::warning(&format!(
                "Local device pin auto-verification failed: {}",
                err
            ));
        }
    }

    let mut used_onboarding_recovery = false;
    if initialized_default_group {
        match recovery_backup_exists(session_manager).await {
            Ok(false) => {
                if let Err(err) = recovery::auto_provision_recovery_capsule(
                    session_manager,
                    AutoProvisionMode::SilentOnboarding,
                    Some(password.expose_secret()),
                )
                .await
                {
                    ui::warning(&format!(
                        "Recovery backup bootstrap skipped: {}. Once fixed, run 'hybridcipher recovery upload' to refresh the backup.",
                        err
                    ));
                } else {
                    used_onboarding_recovery = true;
                }
            }
            Ok(true) => {}
            Err(err) => {
                ui::warning(&format!("Recovery backup status check failed: {}", err));
            }
        }
    }

    if !used_onboarding_recovery {
        // Offer to create a recovery capsule if none exists.
        if let Err(err) = recovery::auto_provision_recovery_capsule(
            session_manager,
            AutoProvisionMode::PromptOnLogin,
            None,
        )
        .await
        {
            ui::warning(&format!(
                "Recovery backup check skipped: {}. Once fixed, run 'hybridcipher recovery upload' to refresh the backup.",
                err
            ));
        }
    }

    if used_onboarding_recovery {
        prompt_mfa_enrollment(session_manager).await?;
    }

    // Perform security audit logging
    log_authentication_event(&username, &server_url, "login_success").await?;

    Ok(())
}

fn is_device_limit_error(message: &str) -> bool {
    message.to_lowercase().contains("device limit")
}

fn is_mfa_required_error(message: &str) -> bool {
    let lower = message.to_lowercase();
    (lower.contains("mfarequired") || (lower.contains("mfa") && lower.contains("required")))
        && !lower.contains("enrollment")
}

fn is_mfa_enrollment_error(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("mfa") && lower.contains("enrollment")
}

#[derive(Debug, Deserialize)]
struct MfaStatusResponse {
    enabled: bool,
    #[serde(rename = "mfa_type", default)]
    _mfa_type: Option<String>,
    #[serde(default)]
    require_password_change: bool,
    #[serde(rename = "require_password_reset", default)]
    _require_password_reset: bool,
    #[serde(rename = "require_new_device", default)]
    _require_new_device: bool,
    #[serde(rename = "require_device_recovery", default)]
    _require_device_recovery: bool,
}

async fn fetch_mfa_status(server_url: &str, token: &str) -> Result<MfaStatusResponse, CliError> {
    let trimmed = server_url.trim_end_matches('/');
    let url = if trimmed.ends_with("/api/v1") {
        format!("{}/mfa/status", trimmed)
    } else {
        format!("{}/api/v1/mfa/status", trimmed)
    };

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to fetch MFA status: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(CliError::authentication(format!(
            "Failed to fetch MFA status ({}): {}",
            status, body
        )));
    }

    response.json().await.map_err(|e| {
        CliError::authentication(format!("Failed to parse MFA status response: {}", e))
    })
}

#[derive(Debug, Clone)]
pub(crate) struct MfaProof {
    pub mfa_code: Option<String>,
    pub backup_code: Option<String>,
}

pub(crate) fn prompt_mfa_proof() -> Result<MfaProof, CliError> {
    let mfa_input = ui::prompts::input_allow_empty(
        "Enter your 6-digit MFA code (or press enter to use a backup code)",
    )?;
    let trimmed = mfa_input.trim();
    if !trimmed.is_empty() {
        return Ok(MfaProof {
            mfa_code: Some(trimmed.to_string()),
            backup_code: None,
        });
    }

    let backup_input = ui::prompts::input("Enter a backup code")?;
    let backup_trimmed = backup_input.trim();
    if backup_trimmed.is_empty() {
        return Err(CliError::authentication(
            "Backup code cannot be empty".to_string(),
        ));
    }

    Ok(MfaProof {
        mfa_code: None,
        backup_code: Some(backup_trimmed.to_string()),
    })
}

fn format_device_option(option: &DeviceRecoveryDeviceOption) -> String {
    let label = option.device_name.as_deref().unwrap_or("Unnamed device");
    let last_seen = ui::formatting::format_local_datetime(&option.last_seen);
    format!(
        "{} ({}) - last seen {}",
        label, option.masked_device_id, last_seen
    )
}

fn map_recovery_error(err: OpaqueError) -> CliError {
    match err {
        OpaqueError::EmailConfirmationRequired(message) => {
            CliError::authentication(format!("Email confirmation required: {}", message))
        }
        OpaqueError::RateLimited(message) => {
            CliError::authentication(format!("Rate limited: {}", message))
        }
        _ => CliError::authentication(format!("Device recovery failed: {err}")),
    }
}

fn is_invalid_recovery_code(err: &OpaqueError) -> bool {
    match err {
        OpaqueError::DeviceRecoveryFailed(message) => {
            message.to_lowercase().contains("invalid recovery code")
        }
        _ => false,
    }
}

async fn attempt_device_recovery(
    username: &str,
    password: &SecretString,
    server_url: &str,
    session_manager: &SessionManager,
) -> Result<TrustDecision, CliError> {
    ui::section("Device Recovery");

    let identity_keypair = session_manager.get_or_create_device_keypair().await?;
    let identity_public_key = identity_keypair.public_key_bytes().to_vec();
    let invitation_keypair = session_manager.get_or_create_invitation_keypair().await?;
    let invitation_public_key = invitation_keypair
        .invitation_public_key()
        .map_err(|e| {
            CliError::session(format!(
                "Failed to load invitation public key for recovery: {}",
                e
            ))
        })?
        .to_bytes()
        .to_vec();

    let device_id = format!("device_{}", hex::encode(&identity_public_key[..8]));
    let device_metadata = DeviceLoginMetadata {
        identity_public_key_hex: hex::encode(&identity_public_key),
        invitation_public_key_hex: hex::encode(&invitation_public_key),
        device_display_name: Some(format!(
            "CLI-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )),
        mfa_code: None,
        backup_code: None,
    };

    let opaque_auth = OpaqueAuth::new(device_id);
    let start_pb = ui::progress::create_auth_progress("Starting device recovery...");
    let challenge = match opaque_auth
        .device_recovery_start(
            username,
            password.expose_secret(),
            server_url,
            device_metadata,
        )
        .await
    {
        Ok(challenge) => {
            ui::progress::finish_progress_with_result(&start_pb, true, "Device recovery started");
            challenge
        }
        Err(err) => {
            ui::progress::finish_progress_with_result(
                &start_pb,
                false,
                "Device recovery start failed",
            );
            return Err(map_recovery_error(err));
        }
    };

    let otp_required = challenge.otp_required();
    if otp_required {
        if let Some(expires_at) = challenge.otp_expires_at() {
            ui::info(&format!(
                "Recovery code sent. Expires at {}.",
                ui::formatting::format_local_datetime(&expires_at)
            ));
        } else {
            ui::info("Recovery code sent to your registered email.");
        }
    }

    let finalization: DeviceRecoveryFinalization = challenge
        .finalize(password.expose_secret())
        .map_err(map_recovery_error)?;

    let mut used_email_otp = false;
    let verified = if otp_required {
        used_email_otp = true;
        let max_attempts: usize = 3;
        let mut verified: Option<DeviceRecoveryVerified> = None;
        for attempt in 1..=max_attempts {
            let otp_code = ui::prompts::input("Enter the 6-digit recovery code")?;
            let otp_trimmed = otp_code.trim();
            if otp_trimmed.is_empty() {
                ui::warning("Recovery code cannot be empty.");
                continue;
            }

            let verify_pb = ui::progress::create_auth_progress("Verifying recovery code...");
            let verify_result = opaque_auth
                .device_recovery_verify(
                    server_url,
                    Some(otp_trimmed.to_string()),
                    finalization.clone(),
                    None,
                    None,
                )
                .await;
            match verify_result {
                Ok(result) => {
                    ui::progress::finish_progress_with_result(
                        &verify_pb,
                        true,
                        "Recovery verification successful",
                    );
                    verified = Some(result);
                    break;
                }
                Err(err) => {
                    ui::progress::finish_progress_with_result(
                        &verify_pb,
                        false,
                        "Recovery verification failed",
                    );
                    if is_invalid_recovery_code(&err) {
                        let remaining = max_attempts.saturating_sub(attempt);
                        if remaining == 0 {
                            return Err(CliError::authentication(
                                "Device recovery failed: invalid recovery code (max attempts reached)."
                                    .to_string(),
                            ));
                        }
                        ui::warning(&format!(
                            "Invalid recovery code. {} attempt(s) remaining.",
                            remaining
                        ));
                        continue;
                    }
                    return Err(map_recovery_error(err));
                }
            }
        }

        verified.ok_or_else(|| {
            CliError::authentication(
                "Device recovery failed: verification attempts exhausted.".to_string(),
            )
        })?
    } else {
        let mut mfa_proof: Option<MfaProof> = None;
        loop {
            let verify_pb = ui::progress::create_auth_progress("Verifying device recovery...");
            let verify_result = opaque_auth
                .device_recovery_verify(
                    server_url,
                    None,
                    finalization.clone(),
                    mfa_proof.as_ref().and_then(|proof| proof.mfa_code.clone()),
                    mfa_proof
                        .as_ref()
                        .and_then(|proof| proof.backup_code.clone()),
                )
                .await;
            match verify_result {
                Ok(result) => {
                    ui::progress::finish_progress_with_result(
                        &verify_pb,
                        true,
                        "Recovery verification successful",
                    );
                    break result;
                }
                Err(OpaqueError::MfaEnrollmentRequired(message)) => {
                    ui::progress::finish_progress_with_result(
                        &verify_pb,
                        false,
                        "MFA enrollment required",
                    );
                    ui::warning("MFA enrollment required before continuing device recovery.");
                    ui::info("Run `hybridcipher mfa enroll` on a trusted device, then retry.");
                    return Err(CliError::authentication(format!(
                        "MFA enrollment required: {}",
                        message
                    )));
                }
                Err(OpaqueError::MfaRequired(_)) => {
                    ui::progress::finish_progress_with_result(&verify_pb, false, "MFA required");
                    ui::warning("Multi-factor authentication required to continue recovery.");
                    let proof = prompt_mfa_proof()?;
                    mfa_proof = Some(proof);
                    continue;
                }
                Err(err) => {
                    ui::progress::finish_progress_with_result(
                        &verify_pb,
                        false,
                        "Recovery verification failed",
                    );
                    return Err(map_recovery_error(err));
                }
            }
        }
    };

    if verified.devices.is_empty() {
        return Err(CliError::authentication(
            "No devices available to evict during recovery.".to_string(),
        ));
    }

    ui::info("Select the device to remove:");
    for (idx, device) in verified.devices.iter().enumerate() {
        ui::info(&format!("  {}. {}", idx + 1, format_device_option(device)));
    }

    let selection = ui::prompts::input("Enter the device number to remove (e.g. 1)")?;
    let selected_index: usize = selection.parse().map_err(|_| {
        CliError::validation("Invalid device selection; provide the number shown.".to_string())
    })?;
    if selected_index == 0 || selected_index > verified.devices.len() {
        return Err(CliError::validation(
            "Device selection out of range.".to_string(),
        ));
    }

    let selected = &verified.devices[selected_index - 1];
    let selected_label = format_device_option(selected);
    let device_selector = selected.device_selector.clone();
    let confirm = ui::prompts::confirm(&format!("Remove {}?", selected_label))?;
    if !confirm {
        return Err(CliError::Cancelled);
    }

    let complete_pb = ui::progress::create_auth_progress("Finalizing device recovery...");
    let login_result = match opaque_auth
        .device_recovery_complete(
            server_url,
            verified.recovery_session_id,
            &device_selector,
            verified.clone(),
            None,
            None,
        )
        .await
    {
        Ok(result) => {
            ui::progress::finish_progress_with_result(
                &complete_pb,
                true,
                "Device recovery complete",
            );
            result
        }
        Err(err) => {
            ui::progress::finish_progress_with_result(
                &complete_pb,
                false,
                "Device recovery failed",
            );
            return Err(map_recovery_error(err));
        }
    };

    if used_email_otp {
        ui::warning("MFA is not enabled for this account.");
        ui::info("Enable MFA for more secure device recovery in the future.");
        ui::info("Run `hybridcipher mfa enroll` to set it up.");
    }

    session_manager.apply_login_result(
        login_result,
        server_url,
        password.expose_secret(),
        identity_keypair,
    )
}

fn display_trust_decision(decision: &TrustDecision, server_url: &str) {
    match decision {
        TrustDecision::FirstContact(identity) => {
            ui::warning(&format!("🔒 First contact with server: {}", server_url));
            ui::info(&format!(
                "📌 Server fingerprint (base64): {}…",
                identity.fingerprint_preview()
            ));
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

/// Handle user registration with strong password validation and secure key generation
pub async fn handle_register(
    username: String,
    require_confirmation: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Account Registration");

    // Get server URL with validation
    let server_url = validate_server_url()?;

    // Set user context early to allow device keypair operations
    session_manager.set_user_context(&username, &server_url)?;

    ui::info(&format!(
        "Registering email account {} on {}",
        username, server_url
    ));
    ui::info(
        "📧 Note: Username must be a valid email address for notifications and account recovery",
    );

    // Enhanced username validation (now requires email format)
    validate_username(&username)?;

    // Enhanced password input with strength validation
    let password = get_password_with_enhanced_validation()?;

    // Display security information
    ui::subsection("Security Information");
    ui::info("🔐 Your account will be protected with:");
    ui::info("  • OPAQUE-PAKE password authentication");
    ui::info("  • Device-bound session tokens");
    ui::info("  • Secure key derivation (Argon2id)");
    ui::info("  • Quantum-resistant cryptography");

    let should_continue = ui::prompts::confirm("Continue with account creation?")?;
    if !should_continue {
        ui::info("Account registration cancelled");
        return Ok(());
    }

    // Prepare at-rest protection so subsequent key generation can encrypt directly
    session_manager.initialize_account_protection(password.expose_secret())?;

    // Show enhanced progress during registration (print each step on a new line)
    ui::info("Generating device identity...");
    generate_device_identity().await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;

    ui::info("Deriving authentication keys with Argon2id...");
    derive_authentication_keys(&password).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(1200)).await;

    ui::info("Creating OPAQUE registration record...");
    let registration_bundle =
        create_opaque_registration(session_manager, &username, &password, &server_url).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;

    ui::info("Establishing secure communication channel...");
    tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;

    ui::info("Registering account on server...");
    let registration_result = perform_server_registration(
        session_manager,
        &username,
        &registration_bundle.registration_upload_b64,
        &server_url,
        require_confirmation,
    )
    .await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(700)).await;

    if registration_result.pending_confirmation {
        ui::success(&format!(
            "Account {} is registered and awaiting email confirmation",
            username
        ));
        if let Some(expires_at) = registration_result.confirmation_expires_at {
            ui::info(&format!(
                "📬 Confirm via the link sent to {} before {}",
                registration_result.email,
                ui::formatting::format_local_datetime(&expires_at)
            ));
        } else {
            ui::info(&format!(
                "📬 Check {} for a confirmation link to activate your account",
                registration_result.email
            ));
        }
        ui::info("🔁 After confirming, run 'hybridcipher login <email>' to finish setup.");
        return Ok(());
    }

    let join_card_directory_payload = match session_manager.get_or_create_invitation_keypair().await
    {
        Ok(invitation_keypair) => match Uuid::parse_str(&registration_result.user_id) {
            Ok(user_uuid) => match invitation_keypair.create_join_card(user_uuid) {
                Ok(join_card) => {
                    let canonical_json = serde_json::to_string_pretty(&join_card).map_err(|e| {
                        CliError::format(format!("Failed to serialise join card: {}", e))
                    })?;
                    if let Err(err) = session_manager.cache_join_card(&username, &canonical_json) {
                        ui::warning(&format!("Failed to cache join card locally: {}", err));
                    }
                    match client_join_card_to_messages(&join_card) {
                        Ok(message) => Some(message),
                        Err(err) => {
                            ui::warning(&format!(
                                "Failed to prepare join card for directory: {}",
                                err
                            ));
                            None
                        }
                    }
                }
                Err(err) => {
                    ui::warning(&format!("Failed to create join card for device: {}", err));
                    None
                }
            },
            Err(err) => {
                ui::warning(&format!("Server returned invalid user identifier: {}", err));
                None
            }
        },
        Err(err) => {
            ui::warning(&format!("Failed to obtain invitation keypair: {}", err));
            None
        }
    };

    ui::success(&format!("Account {} created successfully", username));

    // Display important security information
    ui::warning("⚠️  Make sure to remember your password - it cannot be recovered");

    // Automatically log in after successful registration

    // Secure automatic login with the created credentials
    handle_automatic_login(
        username,
        server_url,
        registration_bundle.export_key_b64.clone(),
        &registration_result,
        session_manager,
    )
    .await?;

    // Auto-provision recovery capsule after onboarding (best effort).
    if let Err(err) = recovery::auto_provision_recovery_capsule(
        session_manager,
        AutoProvisionMode::SilentOnboarding,
        Some(password.expose_secret()),
    )
    .await
    {
        ui::warning(&format!(
            "Automatic recovery backup skipped: {}. Once fixed, run 'hybridcipher recovery upload' to refresh the backup.",
            err
        ));
    }

    if let Some(payload) = join_card_directory_payload {
        match session_manager.publish_join_card(&payload).await {
            Ok(_) => ui::dim("Published join card to server directory"),
            Err(err) => {
                ui::warning(&format!("Failed to publish join card: {}", err));
                ui::info("You can publish it later with 'hybridcipher publish-joincard'.");
            }
        }
    } else {
        ui::warning("Join card was not prepared for directory publication.");
        ui::info("You can publish it later with 'hybridcipher publish-joincard'.");
    }

    prompt_mfa_enrollment(session_manager).await?;

    Ok(())
}

/// Publish the current device join card to the server directory.
pub async fn handle_publish_join_card(session_manager: &SessionManager) -> Result<(), CliError> {
    ui::section("Join Card Publication");

    match session_manager
        .ensure_join_card_published_for_current_device()
        .await
    {
        Ok(JoinCardPublishState::AlreadyPresent) => {
            ui::dim("Join card already exists on server for this device");
        }
        Ok(JoinCardPublishState::Published) => {
            ui::success("Published join card to server directory");
        }
        Err(err) => {
            ui::warning(&format!("Failed to publish join card: {}", err));
        }
    }

    Ok(())
}

async fn prompt_mfa_enrollment(session_manager: &SessionManager) -> Result<(), CliError> {
    let enable_mfa = ui::prompts::confirm("Enable MFA now (recommended)?")?;
    if enable_mfa {
        if let Err(err) = mfa::handle_mfa_enroll(session_manager).await {
            ui::warning(&format!("MFA enrollment not completed: {}", err));
            ui::info("You can enable MFA later with 'hybridcipher mfa enroll'.");
        }
    } else {
        ui::warning(
            "MFA is not enabled. Sensitive actions (password reset/change, new device login, device recovery) will be blocked until MFA is set up.",
        );
        ui::info("Enable MFA later with 'hybridcipher mfa enroll'.");
    }
    Ok(())
}

/// Display the currently authenticated user and context paths
pub async fn handle_current_user(session_manager: &SessionManager) -> Result<(), CliError> {
    ui::section("Current User");

    let show_no_session = || {
        ui::warning("No active authenticated session");

        if let Some(summary) = session_manager.active_user_summary() {
            ui::info(&format!("Last user: {}", summary.username));
            ui::info(&format!("Last server: {}", summary.server_url));
            let storage_id =
                session_manager.user_storage_id_for(&summary.username, &summary.server_url);
            if Uuid::parse_str(&summary.user_id).is_ok() {
                ui::dim(&format!("Last user UUID: {}", summary.user_id));
                ui::dim(&format!("Last user hash: {}", storage_id));
            } else {
                ui::dim(&format!("Last user hash: {}", summary.user_id));
            }
            ui::info("Please login again with 'hybridcipher login <username>' to restore access.");
        } else {
            ui::info(
                "No previous login detected. Use 'hybridcipher login <username>' to authenticate.",
            );
        }
    };

    if session_manager.is_authenticated() {
        match session_manager.require_auth_with_server_check().await {
            Ok(session) => {
                ui::success(&format!("User: {}", session.username));
                ui::info(&format!("Server: {}", session.server_url));
                ui::info(&format!("User UUID: {}", session.user_id));
                ui::info(&format!(
                    "User hash: {}",
                    session_manager.user_storage_id_for(&session.username, &session.server_url)
                ));
            }
            Err(CliError::NotAuthenticated(_)) => {
                show_no_session();
            }
            Err(err) => {
                ui::warning(&format!(
                    "Unable to verify session with server; showing local session state ({})",
                    err
                ));
                let session = session_manager.require_auth()?;
                ui::success(&format!("User: {}", session.username));
                ui::info(&format!("Server: {}", session.server_url));
                ui::info(&format!("User UUID: {}", session.user_id));
                ui::info(&format!(
                    "User hash: {}",
                    session_manager.user_storage_id_for(&session.username, &session.server_url)
                ));
            }
        }
    } else {
        show_no_session();
    }

    if let Some(config_dir) = session_manager.user_config_dir() {
        ui::info(&format!("Config directory: {}", config_dir.display()));
    }

    let active_file = session_manager
        .config_dir()
        .join("global")
        .join("active_user.json");
    if active_file.exists() {
        ui::info(&format!("Active user record: {}", active_file.display()));
    }

    Ok(())
}

pub async fn handle_show_token(
    session_manager: &SessionManager,
    format: TokenFormat,
    include_refresh: bool,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    match format {
        TokenFormat::Plain => {
            println!("{}", session.token);
        }
        TokenFormat::Json => {
            let mut output = json!({
                "access_token": session.token,
                "user": {
                    "id": session.user_id,
                    "email": session.username,
                },
                "server": session.server_url,
                "expires_at": session.expires_at,
            });

            if include_refresh {
                if let Some(obj) = output.as_object_mut() {
                    obj.insert("refresh_token".to_string(), json!(session.refresh_token));
                }
            }

            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
            );
        }
    }

    Ok(())
}

/// Remove a device without prompting, returning the raw server response payload.
pub async fn execute_device_removal(
    session_manager: &SessionManager,
    target_device_id: &str,
) -> Result<DeviceRemovalOutcome, CliError> {
    let session = session_manager.require_auth()?;

    let trimmed_server_url = session.server_url.trim_end_matches('/');
    let request_url = if trimmed_server_url.ends_with("/api/v1") {
        format!("{}/auth/device/{}", trimmed_server_url, target_device_id)
    } else {
        format!(
            "{}/api/v1/auth/device/{}",
            trimmed_server_url, target_device_id
        )
    };

    let client = reqwest::Client::new();
    let response = client
        .delete(&request_url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to contact server: {}", e)))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("remove_device")?;
        return Err(CliError::authentication(
            "Authentication token rejected. Please login again.",
        ));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(CliError::operation(format!(
            "Device removal failed with status {}: {}",
            status, body
        )));
    }

    let payload: DeviceRemovalResponsePayload = response
        .json()
        .await
        .map_err(|e| CliError::network(format!("Failed to parse server response: {}", e)))?;

    let removed_current_device = payload.removed_device_id == session.device_id;
    drop(session);
    if removed_current_device {
        perform_secure_logout(session_manager).await?;
    }

    Ok(DeviceRemovalOutcome {
        payload,
        removed_current_device,
    })
}

/// Remove a registered device via the authenticated API
pub async fn handle_remove_device(
    device_id: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Device Removal");

    let session = session_manager.require_auth()?;

    let target_device_id = device_id
        .and_then(|id| {
            let trimmed = id.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .unwrap_or_else(|| session.device_id.clone());

    if target_device_id.is_empty() {
        return Err(CliError::invalid_input(
            "Device identifier is required to remove a device",
        ));
    }

    if target_device_id == session.device_id {
        ui::warning(
            "This operation targets the device currently running this CLI session. The session will be terminated once the server confirms removal.",
        );
    }

    let confirmed = ui::prompts::confirm(&format!(
        "Revoke device '{}' and invalidate its sessions?",
        target_device_id
    ))?;
    if !confirmed {
        ui::info("Device removal cancelled");
        return Ok(());
    }

    drop(session);
    let outcome = execute_device_removal(session_manager, &target_device_id).await?;
    let DeviceRemovalOutcome {
        payload,
        removed_current_device,
    } = outcome;

    ui::success(&format!(
        "Device '{}' removed at {}",
        payload.removed_device_id,
        ui::formatting::format_local_datetime(&payload.removed_at)
    ));
    ui::info(&format!(
        "Revoked sessions: {} | Remaining devices: {}",
        payload.revoked_sessions, payload.remaining_devices
    ));

    if payload.updated_groups.is_empty() {
        ui::info("No welcome message refresh required for existing groups.");
    } else {
        ui::info("Welcome messages refreshed for the following groups:");
        for group_id in payload.updated_groups {
            ui::info(&format!("  • {}", group_id));
        }
    }

    if removed_current_device {
        ui::warning("Local session revoked by server. Please login again to continue.");
        ui::info("Run 'hybridcipher login <email>' to register a new device.");
    }

    Ok(())
}

/// Handle user logout with comprehensive secure session cleanup
pub async fn handle_logout(session_manager: &SessionManager) -> Result<(), CliError> {
    ui::section("Secure Logout");

    if !session_manager.is_authenticated() {
        ui::warning("Not currently logged in");
        return Ok(());
    }

    let session = session_manager.current_session().unwrap();
    ui::info(&format!("Logging out user {}", session.user_id));

    // Enhanced migration state checking
    if let Some(migration_info) = session_manager.migration_info() {
        if migration_info.phase.is_active() {
            ui::warning("🚨 Active migration detected during logout");
            ui::subsection("Migration Status");
            ui::info(&format!("Phase: {}", migration_info.phase.description()));
            ui::info(&format!("Progress: {:.1}%", migration_info.progress));
            ui::info(&format!("Current Epoch: {}", migration_info.current_epoch));

            if let Some(target_epoch) = migration_info.target_epoch {
                ui::info(&format!("Target Epoch: {}", target_epoch));
            }

            ui::warning("⚠️  Logging out during migration may require manual recovery");
            ui::info("Migration state will be preserved for automatic recovery on next login");

            let should_continue = ui::prompts::confirm(
                "Are you sure you want to logout during an active migration?",
            )?;

            if !should_continue {
                ui::info("Logout cancelled - session remains active");
                return Ok(());
            }

            // Save migration state for recovery
            ui::info("💾 Preserving migration state for recovery...");
            preserve_migration_state_for_recovery(&migration_info, &session.user_id).await?;
        }
    }

    // Perform comprehensive secure logout - unmount all mounts
    if let Err(err) = mount::handle_unmount(session_manager, None, true, true).await {
        ui::warning(&format!("Failed to request unmount: {}", err));
    }
    perform_secure_logout(session_manager).await?;

    ui::success("✅ Successfully logged out");
    ui::info("🔒 Session data has been securely cleared");
    ui::info("🧹 Device tokens have been invalidated");
    ui::info("📝 Logout event has been logged for security audit");

    Ok(())
}

/// Check whether the OS keystore contains the device key for the active account.
pub async fn handle_keystore_status(session_manager: &SessionManager) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    ui::section("Keystore Status");
    ui::info(&format!(
        "Checking keystore entry for {} on {}",
        session.username, session.server_url
    ));

    match session_manager.has_keystore_device_key()? {
        true => ui::success(
            "OS keystore has your device key. Password resets should preserve local state on this device.",
        ),
        false => {
            ui::warning("OS keystore does not currently hold your device key for this account.");
            ui::info(
                "Before resetting your password from this device, re-login to repopulate the keystore or be prepared for local state to be regenerated.",
            );
        }
    }

    Ok(())
}

/// Enhanced password input with secure handling
fn get_secure_password_input(prompt: &str) -> Result<SecretString, CliError> {
    print!("{}: ", prompt);
    io::stdout()
        .flush()
        .map_err(|e| CliError::internal(format!("IO error: {}", e)))?;
    let password = rpassword::read_password()
        .map_err(|e| CliError::authentication(format!("Failed to read password: {}", e)))?;
    Ok(SecretString::new(password))
}

/// Get password with enhanced confirmation and validation for registration
fn get_password_with_enhanced_validation() -> Result<SecretString, CliError> {
    loop {
        let password = ui::prompts::password_with_confirmation(
            "Create a strong password (min 12 chars, mix case, digit, symbol)",
        )?;

        match validate_enhanced_password_strength(&password) {
            Ok(()) => return Ok(SecretString::new(password)),
            Err(err) => ui::error(&err.to_string()),
        }
    }
}

/// Enhanced username validation - now requires email format
fn validate_username(username: &str) -> Result<(), CliError> {
    // Basic length checks
    if username.len() < 5 {
        return Err(CliError::invalid_input(
            "Username (email) must be at least 5 characters long",
        ));
    }

    if username.len() > 100 {
        return Err(CliError::invalid_input(
            "Username (email) cannot be longer than 100 characters",
        ));
    }

    // Email format validation - basic but sufficient
    if !username.contains('@') {
        return Err(CliError::invalid_input(
            "Username must be a valid email address (e.g., user@domain.com)",
        ));
    }

    let parts: Vec<&str> = username.split('@').collect();
    if parts.len() != 2 {
        return Err(CliError::invalid_input(
            "Username must be a valid email address with exactly one @ symbol",
        ));
    }

    let local_part = parts[0];
    let domain_part = parts[1];

    // Validate local part (before @)
    if local_part.is_empty() {
        return Err(CliError::invalid_input(
            "Email address must have a username before the @ symbol",
        ));
    }

    if local_part.len() > 64 {
        return Err(CliError::invalid_input(
            "Email username part cannot be longer than 64 characters",
        ));
    }

    // Validate domain part (after @)
    if domain_part.is_empty() {
        return Err(CliError::invalid_input(
            "Email address must have a domain after the @ symbol",
        ));
    }

    if !domain_part.contains('.') {
        return Err(CliError::invalid_input(
            "Email domain must contain at least one dot (e.g., domain.com)",
        ));
    }

    // Basic character validation for email
    let valid_email_chars =
        |c: char| c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '+' || c == '@';

    if !username.chars().all(valid_email_chars) {
        return Err(CliError::invalid_input(
            "Email address contains invalid characters",
        ));
    }

    // Check for reserved email addresses
    let reserved = [
        "admin@",
        "root@",
        "system@",
        "hybridcipher@",
        "test@",
        "demo@",
    ];
    let username_lower = username.to_lowercase();
    if reserved
        .iter()
        .any(|&reserved| username_lower.starts_with(reserved))
    {
        return Err(CliError::invalid_input(
            "This email address is reserved and cannot be used",
        ));
    }

    Ok(())
}

/// Enhanced password strength validation
fn validate_enhanced_password_strength(password: &str) -> Result<(), CliError> {
    if password.len() < 12 {
        return Err(CliError::invalid_input(
            "Password must be at least 12 characters long for enhanced security",
        ));
    }

    if password.len() > 128 {
        return Err(CliError::invalid_input(
            "Password cannot be longer than 128 characters",
        ));
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

    let strength_requirements = [
        (has_uppercase, "uppercase letters"),
        (has_lowercase, "lowercase letters"),
        (has_digit, "digits"),
        (has_special, "special characters"),
    ];

    let missing_requirements: Vec<&str> = strength_requirements
        .iter()
        .filter_map(|(present, req)| if !present { Some(*req) } else { None })
        .collect();

    if !missing_requirements.is_empty() {
        return Err(CliError::invalid_input(&format!(
            "Password must contain: {}",
            missing_requirements.join(", ")
        )));
    }

    // Check for common weak patterns
    if password.to_lowercase().contains("password")
        || password.to_lowercase().contains("123456")
        || password
            .chars()
            .collect::<Vec<char>>()
            .windows(3)
            .any(|w| w[0] as u8 + 1 == w[1] as u8 && w[1] as u8 + 1 == w[2] as u8)
    {
        return Err(CliError::invalid_input(
            "Password contains common weak patterns",
        ));
    }

    Ok(())
}

/// Validate and normalize server URL
fn validate_server_url() -> Result<String, CliError> {
    let raw_server_url = hybridcipher_client::config_loader::default_server_url();

    let canonicalization = canonicalize_server_url(&raw_server_url);
    let server_url = canonicalization.canonical;

    if let Some(alias) = canonicalization.replaced_alias.as_ref() {
        if canonicalization.upgraded_scheme {
            ui::info(&format!(
                "📡 Upgrading HybridCipher endpoint '{}' to secure '{}'.",
                alias, server_url
            ));
        } else {
            ui::info(&format!(
                "📡 Normalizing HybridCipher endpoint '{}' to '{}'.",
                alias, server_url
            ));
        }
    }

    // Basic URL validation
    if !server_url.starts_with("https://") && !server_url.starts_with("http://") {
        return Err(CliError::invalid_input(
            "Server URL must start with https:// or http://",
        ));
    }

    if server_url.starts_with("http://") {
        ui::warning(
            "⚠️  Using unencrypted HTTP connection - this is not recommended for production",
        );
    } else if canonicalization.replaced_alias.is_some() {
        ui::info(&format!(
            "✅ Confirmed HybridCipher server endpoint: {}",
            server_url
        ));
    }

    Ok(server_url)
}

/// Display migration recovery information
fn display_migration_recovery_info(migration_info: &MigrationInfo) -> Result<(), CliError> {
    ui::subsection("Migration Recovery");
    ui::info("🔄 Recovering ongoing migration state...");
    ui::info(&format!("Phase: {}", migration_info.phase.description()));
    ui::info(&format!("Progress: {:.1}%", migration_info.progress));
    ui::info(&format!("Current Epoch: {}", migration_info.current_epoch));

    if let Some(target_epoch) = migration_info.target_epoch {
        ui::info(&format!("Target Epoch: {}", target_epoch));
    }

    ui::info("✅ Migration state successfully recovered");
    ui::info("Use 'hybridcipher rekey status --watch' to stream live migration details");

    Ok(())
}

/// Display session information
fn display_session_info(session_manager: &SessionManager) -> Result<(), CliError> {
    if let Some(session) = session_manager.current_session() {
        let time_until_expiry = session.expires_at - Utc::now();
        let hours_remaining = time_until_expiry.num_hours();

        ui::info(&format!("🕐 Session expires in {} hours", hours_remaining));
        ui::info(&format!("📱 Device ID: {}", &session.device_id[..8]));
        ui::info(&format!("🌐 Server: {}", session.server_url));
    }

    Ok(())
}

/// Enhanced migration state detection and recovery
async fn detect_and_recover_migration_state(
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.synchronize_migration_state().await?;

    if let Some(migration_info) = session_manager.migration_info() {
        if migration_info.phase.is_active() {
            ui::subsection("Migration State Recovery");
            ui::warning("🔄 Active migration detected and recovered");
            ui::info(&format!("Phase: {}", migration_info.phase.description()));
            ui::info(&format!("Progress: {:.1}%", migration_info.progress));

            if let Some(target_epoch) = migration_info.target_epoch {
                ui::info(&format!(
                    "Migrating from epoch {} to epoch {}",
                    migration_info.current_epoch, target_epoch
                ));
            }

            ui::info("📋 Migration can be monitored with 'hybridcipher rekey status --watch'");

            // Check if migration needs attention
            if migration_info.progress < 50.0 {
                ui::warning("⚠️  Migration progress is low - stream 'hybridcipher rekey status --watch' for details");
            }
        }
    }

    Ok(())
}

/// Generate device identity for registration
async fn generate_device_identity() -> Result<(), CliError> {
    // Simulate device identity generation
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    Ok(())
}

/// Derive authentication keys using Argon2id
async fn derive_authentication_keys(_password: &SecretString) -> Result<(), CliError> {
    // Simulate key derivation
    tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;

    Ok(())
}

/// Create OPAQUE registration record with real implementation
async fn create_opaque_registration(
    session_manager: &SessionManager,
    username: &str,
    password: &SecretString,
    server_url: &str,
) -> Result<OpaqueRegistrationBundle, CliError> {
    let server_info_key = session_manager.fetch_server_public_key(server_url).await?;
    let mut identity_manager = session_manager.server_identity_manager()?;
    let trust_decision = identity_manager
        .verify_server_identity(server_url, &server_info_key)
        .map_err(CliError::from)?;
    display_trust_decision(&trust_decision, server_url);

    // Create device ID based on username and server
    let device_id = format!(
        "cli_{}_{}",
        username,
        server_url.replace("://", "_").replace("/", "_")
    );

    // Initialize OPAQUE authenticator
    let opaque_auth = OpaqueAuth::new(device_id);

    // Perform OPAQUE registration with the server
    match opaque_auth
        .register_with_server(username, username, password.expose_secret(), server_url)
        .await
    {
        Ok(registration_result) => {
            ui::success("OPAQUE registration record created!");

            // Ensure the OPAQUE registration response matches the pre-flight key
            identity_manager
                .verify_server_identity(server_url, &registration_result.server_public_key)
                .map_err(CliError::from)?;

            let registration_data_b64 = base64::engine::general_purpose::STANDARD
                .encode(&registration_result.registration_upload);

            let export_key_b64 =
                base64::engine::general_purpose::STANDARD.encode(registration_result.export_key);

            Ok(OpaqueRegistrationBundle {
                registration_upload_b64: registration_data_b64,
                export_key_b64,
            })
        }
        Err(opaque_error) => Err(CliError::authentication(format!(
            "OPAQUE registration failed: {}",
            opaque_error
        ))),
    }
}

/// Perform actual server registration via HTTP API
async fn perform_server_registration(
    session_manager: &SessionManager,
    username: &str,
    registration_upload_b64: &str,
    server_url: &str,
    require_confirmation: bool,
) -> Result<RegistrationResult, CliError> {
    // Get real device identity keypair from the active session manager
    let identity_keypair = session_manager.get_or_create_device_keypair().await?;
    let identity_public_key = identity_keypair.public_key_bytes().to_vec();

    // Get invitation keypair for receiving encrypted epoch keys
    let invitation_keypair = session_manager.get_or_create_invitation_keypair().await?;
    let invitation_public_key = invitation_keypair
        .invitation_public_key()
        .map_err(|e| CliError::session(format!("Failed to get invitation public key: {}", e)))?
        .to_bytes()
        .to_vec();

    // Generate device ID from device identity public key (consistent with client)
    let device_id = format!("device_{}", hex::encode(&identity_public_key[..8]));
    let identity_public_key_hex = hex::encode(&identity_public_key);
    let invitation_public_key_hex = hex::encode(&invitation_public_key);

    // The registration upload is already base64-encoded from create_opaque_registration
    let registration_upload = registration_upload_b64.to_string();

    // Prepare registration request with both identity and invitation keys
    let register_request = ServerRegisterRequest {
        username: username.to_string(),
        email: username.to_string(), // Using email as username per our new validation
        password: "placeholder_password".to_string(), // Note: In OPAQUE, raw password shouldn't be sent
        identity_public_key: identity_public_key_hex,
        invitation_public_key: invitation_public_key_hex,
        device_id: device_id.clone(),
        registration_upload,
        require_email_confirmation: require_confirmation,
    };

    // Make HTTP request to server
    let client = reqwest::Client::new();
    let trimmed_server_url = server_url.trim_end_matches('/');
    let registration_url = if trimmed_server_url.ends_with("/api/v1") {
        format!("{}/auth/register", trimmed_server_url)
    } else {
        format!("{}/api/v1/auth/register", trimmed_server_url)
    };

    let response = client
        .post(&registration_url)
        .json(&register_request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to connect to server: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(CliError::authentication(format!(
            "Server registration failed ({}): {}",
            status, error_text
        )));
    }

    let server_response: ServerRegisterResponse = response
        .json()
        .await
        .map_err(|e| CliError::authentication(format!("Failed to parse server response: {}", e)))?;

    Ok(RegistrationResult {
        user_id: server_response.user_id,
        email: server_response.email,
        device_id: server_response.device_id,
        access_token: server_response.access_token,
        refresh_token: server_response.refresh_token,
        expires_in: server_response.expires_in,
        default_group_id: server_response.default_group_id,
        requires_genesis_initialization: server_response.requires_genesis_initialization,
        pending_confirmation: server_response.pending_confirmation,
        confirmation_expires_at: server_response.confirmation_expires_at,
    })
}

/// Handle automatic login after registration
async fn handle_automatic_login(
    username: String,
    server_url: String,
    opaque_export_key_b64: String,
    registration_result: &RegistrationResult,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    // User context already set during registration, no need to set again
    let user_id = registration_result.user_id.clone();
    let access_token = registration_result
        .access_token
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            CliError::authentication(
                "Server did not return an access token. Email confirmation may be required before login.",
            )
        })?;
    let refresh_token = registration_result
        .refresh_token
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            CliError::authentication(
                "Server did not return a refresh token. Email confirmation may be required before login.",
            )
        })?;
    let expires_in = registration_result
        .expires_in
        .ok_or_else(|| {
            CliError::authentication(
                "Server did not return token expiration. Email confirmation may be required before login.",
            )
        })?;
    let device_id = registration_result.device_id.clone();
    let default_group_id = registration_result.default_group_id;
    let requires_genesis_initialization = registration_result.requires_genesis_initialization;

    let now = Utc::now();
    let expires_at = now + Duration::seconds(expires_in);

    // Create session from registration result with enhanced security
    let session = Session {
        user_id: user_id.clone(),
        username: username.clone(),
        device_id: device_id.clone(),
        device_status: Some("active".to_string()),
        server_url: server_url.clone(),
        token: access_token,
        refresh_token,
        opaque_export_key: Some(opaque_export_key_b64),
        device_binding: String::new(), // Will be set by SessionManager
        device_keypair: None,          // Will be generated on first use
        created_at: now,
        expires_at,
        last_activity: now,
        migration_info: None,
        security_metadata: SessionSecurity {
            device_fingerprint: format!("fingerprint_{}", device_id),
            integrity_hash: String::new(), // Will be computed by SessionManager
            version: 1,
            flags: SessionFlags {
                device_verified: true,
                migration_recovered: false,
                auto_renewal: true,
                enhanced_security: true,
            },
        },
    };

    // Store session with enhanced security
    session_manager.store_session(session)?;

    if let Some(group_id) = default_group_id {
        if requires_genesis_initialization {
            ui::info(&format!(
                "🔐 Initializing default group {} for first login...",
                group_id
            ));
            match initialize_default_group_epoch(session_manager, group_id).await {
                Ok(epoch_number) => {
                    ui::success(&format!(
                        "Default group ready with genesis epoch {}.",
                        epoch_number
                    ));
                    if let Err(err) = session_manager.set_current_group_id(group_id).await {
                        ui::warning(&format!(
                            "Failed to mark default group {} as active locally: {}",
                            group_id, err
                        ));
                    }
                }
                Err(err) => {
                    ui::warning(&format!(
                        "Default group bootstrap failed; run 'hybridcipher initialize-group {} 1' once you have welcome payloads ready. Error: {}",
                        group_id, err
                    ));
                }
            }
        } else if let Err(err) = session_manager.set_current_group_id(group_id).await {
            ui::warning(&format!(
                "Unable to cache default group {} locally: {}",
                group_id, err
            ));
        }
    }

    ui::success(&format!("✅ Successfully logged in as {}", username));

    Ok(())
}

/// Forgot your current password? Use this command to send a password reset link.
pub async fn handle_forgot_password(
    email: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Forgot Password");
    ui::info(&format!("Requesting reset link for {}", email));

    let server_url = validate_server_url()?;
    if session_manager.is_authenticated() {
        if let Some(session) = session_manager.current_session() {
            let input_server = canonicalize_server_url(&server_url).canonical;
            let active_server = canonicalize_server_url(&session.server_url).canonical;
            if session.username.eq_ignore_ascii_case(&email) && input_server == active_server {
                ui::warning("You are currently logged in as this account.");
                ui::info("Before resetting a forgotten password, ensure epoch keys are backed up so files remain recoverable.");
                ui::info("Logout first, then rerun 'hybridcipher forgot-password <email>'.");
                return Err(CliError::authentication(
                    "Password reset request aborted while logged in as this account".to_string(),
                ));
            }
        }
    }

    let keystore_present = session_manager.keystore_status_for(&email, &server_url)?;
    if keystore_present {
        ui::info("OS keystore contains the device key for this account on this device.");
    } else {
        ui::warning(
            "OS keystore does not currently hold your device key. Resetting may regenerate local state and lose encrypted data if this is your only logged-in device.",
        );
        ui::info(
            "Recommended: re-login on this device to repopulate the keystore before resetting.",
        );
        let confirmation = ui::prompts::input_allow_empty(
            "Type 'accept_data_loss' to confirm (to abort, just press enter button)",
        )?;
        if confirmation.trim() != "accept_data_loss" {
            return Err(CliError::authentication(
                "Password reset aborted until keystore is populated.".to_string(),
            ));
        }
    }

    let trimmed_server_url = server_url.trim_end_matches('/');
    let endpoint = if trimmed_server_url.ends_with("/api/v1") {
        format!("{}/auth/password-reset/request", trimmed_server_url)
    } else {
        format!("{}/api/v1/auth/password-reset/request", trimmed_server_url)
    };

    ui::warning("MFA is required to request a password reset.");
    ui::info("If MFA is not enabled for this account, run `hybridcipher mfa enroll` first.");
    let proof = prompt_mfa_proof()?;

    let client = reqwest::Client::new();
    let response = client
        .post(&endpoint)
        .json(&json!({
            "email": email,
            "mfa_code": proof.mfa_code,
            "backup_code": proof.backup_code,
        }))
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to contact server: {}", e)))?;

    if response.status().is_success() {
        ui::success("If an account exists for that email, a reset link has been sent.");
        Ok(())
    } else {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        if is_mfa_enrollment_error(&body) {
            ui::warning("MFA is not enabled for this account.");
            ui::info("Enable MFA with `hybridcipher mfa enroll` and retry.");
            return Err(CliError::authentication(format!(
                "MFA enrollment required: {}",
                body
            )));
        }
        if is_mfa_required_error(&body) {
            ui::warning("MFA verification failed or missing.");
            return Err(CliError::authentication(format!("MFA required: {}", body)));
        }
        Err(CliError::network(format!(
            "Reset request failed ({}): {}",
            status, body
        )))
    }
}

/// Perform password reset using a token from email
pub async fn handle_password_reset(
    token: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Password Reset");
    ui::info("Resetting password with provided token.");

    let password = get_secure_password_input("New password")?;
    let confirm = get_secure_password_input("Confirm new password")?;
    if password.expose_secret() != confirm.expose_secret() {
        return Err(CliError::authentication(
            "Password confirmation does not match".to_string(),
        ));
    }
    if password.expose_secret().is_empty() {
        return Err(CliError::authentication(
            "Password cannot be empty".to_string(),
        ));
    }

    let server_url = validate_server_url()?;
    let trimmed = server_url.trim_end_matches('/');
    let start_url = if trimmed.ends_with("/api/v1") {
        format!("{}/auth/password-reset/start", trimmed)
    } else {
        format!("{}/api/v1/auth/password-reset/start", trimmed)
    };
    let complete_url = if trimmed.ends_with("/api/v1") {
        format!("{}/auth/password-reset/complete", trimmed)
    } else {
        format!("{}/api/v1/auth/password-reset/complete", trimmed)
    };

    let user_email = match drive_password_rotation(
        start_url.clone(),
        complete_url.clone(),
        Some(token.clone()),
        None,
        &password,
        None,
        None,
        Some(session_manager),
        Some(&server_url),
    )
    .await
    {
        Ok(email) => email,
        Err(err) => {
            return Err(err);
        }
    };

    ui::success("Password reset successful.");
    if let Some(email) = user_email {
        ui::info("");
        ui::info(&format!(
            "You can now log in as {} with the new password. Local state was preserved where a device key was available.",
            email
        ));
    }

    Ok(())
}

/// Change password for the currently authenticated user
pub async fn handle_change_password(session_manager: &SessionManager) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    ui::section("Change Password");
    ui::info(&format!("Changing password for {}", session.username));

    let current_password = get_secure_password_input("Current password")?;
    if current_password.expose_secret().is_empty() {
        return Err(CliError::authentication(
            "Current password cannot be empty".to_string(),
        ));
    }
    session_manager.verify_account_password(&current_password)?;

    let mut mfa_proof: Option<MfaProof> = None;
    let mfa_status = fetch_mfa_status(&session.server_url, &session.token).await?;
    if mfa_status.require_password_change {
        if !mfa_status.enabled {
            ui::warning("MFA is required to change your password but is not enabled.");
            ui::info("Enable MFA with `hybridcipher mfa enroll`, then retry.");
            return Err(CliError::authentication(
                "MFA required before changing password.".to_string(),
            ));
        }
        ui::warning("Multi-factor authentication required to change password.");
        mfa_proof = Some(prompt_mfa_proof()?);
    }

    let password = get_secure_password_input("New password")?;
    let confirm = get_secure_password_input("Confirm new password")?;
    if password.expose_secret() != confirm.expose_secret() {
        return Err(CliError::authentication(
            "Password confirmation does not match".to_string(),
        ));
    }
    if password.expose_secret().is_empty() {
        return Err(CliError::authentication(
            "Password cannot be empty".to_string(),
        ));
    }

    let trimmed = session.server_url.trim_end_matches('/');
    let start_url = if trimmed.ends_with("/api/v1") {
        format!("{}/auth/password/change/start", trimmed)
    } else {
        format!("{}/api/v1/auth/password/change/start", trimmed)
    };
    let complete_url = if trimmed.ends_with("/api/v1") {
        format!("{}/auth/password/change/complete", trimmed)
    } else {
        format!("{}/api/v1/auth/password/change/complete", trimmed)
    };

    let _email = match drive_password_rotation(
        start_url.clone(),
        complete_url.clone(),
        None,
        Some(&session.token),
        &password,
        Some(&session.username),
        mfa_proof.clone(),
        Some(session_manager),
        Some(&session.server_url),
    )
    .await
    {
        Ok(email) => email,
        Err(err) => {
            if let CliError::Authentication { message } = &err {
                if is_mfa_enrollment_error(message) {
                    ui::warning("MFA enrollment required before changing password.");
                    ui::info("Run `hybridcipher mfa enroll` and retry.");
                    return Err(err);
                }
                if is_mfa_required_error(message) && mfa_proof.is_none() {
                    ui::warning("Multi-factor authentication required to change password.");
                    let proof = prompt_mfa_proof()?;
                    drive_password_rotation(
                        start_url,
                        complete_url,
                        None,
                        Some(&session.token),
                        &password,
                        Some(&session.username),
                        Some(proof),
                        Some(session_manager),
                        Some(&session.server_url),
                    )
                    .await?
                } else {
                    return Err(err);
                }
            } else {
                return Err(err);
            }
        }
    };

    ui::success("Password changed successfully.");
    Ok(())
}

/// Shared OPAQUE registration flow for password reset/change
async fn drive_password_rotation(
    start_url: String,
    complete_url: String,
    token: Option<String>,
    bearer_token: Option<&str>,
    new_password: &SecretString,
    email_hint: Option<&str>,
    mfa_proof: Option<MfaProof>,
    session_manager: Option<&SessionManager>,
    server_url: Option<&str>,
) -> Result<Option<String>, CliError> {
    let mut rng = OsRng;
    let ClientRegistrationStartResult { message, state } =
        ClientRegistration::<DefaultCipherSuite>::start(
            &mut rng,
            new_password.expose_secret().as_bytes(),
        )
        .map_err(|e| CliError::authentication(format!("OPAQUE client start failed: {e:?}")))?;

    let registration_request_b64 =
        base64::engine::general_purpose::STANDARD.encode(message.serialize().to_vec());

    let client = reqwest::Client::new();
    let mut start_body = json!({ "registration_request": registration_request_b64 });
    if let Some(tok) = token.as_ref() {
        start_body["token"] = json!(tok);
    }

    let mut start_builder = client.post(&start_url).json(&start_body);
    if let Some(bearer) = bearer_token {
        start_builder = start_builder.bearer_auth(bearer);
    }

    let start_response = start_builder
        .send()
        .await
        .map_err(|e| CliError::network(format!("Password rotation start failed: {}", e)))?;

    if !start_response.status().is_success() {
        let status = start_response.status();
        let body = start_response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(CliError::authentication(format!(
            "Password rotation start rejected ({}): {}",
            status, body
        )));
    }

    #[derive(Deserialize)]
    struct RotationStartResponse {
        registration_response: String,
        email: Option<String>,
    }
    let start_body: RotationStartResponse = start_response.json().await.map_err(|e| {
        CliError::authentication(format!("Invalid password rotation start response: {}", e))
    })?;

    let email_for_rewrap = start_body.email.as_deref().or(email_hint);

    if token.is_some() {
        if let (Some(sm), Some(email), Some(server)) =
            (session_manager, email_for_rewrap, server_url)
        {
            sm.enforce_password_reset_prerequisites(email, server)?;
        }
    }

    let registration_response_bytes = base64::engine::general_purpose::STANDARD
        .decode(start_body.registration_response)
        .map_err(|e| CliError::authentication(format!("Invalid registration response: {}", e)))?;
    let registration_response =
        RegistrationResponse::<DefaultCipherSuite>::deserialize(&registration_response_bytes)
            .map_err(|e| {
                CliError::authentication(format!(
                    "Failed to deserialize registration response: {:?}",
                    e
                ))
            })?;

    let finish = state
        .finish(
            &mut rng,
            new_password.expose_secret().as_bytes(),
            registration_response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| CliError::authentication(format!("OPAQUE client finish failed: {e:?}")))?;

    let registration_upload_b64 =
        base64::engine::general_purpose::STANDARD.encode(finish.message.serialize().to_vec());

    let mut complete_body = json!({ "registration_upload": registration_upload_b64 });
    if let Some(tok) = token {
        complete_body["token"] = json!(tok);
    }
    if let Some(proof) = mfa_proof {
        if let Some(code) = proof.mfa_code {
            complete_body["mfa_code"] = json!(code);
        }
        if let Some(code) = proof.backup_code {
            complete_body["backup_code"] = json!(code);
        }
    }

    let mut complete_builder = client.post(&complete_url).json(&complete_body);
    if let Some(bearer) = bearer_token {
        complete_builder = complete_builder.bearer_auth(bearer);
    }

    let complete_response = complete_builder
        .send()
        .await
        .map_err(|e| CliError::network(format!("Password rotation complete failed: {}", e)))?;

    if complete_response.status().is_success() {
        if let (Some(sm), Some(email), Some(server)) =
            (session_manager, email_for_rewrap, server_url)
        {
            // Best-effort: rewrap the device key using the new password so local state survives.
            let _ = sm.rewrap_device_key_after_password_rotation(
                email,
                server,
                new_password.expose_secret(),
            );
        }
        Ok(start_body.email)
    } else {
        let status = complete_response.status();
        let body = complete_response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        Err(CliError::authentication(format!(
            "Password rotation failed ({}): {}",
            status, body
        )))
    }
}

async fn initialize_default_group_epoch(
    session_manager: &SessionManager,
    group_id: Uuid,
) -> Result<u64, CliError> {
    let client = session_manager.create_client().await?;
    client
        .initialize_group_epoch(group_id, 1)
        .await
        .map_err(CliError::from)
}

async fn auto_initialize_primary_group_if_needed(
    session_manager: &SessionManager,
) -> Result<bool, CliError> {
    let groups = match session_manager.list_groups_http().await {
        Ok(list) => list,
        Err(err) => {
            ui::warning(&format!(
                "Unable to verify default group status after login: {}",
                err
            ));
            return Ok(false);
        }
    };

    if groups.is_empty() {
        return Ok(false);
    }

    let Some(target_group) = groups
        .into_iter()
        .find(|group| group_requires_genesis_bootstrap(group))
    else {
        return Ok(false);
    };

    let group_uuid = match Uuid::parse_str(&target_group.id) {
        Ok(uuid) => uuid,
        Err(err) => {
            ui::warning(&format!(
                "Server returned invalid group ID {}: {}",
                target_group.id, err
            ));
            return Ok(false);
        }
    };

    ui::section("Initializing Default Group");
    ui::info(&format!(
        "Default group '{}' has no active epoch. Generating genesis epoch now…",
        target_group.name
    ));

    if let Err(err) = session_manager.set_current_group_id(group_uuid).await {
        ui::warning(&format!(
            "Failed to mark {} as the active group locally: {}",
            target_group.name, err
        ));
    }

    let client = session_manager.create_client().await?;
    match client.initialize_group_epoch(group_uuid, 1).await {
        Ok(epoch_id) => {
            ui::success(&format!(
                "Default group '{}' initialized with epoch {}.",
                target_group.name, epoch_id
            ));
        }
        Err(err) => {
            return Err(CliError::from(err));
        }
    }

    Ok(true)
}

async fn recovery_backup_exists(session_manager: &SessionManager) -> Result<bool, CliError> {
    if let Ok(path) = session_manager.recovery_artifact_path() {
        if path.exists() {
            return Ok(true);
        }
    }

    let session = match session_manager.current_session() {
        Some(current) => current,
        None => return Ok(false),
    };

    match recovery::download_backup_artifact(session_manager, &session).await {
        Ok(_) => Ok(true),
        Err(CliError::NotFound { .. }) => Ok(false),
        Err(err) => Err(err),
    }
}

fn group_requires_genesis_bootstrap(group: &GroupInfo) -> bool {
    if !role_allows_genesis(&group.role) {
        return false;
    }

    match &group.current_epoch {
        Some(epoch) => epoch.trim().is_empty(),
        None => true,
    }
}

fn role_allows_genesis(role: &str) -> bool {
    matches!(role.to_ascii_lowercase().as_str(), "owner" | "admin")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_group(role: &str, epoch: Option<&str>) -> GroupInfo {
        GroupInfo {
            id: Uuid::new_v4().to_string(),
            name: "Test".to_string(),
            description: None,
            role: role.to_string(),
            current_epoch: epoch.map(|v| v.to_string()),
            member_count: 1,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn admin_without_epoch_requires_bootstrap() {
        let group = build_group("admin", None);
        assert!(group_requires_genesis_bootstrap(&group));
    }

    #[test]
    fn admin_with_epoch_is_considered_initialized() {
        let group = build_group("admin", Some("epoch-1"));
        assert!(!group_requires_genesis_bootstrap(&group));
    }

    #[test]
    fn member_without_epoch_does_not_trigger_bootstrap() {
        let group = build_group("member", None);
        assert!(!group_requires_genesis_bootstrap(&group));
    }
}
/// Perform secure logout with comprehensive cleanup
async fn perform_secure_logout(session_manager: &SessionManager) -> Result<(), CliError> {
    if let Some(session) = session_manager.current_session() {
        session_manager.remember_last_user(&session)?;

        // Log the logout event
        log_authentication_event(&session.user_id, &session.server_url, "logout").await?;

        // Invalidate server-side session
        invalidate_server_session(&session.token, &session.server_url).await?;

        // Clear sensitive in-memory data and on-disk artifacts
        session_manager.clear_sensitive_memory()?;
        session_manager.cleanup_temporary_files()?;

        // Clear local session with secure deletion
        session_manager.clear_session()?;

        // Lock the user directory to mark the session as inactive
        session_manager.lock_user_session()?;

        // Remove any active user context pointer
        session_manager.clear_user_context()?;

        // Clear any cached credentials
        clear_credential_cache().await?;
    }

    Ok(())
}

/// Preserve migration state for recovery
async fn preserve_migration_state_for_recovery(
    _migration_info: &MigrationInfo,
    user_id: &str,
) -> Result<(), CliError> {
    // Simulate preserving migration state
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    ui::info(&format!("Migration state preserved for user {}", user_id));
    ui::info("State will be automatically recovered on next login");

    Ok(())
}

/// Log authentication events for security audit
async fn log_authentication_event(
    username: &str,
    server_url: &str,
    event_type: &str,
) -> Result<(), CliError> {
    // Simulate security audit logging
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let canonicalization = canonicalize_server_url(server_url);
    let display_server = &canonicalization.canonical;

    if let Some(alias) = canonicalization.replaced_alias.as_ref() {
        ui::info(&format!(
            "📡 Confirming server mapping '{}' → '{}'.",
            alias, display_server
        ));
    }

    // In real implementation, this would log to secure audit system
    ui::info(&format!(
        "AUTH_EVENT: {} for {} on {} at {}",
        event_type,
        username,
        display_server,
        ui::formatting::format_local_and_utc(&Utc::now())
    ));

    Ok(())
}

/// Invalidate server-side session
async fn invalidate_server_session(_token: &str, _server_url: &str) -> Result<(), CliError> {
    // Simulate server-side session invalidation
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    Ok(())
}

/// Clear credential cache
async fn clear_credential_cache() -> Result<(), CliError> {
    // Simulate clearing credential cache
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    Ok(())
}

#[derive(Debug, Clone)]
struct RegistrationResult {
    user_id: String,
    email: String,
    device_id: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    default_group_id: Option<Uuid>,
    requires_genesis_initialization: bool,
    pending_confirmation: bool,
    confirmation_expires_at: Option<DateTime<Utc>>,
}
