use crate::{commands::auth::prompt_mfa_proof, error::CliError, session::SessionManager, ui};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use qrcode::render::unicode;
use qrcode::QrCode;
use reqwest::header;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct MfaEnrollStartResponse {
    secret: String,
    otpauth_url: String,
    #[serde(rename = "qr_svg", default)]
    _qr_svg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MfaEnrollVerifyResponse {
    backup_codes: Vec<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    enabled_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct MfaBackupCodesResponse {
    backup_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MfaDisableResponse {
    message: String,
}

pub async fn handle_mfa_enroll(session_manager: &SessionManager) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    ui::section("MFA Enrollment");

    let start_url = api_url(&session.server_url, "/mfa/totp/enroll/start");
    let client = reqwest::Client::new();
    let response = client
        .post(&start_url)
        .bearer_auth(&session.token)
        .json(&json!({}))
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to start MFA enrollment: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(CliError::authentication(format!(
            "MFA enrollment start failed ({}): {}",
            status, body
        )));
    }

    let server_time_hint = server_time_hint(&response);
    let start_body: MfaEnrollStartResponse = response.json().await.map_err(|e| {
        CliError::authentication(format!("Failed to parse MFA enrollment response: {}", e))
    })?;

    ui::info("Open Google Authenticator or Microsoft Authenticator.");
    ui::info("Tap the '+' button, then choose 'Scan a QR code'.");
    ui::info("If you can't scan, choose 'Enter a setup key' instead.");
    ui::info("Use your account email as the name, and select 'Time-based'.");

    ui::info("Scan this QR code:");
    render_qr_code(&start_body.otpauth_url);
    ui::info(&format!("Manual setup key (secret): {}", start_body.secret));
    ui::dim(&format!("otpauth URL: {}", start_body.otpauth_url));
    ui::dim("Keep the secret private. Anyone with it can generate valid codes.");
    if let Some(hint) = server_time_hint {
        ui::info(&hint);
    }

    let verify_url = api_url(&session.server_url, "/mfa/totp/enroll/verify");
    let mut attempts_left: u8 = 3;
    let verify_body = loop {
        let code = ui::prompts::input("Enter the 6-digit code from your authenticator")?;
        let verify_response = client
            .post(&verify_url)
            .bearer_auth(&session.token)
            .json(&json!({ "code": code.trim() }))
            .send()
            .await
            .map_err(|e| CliError::network(format!("Failed to verify MFA enrollment: {}", e)))?;

        if verify_response.status().is_success() {
            let verify_body: MfaEnrollVerifyResponse =
                verify_response.json().await.map_err(|e| {
                    CliError::authentication(format!(
                        "Failed to parse MFA verification response: {}",
                        e
                    ))
                })?;
            break verify_body;
        }

        let status = verify_response.status();
        let body = verify_response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        attempts_left = attempts_left.saturating_sub(1);

        if status.as_u16() == 401 && body.contains("Invalid MFA code") && attempts_left > 0 {
            ui::warning("Invalid code. Make sure the code is the current 6-digit time-based code.");
            ui::info(
                "If it keeps failing, re-scan the QR code and ensure your device time is correct.",
            );
            ui::info(&format!("Attempts left: {}", attempts_left));
            continue;
        }

        if attempts_left == 0 && status.as_u16() == 401 && body.contains("Invalid MFA code") {
            return Err(CliError::authentication(
                "MFA enrollment verification failed after 3 attempts. Re-run 'hybridcipher mfa enroll' and try again."
                    .to_string(),
            ));
        }

        return Err(CliError::authentication(format!(
            "MFA enrollment verification failed ({}): {}",
            status, body
        )));
    };

    ui::success(&format!(
        "MFA enabled at {}",
        ui::formatting::format_local_datetime(&verify_body.enabled_at)
    ));
    ui::warning("Store these backup codes somewhere safe. Each code can be used once.");
    for code in verify_body.backup_codes {
        ui::info(&format!("  {}", code));
    }

    Ok(())
}

pub async fn handle_mfa_backup_codes(session_manager: &SessionManager) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    ui::section("MFA Backup Codes");
    ui::warning("Regenerating backup codes invalidates the previous set.");
    let proceed = ui::prompts::confirm("Continue and generate new backup codes?")?;
    if !proceed {
        return Err(CliError::Cancelled);
    }

    let proof = prompt_mfa_proof()?;
    let url = api_url(&session.server_url, "/mfa/backup-codes/regenerate");
    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .bearer_auth(&session.token)
        .json(&json!({
            "mfa_code": proof.mfa_code,
            "backup_code": proof.backup_code,
        }))
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to regenerate backup codes: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(CliError::authentication(format!(
            "Backup code regeneration failed ({}): {}",
            status, body
        )));
    }

    let body: MfaBackupCodesResponse = response.json().await.map_err(|e| {
        CliError::authentication(format!("Failed to parse backup code response: {}", e))
    })?;

    ui::success("New backup codes generated.");
    ui::warning("Store these backup codes somewhere safe. Each code can be used once.");
    for code in body.backup_codes {
        ui::info(&format!("  {}", code));
    }

    Ok(())
}

pub async fn handle_mfa_disable(session_manager: &SessionManager) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    ui::section("Disable MFA");
    ui::warning("Disabling MFA will invalidate all active sessions.");
    let proceed = ui::prompts::confirm("Disable MFA now?")?;
    if !proceed {
        return Err(CliError::Cancelled);
    }

    let proof = prompt_mfa_proof()?;
    let url = api_url(&session.server_url, "/mfa/disable");
    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .bearer_auth(&session.token)
        .json(&json!({
            "mfa_code": proof.mfa_code,
            "backup_code": proof.backup_code,
        }))
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to disable MFA: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(CliError::authentication(format!(
            "MFA disable failed ({}): {}",
            status, body
        )));
    }

    let body: MfaDisableResponse = response.json().await.map_err(|e| {
        CliError::authentication(format!("Failed to parse MFA disable response: {}", e))
    })?;

    ui::success(&body.message);
    Ok(())
}

fn api_url(base: &str, path: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/api/v1") {
        format!("{}{}", trimmed, path)
    } else {
        format!("{}/api/v1{}", trimmed, path)
    }
}

fn render_qr_code(payload: &str) {
    match QrCode::new(payload.as_bytes()) {
        Ok(code) => {
            let qr = code.render::<unicode::Dense1x2>().quiet_zone(true).build();
            println!("{qr}");
        }
        Err(err) => {
            ui::warning(&format!("Failed to render QR code in terminal: {}", err));
            ui::info("Use the secret and otpauth URL to enroll manually.");
        }
    }
}

fn server_time_hint(response: &reqwest::Response) -> Option<String> {
    let header_value = response.headers().get(header::DATE)?;
    let header_str = header_value.to_str().ok()?;
    let server_time = DateTime::parse_from_rfc2822(header_str).ok()?;
    let server_time_utc = server_time.with_timezone(&Utc);
    let local_time = Utc::now();
    let delta = (server_time_utc - local_time).num_seconds().abs();

    let mut message = format!(
        "Server time: {}",
        ui::formatting::format_local_and_utc(&server_time_utc)
    );
    if delta >= 30 {
        let drift = ChronoDuration::seconds(delta);
        message.push_str(&format!(
            " (your device is off by about {}s). Sync your clock and try again.",
            drift.num_seconds()
        ));
    } else {
        message.push_str(" (clock looks in sync).");
    }

    Some(message)
}
