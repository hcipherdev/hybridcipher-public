use crate::{error::CliError, session::SessionManager, ui};
use base64::engine::{general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct EpochKeysResponse {
    pub group_id: Uuid,
    pub epoch_id: Uuid,
    pub epoch_number: u64,
    pub encrypted_keys: Vec<u8>,
    pub key_derivation_info: Value,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Fetch encrypted epoch key material for administrative recovery workflows.
pub async fn handle_get_epoch_keys(
    group_id: Option<String>,
    epoch_id: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?; // Ensure we have an authenticated context

    let group_uuid = match group_id {
        Some(raw_id) => Uuid::parse_str(raw_id.trim()).map_err(|err| {
            CliError::invalid_input(format!("Invalid group identifier '{}': {}", raw_id, err))
        })?,
        None => session_manager.ensure_current_group().await?,
    };

    session_manager
        .require_group_admin(group_uuid, "hybridcipher get-epoch-keys")
        .await?;

    let epoch_uuid = if let Some(epoch) = epoch_id.as_ref() {
        Some(Uuid::parse_str(epoch.trim()).map_err(|err| {
            CliError::invalid_input(format!("Invalid epoch identifier '{}': {}", epoch, err))
        })?)
    } else {
        None
    };

    let base_url = session.server_url.trim_end_matches('/');
    let mut url = format!("{}/api/v1/crypto/epochs/{}", base_url, group_uuid);
    if let Some(epoch_uuid) = epoch_uuid {
        url.push_str(&format!("?epoch_id={}", epoch_uuid));
    }

    ui::section("Fetch Encrypted Epoch Key");

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|err| CliError::network(format!("Failed to contact server: {}", err)))?;

    match response.status() {
        StatusCode::OK => {
            let payload: EpochKeysResponse = response.json().await.map_err(|err| {
                CliError::network(format!("Failed to parse epoch key response: {}", err))
            })?;

            let group_label = session_manager.group_label(&payload.group_id).await;
            render_epoch_key_response(&payload, &group_label);
            Ok(())
        }
        StatusCode::UNAUTHORIZED => {
            session_manager.invalidate_session("get_epoch_keys")?;
            Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ))
        }
        StatusCode::FORBIDDEN => Err(CliError::permission(
            "Only group administrators can request epoch key material. Ask a group admin to run this command or promote your device.",
        )),
        StatusCode::NOT_FOUND => Err(CliError::not_found(
            "Group or epoch not found. Verify the identifiers and try again.",
        )),
        StatusCode::BAD_REQUEST => {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Server rejected the request.".to_string());
            Err(CliError::validation(message))
        }
        status => {
            let body = response.text().await.unwrap_or_default();
            Err(CliError::network(format!(
                "Server returned {} while fetching epoch keys: {}",
                status, body
            )))
        }
    }
}

fn render_epoch_key_response(response: &EpochKeysResponse, group_label: &str) {
    ui::info(&format!("Group: {}", group_label));
    ui::info(&format!("Epoch ID: {}", response.epoch_id));
    ui::info(&format!("Epoch Number: {}", response.epoch_number));
    ui::info(&format!("Epoch Status: {}", response.status));
    ui::info(&format!("Epoch Created At: {}", response.created_at));

    let ciphertext_b64 = general_purpose::STANDARD.encode(&response.encrypted_keys);
    ui::info(&format!("Encrypted Epoch Key (base64): {}", ciphertext_b64));

    if let Some(device_id) = response
        .key_derivation_info
        .get("recipient_device_id")
        .and_then(|v| v.as_str())
    {
        ui::info(&format!("Recipient Device ID: {}", device_id));
    }

    if let Some(signature_b64) = response
        .key_derivation_info
        .get("signature")
        .and_then(|v| v.as_str())
    {
        ui::info(&format!("Welcome Signature (base64): {}", signature_b64));
    }

    if let Some(signing_key_b64) = response
        .key_derivation_info
        .get("signing_public_key")
        .and_then(|v| v.as_str())
    {
        ui::info(&format!("Signing Public Key (base64): {}", signing_key_b64));
    }

    if let Some(created) = response
        .key_derivation_info
        .get("created_at")
        .and_then(|v| v.as_str())
    {
        ui::info(&format!("Welcome Created At: {}", created));
    }

    if let Some(expires) = response
        .key_derivation_info
        .get("expires_at")
        .and_then(|v| v.as_str())
    {
        ui::info(&format!("Welcome Expires At: {}", expires));
    }

    // ui::info(
    //     "Deliver this ciphertext to the intended device; it can decrypt it with its invitation private key.",
    // );
}
