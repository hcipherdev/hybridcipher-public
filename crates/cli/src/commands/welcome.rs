use crate::{
    commands::members::{record_unverified_devices, UnverifiedDevice},
    error::CliError,
    session::{JoinCardPinState, Session, SessionManager},
    ui,
    ui::formatting::{format_local_datetime, format_local_datetime_with_relative, format_table},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use hybridcipher_client::{
    invitation::JoinCard,
    network::Network,
    rekey::RekeyStatus,
    state::client::{GeneratedWelcomeMessage, WelcomeSyncResult, WelcomeSyncStatus},
    storage::Storage,
    ClientError,
};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct PendingDeviceSummary {
    user_id: Uuid,
    device_id: String,
    device_name: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pending_since: DateTime<Utc>,
    invitation_public_key_hex: String,
    group_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SubmitWelcomeRequest {
    pub encrypted_epoch_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SubmitWelcomeResponse {
    pub message_id: Uuid,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub pending_cleared_at: DateTime<Utc>,
}

/// Handle the `process-welcome-messages` command
pub async fn handle_process_welcome_messages(
    group_id: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;

    ui::section("Process Welcome Messages");

    let client = session_manager.create_client().await?;

    let results = if let Some(group_id) = group_id {
        let group_uuid = Uuid::parse_str(&group_id).map_err(|e| {
            CliError::invalid_input(format!("Invalid group ID '{}': {}", group_id, e))
        })?;

        ui::info(&format!(
            "Fetching Welcome messages for group {}",
            group_uuid
        ));

        vec![client.sync_welcome_messages_for_group(group_uuid).await?]
    } else {
        ui::info("Fetching Welcome messages for all groups");
        client.sync_all_welcome_messages().await?
    };

    if results.is_empty() {
        ui::info("No groups found. Use 'hybridcipher list-groups' to verify your memberships.");
        return Ok(());
    }

    let mut updated_count = 0usize;
    let mut updated_groups = Vec::new();
    for WelcomeSyncResult {
        group_id,
        group_name,
        processed_epoch,
        messages_processed,
        status,
        detail,
    } in &results
    {
        ui::subsection(&format!("{} ({})", group_name, group_id));

        match status {
            WelcomeSyncStatus::Updated => {
                updated_count += 1;
                updated_groups.push(*group_id);
                if let Some(epoch) = processed_epoch {
                    ui::success(&format!(
                        "Installed epoch {} with {} Welcome message(s)",
                        epoch, messages_processed
                    ));
                } else {
                    ui::success(&format!(
                        "Processed {} Welcome message(s)",
                        messages_processed
                    ));
                }
            }
            WelcomeSyncStatus::NoMessages => {
                ui::warning("No Welcome messages were available for this device");
                if let Some(epoch) = processed_epoch {
                    ui::info(&format!("Current server epoch: {}", epoch));
                }
            }
            WelcomeSyncStatus::NoActiveEpoch => {
                ui::warning("Group has no active epoch yet");
                ui::info("Ask a group admin to initialize the group epoch.");
            }
            WelcomeSyncStatus::Skipped => {
                ui::info("Skipped (device is not a member of this group)");
            }
            WelcomeSyncStatus::Error => {
                ui::error("Failed to process Welcome messages for this group");
            }
        }

        if let Some(detail) = detail {
            ui::dim(&format!("➡ {}", detail));
        }
    }

    if updated_count > 0 {
        ui::success(&format!(
            "Welcome synchronization completed for {} group(s)",
            updated_count
        ));
        if let Err(err) = auto_report_rekey_participation(&client, &updated_groups).await {
            ui::warning(&format!(
                "Automatic rekey heartbeat/progress failed: {}",
                err
            ));
        }
    } else {
        ui::info("No epoch keys were updated during this run.");
    }

    Ok(())
}

/// Generate a Welcome payload for an incoming join card
pub async fn handle_generate_welcome(
    group_id: Option<String>,
    join_card_path: PathBuf,
    output: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;

    ui::section("Generate Welcome Payload");

    let group_uuid = match group_id {
        Some(raw_id) => Uuid::parse_str(raw_id.trim()).map_err(|e| {
            CliError::invalid_input(format!("Invalid group ID '{}': {}", raw_id, e))
        })?,
        None => session_manager.ensure_current_group().await?,
    };

    session_manager
        .require_group_admin(group_uuid, "hybridcipher generate-welcome")
        .await?;

    let file_contents = fs::read_to_string(&join_card_path)
        .map_err(|e| CliError::io(format!("Failed to read join card: {}", e)))?;
    let join_card: JoinCard = serde_json::from_str(&file_contents)
        .map_err(|e| CliError::invalid_input(format!("Invalid join card JSON format: {}", e)))?;

    let client = session_manager.create_client().await?;
    let generated = client
        .generate_welcome_for_join_card(group_uuid, join_card, None)
        .await
        .map_err(|e| {
            CliError::member_management(format!("Failed to generate Welcome payload: {}", e))
        })?;

    let api_message = ApiWelcomeMessage::from_generated(&generated);
    write_welcome_file(group_uuid, &[api_message], output.as_deref())?;

    ui::success("Welcome payload generated successfully");
    if let Some(path) = output {
        ui::info(&format!("Saved to {}", path.display()));
    } else {
        ui::dim("Payload emitted to stdout");
    }
    Ok(())
}

/// Issue server-approved Welcome payloads for a pending device
pub async fn handle_issue_welcome(
    device_id: String,
    group_id: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;
    let pin_config = session_manager.load_pinning_config().await?;
    let require_second_party = pin_config.require_second_party_verification;

    ui::section("Approve Pending Device");

    let session = session_manager.require_auth()?;
    let base_url = session.server_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let target_group = if let Some(group_string) = group_id.as_ref() {
        Uuid::parse_str(group_string).map_err(|e| {
            CliError::invalid_input(format!(
                "Invalid group identifier '{}': {}",
                group_string, e
            ))
        })?
    } else {
        session_manager.ensure_current_group().await?
    };
    let pending_devices = fetch_pending_devices(&session, session_manager, target_group).await?;

    let pending = pending_devices
        .into_iter()
        .find(|device| device.device_id == device_id)
        .ok_or_else(|| {
            CliError::invalid_input(format!("Device '{}' is not awaiting approval", device_id))
        })?;

    let invitation_public_key = hex::decode(&pending.invitation_public_key_hex).map_err(|e| {
        CliError::configuration(format!(
            "Server returned invalid invitation key for device {}: {}",
            pending.device_id, e
        ))
    })?;

    if !pending.group_ids.contains(&target_group) {
        return Err(CliError::invalid_input(format!(
            "Device '{}' does not belong to group {}",
            pending.device_id, target_group
        )));
    }

    let target_groups = vec![target_group];

    for group_id in &target_groups {
        session_manager
            .require_group_admin(*group_id, "hybridcipher issue-welcome")
            .await?;
    }

    ui::info(&format!(
        "Device '{}' has been pending since {}",
        pending.device_id,
        format_local_datetime(&pending.pending_since)
    ));
    if let Some(name) = pending.device_name.as_ref() {
        ui::dim(&format!("Recorded device name: {}", name));
    }
    let owner_label = session_manager
        .cached_email_for_user_id(&pending.user_id.to_string())
        .await
        .unwrap_or_else(|| pending.user_id.to_string());
    ui::dim(&format!("Device owner: {}", owner_label));

    let mut unverified_reasons: Vec<String> = Vec::new();
    let mut pin_reasons: Vec<String> = Vec::new();
    let mut pin_ok = false;

    match session_manager
        .fetch_join_cards_for_user_id(&pending.user_id)
        .await
    {
        Ok(cards) => {
            if let Some(join_card) = cards
                .into_iter()
                .find(|card| card.device_id == pending.device_id)
            {
                match session_manager
                    .check_or_restore_join_card_pin_with_auto_pin(&join_card, true)
                    .await
                {
                    Ok(state) => match state {
                        JoinCardPinState::AlreadyPinned | JoinCardPinState::RestoredFromCache => {
                            pin_ok = true;
                        }
                        JoinCardPinState::Unverified { auto_pinned } => {
                            if auto_pinned {
                                pin_reasons
                                    .push("Pin status: auto-pinned (unverified)".to_string());
                            } else {
                                pin_reasons.push("Pin status: unverified".to_string());
                            }
                        }
                        JoinCardPinState::Missing => {
                            pin_reasons.push("Pin status: unpinned".to_string());
                        }
                        JoinCardPinState::Expired(pinned_at) => {
                            pin_reasons.push(format!(
                                "Pin status: expired at {}",
                                format_local_datetime(&pinned_at)
                            ));
                        }
                    },
                    Err(err) => {
                        pin_reasons.push(format!("Pin status unavailable: {}", err));
                    }
                }
            } else {
                pin_reasons.push("Pin status: unknown (join card not found)".to_string());
            }
        }
        Err(err) => {
            pin_reasons.push(format!("Pin status unavailable: {}", err));
        }
    }

    if require_second_party {
        match session_manager
            .get_second_party_status(&pending.user_id.to_string(), &pending.device_id)
            .await
        {
            Ok(Some((status, last_error))) => {
                if status != "verified" {
                    let mut reason = if pin_reasons.is_empty() && pin_ok {
                        format!("Pinned but second-party not verified: {}", status)
                    } else {
                        format!("Second-party status: {}", status)
                    };
                    if let Some(error) = last_error {
                        reason.push_str(&format!(" ({})", error));
                    }
                    unverified_reasons.push(reason);
                }
            }
            Ok(None) => {
                let reason = if pin_reasons.is_empty() && pin_ok {
                    "Pinned but second-party not verified: unknown".to_string()
                } else {
                    "Second-party status: unknown".to_string()
                };
                unverified_reasons.push(reason);
            }
            Err(err) => {
                let reason = if pin_reasons.is_empty() && pin_ok {
                    format!(
                        "Pinned but second-party not verified: unavailable ({})",
                        err
                    )
                } else {
                    format!("Second-party status unavailable: {}", err)
                };
                unverified_reasons.push(reason);
            }
        }
    }

    if !pin_reasons.is_empty() {
        unverified_reasons.extend(pin_reasons);
    }

    if !unverified_reasons.is_empty() {
        let devices = vec![UnverifiedDevice {
            user_id: pending.user_id,
            device_id: pending.device_id.clone(),
            reasons: unverified_reasons.clone(),
        }];

        if let Err(err) = record_unverified_devices(
            session_manager,
            target_group,
            Some(owner_label.clone()),
            &devices,
        )
        .await
        {
            ui::warning(&format!(
                "Failed to record unverified device locally: {}",
                err
            ));
        }

        if require_second_party {
            ui::warning("Issuing Welcome without pinning and/or second-party verification:");
        } else {
            ui::warning("Issuing Welcome without pinning verification:");
        }
        for reason in unverified_reasons {
            ui::info(&format!("- {}", reason));
        }
        if require_second_party {
            ui::dim(
                "Next steps: pin unpinned device keys (`hybridcipher pin add --user <EMAIL_OR_ID> --device <DEVICE_ID>`) and complete second-party verification (`hybridcipher pin second-party-enqueue --status --target-user <USER_ID_OR_EMAIL> --target-device <DEVICE_ID>`).",
            );
        } else {
            ui::dim(
                "Next steps: pin unpinned device keys (`hybridcipher pin add --user <EMAIL_OR_ID> --device <DEVICE_ID>`).",
            );
        }
    }

    let api_base = if base_url.ends_with("/api/v1") {
        base_url.to_string()
    } else {
        format!("{}/api/v1", base_url)
    };

    let hybrid_client = session_manager.create_client().await?;

    for group_id in target_groups {
        let group_label = session_manager.group_label(&group_id).await;
        ui::subsection(&format!("Issuing Welcome for group {}", group_label));

        let generated = hybrid_client
            .generate_welcome_for_pending_device(
                group_id,
                &pending.device_id,
                pending.user_id,
                &invitation_public_key,
            )
            .await
            .map_err(|e| {
                CliError::member_management(format!(
                    "Failed to generate Welcome payload for group {}: {}",
                    group_id, e
                ))
            })?;

        let request = SubmitWelcomeRequest {
            encrypted_epoch_key: generated.encrypted_epoch_key.clone(),
            signature: generated.signature.clone(),
            signing_public_key: generated.signing_public_key.clone(),
            created_at: generated.created_at,
            expires_at: generated.expires_at,
        };

        let endpoint = format!(
            "{}/groups/{}/devices/{}/welcome",
            api_base, group_id, pending.device_id
        );

        let response = client
            .post(&endpoint)
            .bearer_auth(&session.token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                CliError::network(format!(
                    "Failed to submit Welcome payload for group {}: {}",
                    group_id, e
                ))
            })?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            session_manager.invalidate_session("issue_welcome_submit")?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }

        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(CliError::invalid_state(format!(
                "Server reported that device '{}' is no longer pending",
                pending.device_id
            )));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            return Err(CliError::network(format!(
                "Server rejected Welcome payload for group {}: {} - {}",
                group_id, status, body
            )));
        }

        let confirmation: SubmitWelcomeResponse = response.json().await.map_err(|e| {
            CliError::network(format!(
                "Failed to parse Welcome submission response: {}",
                e
            ))
        })?;

        ui::success(&format!(
            "Welcome message {} stored; pending flag cleared at {}",
            confirmation.message_id,
            format_local_datetime(&confirmation.pending_cleared_at)
        ));
    }

    ui::info("✅ Device approved. Ask the new device to rerun 'hybridcipher process-welcome-messages' to fetch the new epoch keys.");

    Ok(())
}

/// List pending devices for the active group
pub async fn handle_pending_devices(session_manager: &SessionManager) -> Result<(), CliError> {
    session_manager.require_auth()?;

    ui::section("Pending Devices");

    let group_id = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(group_id, "hybridcipher pending-devices")
        .await?;
    let group_label = session_manager.group_label(&group_id).await;
    ui::info(&format!(
        "Checking pending devices for current group {}",
        group_label
    ));

    let session = session_manager.require_auth()?;
    let pending_devices = fetch_pending_devices(&session, session_manager, group_id).await?;
    let mut pending_for_group: Vec<PendingDeviceSummary> = pending_devices
        .into_iter()
        .filter(|device| device.group_ids.contains(&group_id))
        .collect();

    if pending_for_group.is_empty() {
        ui::success("No pending devices found for the current group.");
        ui::dim("Use 'hybridcipher issue-welcome --device <DEVICE_ID>' to approve a device.");
        return Ok(());
    }

    pending_for_group.sort_by_key(|device| device.pending_since);

    let headers = ["Device ID", "User", "Name", "Pending Since"];
    let mut rows = Vec::with_capacity(pending_for_group.len());
    for device in &pending_for_group {
        let user_label = session_manager
            .cached_email_for_user_id(&device.user_id.to_string())
            .await
            .unwrap_or_else(|| device.user_id.to_string());
        let name = device
            .device_name
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("-");
        rows.push(vec![
            device.device_id.clone(),
            user_label,
            name.to_string(),
            format_pending_datetime(&device.pending_since),
        ]);
    }

    println!("{}", format_table(&headers, &rows));
    ui::info(&format!(
        "{} pending device(s) awaiting approval.",
        pending_for_group.len()
    ));
    ui::dim("Approve a device with 'hybridcipher issue-welcome --device <DEVICE_ID>'.");

    Ok(())
}

async fn fetch_pending_devices(
    session: &Session,
    session_manager: &SessionManager,
    group_id: Uuid,
) -> Result<Vec<PendingDeviceSummary>, CliError> {
    let client = reqwest::Client::new();
    let base_url = session.server_url.trim_end_matches('/');
    let pending_endpoint = if base_url.ends_with("/api/v1") {
        format!("{}/groups/{}/pending-devices", base_url, group_id)
    } else {
        format!("{}/api/v1/groups/{}/pending-devices", base_url, group_id)
    };

    let pending_response = client
        .get(&pending_endpoint)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to fetch pending devices: {}", e)))?;

    if pending_response.status() == reqwest::StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("pending_devices")?;
        return Err(CliError::authentication(
            "Session rejected by server while fetching pending devices",
        ));
    }

    if !pending_response.status().is_success() {
        let status = pending_response.status();
        let body = pending_response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(CliError::network(format!(
            "Failed to load pending devices: {} - {}",
            status, body
        )));
    }

    pending_response
        .json()
        .await
        .map_err(|e| CliError::network(format!("Invalid pending device listing: {}", e)))
}

fn format_pending_datetime(value: &DateTime<Utc>) -> String {
    format_local_datetime_with_relative(value)
}

/// Serialized welcome payload suitable for API submission
#[derive(Clone, Serialize)]
pub struct ApiWelcomeMessage {
    pub recipient_user_id: Uuid,
    pub device_id: String,
    pub encrypted_epoch_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

impl ApiWelcomeMessage {
    pub fn from_generated(message: &GeneratedWelcomeMessage) -> Self {
        Self {
            recipient_user_id: message.recipient_user_id,
            device_id: message.device_id.clone(),
            encrypted_epoch_key: message.encrypted_epoch_key.clone(),
            signature: message.signature.clone(),
            signing_public_key: message.signing_public_key.clone(),
            created_at: message.created_at.timestamp(),
            expires_at: message.expires_at.map(|ts| ts.timestamp()),
        }
    }
}

/// Parsed Welcome payload bundle from disk
pub struct WelcomePayloadBundle {
    pub group_id: Option<Uuid>,
    pub messages: Vec<ApiWelcomeMessage>,
}

#[derive(Serialize, Deserialize)]
struct WelcomeFile {
    group_id: Option<String>,
    messages: Vec<WelcomeFileEntry>,
}

#[derive(Serialize, Deserialize)]
struct WelcomeFileEntry {
    recipient_user_id: String,
    device_id: String,
    encrypted_epoch_key: String,
    signature: String,
    signing_public_key: String,
    created_at: i64,
    expires_at: Option<i64>,
}

fn encode_entry(message: &ApiWelcomeMessage) -> WelcomeFileEntry {
    WelcomeFileEntry {
        recipient_user_id: message.recipient_user_id.to_string(),
        device_id: message.device_id.clone(),
        encrypted_epoch_key: BASE64.encode(&message.encrypted_epoch_key),
        signature: BASE64.encode(&message.signature),
        signing_public_key: BASE64.encode(&message.signing_public_key),
        created_at: message.created_at,
        expires_at: message.expires_at,
    }
}

/// Write payloads to a JSON file (or stdout if no output path is specified)
fn write_welcome_file(
    group_id: Uuid,
    messages: &[ApiWelcomeMessage],
    output: Option<&Path>,
) -> Result<(), CliError> {
    let file = WelcomeFile {
        group_id: Some(group_id.to_string()),
        messages: messages.iter().map(encode_entry).collect(),
    };

    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| CliError::format(format!("Failed to serialize Welcome payload: {}", e)))?;

    if let Some(path) = output {
        fs::write(path, json)
            .map_err(|e| CliError::io(format!("Failed to write Welcome payload: {}", e)))?;
    } else {
        println!("{}", json);
    }
    Ok(())
}

/// Load welcome payloads from disk and decode base64 content
pub fn load_welcome_payloads(path: &Path) -> Result<WelcomePayloadBundle, CliError> {
    let file_contents = fs::read_to_string(path)
        .map_err(|e| CliError::io(format!("Failed to read Welcome payload file: {}", e)))?;
    let file: WelcomeFile = serde_json::from_str(&file_contents).map_err(|e| {
        CliError::invalid_input(format!("Welcome payload file is not valid JSON: {}", e))
    })?;

    let mut messages = Vec::new();
    for entry in file.messages {
        let recipient_user_id = Uuid::parse_str(&entry.recipient_user_id).map_err(|e| {
            CliError::invalid_input(format!(
                "Invalid recipient_user_id '{}' in Welcome payload: {}",
                entry.recipient_user_id, e
            ))
        })?;

        let encrypted_epoch_key = BASE64
            .decode(entry.encrypted_epoch_key.as_bytes())
            .map_err(|e| {
                CliError::invalid_input(format!("Invalid base64 for encrypted_epoch_key: {}", e))
            })?;

        let signature = BASE64
            .decode(entry.signature.as_bytes())
            .map_err(|e| CliError::invalid_input(format!("Invalid base64 for signature: {}", e)))?;

        let signing_public_key =
            BASE64
                .decode(entry.signing_public_key.as_bytes())
                .map_err(|e| {
                    CliError::invalid_input(format!("Invalid base64 for signing_public_key: {}", e))
                })?;

        messages.push(ApiWelcomeMessage {
            recipient_user_id,
            device_id: entry.device_id,
            encrypted_epoch_key,
            signature,
            signing_public_key,
            created_at: entry.created_at,
            expires_at: entry.expires_at,
        });
    }

    let group_id = match file.group_id {
        Some(gid) => Some(Uuid::parse_str(&gid).map_err(|e| {
            CliError::invalid_input(format!(
                "Invalid group_id '{}' in Welcome payload: {}",
                gid, e
            ))
        })?),
        None => None,
    };

    Ok(WelcomePayloadBundle { group_id, messages })
}

/// Convert payloads into JSON values suitable for server requests
pub fn serialize_welcome_payloads(messages: &[ApiWelcomeMessage]) -> Result<Vec<Value>, CliError> {
    messages
        .iter()
        .map(|msg| {
            serde_json::to_value(msg).map_err(|e| {
                CliError::format(format!(
                    "Failed to serialize Welcome payload for request: {}",
                    e
                ))
            })
        })
        .collect()
}

async fn auto_report_rekey_participation<S, N>(
    client: &hybridcipher_client::state::client::Client<S, N>,
    updated_groups: &[Uuid],
) -> Result<(), ClientError>
where
    S: Storage + Send + Sync + 'static,
    N: Network + Send + Sync + 'static,
{
    if updated_groups.is_empty() {
        return Ok(());
    }

    match client.rekey_status().await {
        Ok(Some(operation)) => {
            if !updated_groups.contains(&operation.group_id) {
                return Ok(());
            }

            match operation.status {
                RekeyStatus::Completed | RekeyStatus::Cancelled | RekeyStatus::Failed => {
                    return Ok(())
                }
                _ => {}
            }

            match client.emit_rekey_heartbeat().await {
                Ok(_) => ui::info("📡 Device heartbeat sent for active rekey"),
                Err(err) => ui::warning(&format!(
                    "Unable to emit rekey heartbeat automatically: {}",
                    err
                )),
            }

            match client.report_rekey_progress(None, None).await {
                Ok(_) => ui::info("📝 Reported rekey progress for this device"),
                Err(err) => ui::warning(&format!(
                    "Unable to report rekey progress automatically: {}",
                    err
                )),
            }

            Ok(())
        }
        Ok(None) => Ok(()),
        Err(err) => {
            // Log the full error for debugging
            eprintln!("DEBUG: rekey_status call failed with error: {:?}", err);

            match err {
                ClientError::InvalidState(_) => {
                    ui::dim(
                        "Skipping automatic rekey reporting (no active rekey operation detected)",
                    );
                }
                ClientError::NetworkError { .. } | ClientError::Network(_) => {
                    ui::warning(&format!(
                        "Automatic rekey reporting skipped because the status request failed: {}",
                        err
                    ));
                }
                other => {
                    ui::warning(&format!(
                        "Automatic rekey reporting skipped due to unexpected error: {}",
                        other
                    ));
                }
            }
            Ok(())
        }
    }
}
