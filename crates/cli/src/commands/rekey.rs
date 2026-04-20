use crate::{
    commands::{diagnostics, welcome, RekeyCommands},
    error::CliError,
    session::{
        CurrentDevicePinState, JoinCardPinState, MigrationInfo, MigrationPhase, SessionManager,
    },
    ui,
};
use chrono::{DateTime, Utc};
use humantime::parse_duration;
use hybridcipher_client::{
    network::MockNetwork, rekey::RekeyProgressState, storage::LocalFsStorage, ClientError,
};
use hybridcipher_crypto::epoch_id::EpochIdMapper;
use reqwest::StatusCode;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

const DEFAULT_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(5);
const LOCAL_PROGRESS_REFRESH_INTERVAL: Duration = Duration::from_millis(1000);
const EMPTY_PROGRESS_RETRY_LIMIT: u32 = 3;

fn status_poll_interval() -> Duration {
    if let Ok(value) = std::env::var("HYBRIDCIPHER_REKEY_STATUS_POLL_SECS") {
        if let Ok(secs) = value.parse::<u64>() {
            return Duration::from_secs(secs.max(1));
        }
    }
    DEFAULT_STATUS_POLL_INTERVAL
}

type LocalClient = hybridcipher_client::state::client::Client<LocalFsStorage, MockNetwork>;

fn parse_activation_delay_argument(raw: &str) -> Result<u64, CliError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::invalid_input(
            "Activation delay value cannot be empty",
        ));
    }

    let normalized = trimmed.to_lowercase();
    if matches!(normalized.as_str(), "immediate" | "now" | "0" | "0s") {
        return Ok(0);
    }

    if let Ok(secs) = normalized.parse::<u64>() {
        return Ok(secs);
    }

    match parse_duration(trimmed) {
        Ok(duration) => {
            let secs = duration.as_secs();
            if secs > i64::MAX as u64 {
                Err(CliError::invalid_input(
                    "Activation delay exceeds supported range",
                ))
            } else {
                Ok(secs)
            }
        }
        Err(err) => Err(CliError::invalid_input(format!(
            "Invalid activation delay '{}': {}",
            raw, err
        ))),
    }
}

pub async fn handle_rekey_command(
    command: RekeyCommands,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    match command {
        RekeyCommands::Start {
            activation_delay,
            force,
            welcome_file,
        } => handle_rekey_start(force, activation_delay, welcome_file, session_manager).await,
        RekeyCommands::Status { watch } => handle_rekey_status(watch, session_manager).await,
        RekeyCommands::Cutover {
            force,
            immediate_cleanup,
        } => handle_rekey_cutover(force, immediate_cleanup, session_manager).await,
        RekeyCommands::Fallback { reason, yes } => {
            handle_rekey_fallback(reason, yes, session_manager).await
        }
    }
}

/// Information about a device that was skipped during welcome generation
#[derive(Debug, Clone)]
struct SkippedDevice {
    user_id: Uuid,
    device_id: String,
    reason: String,
}

async fn handle_rekey_start(
    force: bool,
    activation_delay: Option<String>,
    welcome_file: Option<PathBuf>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Start Rekey Operation");

    let session = session_manager.require_auth()?;
    let hc_client = session_manager.create_client().await?;
    let group_id = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(group_id, "hybridcipher rekey start")
        .await?;

    match session_manager
        .ensure_current_device_pin_verified("rekey start")
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
            return Err(CliError::PinningFailed(format!(
                "Local device pin verification failed: {}",
                err
            )));
        }
    }

    let server_url = session.server_url.clone();
    let http_client = reqwest::Client::new();

    // Check for existing active rekey operation before starting a new one
    match fetch_rekey_status(
        &http_client,
        session_manager,
        &session,
        group_id,
        &server_url,
    )
    .await
    {
        Ok(existing_status) => {
            // There's an active rekey - check if it needs cutover or fallback
            let state = existing_status.status.as_str();
            let is_completed = matches!(
                state,
                "completed" | "cutover_completed" | "cancelled" | "failed"
            );

            if !is_completed {
                ui::error("An active rekey operation already exists for this group.");
                ui::info(&format!("  Rekey ID: {}", existing_status.rekey_id));
                ui::info(&format!("  State: {}", state));
                let progress_pct = if existing_status.progress.total_files > 0 {
                    (existing_status.progress.migrated_files as f64
                        / existing_status.progress.total_files as f64)
                        * 100.0
                } else {
                    0.0
                };
                ui::info(&format!(
                    "  Progress: {:.1}% ({}/{})",
                    progress_pct,
                    existing_status.progress.migrated_files,
                    existing_status.progress.total_files
                ));
                println!();
                ui::info("To proceed, you must first complete or cancel the existing rekey:");
                ui::info("  • Run 'hybridcipher rekey cutover' to complete the migration");
                ui::info("  • Run 'hybridcipher rekey fallback' to cancel and rollback");
                return Err(CliError::migration(
                    "Cannot start a new rekey while another is in progress. Complete or cancel the existing rekey first."
                ));
            }
        }
        Err(e) => {
            // NOT_FOUND is expected when no active rekey exists - that's fine
            let is_not_found = e.to_string().contains("No active rekey operation");
            if !is_not_found {
                // Some other error - log it but continue (might be a transient issue)
                ui::dim(&format!("Note: Could not check for existing rekey: {}", e));
            }
        }
    }

    let activation_delay_seconds = activation_delay
        .as_deref()
        .map(parse_activation_delay_argument)
        .transpose()?;

    let audit = diagnostics::fetch_device_audit(session_manager, group_id, 30).await?;

    let stale_devices: Vec<String> = audit
        .devices
        .iter()
        .filter(|device| device.stale)
        .map(|device| format!("{} (user {})", device.device_id, device.user_id))
        .collect();
    if !stale_devices.is_empty() {
        return Err(CliError::migration(format!(
            "Device audit detected stale or incomplete records. Resolve before rekey: {}",
            stale_devices.join(", ")
        )));
    }

    // Always use fresh client state as the authoritative source
    let current_epoch = hc_client.current_epoch().await;

    // Only use migration state if it's for a future epoch (active migration)
    // Ignore completed migrations where to_epoch == current_epoch
    let target_epoch = hc_client
        .migration_snapshot()
        .await
        .and_then(|state| {
            if state.to_epoch > current_epoch {
                Some(state.to_epoch)
            } else {
                None // Stale/completed migration, ignore it
            }
        })
        .unwrap_or_else(|| current_epoch.saturating_add(1));

    let migration_snapshot = session_manager.migration_info();

    hc_client
        .ensure_future_epoch_state(group_id, target_epoch)
        .await
        .map_err(|e| {
            CliError::migration(format!(
                "Failed to stage epoch {} for welcome generation: {}",
                target_epoch, e
            ))
        })?;

    let (messages, skipped_devices) = match welcome_file {
        Some(path) => {
            let welcome_payload = welcome::load_welcome_payloads(&path)?;
            if let Some(file_group) = welcome_payload.group_id {
                if file_group != group_id {
                    return Err(CliError::invalid_input(format!(
                        "Welcome payload targets group {} but the active group is {}",
                        file_group, group_id
                    )));
                }
            }

            if welcome_payload.messages.is_empty() {
                return Err(CliError::invalid_input(
                    "Welcome payload file does not contain any messages",
                ));
            }

            (welcome_payload.messages, Vec::new())
        }
        None => {
            ui::dim("No welcome bundle provided; generating payloads for all active devices.");
            auto_generate_welcome_payloads(session_manager, group_id, &audit, target_epoch, force)
                .await?
        }
    };

    match session_manager.pinned_welcome_signing_key()? {
        Some(_) => ui::dim("Pinned welcome signing key verified for this server."),
        None => ui::warning(
            "No pinned welcome signing key found for this server. Run 'hybridcipher pin server-trust add' to avoid untrusted announcements.",
        ),
    }

    // Run coverage scan to get current tracked/orphaned/unmanaged counts
    let coverage_info = match hc_client.coverage_rescan(None).await {
        Ok(summary) => Some((
            summary.files_indexed,
            summary.orphaned_files,
            summary.unmanaged_files,
        )),
        Err(err) => {
            ui::dim(&format!("Coverage scan skipped: {}", err));
            None
        }
    };

    // Count enrolled files from client's file index
    let enrolled_file_count = hc_client.get_enrolled_file_count().await.unwrap_or(0);

    let affected_files = if enrolled_file_count > 0 {
        enrolled_file_count
    } else {
        // Fallback to legacy migration snapshot or device count
        std::cmp::max(
            migration_snapshot
                .as_ref()
                .map(|info| info.pending_files.len())
                .unwrap_or(0),
            messages.len(),
        )
    };

    if !ui::prompts::migration_impact_warning_with_coverage(
        current_epoch,
        target_epoch,
        affected_files,
        coverage_info,
    )? {
        ui::info("Rekey start cancelled");
        return Ok(());
    }

    let mut migration_record = migration_snapshot.clone().unwrap_or_else(|| MigrationInfo {
        current_epoch,
        target_epoch: Some(target_epoch),
        migration_start: Some(Utc::now()),
        phase: MigrationPhase::Idle,
        pending_files: Vec::new(),
        progress: 0.0,
        total_files: affected_files as u64,
    });
    migration_record.current_epoch = current_epoch;
    migration_record.target_epoch = Some(target_epoch);
    migration_record.migration_start = Some(Utc::now());
    migration_record.phase = MigrationPhase::Started;
    migration_record.total_files = affected_files as u64;
    if migration_record.pending_files.is_empty() {
        migration_record.pending_files = messages
            .iter()
            .map(|msg| format!("device:{}", msg.device_id))
            .collect();
    }
    migration_record.progress = 0.0;
    session_manager.update_migration_info(migration_record)?;

    let welcome_json = welcome::serialize_welcome_payloads(&messages)?;

    let mut payload = serde_json::Map::new();
    payload.insert(
        "reason".into(),
        serde_json::Value::String("key_rotation".into()),
    );
    payload.insert("config".into(), serde_json::Value::Null);
    payload.insert("member_updates".into(), serde_json::Value::Null);
    payload.insert(
        "welcome_messages".into(),
        serde_json::Value::Array(welcome_json),
    );
    payload.insert("emergency".into(), serde_json::Value::Bool(force));
    payload.insert(
        "client_epoch_id".into(),
        serde_json::Value::Number(serde_json::Number::from(target_epoch)),
    );
    if let Some(secs) = activation_delay_seconds {
        payload.insert(
            "policy_overrides".into(),
            serde_json::json!({ "activation_delay_seconds": secs }),
        );
    }
    let payload = serde_json::Value::Object(payload);

    let response = http_client
        .post(format!("{}/api/v1/groups/{}/rekey", server_url, group_id))
        .bearer_auth(&session.token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to contact server: {}", e)))?;

    if response.status() == StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("rekey_start")?;
        return Err(CliError::authentication(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    let active_status = if response.status().is_success() {
        let rekey: ApiRekeyResponse = response
            .json()
            .await
            .map_err(|e| CliError::network(format!("Failed to parse rekey response: {}", e)))?;

        ui::success("Epoch descriptor published");
        ui::info(&format!("Rekey ID: {}", rekey.rekey_id));
        ui::info(&format!(
            "Target epoch: {}",
            rekey
                .new_epoch_id
                .parse::<Uuid>()
                .map(|id| id.to_string())
                .unwrap_or_else(|_| rekey.new_epoch_id.clone())
        ));
        ui::info(&format!("Initiated: {}", rekey.initiated_at));

        // Brief delay to allow server to fully persist the rekey operation
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Send initial heartbeat before fetching status so server has file counts
        if let Err(err) = ensure_initiator_progress(&hc_client).await {
            let is_transient_race = match &err {
                ClientError::NetworkError { context, .. } => {
                    context.message.contains("No active rekey operation")
                }
                ClientError::InvalidState(message) => message.contains("No active rekey operation"),
                _ => false,
            };
            if !is_transient_race {
                ui::warning(&format!(
                    "Initial heartbeat not yet accepted; background worker will retry."
                ));
            }
        }

        match fetch_rekey_status(
            &http_client,
            session_manager,
            &session,
            group_id,
            &server_url,
        )
        .await
        {
            Ok(status) => Some(status),
            Err(err) => {
                ui::warning(&format!(
                    "Descriptor published but dashboard unavailable: {}",
                    err
                ));
                None
            }
        }
    } else if response.status() == StatusCode::CONFLICT
        || response.status() == StatusCode::BAD_REQUEST
    {
        ui::warning("An active rekey operation already exists – displaying dashboard");
        fetch_rekey_status(
            &http_client,
            session_manager,
            &session,
            group_id,
            &server_url,
        )
        .await
        .ok()
    } else {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(CliError::network(format!(
            "Rekey publish failed with status {}: {}",
            status, body
        )));
    };

    if let Some(status) = active_status.as_ref() {
        if std::env::var("HYBRIDCIPHER_DEBUG_REKEY")
            .map(|v| !v.is_empty() && v != "0" && v.to_ascii_lowercase() != "false")
            .unwrap_or(false)
        {
            render_rekey_dashboard(status);
        }
        update_session_migration_from_status(session_manager, status).await?;
    }

    ui::info("Run 'hybridcipher rekey status --watch' to monitor progress.");

    // Display warning about skipped devices if any
    if !skipped_devices.is_empty() {
        println!();
        ui::warning(&format!(
            "⚠️  {} device(s) were skipped during Welcome generation:",
            skipped_devices.len()
        ));
        println!();

        // Fetch user emails for better reporting
        let user_emails = fetch_user_emails_for_devices(
            &http_client,
            session_manager,
            &session,
            &server_url,
            &skipped_devices,
        )
        .await?;

        for skipped in &skipped_devices {
            let email = user_emails
                .get(&skipped.user_id)
                .map(|s| s.as_str())
                .unwrap_or("<unknown>");
            ui::error(&format!(
                "  • {} (device: {}) - {}",
                email, skipped.device_id, skipped.reason
            ));
        }

        println!();
        ui::warning("⚠️  These devices will NOT receive the new epoch key.");
        ui::info("To resolve:");
        ui::info("  1. Ensure each device has a valid join card:");
        ui::info("     hybridcipher pin add --user <USER_ID> --device <DEVICE_ID>");
        ui::info("  2. Manually issue Welcome messages:");
        ui::info("     hybridcipher welcome issue <DEVICE_ID>");
        println!();
    }

    if ui::prompts::confirm_with_default("Run local coverage migration now?", true)? {
        run_local_coverage_migration(&hc_client).await?;
    } else {
        ui::info("Migration deferred. When ready, run:");
        ui::info("  hybridcipher coverage scan");
        ui::info("  hybridcipher coverage migrate --all");
    }

    Ok(())
}

async fn auto_generate_welcome_payloads(
    session_manager: &SessionManager,
    group_id: Uuid,
    audit: &diagnostics::DeviceAuditResponse,
    target_epoch: u64,
    force: bool,
) -> Result<(Vec<welcome::ApiWelcomeMessage>, Vec<SkippedDevice>), CliError> {
    if audit.devices.is_empty() {
        return Err(CliError::migration(
            "Device roster is empty; cannot produce Welcome payloads for rekey.".to_string(),
        ));
    }

    let cached_cards_vec = session_manager.load_cached_join_cards()?;
    let mut cached_cards: HashMap<(Uuid, String), hybridcipher_client::invitation::JoinCard> =
        HashMap::with_capacity(cached_cards_vec.len());
    for card in cached_cards_vec {
        cached_cards.insert((card.user_id, card.device_id.clone()), card);
    }

    let mut directory_cache: HashMap<Uuid, Vec<hybridcipher_client::invitation::JoinCard>> =
        HashMap::new();
    let client = session_manager.create_client().await?;
    let pin_config = session_manager.load_pinning_config().await?;
    let require_second_party = pin_config.require_second_party_verification;

    let mut missing_invitation_keys = Vec::new();
    let mut missing_join_cards = Vec::new();
    let mut missing_pins = Vec::new();
    let mut expired_pins = Vec::new();
    let mut payloads = Vec::new();
    let mut skipped_devices = Vec::new();

    for device in &audit.devices {
        if !device.invitation_key_present {
            missing_invitation_keys.push(format!("{} (user {})", device.device_id, device.user_id));
            continue;
        }

        let device_key = (device.user_id, device.device_id.clone());
        let join_card = if let Some(card) = cached_cards.get(&device_key) {
            card.clone()
        } else {
            if !directory_cache.contains_key(&device.user_id) {
                let fetched = session_manager
                    .fetch_join_cards_for_user_id(&device.user_id)
                    .await?;
                directory_cache.insert(device.user_id, fetched);
            }

            let fetched_cards = match directory_cache.get(&device.user_id) {
                Some(cards) => cards,
                None => {
                    return Err(CliError::internal(
                        "Join card directory cache missing entry after fetch.".to_string(),
                    ))
                }
            };
            if let Some(card) = fetched_cards
                .iter()
                .find(|card| card.device_id == device.device_id)
            {
                cached_cards.insert(device_key.clone(), card.clone());
                card.clone()
            } else {
                missing_join_cards.push(format!("{} (user {})", device.device_id, device.user_id));
                continue;
            }
        };

        match session_manager
            .check_or_restore_join_card_pin(&join_card)
            .await?
        {
            JoinCardPinState::AlreadyPinned => {}
            JoinCardPinState::RestoredFromCache => {
                ui::dim(&format!(
                    "Restored cached verification for {} (device {}).",
                    device.user_id, device.device_id
                ));
            }
            JoinCardPinState::Unverified { .. } => {
                missing_pins.push(format!("{} (user {})", device.device_id, device.user_id));
                continue;
            }
            JoinCardPinState::Missing => {
                missing_pins.push(format!("{} (user {})", device.device_id, device.user_id));
                continue;
            }
            JoinCardPinState::Expired(pinned_at) => {
                expired_pins.push((device.device_id.clone(), device.user_id, pinned_at));
                continue;
            }
        }

        if require_second_party {
            // Enforce second-party verification status if present for this device.
            if let Ok(Some((status, last_error))) = session_manager
                .get_second_party_status(&device.user_id.to_string(), &device.device_id)
                .await
            {
                if status != "verified" {
                    let reason = last_error.map(|e| format!(" ({})", e)).unwrap_or_default();
                    missing_pins.push(format!(
                        "{} (user {}) - second-party verification {}{}",
                        device.device_id, device.user_id, status, reason
                    ));
                    continue;
                }
            }
        }

        let generated = client
            .generate_welcome_for_join_card(group_id, join_card.clone(), Some(target_epoch))
            .await
            .map_err(|e| {
                CliError::migration(format!(
                    "Failed to generate Welcome payload for device {} (user {}): {}",
                    device.device_id, device.user_id, e
                ))
            })?;

        payloads.push(welcome::ApiWelcomeMessage::from_generated(&generated));
    }

    // Collect all errors for skipped devices
    for missing in &missing_invitation_keys {
        if let Some(device) = audit
            .devices
            .iter()
            .find(|d| format!("{} (user {})", d.device_id, d.user_id) == *missing)
        {
            skipped_devices.push(SkippedDevice {
                user_id: device.user_id,
                device_id: device.device_id.clone(),
                reason: "Invitation key missing".to_string(),
            });
        }
    }

    for missing in &missing_join_cards {
        if let Some(device) = audit
            .devices
            .iter()
            .find(|d| format!("{} (user {})", d.device_id, d.user_id) == *missing)
        {
            skipped_devices.push(SkippedDevice {
                user_id: device.user_id,
                device_id: device.device_id.clone(),
                reason: "Join card not found".to_string(),
            });
        }
    }

    for missing in &missing_pins {
        if let Some(device) = audit
            .devices
            .iter()
            .find(|d| format!("{} (user {})", d.device_id, d.user_id) == *missing)
        {
            skipped_devices.push(SkippedDevice {
                user_id: device.user_id,
                device_id: device.device_id.clone(),
                reason: "Key pinning verification required".to_string(),
            });
        }
    }

    for (device_id, user_id, pinned_at) in &expired_pins {
        skipped_devices.push(SkippedDevice {
            user_id: *user_id,
            device_id: device_id.clone(),
            reason: format!(
                "Pinned key expired at {}",
                ui::formatting::format_local_datetime(&pinned_at)
            ),
        });
    }

    // When force is false, return errors as before
    if !force {
        // Collect all problematic devices with reasons
        let mut problem_devices = Vec::new();

        for missing in &missing_invitation_keys {
            if let Some(device) = audit
                .devices
                .iter()
                .find(|d| format!("{} (user {})", d.device_id, d.user_id) == *missing)
            {
                problem_devices.push((
                    device.user_id,
                    device.device_id.clone(),
                    "Invitation key missing",
                ));
            }
        }

        for missing in &missing_join_cards {
            if let Some(device) = audit
                .devices
                .iter()
                .find(|d| format!("{} (user {})", d.device_id, d.user_id) == *missing)
            {
                problem_devices.push((
                    device.user_id,
                    device.device_id.clone(),
                    "Join card not found",
                ));
            }
        }

        for missing in &missing_pins {
            if let Some(device) = audit
                .devices
                .iter()
                .find(|d| format!("{} (user {})", d.device_id, d.user_id) == *missing)
            {
                problem_devices.push((
                    device.user_id,
                    device.device_id.clone(),
                    "Join card not pinned",
                ));
            }
        }

        for (device_id, user_id, _) in &expired_pins {
            problem_devices.push((*user_id, device_id.clone(), "Pinned key expired"));
        }

        if !problem_devices.is_empty() {
            // Fetch user emails from group members list
            let mut user_emails = HashMap::new();

            let http_client = reqwest::Client::new();
            let session = session_manager.require_auth()?;
            let server_url = session.server_url.clone();

            // Fetch group members to get email addresses
            let members_url = format!("{}/api/v1/groups/{}/members", server_url, group_id);
            if let Ok(response) = http_client
                .get(&members_url)
                .bearer_auth(&session.token)
                .send()
                .await
            {
                if response.status() == StatusCode::UNAUTHORIZED {
                    session_manager.invalidate_session("rekey_missing_join_cards")?;
                    return Err(CliError::authentication(
                        "Authentication token rejected. Please login again.".to_string(),
                    ));
                }

                if response.status().is_success() {
                    if let Ok(members_data) = response.json::<serde_json::Value>().await {
                        if let Some(members) =
                            members_data.get("members").and_then(|m| m.as_array())
                        {
                            for member in members {
                                if let (Some(user_id), Some(email)) = (
                                    member
                                        .get("user_id")
                                        .and_then(|id| id.as_str())
                                        .and_then(|s| Uuid::parse_str(s).ok()),
                                    member.get("email").and_then(|e| e.as_str()),
                                ) {
                                    user_emails.insert(user_id, email.to_string());
                                }
                            }
                        }
                    }
                }
            }

            // Build detailed error message
            let mut error_msg = String::from(
                "Rekey cannot start because device join card or pin requirements are not met for the following devices:\n\n",
            );

            let mut has_missing_join_card = false;
            let mut has_missing_invitation_key = false;
            let mut has_unverified_pin = false;
            let mut has_expired_pin = false;

            for (idx, (user_id, device_id, reason)) in problem_devices.iter().enumerate() {
                let user_id_str = user_id.to_string();
                let email = user_emails
                    .get(user_id)
                    .map(|s| s.as_str())
                    .unwrap_or(&user_id_str);
                error_msg.push_str(&format!(
                    "  {}. {} ({}) - {}\n",
                    idx + 1,
                    device_id,
                    email,
                    reason
                ));

                match *reason {
                    "Join card not found" => has_missing_join_card = true,
                    "Invitation key missing" => has_missing_invitation_key = true,
                    "Join card not pinned" => has_unverified_pin = true,
                    "Pinned key expired" => has_expired_pin = true,
                    _ => {}
                }
            }

            error_msg.push_str("\nTo resolve:\n");
            if has_missing_join_card || has_missing_invitation_key {
                error_msg.push_str(
                    "  • Missing join card: ask the device owner to run `hybridcipher publish-joincard` on the affected device\n",
                );
            }
            if has_unverified_pin {
                error_msg.push_str(
                    "  • Unverified device: run `hybridcipher pin verify <USER_ID_OR_EMAIL> <DEVICE_ID>` to verify the pin\n",
                );
            }
            if has_expired_pin {
                error_msg.push_str(
                    "  • Expired pin: request a fresh join card, then re-pin and verify\n",
                );
            }
            error_msg.push_str("  • Or remove unused devices\n");
            error_msg.push_str(
                "  • Or use --force to skip these devices (they will not receive the new epoch key)\n",
            );

            return Err(CliError::migration(error_msg));
        }
    }

    if payloads.is_empty() {
        return Err(CliError::migration(
            "No Welcome payloads were generated; aborting rekey.".to_string(),
        ));
    }

    ui::info(&format!(
        "Generated Welcome payloads for {} device(s).",
        payloads.len()
    ));

    if force && !skipped_devices.is_empty() {
        ui::warning(&format!(
            "⚠️  {} device(s) skipped (will display details after rekey start)",
            skipped_devices.len()
        ));
    }

    Ok((payloads, skipped_devices))
}

/// Fetch user emails for a list of devices
async fn fetch_user_emails_for_devices(
    client: &reqwest::Client,
    session_manager: &SessionManager,
    session: &crate::session::Session,
    server_url: &str,
    skipped_devices: &[SkippedDevice],
) -> Result<HashMap<Uuid, String>, CliError> {
    let mut emails = HashMap::new();
    let unique_user_ids: std::collections::HashSet<Uuid> =
        skipped_devices.iter().map(|d| d.user_id).collect();

    for user_id in unique_user_ids {
        // Try to fetch user info from server
        let url = format!("{}/api/v1/users/{}", server_url, user_id);
        match client.get(&url).bearer_auth(&session.token).send().await {
            Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                session_manager.invalidate_session("rekey_fetch_user_emails")?;
                return Err(CliError::authentication(
                    "Authentication token rejected. Please login again.".to_string(),
                ));
            }
            Ok(response) if response.status().is_success() => {
                if let Ok(user_data) = response.json::<serde_json::Value>().await {
                    if let Some(email) = user_data.get("email").and_then(|e| e.as_str()) {
                        emails.insert(user_id, email.to_string());
                    }
                }
            }
            _ => {
                // If we can't fetch email, use user_id as fallback
                emails.insert(user_id, user_id.to_string());
            }
        }
    }

    Ok(emails)
}

async fn handle_rekey_status(
    watch: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    let group_id = session_manager.ensure_current_group().await?;
    let server_url = session.server_url.clone();
    let client = reqwest::Client::new();
    let local_client = session_manager.create_client().await?;

    // Use the total_files saved when rekey started (persistent across invocations)
    // Only use if migration is still active (not failed/completed/idle)
    let saved_total_files = session_manager
        .migration_info()
        .filter(|info| info.phase.is_active())
        .map(|info| info.total_files)
        .unwrap_or(0);

    let mut progress_bar: Option<indicatif::ProgressBar> = None;
    let mut progress_total: u64 = 0;
    let mut last_status: Option<ApiRekeyStatus> = None;
    let mut backup_triggered: bool = false;
    let mut waiting_for_cutover: bool = false;
    let mut last_poll = std::time::Instant::now()
        .checked_sub(status_poll_interval())
        .unwrap_or_else(std::time::Instant::now);
    let mut last_progress: Option<(u64, u64)> = None;
    let mut stagnant_updates: u32 = 0;
    let mut empty_progress_streak: u32 = 0;
    let mut force_poll_server = false;

    let poll = || async {
        fetch_rekey_status(&client, session_manager, &session, group_id, &server_url).await
    };

    if watch {
        ui::section("Rekey Status (watching)");
    } else {
        ui::section("Rekey Status");
    }

    if !watch {
        let mut status = poll().await?;
        // Use the total_files saved when rekey started
        if saved_total_files > 0 {
            status.progress.total_files = saved_total_files;
            status.progress.migrated_files = status.progress.migrated_files.min(saved_total_files);
        }
        if let Ok((local_total, local_migrated)) = local_client.coverage_progress_snapshot().await {
            if local_total > 0 {
                status.progress.total_files = status.progress.total_files.max(local_total);
                status.progress.migrated_files = status
                    .progress
                    .migrated_files
                    .max(local_migrated.min(local_total))
                    .min(status.progress.total_files);
            }
        }
        render_rekey_dashboard(&status);
        update_session_migration_from_status(session_manager, &status).await?;
        ensure_cutover_backup(session_manager, &status, &mut backup_triggered).await?;
        return Ok(());
    }

    loop {
        let now = std::time::Instant::now();
        let should_poll_server = force_poll_server
            || now.duration_since(last_poll) >= status_poll_interval()
            || last_status.is_none();

        if should_poll_server {
            force_poll_server = false;
            match poll().await {
                Ok(status) => {
                    last_status = Some(status);
                    last_poll = now;
                    if let Some(status_ref) = last_status.as_mut() {
                        // Use the total_files saved when rekey started
                        if saved_total_files > 0 {
                            status_ref.progress.total_files = saved_total_files;
                            status_ref.progress.migrated_files =
                                status_ref.progress.migrated_files.min(saved_total_files);
                        }
                    }
                    if let Some(status_ref) = last_status.as_ref() {
                        // Render dashboard using server values, with local coverage progress applied.
                        let mut display_total = status_ref.progress.total_files;
                        let mut display_migrated = status_ref.progress.migrated_files;

                        let mut used_local = false;
                        if let Ok((local_total, local_migrated)) =
                            local_client.coverage_progress_snapshot().await
                        {
                            if local_total > 0 {
                                let local_migrated = local_migrated.min(local_total);
                                display_total = display_total.max(local_total);
                                display_migrated = display_migrated.max(local_migrated);
                                display_migrated = display_migrated.min(display_total);
                                used_local = true;
                            }
                        }

                        // Detect stalled progress (same values repeated) and fall back to queue snapshot.
                        if display_total > 0 && display_migrated < display_total {
                            if let Some((prev_total, prev_migrated)) = last_progress {
                                if prev_total == display_total && prev_migrated == display_migrated
                                {
                                    stagnant_updates = stagnant_updates.saturating_add(1);
                                } else {
                                    stagnant_updates = 0;
                                }
                            }

                            if stagnant_updates >= 2 && !used_local {
                                if let Ok(snapshot) = local_client.rewrap_queue_snapshot().await {
                                    if snapshot.total_files >= display_total
                                        && snapshot.migrated_files >= display_migrated
                                    {
                                        display_total = snapshot.total_files;
                                        display_migrated =
                                            snapshot.migrated_files.min(snapshot.total_files);
                                    }
                                }
                            }
                            last_progress = Some((display_total, display_migrated));
                        } else {
                            stagnant_updates = 0;
                            last_progress = Some((display_total, display_migrated));
                        }

                        // Use a local copy of the status for display so table and bar stay in sync.
                        let mut display_status = status_ref.clone();
                        display_status.progress.total_files = display_total;
                        display_status.progress.migrated_files = display_migrated;

                        if display_total > 0 {
                            if progress_bar.is_none() || progress_total != display_total {
                                if let Some(existing) = progress_bar.take() {
                                    existing.finish_and_clear();
                                }
                                let pb = ui::progress::create_progress_bar(
                                    display_total,
                                    "Migrating files",
                                );
                                progress_total = display_total;
                                progress_bar = Some(pb);
                            }
                            if let Some(pb) = progress_bar.as_ref() {
                                let message = format!(
                                    "Migrated {} of {} files",
                                    display_migrated, display_total
                                );
                                ui::progress::update_progress_with_message(
                                    pb,
                                    display_migrated,
                                    &message,
                                );
                                pb.suspend(|| {
                                    render_rekey_dashboard(&display_status);
                                });
                            } else {
                                render_rekey_dashboard(&display_status);
                            }
                        } else {
                            if let Some(pb) = progress_bar.take() {
                                pb.finish_and_clear();
                                progress_total = 0;
                            }
                            render_rekey_dashboard(&display_status);
                        }

                        update_session_migration_from_status(session_manager, &display_status)
                            .await?;
                        ensure_cutover_backup(
                            session_manager,
                            &display_status,
                            &mut backup_triggered,
                        )
                        .await?;

                        let is_terminal = is_terminal_state(status_ref.status.as_str());
                        let is_empty_progress = display_total == 0 && !is_terminal;

                        // If the server reports no files, retry a few times with a short delay
                        // before giving up to allow recently enrolled folders to appear.
                        if is_empty_progress {
                            empty_progress_streak = empty_progress_streak.saturating_add(1);
                            if empty_progress_streak < EMPTY_PROGRESS_RETRY_LIMIT {
                                force_poll_server = true;
                                if let Some(pb) = progress_bar.as_ref() {
                                    pb.suspend(|| {
                                        ui::dim("No protected files reported yet; retrying...");
                                    });
                                } else {
                                    ui::dim("No protected files reported yet; retrying...");
                                }
                            }
                        } else {
                            empty_progress_streak = 0;
                        }

                        // Check if migration is actually complete (all files migrated)
                        let files_complete = if is_empty_progress {
                            empty_progress_streak >= EMPTY_PROGRESS_RETRY_LIMIT
                        } else {
                            display_migrated >= display_total
                        };

                        // Exit watch mode when:
                        // 1. All files migrated (work complete, awaiting cutover is fine), OR
                        // 2. Operation completed/failed/cancelled (terminal states)
                        let should_exit = is_terminal || files_complete;

                        if files_complete && !is_terminal && !waiting_for_cutover {
                            waiting_for_cutover = true;
                            if let Some(pb) = progress_bar.as_ref() {
                                pb.suspend(|| {
                                    ui::dim(
                                        "Files migrated; waiting for server cutover to complete...",
                                    );
                                });
                            } else {
                                ui::dim(
                                    "Files migrated; waiting for server cutover to complete...",
                                );
                            }
                        }

                        if should_exit {
                            if let Some(pb) = progress_bar.take() {
                                if status_ref.status.eq_ignore_ascii_case("completed") {
                                    // Completed - clear progress bar (dashboard already shows N/A)
                                    pb.finish_and_clear();
                                } else if files_complete {
                                    // All files migrated - show success
                                    ui::progress::finish_progress_with_result(
                                        &pb,
                                        true,
                                        "Rekey migration completed",
                                    );
                                } else {
                                    // Failed/cancelled before migration complete
                                    ui::progress::finish_progress_with_result(
                                        &pb,
                                        false,
                                        match status_ref.status.as_str() {
                                            "failed" => "Rekey failed",
                                            "cancelled" => "Rekey cancelled",
                                            _ => "Rekey finished",
                                        },
                                    );
                                }
                            }
                            break;
                        }
                    }
                }
                Err(err) => {
                    if let Some(pb) = progress_bar.as_ref() {
                        pb.suspend(|| {
                            ui::warning(&format!("Failed to refresh dashboard: {}", err));
                        });
                    } else {
                        ui::warning(&format!("Failed to refresh dashboard: {}", err));
                    }
                }
            }
        }

        // Local coverage snapshot to keep progress visible without server hits
        if let Ok((total, migrated)) = local_client.coverage_progress_snapshot().await {
            if total > 0 {
                let migrated = migrated.min(total);
                if progress_bar.is_none() || progress_total != total {
                    if let Some(existing) = progress_bar.take() {
                        existing.finish_and_clear();
                    }
                    let pb = ui::progress::create_progress_bar(total, "Migrating files");
                    progress_total = total;
                    progress_bar = Some(pb);
                }
                if let Some(pb) = progress_bar.as_ref() {
                    let message = format!("Local coverage: {} of {} files", migrated, total);
                    ui::progress::update_progress_with_message(pb, migrated, &message);
                }
            } else if let Ok(snapshot) = local_client.rewrap_queue_snapshot().await {
                if snapshot.total_files > 0 {
                    let migrated = snapshot.migrated_files.min(snapshot.total_files);
                    if progress_bar.is_none() || progress_total != snapshot.total_files {
                        if let Some(existing) = progress_bar.take() {
                            existing.finish_and_clear();
                        }
                        let pb = ui::progress::create_progress_bar(
                            snapshot.total_files,
                            "Migrating files",
                        );
                        progress_total = snapshot.total_files;
                        progress_bar = Some(pb);
                    }
                    if let Some(pb) = progress_bar.as_ref() {
                        let message = format!(
                            "Local rewrap: {} of {} files (pending {})",
                            migrated, snapshot.total_files, snapshot.pending_rewraps
                        );
                        ui::progress::update_progress_with_message(pb, migrated, &message);
                    }
                }
            }
        }

        sleep(LOCAL_PROGRESS_REFRESH_INTERVAL).await;
    }

    Ok(())
}

async fn handle_rekey_cutover(
    force: bool,
    immediate_cleanup: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Force Rekey Cutover");

    let group_id = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(group_id, "hybridcipher rekey cutover")
        .await?;

    let client = session_manager.create_client().await?;

    match client.rekey_status().await? {
        Some(_) => {}
        None => {
            return Err(CliError::validation(
                "No active rekey operation is available for cutover",
            ));
        }
    }
    let summary = client
        .cutover_rekey(force, immediate_cleanup)
        .await
        .map_err(CliError::from)?;

    ui::success("Cutover completed.");
    ui::info(&format!("Cutover ID: {}", summary.cutover_id));
    ui::info(&format!("New epoch: {}", summary.new_epoch_id));
    ui::info(&format!("Old epoch: {}", summary.old_epoch_id));
    ui::info(&format!("Completed at: {}", summary.completed_at));
    ui::info(&format!("Cleanup status: {}", summary.cleanup_status));
    ui::info("Run 'hybridcipher rekey status' to verify the migration state.");

    if let Err(err) = crate::commands::recovery::append_active_epoch_to_artifact(
        session_manager,
        summary.group_id,
    )
    .await
    {
        ui::warning(&format!(
            "Cutover completed but failed to append backup artifact: {}",
            err
        ));
    }

    Ok(())
}

async fn handle_rekey_fallback(
    reason: Option<String>,
    assume_yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    ui::section("Cancel Rekey Operation");

    let group_id = session_manager.ensure_current_group().await?;
    session_manager
        .require_group_admin(group_id, "hybridcipher rekey fallback")
        .await?;

    let normalized_reason = reason
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    if !assume_yes {
        let mut prompt = String::from(
            "This will cancel the active rekey operation and restore the previous epoch. Continue?",
        );
        if let Some(ref detail) = normalized_reason {
            prompt.push_str(&format!("\nReason: {}", detail));
        }

        if !ui::prompts::confirm_with_default(&prompt, false)? {
            ui::info("Rekey fallback aborted at user request.");
            return Ok(());
        }
    }

    session_manager.require_auth()?;
    session_manager.ensure_current_group().await?;
    let client = session_manager.create_client().await?;

    let summary = client
        .fallback_rekey(normalized_reason.clone())
        .await
        .map_err(CliError::from)?;

    if let Some(mut info) = session_manager.migration_info() {
        info.phase = MigrationPhase::Failed {
            error: "Rekey cancelled via fallback".to_string(),
        };
        info.target_epoch = None;
        info.progress = 0.0;
        info.total_files = 0;
        info.pending_files.clear();
        session_manager.update_migration_info(info)?;
    }

    session_manager.synchronize_migration_state().await?;

    ui::success("Rekey operation cancelled.");
    let group_label = session_manager.group_label(&summary.group_id).await;
    ui::info(&format!("Group: {}", group_label));
    ui::info(&format!("Rekey ID: {}", summary.rekey_id));
    ui::info(&format!(
        "Cancelled at: {}",
        ui::formatting::format_local_datetime(&summary.cancelled_at)
    ));

    if let Some(reason) = summary.reason.as_ref() {
        ui::info(&format!("Reason: {}", reason));
    }

    if let Some(epoch) = summary.previous_epoch_number {
        ui::info(&format!("Restored epoch: {}", epoch));
    } else {
        ui::dim("Previous epoch information unavailable; verify with status command.");
    }

    if let Some(epoch) = summary.new_epoch_number {
        ui::dim(&format!("Discarded staged epoch: {}", epoch));
    }

    ui::info("Run 'hybridcipher rekey status' to confirm the current state.");

    Ok(())
}

async fn fetch_rekey_status(
    client: &reqwest::Client,
    session_manager: &SessionManager,
    session: &crate::session::Session,
    group_id: Uuid,
    server_url: &str,
) -> Result<ApiRekeyStatus, CliError> {
    let response = client
        .get(format!(
            "{}/api/v1/groups/{}/rekey/status",
            server_url, group_id
        ))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to query rekey status: {}", e)))?;

    if response.status() == StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("rekey_status")?;
        return Err(CliError::authentication(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    if response.status() == StatusCode::NOT_FOUND {
        return Err(CliError::validation(
            "No active rekey operation for the current group",
        ));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(CliError::network(format!(
            "Failed to fetch rekey status ({}): {}",
            status, body
        )));
    }

    response
        .json()
        .await
        .map_err(|e| CliError::network(format!("Failed to parse rekey status response: {}", e)))
}

fn render_rekey_dashboard(status: &ApiRekeyStatus) {
    use crate::ui::formatting::{format_progress, format_table};

    ui::section("Rekey Dashboard");
    ui::info(&format!("Rekey ID: {}", status.rekey_id));
    if let Some(epoch) = &status.new_epoch_id {
        ui::info(&format!("Target epoch: {}", epoch));
    }
    ui::info(&format!("State: {}", status.status));
    ui::info(&format!("Started: {}", status.started_at));
    ui::info(&format!("Last update: {}", status.last_updated));
    if let Ok(elapsed) = (status.last_updated - status.started_at).to_std() {
        ui::info(&format!(
            "Elapsed: {}",
            ui::formatting::format_duration(elapsed)
        ));
        if status.progress.total_files > 0 {
            let eta = ui::progress::utils::display_eta(
                status.progress.migrated_files,
                status.progress.total_files,
                elapsed,
            );
            ui::info(&format!("Estimated time remaining: {}", eta));
        }
    }
    ui::info(&format!(
        "Cutover gates pass automatically: {}",
        if status.can_cutover { "yes" } else { "pending" }
    ));
    if let Some(commitment) = &status.descriptor_commitment {
        ui::info(&format!("Descriptor commitment: {}", commitment));
    }

    // Show rekey operation state machine progress
    ui::subsection("Rekey Operation Progress");
    let rekey_state = match status.status.as_str() {
        "in_progress" => "Start → [Active] → Cutover → Complete",
        "ready_for_cutover" | "ready" => "Start → Active → [Cutover] → Complete",
        "completed" => "Start → Active → Cutover → [Complete] ✓",
        "failed" => "Start → Active → [Failed] ✗",
        "cancelled" => "Start → [Cancelled] ✗",
        _ => &format!("[{}]", status.status),
    };
    ui::info(&format!("State: {}", rekey_state));

    // Show file migration progress separately
    ui::subsection("File Migration Progress");
    let mut progress_rows = Vec::new();
    if status.status == "completed" {
        // For completed rekeys, show N/A since migration tracking data may be stale
        progress_rows.push(vec![
            "Files migrated".to_string(),
            "N/A (rekey completed)".to_string(),
        ]);
        println!("{}", format_table(&["Metric", "Value"], &progress_rows));
        ui::info("Tip: Use 'hybridcipher coverage scan' followed by 'hybridcipher coverage status' to check the current migration status for the active epoch.");
    } else if status.progress.total_files == 0 {
        progress_rows.push(vec![
            "Files migrated".to_string(),
            "No protected files in group (nothing to migrate)".to_string(),
        ]);
        println!("{}", format_table(&["Metric", "Value"], &progress_rows));
    } else {
        let file_percent =
            (status.progress.migrated_files as f64 / status.progress.total_files as f64) * 100.0;
        progress_rows.push(vec![
            "Files migrated".to_string(),
            format!(
                "{} / {} ({})",
                status.progress.migrated_files,
                status.progress.total_files,
                format_progress(file_percent)
            ),
        ]);
        println!("{}", format_table(&["Metric", "Value"], &progress_rows));
    }

    // For completed operations, show completion message instead of stale policy data
    if status.status == "completed" && status.policy.is_none() {
        ui::subsection("Policy Gates");
        ui::success("✓ All policy gates passed - cutover completed successfully");
        ui::info(&format!(
            "New epoch {} is now active",
            status.new_epoch_id.as_deref().unwrap_or("unknown")
        ));
    } else if let Some(policy) = &status.policy {
        let mut policy_rows = Vec::new();
        policy_rows.push(vec!["Decision".to_string(), policy.decision.to_uppercase()]);
        let quorum_requirement = if policy.device_population == 0 {
            "No users registered".to_string()
        } else if policy.device_population < 6 {
            // For small groups, show exact user count more prominently
            format!(
                "{}/{} users required",
                policy.minimum_quorum_devices.max(1),
                policy.device_population
            )
        } else {
            // For larger groups, show percentage with user count
            format!(
                "{} of {} users ({} required)",
                format_progress(policy.minimum_quorum_percent.clamp(0.0, 100.0)),
                policy.device_population,
                policy.minimum_quorum_devices.max(1)
            )
        };
        policy_rows.push(vec!["Quorum requirement".to_string(), quorum_requirement]);

        let confirmed_value = if policy.device_population > 0 {
            format!(
                "{}/{}",
                policy.required_devices_met, policy.device_population
            )
        } else {
            policy.required_devices_met.to_string()
        };
        policy_rows.push(vec!["Confirmed users".to_string(), confirmed_value]);

        let required_missing = policy
            .required_devices
            .saturating_sub(policy.required_devices_met);
        policy_rows.push(vec![
            "Required users met".to_string(),
            format!(
                "{}/{} (missing {})",
                policy.required_devices_met, policy.required_devices, required_missing
            ),
        ]);
        policy_rows.push(vec![
            "Stale devices".to_string(),
            policy.stale_devices.to_string(),
        ]);
        policy_rows.push(vec![
            "Activation time".to_string(),
            policy.activation_time.to_string(),
        ]);
        policy_rows.push(vec![
            "Grace deadline".to_string(),
            policy.grace_deadline.to_string(),
        ]);
        policy_rows.push(vec![
            "Retention deadline".to_string(),
            policy.retention_deadline.to_string(),
        ]);

        ui::subsection("Policy Gates");
        println!("{}", format_table(&["Gate", "Value"], &policy_rows));
    }

    if !status.errors.is_empty() {
        ui::subsection("Recent Issues");
        for error in &status.errors {
            ui::warning(&format!("[{}] {}", error.error_type, error.message));
        }
    }
}

fn is_terminal_state(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

async fn ensure_initiator_progress(client: &LocalClient) -> Result<(), ClientError> {
    let status = match client.rekey_status().await {
        Ok(Some(op)) => op,
        Ok(None) => return Ok(()),
        Err(ClientError::InvalidState(_)) => return Ok(()),
        Err(err) => return Err(err),
    };

    let progress_result = if status.progress.confirmed_members == 0 {
        client
            .report_rekey_progress(Some(RekeyProgressState::Confirmed), Some(100))
            .await
    } else {
        client.report_rekey_progress(None, None).await
    };

    if let Err(err) = progress_result {
        if !matches!(err, ClientError::InvalidState(_)) {
            return Err(err);
        }
    }

    client.schedule_rekey_heartbeat().await;

    Ok(())
}

async fn run_local_coverage_migration(client: &LocalClient) -> Result<(), CliError> {
    ui::section("Local Coverage Migration");
    ui::info("Running coverage scan...");
    client
        .coverage_rescan(None)
        .await
        .map_err(|err| CliError::coverage(format!("Coverage scan failed: {}", err)))?;
    ui::success("Coverage scan complete.");

    let mut progress_bar: Option<indicatif::ProgressBar> = None;
    let mut progress_total: u64 = 0;

    let progress = client
        .coverage_migrate_orphans_with_progress(None, None, true, |progress| {
            let total = progress.total_files as u64;
            if total == 0 {
                return;
            }
            if progress_bar.is_none() || progress_total != total {
                if let Some(existing) = progress_bar.take() {
                    existing.finish_and_clear();
                }
                let pb = ui::progress::create_progress_bar(total, "Migrating files");
                progress_total = total;
                progress_bar = Some(pb);
            }
            if let Some(pb) = progress_bar.as_ref() {
                let message = if progress.failed_files > 0 {
                    format!(
                        "Migrated {} of {} files ({} failed)",
                        progress.migrated_files, progress.total_files, progress.failed_files
                    )
                } else {
                    format!(
                        "Migrated {} of {} files",
                        progress.migrated_files, progress.total_files
                    )
                };
                ui::progress::update_progress_with_message(
                    pb,
                    progress.migrated_files as u64,
                    &message,
                );
            }
        })
        .await
        .map_err(|err| {
            CliError::coverage(format!("Failed to migrate orphaned entries: {}", err))
        })?;

    if let Some(pb) = progress_bar.take() {
        if progress.total_files > 0 {
            let success = progress.failed_files == 0;
            let message = if progress.failed_files > 0 {
                format!(
                    "Coverage migration completed with {} failure{}",
                    progress.failed_files,
                    if progress.failed_files == 1 { "" } else { "s" }
                )
            } else {
                "Coverage migration completed".to_string()
            };
            ui::progress::finish_progress_with_result(&pb, success, &message);
        } else {
            pb.finish_and_clear();
        }
    }

    if progress.total_files == 0 {
        ui::info("No wrong-epoch orphaned entries were migrated.");
    } else if progress.migrated_files == 0 {
        ui::warning("No files were migrated during this run.");
    } else if progress.failed_files > 0 {
        ui::warning(&format!(
            "Migrated {} of {} files ({} failed).",
            progress.migrated_files, progress.total_files, progress.failed_files
        ));
        println!();
        ui::info("ℹ️  Cutover will be performed automatically after 24 hours, or you can perform it manually using:");
        ui::info("   hybridcipher rekey cutover");
    } else {
        ui::success(&format!(
            "Migrated {} of {} files.",
            progress.migrated_files, progress.total_files
        ));
        println!();
        ui::info("ℹ️  Cutover will be performed automatically after 24 hours, or you can perform it manually using:");
        ui::info("   hybridcipher rekey cutover");
    }

    Ok(())
}

fn is_cutover_complete(status: &ApiRekeyStatus) -> bool {
    let state = status.status.as_str();
    state.eq_ignore_ascii_case("completed")
        || state.eq_ignore_ascii_case("cutover_completed")
        || state.eq_ignore_ascii_case("cutover_complete")
}

async fn ensure_cutover_backup(
    session_manager: &SessionManager,
    status: &ApiRekeyStatus,
    backup_triggered: &mut bool,
) -> Result<(), CliError> {
    if *backup_triggered || !is_cutover_complete(status) {
        return Ok(());
    }

    ui::dim("Detected rekey cutover completion; refreshing recovery backup...");
    match crate::commands::recovery::append_active_epoch_to_artifact(
        session_manager,
        status.group_id,
    )
    .await
    {
        Ok(_) => {
            *backup_triggered = true;
        }
        Err(err) => {
            *backup_triggered = true;
            ui::warning(&format!(
                "Rekey cutover completed, but recovery backup update failed: {}",
                err
            ));
        }
    }

    Ok(())
}

async fn update_session_migration_from_status(
    session_manager: &SessionManager,
    status: &ApiRekeyStatus,
) -> Result<(), CliError> {
    let progress_percent = if status.progress.total_files == 0 {
        0.0
    } else {
        (status.progress.migrated_files as f64 / status.progress.total_files as f64) * 100.0
    };

    let mut info = session_manager
        .migration_info()
        .unwrap_or_else(|| MigrationInfo {
            current_epoch: 0,
            target_epoch: None,
            migration_start: Some(status.started_at),
            phase: MigrationPhase::Idle,
            pending_files: Vec::new(),
            progress: 0.0,
            total_files: status.progress.total_files,
        });

    if info.migration_start.is_none() {
        info.migration_start = Some(status.started_at);
    }
    if info.current_epoch == 0 {
        if let Ok(client) = session_manager.create_client().await {
            if let Some(epoch) = client.current_epoch_id().await {
                info.current_epoch = epoch;
            }
        }
    }
    if info.target_epoch.is_none() {
        info.target_epoch = parse_epoch_hint(status.new_epoch_id.as_deref(), Some(status.group_id));
    }
    info.progress = progress_percent;
    info.phase = migration_phase_from_status(status);

    match status.status.as_str() {
        "completed" => {
            if let Some(target_epoch) = info.target_epoch {
                info.current_epoch = target_epoch;
            }
            info.target_epoch = None;
            // Don't override progress to 100% - keep actual file migration percentage
            // The rekey operation completed, but files may still be migrating
        }
        "failed" | "cancelled" => {
            info.target_epoch = None;
        }
        _ => {}
    }

    session_manager.update_migration_info(info)?;
    session_manager.synchronize_migration_state().await?;
    Ok(())
}

fn migration_phase_from_status(status: &ApiRekeyStatus) -> MigrationPhase {
    match status.status.as_str() {
        "completed" => MigrationPhase::Completed,
        "ready_for_cutover" | "ready" => MigrationPhase::ReadyForCutover,
        "cutover_in_progress" | "cutover" => MigrationPhase::CutoverInProgress,
        "failed" => MigrationPhase::Failed {
            error: status
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Rekey operation failed".to_string()),
        },
        "in_progress" | "migrating" => MigrationPhase::InProgress,
        "cancelled" => MigrationPhase::Failed {
            error: "Rekey operation was cancelled".to_string(),
        },
        _ => MigrationPhase::Started,
    }
}

fn parse_epoch_hint(epoch_id: Option<&str>, group_id: Option<Uuid>) -> Option<u64> {
    let Some(id) = epoch_id else {
        return None;
    };
    if let Some(group) = group_id {
        if let Ok(uuid) = Uuid::parse_str(id) {
            if let Some(mapped) = EpochIdMapper::uuid_to_u64(uuid, group.as_bytes()) {
                return Some(mapped);
            }
        }
    }

    // Legacy fallback for descriptors created before deterministic mapping.
    let digits: String = id.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

#[derive(Debug, Deserialize)]
struct ApiRekeyResponse {
    rekey_id: Uuid,
    #[serde(rename = "group_id")]
    _group_id: Uuid,
    new_epoch_id: String,
    #[serde(rename = "status")]
    _status: String,
    initiated_at: DateTime<Utc>,
    #[serde(rename = "estimated_completion")]
    _estimated_completion: DateTime<Utc>,
    #[serde(rename = "migration_progress")]
    _migration_progress: ApiMigrationProgress,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiRekeyStatus {
    rekey_id: Uuid,
    #[serde(rename = "group_id")]
    group_id: Uuid,
    status: String,
    #[serde(default)]
    new_epoch_id: Option<String>,
    progress: ApiMigrationProgress,
    started_at: DateTime<Utc>,
    last_updated: DateTime<Utc>,
    errors: Vec<ApiRekeyError>,
    can_cutover: bool,
    #[serde(default)]
    policy: Option<ApiPolicySnapshot>,
    #[serde(default)]
    descriptor_commitment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiMigrationProgress {
    total_files: u64,
    migrated_files: u64,
    #[serde(rename = "total_members")]
    _total_members: u32,
    #[serde(rename = "confirmed_members")]
    _confirmed_members: u32,
    #[serde(default)]
    #[serde(rename = "reporting_members")]
    _reporting_members: u32,
    #[serde(rename = "estimated_time_remaining_minutes")]
    _estimated_time_remaining_minutes: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiRekeyError {
    error_type: String,
    message: String,
    #[serde(default)]
    #[serde(rename = "timestamp")]
    _timestamp: Option<DateTime<Utc>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct ApiPolicySnapshot {
    decision: String,
    activation_time: DateTime<Utc>,
    grace_deadline: DateTime<Utc>,
    retention_deadline: DateTime<Utc>,
    #[serde(default)]
    coverage_percent_bytes: Option<f64>,
    #[serde(default)]
    coverage_percent_items: Option<f64>,
    #[serde(rename = "quorum_devices")]
    _quorum_devices: usize,
    minimum_quorum_devices: usize,
    #[serde(default)]
    minimum_quorum_percent: f64,
    #[serde(default)]
    device_population: usize,
    #[serde(default)]
    required_devices: usize,
    required_devices_met: usize,
    #[serde(default)]
    stale_devices: usize,
}
