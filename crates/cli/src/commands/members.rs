use crate::{
    commands::{rekey, RekeyCommands},
    error::CliError,
    security::membership_signing,
    session::{
        messages_join_card_to_client, JoinCardPinState, SessionManager, UnverifiedDeviceReport,
    },
    ui,
    ui::formatting::{format_local_datetime_with_relative, format_table},
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use hex;
use hybridcipher_client::{invitation::JoinCard, PinningPolicy, Storage};
use hybridcipher_crypto::signatures::{self, Signature as MembershipSignature, VerifyingKey};
use hybridcipher_merkle::InclusionProof;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MEMBERSHIP_LEAF_PREFIX: &str = "membership-leaf";
const MEMBERSHIP_ROOT_PREFIX: &[u8] = b"membership-root:";
const UNVERIFIED_DEVICES_CACHE_PREFIX: &str = "unverified_devices";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MembershipProofResponse {
    snapshot_id: Uuid,
    group_id: Uuid,
    merkle_root_hex: String,
    signature_base64: String,
    verifying_key_base64: String,
    signing_key_id: Option<String>,
    total_members: u64,
    membership_generated_at: DateTime<Utc>,
    user_id: Uuid,
    role: String,
    salt_base64: String,
    leaf: String,
    proof: InclusionProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MembershipProofCacheEntry {
    cached_at: DateTime<Utc>,
    proof: MembershipProofResponse,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UnverifiedDeviceEntry {
    group_id: Uuid,
    user_id: Uuid,
    device_id: String,
    reasons: Vec<String>,
    recorded_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    member_label: Option<String>,
}

const MEMBERSHIP_PROOF_CACHE_PREFIX: &str = "membership_proof_cache";

/// Handle add member command
pub async fn handle_add_member(
    user_id: String,
    require_verified: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    // Require authentication
    session_manager.require_auth()?;
    let pin_config = session_manager.load_pinning_config().await?;
    let require_second_party = pin_config.require_second_party_verification || require_verified;

    ui::section("Add Group Member");
    ui::info(&format!("Adding member: {}", user_id));

    // Determine active group for validation and to pass into session layer
    let group_id = session_manager.ensure_active_group().await?;

    session_manager
        .require_group_admin(group_id, "hybridcipher add-member")
        .await?;

    let mut join_card_materials: Vec<JoinCardMaterial> = Vec::new();
    if user_id.contains('@') {
        match session_manager.fetch_join_cards_for_email(&user_id).await {
            Ok(cards) => {
                if cards.is_empty() {
                    ui::dim("No join card published for this user yet");
                } else {
                    ui::dim(&format!(
                        "Found {} join card(s) in server directory",
                        cards.len()
                    ));
                }

                for server_card in cards {
                    match messages_join_card_to_client(&server_card) {
                        Ok(join_card) => {
                            let canonical_json =
                                serde_json::to_string_pretty(&join_card).map_err(|e| {
                                    CliError::format(format!(
                                        "Failed to serialise join card: {}",
                                        e
                                    ))
                                })?;
                            join_card_materials.push(JoinCardMaterial {
                                join_card,
                                canonical_json,
                                from_cache: false,
                                source_path: None,
                            });
                        }
                        Err(err) => {
                            ui::warning(&format!(
                                "Join card from directory failed validation: {}",
                                err
                            ));
                        }
                    }
                }
            }
            Err(err) => {
                ui::warning(&format!("Failed to fetch join card directory: {}", err));
            }
        }
    }

    if join_card_materials.is_empty() {
        join_card_materials.push(load_join_card_for_member(&user_id, session_manager)?);
    }

    let allow_cache = join_card_materials.len() == 1;
    if !allow_cache {
        ui::dim("Multiple join cards detected; skipping local cache to avoid overwriting");
    }

    let mut seen_devices: HashSet<String> = HashSet::new();
    let mut welcome_messages: Vec<crate::commands::welcome::ApiWelcomeMessage> = Vec::new();
    let mut unverified_devices: Vec<UnverifiedDevice> = Vec::new();

    let client = session_manager.create_client().await?;
    let pinning_policy = PinningPolicy::AllowUnverified;

    for material in join_card_materials {
        let JoinCardMaterial {
            join_card,
            canonical_json,
            from_cache,
            source_path,
        } = material;

        let device_id = join_card.device_id.clone();
        if !seen_devices.insert(device_id.clone()) {
            ui::warning(&format!(
                "Duplicate join card detected for device {}; ignoring duplicate",
                device_id
            ));
            continue;
        }

        let mut unverified_reasons: Vec<String> = Vec::new();
        let mut pin_reasons: Vec<String> = Vec::new();
        let mut pin_ok = true;

        let pin_state = match session_manager
            .check_or_restore_join_card_pin_with_auto_pin(&join_card, true)
            .await
        {
            Ok(state) => state,
            Err(err) => {
                let message = format!(
                    "Join card validation failed for device {}: {}",
                    device_id, err
                );
                if require_verified {
                    return Err(CliError::member_management(message));
                }
                ui::warning(&message);
                continue;
            }
        };

        match pin_state {
            JoinCardPinState::AlreadyPinned | JoinCardPinState::RestoredFromCache => {}
            JoinCardPinState::Unverified { auto_pinned } => {
                pin_ok = false;
                if auto_pinned {
                    pin_reasons.push("Pin status: auto-pinned (unverified)".to_string());
                } else {
                    pin_reasons.push("Pin status: unverified".to_string());
                }
            }
            JoinCardPinState::Missing => {
                pin_ok = false;
                pin_reasons.push("Pin status: unpinned".to_string());
            }
            JoinCardPinState::Expired(pinned_at) => {
                pin_ok = false;
                pin_reasons.push(format!(
                    "Pin status: expired at {}",
                    ui::formatting::format_local_datetime(&pinned_at)
                ));
            }
        }

        if require_second_party {
            match session_manager
                .get_second_party_status(&join_card.user_id.to_string(), &join_card.device_id)
                .await
            {
                Ok(Some((status, last_error))) => {
                    if status != "verified" {
                        let mut reason = if pin_ok {
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
                    let reason = if pin_ok {
                        "Pinned but second-party not verified: unknown".to_string()
                    } else {
                        "Second-party status: unknown".to_string()
                    };
                    unverified_reasons.push(reason);
                }
                Err(err) => {
                    let reason = if pin_ok {
                        format!(
                            "Pinned but second-party not verified: unavailable ({})",
                            err
                        )
                    } else {
                        format!("Second-party status unavailable: {}", err)
                    };
                    if require_verified {
                        return Err(CliError::member_management(reason));
                    }
                    unverified_reasons.push(reason);
                }
            }
        }

        if require_verified && !unverified_reasons.is_empty() {
            let mut blocking_reasons = unverified_reasons.clone();
            if !pin_reasons.is_empty() {
                blocking_reasons.extend(pin_reasons.iter().cloned());
            }

            let mut strict_steps: Vec<String> = Vec::new();
            if pin_reasons
                .iter()
                .any(|reason| reason.contains("unpinned") || reason.contains("expired"))
            {
                strict_steps.push(format!(
                    "If device is not pinned: `hybridcipher pin add --user {} --device {} --fingerprint <FP>`",
                    user_id, join_card.device_id
                ));
            }
            if pin_reasons
                .iter()
                .any(|reason| reason.contains("unverified"))
            {
                strict_steps.push(format!(
                    "If device is already pinned but unverified: `hybridcipher pin verify {} {} --fingerprint <FP>`",
                    user_id, join_card.device_id
                ));
            }
            if require_second_party {
                strict_steps.push(format!(
                    "If second-party is not verified: `hybridcipher pin second-party-enqueue --target-user {} --target-device {} --fingerprint <FP>`",
                    user_id, join_card.device_id
                ));
            }
            strict_steps.push(format!(
                "Retry strict add: `hybridcipher add-member --verified {}`",
                user_id
            ));
            let strict_steps = strict_steps
                .into_iter()
                .enumerate()
                .map(|(idx, step)| format!("{}. {}", idx + 1, step))
                .collect::<Vec<_>>();

            return Err(CliError::member_management(format!(
                "Strict verification required: `add-member --verified` was blocked.\n\
                 \n\
                 Target device: {}:{}\n\
                 Trust state: {}\n\
                 \n\
                 To continue in strict mode:\n\
                 {}\n\
                 \n\
                 Optional non-strict path:\n\
                 - Add now, verify later: `hybridcipher add-member {}`",
                join_card.user_id,
                join_card.device_id,
                blocking_reasons.join("; "),
                strict_steps.join("\n"),
                user_id
            )));
        }

        let generated_welcome = match client
            .generate_welcome_for_join_card_with_policy(
                group_id,
                join_card.clone(),
                None,
                pinning_policy,
            )
            .await
        {
            Ok(welcome) => welcome,
            Err(err) => {
                let message = format!(
                    "Failed to generate Welcome payload for device {}: {}",
                    device_id, err
                );
                if require_verified {
                    return Err(CliError::member_management(message));
                }
                ui::warning(&message);
                continue;
            }
        };

        welcome_messages.push(crate::commands::welcome::ApiWelcomeMessage::from_generated(
            &generated_welcome,
        ));

        let verified = unverified_reasons.is_empty() && pin_reasons.is_empty();
        if !pin_reasons.is_empty() {
            unverified_reasons.extend(pin_reasons);
        }
        if !verified {
            unverified_devices.push(UnverifiedDevice {
                user_id: join_card.user_id,
                device_id: device_id.clone(),
                reasons: unverified_reasons,
            });
        }

        // Cache join card securely for future use if it was newly provided and verified.
        if !from_cache && allow_cache {
            if verified {
                match session_manager.cache_join_card(&user_id, &canonical_json) {
                    Ok(path) => {
                        ui::dim(&format!("Join card cached securely at {}", path.display()));
                        if let Some(source) = &source_path {
                            ui::dim(&format!(
                                "Reminder: remove or archive the plaintext join card at {} once onboarding is complete.",
                                source.display()
                            ));
                        }
                    }
                    Err(err) => {
                        ui::warning(&format!(
                            "Failed to cache join card for future use: {}",
                            err
                        ));
                    }
                }
            } else {
                ui::dim(&format!(
                    "Join card for device {} not cached because it is unverified",
                    device_id
                ));
            }
        }
    }

    if welcome_messages.is_empty() {
        return Err(CliError::member_management(
            "No valid join cards were available to generate Welcome messages.".to_string(),
        ));
    }

    let welcome_json = crate::commands::welcome::serialize_welcome_payloads(&welcome_messages)?;

    match session_manager
        .add_member_http(&user_id, welcome_json)
        .await
    {
        Ok(()) => {
            ui::success(&format!("Member '{}' added successfully!", user_id));
            ui::info("Welcome messages generated locally and submitted to the server");
        }
        Err(e) => {
            ui::error(&format!("Failed to add member: {}", e));
            return Err(e);
        }
    }

    if !unverified_devices.is_empty() {
        if let Err(err) = record_unverified_devices(
            session_manager,
            group_id,
            Some(user_id.clone()),
            &unverified_devices,
        )
        .await
        {
            ui::warning(&format!(
                "Failed to record unverified devices locally: {}",
                err
            ));
        }

        if require_second_party {
            ui::warning(
                "Some devices were added without pinning and/or second-party verification:",
            );
        } else {
            ui::warning("Some devices were added without pinning verification:");
        }
        for device in &unverified_devices {
            ui::info(&format!(
                "- {}:{} ({})",
                device.user_id,
                device.device_id,
                device.reasons.join("; ")
            ));
        }
        if require_second_party {
            ui::dim(
                "Next steps: verify unverified pins (`hybridcipher pin verify <USER_ID_OR_EMAIL> <DEVICE_ID> --fingerprint <FP>` or `--safety-number <SN>`), pin missing devices (`hybridcipher pin add --user <EMAIL_OR_ID> --device <DEVICE_ID>`), and complete second-party verification (`hybridcipher pin second-party-enqueue --status --target-user <USER_ID_OR_EMAIL> --target-device <DEVICE_ID>`).",
            );
        } else {
            ui::dim(
                "Next steps: verify unverified pins (`hybridcipher pin verify <USER_ID_OR_EMAIL> <DEVICE_ID> --fingerprint <FP>` or `--safety-number <SN>`) and pin missing devices (`hybridcipher pin add --user <EMAIL_OR_ID> --device <DEVICE_ID>`).",
            );
        }
    }

    Ok(())
}

/// List unverified devices recorded for a group
pub async fn handle_unverified_devices(
    group_id: Option<String>,
    all_group: bool,
    include_resolved: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    session_manager.require_auth()?;

    ui::section("Unverified Devices");

    if all_group {
        let group_ids = session_manager.list_admin_group_ids_with_cache().await?;
        if group_ids.is_empty() {
            ui::success("No admin groups found for the current user.");
            return Ok(());
        }

        let mut total_devices = 0usize;
        for group_id in group_ids {
            let group_uuid = match Uuid::parse_str(&group_id) {
                Ok(uuid) => uuid,
                Err(err) => {
                    ui::warning(&format!(
                        "Skipping invalid group ID '{}': {}",
                        group_id, err
                    ));
                    continue;
                }
            };

            let group_label = session_manager.group_label_for_id(&group_id).await;
            ui::info(&format!("Group: {}", group_label));
            match collect_unverified_devices_for_group(
                group_uuid,
                include_resolved,
                session_manager,
            )
            .await?
            {
                UnverifiedDevicesSource::Server(entries) => {
                    if entries.is_empty() {
                        ui::dim("  No unverified devices recorded.");
                        continue;
                    }
                    total_devices += entries.len();
                    render_unverified_devices_server(session_manager, group_uuid, &entries).await?;
                }
                UnverifiedDevicesSource::Cache(entries) => {
                    if entries.is_empty() {
                        ui::dim("  No unverified devices recorded (cache).");
                        continue;
                    }
                    total_devices += entries.len();
                    render_unverified_devices_cache(session_manager, group_uuid, &entries).await?;
                }
            }
        }

        if total_devices == 0 {
            ui::success("No unverified devices recorded across admin groups.");
        } else {
            ui::info(&format!(
                "{} unverified device(s) recorded across admin groups.",
                total_devices
            ));
        }
        return Ok(());
    }

    let group_uuid = if let Some(group_id) = group_id {
        Uuid::parse_str(&group_id).map_err(|e| {
            CliError::invalid_input(format!("Invalid group ID '{}': {}", group_id, e))
        })?
    } else {
        session_manager.ensure_active_group().await?
    };

    session_manager
        .require_group_admin(group_uuid, "hybridcipher unverified-devices")
        .await?;

    match collect_unverified_devices_for_group(group_uuid, include_resolved, session_manager)
        .await?
    {
        UnverifiedDevicesSource::Server(entries) => {
            if entries.is_empty() {
                ui::success("No unverified devices recorded for this group.");
                return Ok(());
            }
            render_unverified_devices_server(session_manager, group_uuid, &entries).await?;
        }
        UnverifiedDevicesSource::Cache(entries) => {
            if entries.is_empty() {
                ui::success("No unverified devices recorded for this group.");
                return Ok(());
            }
            render_unverified_devices_cache(session_manager, group_uuid, &entries).await?;
        }
    }

    Ok(())
}

enum UnverifiedDevicesSource {
    Server(Vec<crate::session::UnverifiedDeviceInfo>),
    Cache(Vec<UnverifiedDeviceEntry>),
}

async fn collect_unverified_devices_for_group(
    group_uuid: Uuid,
    include_resolved: bool,
    session_manager: &SessionManager,
) -> Result<UnverifiedDevicesSource, CliError> {
    match session_manager
        .list_unverified_devices(group_uuid, include_resolved)
        .await
    {
        Ok(entries) => Ok(UnverifiedDevicesSource::Server(entries)),
        Err(err) => {
            ui::warning(&format!(
                "Failed to fetch server unverified devices: {}. Falling back to local cache.",
                err
            ));
            let entries = load_unverified_devices(session_manager, group_uuid).await?;
            Ok(UnverifiedDevicesSource::Cache(entries))
        }
    }
}

async fn render_unverified_devices_server(
    session_manager: &SessionManager,
    group_uuid: Uuid,
    entries: &[crate::session::UnverifiedDeviceInfo],
) -> Result<(), CliError> {
    hydrate_user_email_cache(session_manager, group_uuid, entries, &[])
        .await
        .ok();

    let headers = [
        "User",
        "Device",
        "Reasons",
        "First Seen",
        "Last Seen",
        "Reported By",
    ];
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        let user_display = format_user_display(session_manager, entry.user_id, None).await;
        let reported_by_display =
            format_user_display(session_manager, entry.reported_by, None).await;
        let mut reasons = entry.reasons.join("; ");
        if let Some(resolved_at) = entry.resolved_at {
            let resolved_label = format!(
                "resolved at {}",
                format_local_datetime_with_relative(&resolved_at)
            );
            if let Some(reason) = entry.resolved_reason.as_deref() {
                reasons = if reasons.is_empty() {
                    format!("Resolved: {} ({})", reason, resolved_label)
                } else {
                    format!("{} | Resolved: {} ({})", reasons, reason, resolved_label)
                };
            } else {
                reasons = if reasons.is_empty() {
                    format!("Resolved ({})", resolved_label)
                } else {
                    format!("{} | Resolved ({})", reasons, resolved_label)
                };
            }
        }
        rows.push(vec![
            user_display,
            entry.device_id.clone(),
            reasons,
            format_local_datetime_with_relative(&entry.first_seen_at),
            format_local_datetime_with_relative(&entry.last_seen_at),
            reported_by_display,
        ]);
    }

    println!("{}", format_table(&headers, &rows));
    ui::info(&format!("{} unverified device(s) recorded.", entries.len()));
    Ok(())
}

async fn render_unverified_devices_cache(
    session_manager: &SessionManager,
    group_uuid: Uuid,
    entries: &[UnverifiedDeviceEntry],
) -> Result<(), CliError> {
    let mut entries = entries.to_vec();
    entries.sort_by_key(|entry| entry.last_seen_at);

    hydrate_user_email_cache(session_manager, group_uuid, &[], &entries)
        .await
        .ok();

    let headers = ["User", "Device", "Reasons", "First Seen", "Last Seen"];
    let mut rows = Vec::with_capacity(entries.len());
    for entry in &entries {
        let label = entry
            .member_label
            .as_ref()
            .filter(|label| !label.trim().is_empty());
        let user_display =
            format_user_display(session_manager, entry.user_id, label.map(String::as_str)).await;
        rows.push(vec![
            user_display,
            entry.device_id.clone(),
            entry.reasons.join("; "),
            format_local_datetime_with_relative(&entry.recorded_at),
            format_local_datetime_with_relative(&entry.last_seen_at),
        ]);
    }

    println!("{}", format_table(&headers, &rows));
    ui::info(&format!(
        "{} unverified device(s) recorded (local cache).",
        entries.len()
    ));
    Ok(())
}

struct JoinCardMaterial {
    join_card: JoinCard,
    canonical_json: String,
    from_cache: bool,
    source_path: Option<PathBuf>,
}

async fn hydrate_user_email_cache(
    session_manager: &SessionManager,
    group_id: Uuid,
    server_entries: &[crate::session::UnverifiedDeviceInfo],
    cached_entries: &[UnverifiedDeviceEntry],
) -> Result<(), CliError> {
    let mut ids_to_resolve: HashSet<String> = HashSet::new();

    for entry in server_entries {
        ids_to_resolve.insert(entry.user_id.to_string());
        ids_to_resolve.insert(entry.reported_by.to_string());
    }

    for entry in cached_entries {
        ids_to_resolve.insert(entry.user_id.to_string());
    }

    if ids_to_resolve.is_empty() {
        return Ok(());
    }

    let mut missing = Vec::new();
    for user_id in ids_to_resolve {
        let cached = session_manager.cached_email_for_user_id(&user_id).await;
        let needs_refresh = cached
            .as_deref()
            .map(|email| email.trim().is_empty())
            .unwrap_or(true);
        if needs_refresh {
            missing.push(user_id);
        }
    }

    if missing.is_empty() {
        return Ok(());
    }

    let group_id_str = group_id.to_string();
    let Ok(members) = session_manager.list_group_members_http(&group_id_str).await else {
        return Ok(());
    };

    let cache_entries = members
        .iter()
        .map(|member| (member.email.clone(), member.user_id.clone()))
        .collect::<Vec<_>>();
    let _ = session_manager.cache_user_identities(cache_entries).await;

    Ok(())
}

async fn format_user_display(
    session_manager: &SessionManager,
    user_id: Uuid,
    label: Option<&str>,
) -> String {
    let user_id_str = user_id.to_string();
    let mut email = label
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    if email.as_deref() == Some(user_id_str.as_str()) {
        email = None;
    }

    if email.is_none() {
        if let Some(cached) = session_manager.cached_email_for_user_id(&user_id_str).await {
            let trimmed = cached.trim();
            if !trimmed.is_empty() && trimmed != user_id_str {
                email = Some(trimmed.to_string());
            }
        }
    }

    match email {
        Some(value) => format!("{} (User UUID: {})", value, user_id_str),
        None => format!("User UUID: {}", user_id_str),
    }
}

pub(crate) struct UnverifiedDevice {
    pub(crate) user_id: Uuid,
    pub(crate) device_id: String,
    pub(crate) reasons: Vec<String>,
}

fn membership_leaf(group_id: Uuid, user_id: Uuid, role: &str, salt: &[u8]) -> String {
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
    format!("{MEMBERSHIP_LEAF_PREFIX}:{group_id}:{user_id}:{role}:{salt_b64}")
}

fn membership_signature_message(root: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(MEMBERSHIP_ROOT_PREFIX.len() + root.len());
    message.extend_from_slice(MEMBERSHIP_ROOT_PREFIX);
    message.extend_from_slice(root);
    message
}

fn membership_proof_cache_key(group_id: Uuid, user_id: Uuid) -> String {
    format!("{}:{}:{}", MEMBERSHIP_PROOF_CACHE_PREFIX, group_id, user_id)
}

fn unverified_devices_cache_key(group_id: Uuid) -> String {
    format!("{}:{}", UNVERIFIED_DEVICES_CACHE_PREFIX, group_id)
}

async fn load_unverified_devices(
    session_manager: &SessionManager,
    group_id: Uuid,
) -> Result<Vec<UnverifiedDeviceEntry>, CliError> {
    let storage = session_manager.current_storage()?;
    let key = unverified_devices_cache_key(group_id);
    let raw = storage
        .load_config(&key)
        .await
        .map_err(|e| CliError::storage(format!("Failed to load unverified device list: {}", e)))?;

    let Some(raw) = raw else {
        return Ok(Vec::new());
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str::<Vec<UnverifiedDeviceEntry>>(trimmed).map_err(|e| {
        CliError::storage(format!(
            "Unverified device list is corrupted; clear it and retry ({})",
            e
        ))
    })
}

async fn store_unverified_devices(
    session_manager: &SessionManager,
    group_id: Uuid,
    entries: &[UnverifiedDeviceEntry],
) -> Result<(), CliError> {
    let storage = session_manager.current_storage()?;
    let key = unverified_devices_cache_key(group_id);
    let serialized = serde_json::to_string(entries).map_err(|e| {
        CliError::configuration(format!("Failed to serialize unverified device list: {}", e))
    })?;
    storage
        .store_config(&key, &serialized)
        .await
        .map_err(|e| CliError::storage(format!("Failed to store unverified device list: {}", e)))
}

pub(crate) async fn clear_unverified_device_cache(
    session_manager: &SessionManager,
    group_id: Uuid,
    user_id: Uuid,
    device_id: &str,
) -> Result<bool, CliError> {
    let mut entries = load_unverified_devices(session_manager, group_id).await?;
    let before = entries.len();
    entries.retain(|entry| !(entry.user_id == user_id && entry.device_id == device_id));
    if entries.len() == before {
        return Ok(false);
    }
    store_unverified_devices(session_manager, group_id, &entries).await?;
    Ok(true)
}

pub(crate) async fn record_unverified_devices(
    session_manager: &SessionManager,
    group_id: Uuid,
    member_label: Option<String>,
    devices: &[UnverifiedDevice],
) -> Result<(), CliError> {
    if devices.is_empty() {
        return Ok(());
    }

    let reports: Vec<UnverifiedDeviceReport> = devices
        .iter()
        .map(|device| UnverifiedDeviceReport {
            user_id: device.user_id,
            device_id: device.device_id.clone(),
            reasons: device.reasons.clone(),
        })
        .collect();

    let server_result = session_manager
        .report_unverified_devices(group_id, &reports)
        .await;

    let mut entries = load_unverified_devices(session_manager, group_id).await?;
    let now = Utc::now();

    for device in devices {
        if let Some(existing) = entries
            .iter_mut()
            .find(|entry| entry.user_id == device.user_id && entry.device_id == device.device_id)
        {
            existing.reasons = device.reasons.clone();
            existing.last_seen_at = now;
            if existing.member_label.is_none() {
                existing.member_label = member_label.clone();
            }
            continue;
        }

        entries.push(UnverifiedDeviceEntry {
            group_id,
            user_id: device.user_id,
            device_id: device.device_id.clone(),
            reasons: device.reasons.clone(),
            recorded_at: now,
            last_seen_at: now,
            member_label: member_label.clone(),
        });
    }

    store_unverified_devices(session_manager, group_id, &entries).await?;

    if let Err(err) = server_result {
        return Err(err);
    }

    Ok(())
}

async fn load_cached_membership_proof(
    session_manager: &SessionManager,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<Option<MembershipProofCacheEntry>, CliError> {
    let storage = session_manager.current_storage()?;
    let key = membership_proof_cache_key(group_id, user_id);
    let raw = storage
        .load_config(&key)
        .await
        .map_err(|e| CliError::storage(format!("Failed to load membership proof cache: {}", e)))?;

    let Some(raw) = raw else {
        return Ok(None);
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    match serde_json::from_str::<MembershipProofCacheEntry>(trimmed) {
        Ok(entry) => Ok(Some(entry)),
        Err(err) => {
            ui::warning(&format!(
                "Cached membership proof is corrupted; ignoring cache ({})",
                err
            ));
            Ok(None)
        }
    }
}

async fn store_cached_membership_proof(
    session_manager: &SessionManager,
    group_id: Uuid,
    user_id: Uuid,
    proof: &MembershipProofResponse,
) -> Result<(), CliError> {
    let storage = session_manager.current_storage()?;
    let key = membership_proof_cache_key(group_id, user_id);
    let entry = MembershipProofCacheEntry {
        cached_at: Utc::now(),
        proof: proof.clone(),
    };
    let serialized = serde_json::to_string(&entry).map_err(|e| {
        CliError::configuration(format!("Failed to serialize membership proof cache: {}", e))
    })?;
    storage
        .store_config(&key, &serialized)
        .await
        .map_err(|e| CliError::storage(format!("Failed to store membership proof cache: {}", e)))
}

fn load_join_card_for_member(
    member_identifier: &str,
    session_manager: &SessionManager,
) -> Result<JoinCardMaterial, CliError> {
    if let Some(raw_json) = session_manager.load_cached_join_card(member_identifier)? {
        let (join_card, canonical_json) = parse_join_card(&raw_json, "from secure cache")?;
        ui::dim("Using join card from secure local cache");
        return Ok(JoinCardMaterial {
            join_card,
            canonical_json,
            from_cache: true,
            source_path: None,
        });
    }

    if let Some(suggested_path) = session_manager.suggested_join_card_path(member_identifier) {
        if suggested_path.exists() {
            ui::dim(&format!("Found join card at {}", suggested_path.display()));
            let (join_card, canonical_json) = load_join_card_from_path(&suggested_path)?;
            return Ok(JoinCardMaterial {
                join_card,
                canonical_json,
                from_cache: false,
                source_path: Some(suggested_path),
            });
        }
    }

    // Attempt to locate join card using common naming conventions
    for path in join_card_candidate_paths(session_manager, member_identifier)? {
        if path.exists() {
            ui::dim(&format!("Discovered join card at {}", path.display()));
            let (join_card, canonical_json) = load_join_card_from_path(&path)?;
            return Ok(JoinCardMaterial {
                join_card,
                canonical_json,
                from_cache: false,
                source_path: Some(path),
            });
        }
    }

    ui::warning(
        "No cached join card found. Provide the verified join card to encrypt the Welcome message.",
    );
    if let Some(hint) = session_manager.suggested_join_card_path(member_identifier) {
        ui::dim(&format!(
            "Hint: place the join card at {} to skip this prompt next time.",
            hint.display()
        ));
    }

    let path_input = ui::prompts::input("Enter path to join card JSON file")?;
    let path = PathBuf::from(path_input.trim());
    if !path.exists() {
        return Err(CliError::invalid_input(format!(
            "Join card file '{}' not found",
            path.display()
        )));
    }

    let (join_card, canonical_json) = load_join_card_from_path(&path)?;
    Ok(JoinCardMaterial {
        join_card,
        canonical_json,
        from_cache: false,
        source_path: Some(path),
    })
}

fn join_card_candidate_paths(
    session_manager: &SessionManager,
    member_identifier: &str,
) -> Result<Vec<PathBuf>, CliError> {
    let Some(base_path) = session_manager.suggested_join_card_path(member_identifier) else {
        return Ok(Vec::new());
    };

    let mut candidates = Vec::new();
    let variants = join_card_name_variants(member_identifier);

    if let Some(dir) = base_path.parent() {
        for variant in variants {
            let variant = variant.trim();
            if variant.is_empty() {
                continue;
            }
            candidates.push(dir.join(format!("{}.json", variant)));
            candidates.push(dir.join(format!("{}.json.enc", variant)));
            candidates.push(dir.join(format!("join_card_{}.json", variant)));
            candidates.push(dir.join(format!("join_card_{}.json.enc", variant)));
            candidates.push(dir.join(format!("{}_join_card.json", variant)));
            candidates.push(dir.join(format!("{}_join_card.json.enc", variant)));
        }
    }

    // Ensure deterministic ordering and no duplicates
    candidates.sort();
    candidates.dedup();

    // Restore base path (sanitized suggestion) at the front for priority if it exists
    if let Some(pos) = candidates.iter().position(|p| p == &base_path) {
        let primary = candidates.remove(pos);
        candidates.insert(0, primary);
    } else {
        candidates.insert(0, base_path);
    }

    Ok(candidates)
}

fn join_card_name_variants(identifier: &str) -> HashSet<String> {
    let mut variants = HashSet::new();

    let trimmed = identifier.trim();
    if trimmed.is_empty() {
        return variants;
    }

    variants.insert(trimmed.to_string());
    variants.insert(trimmed.to_lowercase());
    variants.insert(trimmed.replace('@', "_at_"));
    variants.insert(trimmed.replace('@', "_").replace('.', "_"));
    variants.insert(trimmed.replace('@', "-").replace('.', "-"));
    variants.insert(trimmed.replace(['@', '.'], ""));
    variants.insert(normalize_identifier(trimmed));

    variants
}

fn normalize_identifier(identifier: &str) -> String {
    let mut slug = String::new();
    let mut prev_sep = false;

    for ch in identifier.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep {
            slug.push('_');
            prev_sep = true;
        }
    }

    slug.trim_matches('_').to_string()
}

fn load_join_card_from_path(path: &Path) -> Result<(JoinCard, String), CliError> {
    let contents = fs::read_to_string(path).map_err(|e| {
        CliError::io(format!(
            "Failed to read join card from '{}': {}",
            path.display(),
            e
        ))
    })?;

    parse_join_card(&contents, &format!("in '{}'", path.display()))
}

fn parse_join_card(json: &str, context: &str) -> Result<(JoinCard, String), CliError> {
    let join_card: JoinCard = serde_json::from_str(json)
        .map_err(|e| CliError::invalid_input(format!("Join card {} is invalid: {}", context, e)))?;

    let canonical_json = serde_json::to_string_pretty(&join_card).map_err(|e| {
        CliError::format(format!("Failed to normalise join card {}: {}", context, e))
    })?;

    Ok((join_card, canonical_json))
}

/// Handle remove member command
pub async fn handle_remove_member(
    user_id: String,
    force: bool,
    auto_rekey: bool,
    yes: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    // Require authentication
    session_manager.require_auth()?;

    ui::section("Remove Group Member");

    ui::warning(&format!("Removing member: {}", user_id));

    if force {
        ui::warning("Force mode enabled - member will be removed even if online");
    }

    if auto_rekey {
        ui::info("Auto-rekey enabled - you'll be prompted to start rekey after removal");
    }

    let group_id = session_manager.ensure_active_group().await?;
    session_manager
        .require_group_admin(group_id, "hybridcipher remove-member")
        .await?;

    let consequences: Vec<&str> = if auto_rekey {
        vec![
            "Member will lose access to all group files",
            "Member cannot be re-added without administrator approval",
            "Active sessions for this member will be terminated",
            "Rekey can be started immediately after removal",
        ]
    } else {
        vec![
            "Member will lose access to all group files",
            "Member cannot be re-added without administrator approval",
            "Active sessions for this member will be terminated",
            "A rekey operation may be required to maintain security",
        ]
    };

    // Show destructive operation warning
    let should_proceed = yes
        || ui::prompts::destructive_operation_warning(
            &format!("Remove member {}", user_id),
            &consequences,
            "REMOVE",
        )?;

    if !should_proceed {
        ui::info("Member removal cancelled");
        return Ok(());
    }

    let resolved_user_id = session_manager.resolve_user_identifier(&user_id).await?;
    let target_user_id = Uuid::parse_str(&resolved_user_id).map_err(|_| {
        CliError::invalid_input("Member identifier must resolve to a UUID.".to_string())
    })?;

    match session_manager
        .remove_member_http(group_id, target_user_id)
        .await
    {
        Ok(()) => {
            ui::success(&format!("Member '{}' removed successfully!", user_id));
            ui::info("Group membership updated on the server");
        }
        Err(e) => {
            ui::error(&format!("Failed to remove member: {}", e));
            return Err(e);
        }
    }

    if auto_rekey {
        let start_rekey = yes
            || ui::prompts::confirm_with_default(
                "Start rekey now? (activation delay: immediate)",
                true,
            )?;
        if start_rekey {
            ui::info("Starting rekey now...");
            rekey::handle_rekey_command(
                RekeyCommands::Start {
                    activation_delay: Some("immediate".to_string()),
                    force: false,
                    welcome_file: None,
                    local_migration: if yes { "defer" } else { "prompt" }.to_string(),
                },
                session_manager,
            )
            .await?;
        } else {
            ui::info(
                "Rekey deferred. Run 'hybridcipher rekey start --activation-delay immediate' when ready.",
            );
        }
    }

    Ok(())
}

/// Handle list groups command
pub async fn handle_list_groups(
    verbose: bool,
    format: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    // Require authentication
    session_manager.require_auth()?;

    ui::section("User Groups");

    ui::info(&format!("Output format: {}", format));

    // Call the server API to get actual groups
    match session_manager.list_groups_http().await {
        Ok(groups) => {
            if groups.is_empty() {
                ui::info("You are not a member of any groups yet.");
                ui::info(
                    "Use 'hybridcipher add-member <email>' to create a group and add members.",
                );
                return Ok(());
            }

            ui::subsection(&format!("Groups ({})", groups.len()));
            for (i, group) in groups.iter().enumerate() {
                ui::info(&format!("{}. {} (ID: {})", i + 1, group.name, group.id));
                if verbose {
                    ui::info(&format!(
                        "   Description: {}",
                        group.description.as_deref().unwrap_or("No description")
                    ));
                    ui::info(&format!("   Role: {}", group.role));
                    ui::info(&format!("   Members: {}", group.member_count));
                    ui::info(&format!("   Created: {}", group.created_at));
                }
            }

            if verbose {
                ui::subsection("Usage");
                ui::info("To list members of a group, use: hybridcipher list-members [GROUP_ID]");
            }
        }
        Err(e) => {
            ui::error(&format!("Failed to list groups: {}", e));
            return Err(e);
        }
    }

    Ok(())
}

/// Handle list members command
pub async fn handle_list_members(
    verbose: bool,
    format: String,
    group_id: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    // Require authentication
    let session = session_manager.require_auth()?;

    ui::section("Group Members");

    ui::info(&format!("Output format: {}", format));

    // Check if group_id is provided
    let group_id = match group_id {
        Some(id) => id,
        None => session_manager.ensure_current_group().await?.to_string(),
    };

    let group_label = session_manager.group_label_for_id(&group_id).await;
    if verbose {
        ui::info(&format!("Listing members for group: {}", group_label));
    }

    // Call the server API to get actual group members
    match session_manager.list_group_members_http(&group_id).await {
        Ok(members) => {
            if members.is_empty() {
                ui::info("This group has no members yet.");
                return Ok(());
            }

            let mut viewer_role = members
                .iter()
                .find(|member| member.user_id.eq_ignore_ascii_case(&session.user_id))
                .map(|member| member.role.clone());
            if viewer_role.is_none() {
                if let Ok(group_uuid) = Uuid::parse_str(&group_id) {
                    if let Some((_, role)) =
                        session_manager.group_membership_from_state(&group_uuid)
                    {
                        viewer_role = role;
                    } else if let Ok(groups) = session_manager.list_groups_http().await {
                        if let Some(group) = groups
                            .iter()
                            .find(|entry| entry.id.eq_ignore_ascii_case(&group_id))
                        {
                            viewer_role = Some(group.role.clone());
                        }
                    }
                }
            }
            let viewer_is_admin = viewer_role
                .as_deref()
                .map(role_allows_admin)
                .unwrap_or(false);

            let cache_entries = members
                .iter()
                .map(|member| (member.email.clone(), member.user_id.clone()))
                .collect::<Vec<_>>();
            let _ = session_manager.cache_user_identities(cache_entries).await;

            let mut admin_emails = Vec::new();
            for member in members
                .iter()
                .filter(|member| role_allows_admin(&member.role))
            {
                let mut email = member.email.trim().to_string();
                if email.is_empty() || email.contains('*') {
                    if let Some(cached) = session_manager
                        .cached_email_for_user_id(&member.user_id)
                        .await
                    {
                        let trimmed = cached.trim();
                        if !trimmed.is_empty() && !trimmed.contains('*') {
                            email = trimmed.to_string();
                        }
                    }
                }
                if !email.is_empty() {
                    admin_emails.push(email);
                }
            }
            admin_emails.sort();
            admin_emails.dedup();

            ui::subsection(&format!("Members ({})", members.len()));
            if admin_emails.is_empty() {
                ui::dim("Admin contacts: unavailable.");
            } else {
                ui::info(&format!("Admin contacts: {}", admin_emails.join(", ")));
            }
            for (i, member) in members.iter().enumerate() {
                let line = if viewer_is_admin {
                    format!(
                        "{}. {} (User UUID: {}) [{}]",
                        i + 1,
                        member.email,
                        member.user_id,
                        member.role
                    )
                } else {
                    format!("{}. User UUID: {} [{}]", i + 1, member.user_id, member.role)
                };
                ui::info(&line);
                if verbose {
                    ui::info(&format!("   User UUID: {}", member.user_id));
                    ui::info(&format!("   Joined: {}", member.joined_at));
                    ui::info(&format!("   Status: {}", member.status));
                }
            }
        }
        Err(e) => {
            ui::error(&format!("Failed to list group members: {}", e));
            ui::info("Make sure you have permission to view this group's members.");
            return Err(e);
        }
    }

    Ok(())
}

/// Handle membership proof verification
pub async fn handle_verify_membership(
    group_id: Option<String>,
    user: Option<String>,
    offline: bool,
    verbose: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    ui::section("Membership Proof Verification");

    let group_id = match group_id {
        Some(id) => id,
        None => session_manager.ensure_current_group().await?.to_string(),
    };

    let group_uuid = Uuid::parse_str(&group_id).map_err(|_| {
        CliError::invalid_input(format!("Invalid group ID '{}'. Expected a UUID.", group_id))
    })?;

    let target_user_id = match user {
        Some(identifier) => session_manager.resolve_user_identifier(&identifier).await?,
        None => session.user_id.clone(),
    };

    let target_user_uuid = Uuid::parse_str(&target_user_id).map_err(|_| {
        CliError::invalid_input(format!(
            "Invalid user ID '{}'. Expected a UUID.",
            target_user_id
        ))
    })?;

    let group_label = session_manager.group_label_for_id(&group_id).await;
    ui::info(&format!("Group: {}", group_label));
    ui::info(&format!("User ID: {}", target_user_uuid));

    let cached_entry =
        load_cached_membership_proof(session_manager, group_uuid, target_user_uuid).await?;
    let cached = cached_entry.clone().map(|entry| entry.proof);
    let cached_at = cached_entry.map(|entry| entry.cached_at);

    let proof: MembershipProofResponse;
    let mut from_cache = false;

    if offline {
        let Some(entry) = cached else {
            return Err(CliError::not_found(
                "No cached membership proof available for this group/user.".to_string(),
            ));
        };
        ui::warning("Using cached membership proof (offline mode).");
        proof = entry;
        from_cache = true;
    } else {
        let fetch = async {
            let base_url = session.server_url.trim_end_matches('/');
            let api_base = if base_url.ends_with("/api/v1") {
                base_url.to_string()
            } else {
                format!("{}/api/v1", base_url)
            };

            let mut endpoint = format!("{}/groups/{}/membership/proof", api_base, group_uuid);
            if !target_user_id.is_empty() && target_user_id != session.user_id {
                endpoint.push_str("?user_id=");
                endpoint.push_str(&urlencoding::encode(&target_user_id));
            }

            let client = reqwest::Client::new();
            let response = client
                .get(&endpoint)
                .header("Authorization", format!("Bearer {}", session.token))
                .send()
                .await
                .map_err(|e| {
                    CliError::network(format!("Failed to fetch membership proof: {}", e))
                })?;

            match response.status() {
                StatusCode::OK => {}
                StatusCode::UNAUTHORIZED => {
                    session_manager.invalidate_session("membership_proof")?;
                    return Err(CliError::authentication(
                        "Authentication token rejected. Please login again.".to_string(),
                    ));
                }
                StatusCode::FORBIDDEN => {
                    return Err(CliError::permission(
                        "You do not have permission to access this membership proof.".to_string(),
                    ));
                }
                StatusCode::NOT_FOUND => {
                    return Err(CliError::not_found(
                        "Membership proof not found for this group/user.".to_string(),
                    ));
                }
                status => {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    return Err(CliError::network(format!(
                        "Failed to fetch membership proof: {} - {}",
                        status, error_text
                    )));
                }
            }

            response
                .json::<MembershipProofResponse>()
                .await
                .map_err(|e| CliError::network(format!("Invalid membership proof response: {}", e)))
        };

        match fetch.await {
            Ok(remote) => {
                proof = remote;
            }
            Err(err) => {
                if let Some(entry) = cached {
                    ui::warning(&format!(
                        "Failed to fetch membership proof ({}); falling back to cached proof.",
                        err
                    ));
                    proof = entry;
                    from_cache = true;
                } else {
                    return Err(err);
                }
            }
        }
    }

    let mut issues = Vec::new();

    if proof.group_id != group_uuid {
        issues.push("Response group_id does not match requested group.".to_string());
    }
    if proof.user_id != target_user_uuid {
        issues.push("Response user_id does not match requested user.".to_string());
    }

    let max_age_hours = session_manager.membership_proof_max_age_hours();
    if max_age_hours > 0 {
        let max_age = chrono::Duration::hours(max_age_hours as i64);
        let age = Utc::now().signed_duration_since(proof.membership_generated_at);
        if age > max_age {
            issues.push(format!(
                "Membership proof is older than {} hours (age: {} hours).",
                max_age_hours,
                age.num_hours()
            ));
        } else if age.num_seconds() < 0 {
            issues.push(
                "Membership proof timestamp is in the future; check system clock.".to_string(),
            );
        }
    }

    let root_bytes = hex::decode(&proof.merkle_root_hex)
        .map_err(|e| CliError::member_management(format!("Invalid Merkle root hex: {}", e)))?;
    let merkle_root: [u8; 32] = root_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CliError::member_management("Merkle root must be 32 bytes.".to_string()))?;

    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&proof.salt_base64)
        .map_err(|e| CliError::member_management(format!("Invalid salt: {}", e)))?;
    let expected_leaf = membership_leaf(group_uuid, target_user_uuid, &proof.role, &salt_bytes);
    let leaf_matches = proof.leaf == expected_leaf;
    if !leaf_matches {
        issues.push("Leaf mismatch between server response and local computation.".to_string());
    }

    let proof_valid = proof
        .proof
        .verify(&merkle_root, expected_leaf.as_bytes())
        .map_err(|e| CliError::member_management(format!("Merkle proof error: {}", e)))?;
    if !proof_valid {
        issues.push("Merkle proof verification failed.".to_string());
    }

    let verifying_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&proof.verifying_key_base64)
        .map_err(|e| CliError::member_management(format!("Invalid verifying key: {}", e)))?;
    let server_verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|e| CliError::member_management(format!("Invalid verifying key: {}", e)))?;

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&proof.signature_base64)
        .map_err(|e| CliError::member_management(format!("Invalid signature: {}", e)))?;
    let signature = MembershipSignature::from_bytes(&signature_bytes)
        .map_err(|e| CliError::member_management(format!("Invalid signature: {}", e)))?;

    let signature_message = membership_signature_message(&merkle_root);
    let pinned_keys = membership_signing::membership_verifying_keys()?;
    let signature_valid = pinned_keys
        .iter()
        .any(|key| signatures::verify(key, &signature_message, &signature).is_ok());
    if !signature_valid {
        issues.push("Snapshot signature verification failed.".to_string());
    }
    if !membership_signing::membership_key_matches(&server_verifying_key) {
        issues.push("Server-provided verifying key is not pinned locally.".to_string());
    }

    ui::info(&format!("Role: {}", proof.role));
    if from_cache {
        ui::info("Proof Source: cache");
    } else {
        ui::info("Proof Source: server");
    }

    if verbose {
        ui::info(&format!("Snapshot ID: {}", proof.snapshot_id));
        ui::info(&format!("Merkle Root: {}", proof.merkle_root_hex));
        ui::info(&format!(
            "Membership Generated At: {}",
            proof.membership_generated_at
        ));
        if from_cache {
            if let Some(cached_at) = cached_at {
                ui::info(&format!("Cached At: {}", cached_at));
            }
        }
        if max_age_hours > 0 {
            ui::info(&format!("Max Proof Age (hours): {}", max_age_hours));
        }
        ui::info(&format!("Total Members: {}", proof.total_members));
        if let Some(signing_key_id) = proof.signing_key_id.as_deref() {
            if !signing_key_id.trim().is_empty() {
                ui::info(&format!("Signing Key ID: {}", signing_key_id));
            }
        }
        ui::info(&format!("Leaf: {}", expected_leaf));
        ui::info(&format!(
            "Proof Path Length: {}",
            proof.proof.sibling_hashes.len()
        ));
    }

    if issues.is_empty() {
        if !from_cache {
            if let Err(err) =
                store_cached_membership_proof(session_manager, group_uuid, target_user_uuid, &proof)
                    .await
            {
                ui::warning(&format!("Failed to cache membership proof: {}", err));
            }
        }
        ui::success("Membership proof verified.");
        Ok(())
    } else {
        ui::error("Membership proof verification failed.");
        for issue in issues {
            ui::info(&format!(" - {}", issue));
        }
        Err(CliError::member_management(
            "Membership proof verification failed.".to_string(),
        ))
    }
}

fn role_allows_admin(role: &str) -> bool {
    matches!(role.to_ascii_lowercase().as_str(), "admin" | "owner")
}
