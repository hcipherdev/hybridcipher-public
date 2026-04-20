use super::{
    AuditDevicesArgs, AuditDevicesRemovalArgs, AuditDevicesRemovalCommand,
    AuditDevicesStaleCommand, AuditDevicesSubcommand,
};
use crate::{error::CliError, session::SessionManager, ui};
use chrono::{DateTime, Duration, Utc};
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Deserialize, Clone)]
pub struct DeviceAuditResponse {
    pub group_id: Uuid,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub generated_at: DateTime<Utc>,
    pub stale_threshold_days: i64,
    pub devices: Vec<DeviceAuditEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DeviceAuditEntry {
    pub user_id: Uuid,
    pub device_id: String,
    pub device_name: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub last_seen: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    #[serde(rename = "created_at")]
    pub _created_at: DateTime<Utc>,
    pub invitation_key_present: bool,
    pub stale: bool,
    pub reasons: Vec<String>,
}

pub async fn fetch_device_audit(
    session_manager: &SessionManager,
    group_id: Uuid,
    stale_days: u64,
) -> Result<DeviceAuditResponse, CliError> {
    let session = session_manager.require_auth()?;
    let normalized_stale_days = stale_days.clamp(1, 365);

    let base_url = session.server_url.trim_end_matches('/');
    let url = format!(
        "{}/api/v1/groups/{}/devices?stale_days={}",
        base_url, group_id, normalized_stale_days
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to contact server: {}", e)))?;

    if response.status() == StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("device_audit")?;
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
            "Device audit request failed ({}): {}",
            status, body
        )));
    }

    let audit: DeviceAuditResponse = response.json().await.map_err(|e| {
        CliError::operation(format!("Failed to parse device audit response: {}", e))
    })?;

    Ok(audit)
}

pub async fn handle_audit_devices(
    session_manager: &SessionManager,
    args: AuditDevicesArgs,
) -> Result<(), CliError> {
    let group_uuid = resolve_group_uuid(session_manager, args.group_id.clone()).await?;

    match args.action {
        None => display_full_audit(session_manager, group_uuid, args.stale_days).await,
        Some(AuditDevicesSubcommand::Stale { command }) => match command {
            None => display_stale_audit(session_manager, group_uuid, args.stale_days).await,
            Some(AuditDevicesStaleCommand::Remove { strategy }) => match strategy {
                AuditDevicesRemovalCommand::LongAbsent(removal_args) => {
                    remediate_stale_devices(
                        session_manager,
                        group_uuid,
                        args.stale_days,
                        removal_args,
                        RemovalStrategy::LongAbsent,
                    )
                    .await
                }
                AuditDevicesRemovalCommand::KeyMissing(removal_args) => {
                    remediate_stale_devices(
                        session_manager,
                        group_uuid,
                        args.stale_days,
                        removal_args,
                        RemovalStrategy::KeyMissing,
                    )
                    .await
                }
            },
        },
    }
}

async fn display_full_audit(
    session_manager: &SessionManager,
    group_id: Uuid,
    stale_days: u64,
) -> Result<(), CliError> {
    let audit = fetch_device_audit(session_manager, group_id, stale_days).await?;
    let group_label = session_manager.group_label(&audit.group_id).await;
    let user_emails = build_member_email_map(session_manager, audit.group_id).await;

    print_audit_header("Device Roster Audit", &audit, &group_label);

    if audit.devices.is_empty() {
        ui::success("No devices registered for this group.");
        return Ok(());
    }

    let mut stale_devices = Vec::new();
    for device in &audit.devices {
        print_device_entry(device, &user_emails);
        if device.stale {
            let user_label = format_user_label(device.user_id, &user_emails);
            stale_devices.push(format!("{} (user {})", device.device_id, user_label));
        }
    }

    if !stale_devices.is_empty() {
        return Err(CliError::operation(format!(
            "Device audit detected stale or incomplete records: {}",
            stale_devices.join(", ")
        )));
    }

    ui::success("All registered devices are healthy.");
    Ok(())
}

async fn display_stale_audit(
    session_manager: &SessionManager,
    group_id: Uuid,
    stale_days: u64,
) -> Result<(), CliError> {
    let audit = fetch_device_audit(session_manager, group_id, stale_days).await?;
    let group_label = session_manager.group_label(&audit.group_id).await;
    let user_emails = build_member_email_map(session_manager, audit.group_id).await;
    print_audit_header("Stale Device Report", &audit, &group_label);

    if audit.devices.is_empty() {
        ui::success("No devices registered for this group.");
        return Ok(());
    }

    let total_devices = audit.devices.len();
    let mut stale_entries = Vec::new();

    for device in &audit.devices {
        if device.stale {
            print_device_entry(device, &user_emails);
            stale_entries.push(device.clone());
        }
    }

    if stale_entries.is_empty() {
        ui::success("Roster is clean. No stale devices found.");
        return Ok(());
    }

    let summary = format!(
        "{} out of {} device(s) are stale.",
        stale_entries.len(),
        total_devices
    );
    ui::warning(&summary);

    Err(CliError::operation(summary))
}

async fn remediate_stale_devices(
    session_manager: &SessionManager,
    group_id: Uuid,
    stale_days: u64,
    removal_args: AuditDevicesRemovalArgs,
    strategy: RemovalStrategy,
) -> Result<(), CliError> {
    let audit = fetch_device_audit(session_manager, group_id, stale_days).await?;
    let group_label = session_manager.group_label(&audit.group_id).await;
    let user_emails = build_member_email_map(session_manager, audit.group_id).await;
    print_audit_header("Stale Device Remediation", &audit, &group_label);

    if audit.devices.is_empty() {
        ui::success("No devices registered for this group.");
        return Ok(());
    }

    let session = session_manager.require_auth()?;
    let current_device_id = session.device_id.clone();
    drop(session);

    let candidates: Vec<DeviceAuditEntry> = audit
        .devices
        .iter()
        .cloned()
        .filter(|device| matches_strategy(&audit, device, &strategy))
        .collect();

    if candidates.is_empty() {
        ui::success(match strategy {
            RemovalStrategy::LongAbsent => {
                "No long-absent stale devices matched the removal criteria."
            }
            RemovalStrategy::KeyMissing => {
                "No stale devices with missing invitation keys were found."
            }
        });
        return Ok(());
    }

    // Process remote devices first so the session remains valid for remaining calls.
    let (remote_devices, mut self_devices): (Vec<DeviceAuditEntry>, Vec<DeviceAuditEntry>) =
        candidates
            .into_iter()
            .partition(|device| device.device_id != current_device_id);
    let mut ordered_candidates = remote_devices;
    ordered_candidates.append(&mut self_devices);

    ui::info(&format!(
        "Preparing to remove {} device(s) matching {} criteria.",
        ordered_candidates.len(),
        strategy.label()
    ));
    for device in &ordered_candidates {
        print_device_entry(device, &user_emails);
    }

    if !removal_args.yes {
        let confirm = ui::prompts::confirm(&format!(
            "Remove {} stale device(s)?",
            ordered_candidates.len()
        ))?;
        if !confirm {
            ui::info("Stale device removal cancelled.");
            return Ok(());
        }
    }

    let mut removed = Vec::new();
    let mut failures = Vec::new();

    for device in &ordered_candidates {
        match super::auth::execute_device_removal(session_manager, &device.device_id).await {
            Ok(outcome) => {
                let super::auth::DeviceRemovalOutcome {
                    payload,
                    removed_current_device,
                } = outcome;

                removed.push(payload.removed_device_id.clone());
                ui::success(&format!(
                    "Removed device {} (revoked sessions: {}, remaining devices: {})",
                    payload.removed_device_id, payload.revoked_sessions, payload.remaining_devices
                ));

                if removed_current_device {
                    ui::warning(
                        "Local session revoked during remediation. Please login again if further actions are required.",
                    );
                    break;
                }
            }
            Err(err) => {
                failures.push((device.device_id.clone(), err.to_string()));
            }
        }
    }

    if !failures.is_empty() {
        for (device_id, reason) in &failures {
            ui::error(&format!(
                "Failed to remove device {}: {}",
                device_id, reason
            ));
        }
        return Err(CliError::operation(format!(
            "Removed {} device(s); {} failed.",
            removed.len(),
            failures.len()
        )));
    }

    if removed.is_empty() {
        ui::info("No devices were removed.");
    } else {
        ui::success(&format!(
            "Removed {} device(s): {}",
            removed.len(),
            removed.join(", ")
        ));
    }

    Ok(())
}

async fn resolve_group_uuid(
    session_manager: &SessionManager,
    group_id: Option<String>,
) -> Result<Uuid, CliError> {
    if let Some(group_id) = group_id {
        let trimmed = group_id.trim();
        if trimmed.is_empty() {
            return Err(CliError::invalid_input(
                "Group identifier cannot be blank.".to_string(),
            ));
        }

        Uuid::parse_str(trimmed).map_err(|e| {
            CliError::invalid_input(format!("Invalid group identifier '{}': {}", trimmed, e))
        })
    } else {
        session_manager.ensure_current_group().await
    }
}

fn print_audit_header(title: &str, audit: &DeviceAuditResponse, group_label: &str) {
    ui::section(title);
    ui::info(&format!("Group: {}", group_label));
    ui::info(&format!(
        "Generated at: {}",
        ui::formatting::format_local_and_utc(&audit.generated_at)
    ));
    ui::info(&format!(
        "Stale threshold: {} day(s)",
        audit.stale_threshold_days
    ));
}

fn print_device_entry(device: &DeviceAuditEntry, user_emails: &HashMap<Uuid, String>) {
    let status_label = if device.stale { "STALE" } else { "OK" };
    let name = device.device_name.as_deref().unwrap_or("<unnamed device>");
    let reasons = if device.reasons.is_empty() {
        "-".to_string()
    } else {
        device.reasons.join("; ")
    };
    let user_label = format_user_label(device.user_id, user_emails);

    ui::info(&format!(
        "[{}] {} ({}) user={} last_seen={} invitation_key={}",
        status_label,
        device.device_id,
        name,
        user_label,
        ui::formatting::format_local_datetime(&device.last_seen),
        if device.invitation_key_present {
            "present"
        } else {
            "missing"
        }
    ));

    if device.stale {
        ui::warning(&format!("  ↳ Reasons: {}", reasons));
    }
}

async fn build_member_email_map(
    session_manager: &SessionManager,
    group_id: Uuid,
) -> HashMap<Uuid, String> {
    let mut emails = HashMap::new();
    if let Ok(members) = session_manager
        .list_group_members_http(&group_id.to_string())
        .await
    {
        for member in members {
            let email = member.email.trim();
            if email.is_empty() || email.contains('*') {
                continue;
            }
            if let Ok(user_id) = Uuid::parse_str(member.user_id.trim()) {
                emails.insert(user_id, email.to_string());
            }
        }
    }
    emails
}

fn format_user_label(user_id: Uuid, user_emails: &HashMap<Uuid, String>) -> String {
    if let Some(email) = user_emails.get(&user_id) {
        return format!("{} ({})", email, user_id);
    }
    user_id.to_string()
}

fn matches_strategy(
    audit: &DeviceAuditResponse,
    device: &DeviceAuditEntry,
    strategy: &RemovalStrategy,
) -> bool {
    if !device.stale {
        return false;
    }

    match strategy {
        RemovalStrategy::LongAbsent => {
            let absent_duration = audit.generated_at - device.last_seen;
            let threshold = Duration::days(audit.stale_threshold_days.max(0));
            absent_duration > threshold
                || device
                    .reasons
                    .iter()
                    .any(|reason| reason.to_lowercase().contains("last seen"))
        }
        RemovalStrategy::KeyMissing => {
            !device.invitation_key_present
                || device.reasons.iter().any(|reason| {
                    reason
                        .to_lowercase()
                        .contains("invitation public key missing")
                })
        }
    }
}

#[derive(Debug)]
enum RemovalStrategy {
    LongAbsent,
    KeyMissing,
}

impl RemovalStrategy {
    fn label(&self) -> &'static str {
        match self {
            RemovalStrategy::LongAbsent => "long-absent",
            RemovalStrategy::KeyMissing => "missing invitation key",
        }
    }
}
