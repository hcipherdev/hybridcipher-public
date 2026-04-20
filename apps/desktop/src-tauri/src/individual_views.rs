use chrono::{DateTime, Utc};
use hybridcipher_client::{
    coverage::{FileCoverageState, FileOrphanKind},
    state::client::{CoverageFileRecord, CoverageRootStats},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndividualSecuritySnapshot {
    pub mfa_enabled: bool,
    pub recovery_backup_ok: bool,
    pub recovery_auto_backup_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndividualSettingsSnapshot {
    pub coverage_last_scan: Option<String>,
    pub registry_last_upload: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurrentDeviceSnapshot {
    pub device_id: String,
    pub is_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DeviceCountSnapshot {
    pub trusted: usize,
    pub pending: usize,
    pub stale: usize,
    pub unverified: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FolderAttentionSnapshot {
    pub conflicts: usize,
    pub recovery_copies: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndividualHomeStatusInput {
    pub security: IndividualSecuritySnapshot,
    pub settings: IndividualSettingsSnapshot,
    pub protected_count: usize,
    pub mounted_count: usize,
    pub current_device: Option<CurrentDeviceSnapshot>,
    pub device_counts: DeviceCountSnapshot,
    pub folder_attention: FolderAttentionSnapshot,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndividualHomeStatus {
    pub protected_count: usize,
    pub mounted_count: usize,
    pub attention_count: usize,
    pub post_quantum_status: String,
    pub post_quantum_primary_text: String,
    pub post_quantum_secondary_text: String,
    pub post_quantum_explainer_available: bool,
    pub mfa_enabled: bool,
    pub recovery_backup_ok: bool,
    pub recovery_auto_backup_ok: bool,
    pub last_scan_at: Option<String>,
    pub last_backup_upload_at: Option<String>,
    pub current_device: Option<CurrentDeviceSnapshot>,
    pub device_counts: DeviceCountSnapshot,
    pub folder_attention: FolderAttentionSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDeviceRecord {
    pub device_id: String,
    pub device_name: Option<String>,
    pub created_at: String,
    pub last_seen: String,
    pub is_current_device: bool,
    pub is_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeviceRecord {
    pub device_id: String,
    pub email: String,
    pub device_name: Option<String>,
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleDeviceRecord {
    pub device_id: String,
    pub email: String,
    pub device_name: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnverifiedDeviceRecord {
    pub device_id: String,
    pub email: String,
    pub device_name: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalDevicesOverviewInput {
    pub current_device_id: Option<String>,
    pub registered_devices: Vec<RegisteredDeviceRecord>,
    pub pending_devices: Vec<PendingDeviceRecord>,
    pub stale_devices: Vec<StaleDeviceRecord>,
    pub unverified_devices: Vec<UnverifiedDeviceRecord>,
    pub rename_supported: bool,
    pub revoke_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalDeviceRecord {
    pub device_id: String,
    pub device_name: Option<String>,
    pub email: Option<String>,
    pub status: String,
    pub added_at: Option<String>,
    pub last_seen: Option<String>,
    pub is_current_device: bool,
    pub is_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalDevicesOverview {
    pub current_device: Option<PersonalDeviceRecord>,
    pub trusted_devices: Vec<PersonalDeviceRecord>,
    pub setup_devices: Vec<PersonalDeviceRecord>,
    pub review_devices: Vec<PersonalDeviceRecord>,
    pub rename_supported: bool,
    pub revoke_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderCoverageFile {
    pub relative_path: String,
    pub last_seen: Option<String>,
    pub size: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderCoverageGroup {
    pub id: String,
    pub title: String,
    pub reason_text: String,
    pub item_count: usize,
    pub sample_paths: Vec<String>,
    pub files: Vec<FolderCoverageFile>,
    pub recommended_action: String,
    pub primary_cta_label: String,
    pub severity: String,
    pub can_run_action: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderCoverageReview {
    pub folder_path: String,
    pub last_scan_at: Option<String>,
    pub coverage_percent: u64,
    pub state_label: String,
    pub summary_text: String,
    pub tracked_files: usize,
    pub unresolved_item_count: usize,
    pub groups: Vec<FolderCoverageGroup>,
}

fn parse_timestamp(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        singular.to_string()
    } else {
        plural.to_string()
    }
}

fn build_post_quantum_home_snapshot(protected_count: usize) -> (String, String, String, bool) {
    if protected_count > 0 {
        (
            "protected_now".to_string(),
            "Protected now".to_string(),
            "Your protected folders are secured now with quantum-resistant encryption.".to_string(),
            true,
        )
    } else {
        (
            "needs_review".to_string(),
            "Needs review".to_string(),
            "Add a protected folder to start securing files now with post-quantum encryption."
                .to_string(),
            true,
        )
    }
}

fn coverage_reason_for_entry(entry: &hybridcipher_client::coverage::FileIndexEntry) -> String {
    match (&entry.state, entry.orphan_kind.as_ref()) {
        (FileCoverageState::Unmanaged, _) => {
            "Present in this folder but not currently protected".to_string()
        }
        (_, Some(FileOrphanKind::MissingMetadata)) => {
            "Protected data exists, but the local protection record is missing".to_string()
        }
        (_, Some(FileOrphanKind::Outcast)) => {
            "Leftover protected data from another group or old state".to_string()
        }
        (_, Some(FileOrphanKind::WrongEpoch)) => {
            "Protection history needs repair before this item is fully trusted".to_string()
        }
        (_, Some(FileOrphanKind::MissingFile)) | (FileCoverageState::Orphaned, None) => {
            "Tracked before, now missing from disk".to_string()
        }
        _ => "Needs review".to_string(),
    }
}

fn make_coverage_file(record: CoverageFileRecord) -> FolderCoverageFile {
    let reason = coverage_reason_for_entry(&record.entry);
    FolderCoverageFile {
        relative_path: record.entry.relative_path,
        last_seen: Some(record.entry.last_seen.to_rfc3339()),
        size: Some(record.entry.size),
        reason,
    }
}

fn sample_paths_from_files(files: &[FolderCoverageFile]) -> Vec<String> {
    files
        .iter()
        .map(|file| file.relative_path.clone())
        .take(3)
        .collect()
}

fn push_group_if_any(
    groups: &mut Vec<FolderCoverageGroup>,
    id: &str,
    title: &str,
    reason_text: &str,
    item_count: usize,
    sample_paths: Vec<String>,
    mut files: Vec<FolderCoverageFile>,
    recommended_action: &str,
    primary_cta_label: String,
    severity: &str,
    can_run_action: bool,
) {
    if item_count == 0 && files.is_empty() {
        return;
    }

    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let sample_paths = if sample_paths.is_empty() {
        sample_paths_from_files(&files)
    } else {
        sample_paths
    };

    groups.push(FolderCoverageGroup {
        id: id.to_string(),
        title: title.to_string(),
        reason_text: reason_text.to_string(),
        item_count,
        sample_paths,
        files,
        recommended_action: recommended_action.to_string(),
        primary_cta_label,
        severity: severity.to_string(),
        can_run_action,
    });
}

fn group_sort_key(id: &str) -> usize {
    match id {
        "restore_protection" => 0,
        "clean_up_missing" => 1,
        "remove_leftover_data" => 2,
        "repair_protection" => 3,
        "review_unprotected" => 4,
        _ => 99,
    }
}

pub fn build_folder_coverage_review(
    summary: CoverageRootStats,
    records: Vec<CoverageFileRecord>,
) -> FolderCoverageReview {
    let coverage_percent = (summary.coverage_ratio * 100.0).round().clamp(0.0, 100.0) as u64;
    let unresolved_item_count = summary.orphaned_files + summary.unmanaged_files;

    let mut restore_protection_files = Vec::new();
    let mut clean_up_missing_files = Vec::new();
    let mut remove_leftover_files = Vec::new();
    let mut repair_protection_files = Vec::new();
    let mut review_unprotected_files = Vec::new();

    for record in records {
        match (&record.entry.state, record.entry.orphan_kind.as_ref()) {
            (FileCoverageState::Unmanaged, _) => {
                review_unprotected_files.push(make_coverage_file(record))
            }
            (FileCoverageState::Orphaned, Some(FileOrphanKind::MissingMetadata)) => {
                restore_protection_files.push(make_coverage_file(record));
            }
            (FileCoverageState::Orphaned, Some(FileOrphanKind::Outcast)) => {
                remove_leftover_files.push(make_coverage_file(record));
            }
            (FileCoverageState::Orphaned, Some(FileOrphanKind::WrongEpoch)) => {
                repair_protection_files.push(make_coverage_file(record));
            }
            (FileCoverageState::Orphaned, Some(FileOrphanKind::MissingFile))
            | (FileCoverageState::Orphaned, None) => {
                clean_up_missing_files.push(make_coverage_file(record));
            }
            _ => {}
        }
    }

    let mut groups = Vec::new();
    push_group_if_any(
        &mut groups,
        "restore_protection",
        "Restore protection",
        "These items still belong in this protected folder, but their protection records need to be restored.",
        summary.orphan_missing_metadata.max(restore_protection_files.len()),
        summary
            .recent_orphans
            .iter()
            .filter(|sample| sample.orphan_kind == Some(FileOrphanKind::MissingMetadata))
            .map(|sample| sample.relative_path.clone())
            .take(3)
            .collect(),
        restore_protection_files,
        "adopt_missing_metadata",
        if summary.orphan_missing_metadata == 1 {
            "Restore protection".to_string()
        } else {
            format!("Restore protection for {} items", summary.orphan_missing_metadata)
        },
        "warning",
        true,
    );
    push_group_if_any(
        &mut groups,
        "clean_up_missing",
        "Missing items",
        "These files were tracked before but are now missing from disk. Clean up the old tracking records if that was intentional.",
        summary.orphan_missing_file.max(clean_up_missing_files.len()),
        summary
            .recent_orphans
            .iter()
            .filter(|sample| {
                sample.orphan_kind == Some(FileOrphanKind::MissingFile) || sample.orphan_kind.is_none()
            })
            .map(|sample| sample.relative_path.clone())
            .take(3)
            .collect(),
        clean_up_missing_files,
        "prune_missing_files",
        format!(
            "Clean up {} missing {}",
            summary.orphan_missing_file.max(1),
            pluralize(summary.orphan_missing_file.max(1), "item", "items")
        ),
        "warning",
        true,
    );
    push_group_if_any(
        &mut groups,
        "remove_leftover_data",
        "Remove leftover protected data",
        "These items look like leftover protected records that no longer belong in this folder.",
        summary.orphan_outcast.max(remove_leftover_files.len()),
        summary
            .recent_orphans
            .iter()
            .filter(|sample| sample.orphan_kind == Some(FileOrphanKind::Outcast))
            .map(|sample| sample.relative_path.clone())
            .take(3)
            .collect(),
        remove_leftover_files,
        "purge_outcasts",
        if summary.orphan_outcast <= 1 {
            "Review cleanup".to_string()
        } else {
            format!("Review cleanup for {} items", summary.orphan_outcast)
        },
        "danger",
        true,
    );
    push_group_if_any(
        &mut groups,
        "repair_protection",
        "Repair protection history",
        "These items have protection history that needs repair before the folder is fully healthy again.",
        summary.orphan_wrong_epoch.max(repair_protection_files.len()),
        summary
            .recent_orphans
            .iter()
            .filter(|sample| sample.orphan_kind == Some(FileOrphanKind::WrongEpoch))
            .map(|sample| sample.relative_path.clone())
            .take(3)
            .collect(),
        repair_protection_files,
        "migrate_wrong_epoch",
        if summary.orphan_wrong_epoch <= 1 {
            "Repair protection".to_string()
        } else {
            format!("Repair protection for {} items", summary.orphan_wrong_epoch)
        },
        "warning",
        true,
    );
    push_group_if_any(
        &mut groups,
        "review_unprotected",
        "Review unprotected files",
        "These files are in the folder but are not currently protected. Encrypt them or move them outside this folder.",
        summary.unmanaged_files.max(review_unprotected_files.len()),
        summary
            .recent_unmanaged
            .iter()
            .map(|sample| sample.relative_path.clone())
            .take(3)
            .collect(),
        review_unprotected_files,
        "encrypt_or_move",
        "Review unprotected files".to_string(),
        "warning",
        false,
    );

    groups.sort_by_key(|group| group_sort_key(&group.id));

    let has_danger = groups.iter().any(|group| group.severity == "danger");
    let state_label = if summary.tracked_files == 0 && unresolved_item_count == 0 {
        "No protected items indexed yet".to_string()
    } else if unresolved_item_count == 0 && coverage_percent == 100 {
        "Fully protected".to_string()
    } else if coverage_percent >= 99 && !has_danger {
        "Almost fully protected".to_string()
    } else {
        "Needs attention".to_string()
    };

    let summary_text = match state_label.as_str() {
        "Fully protected" => "Everything in this folder is currently covered.".to_string(),
        "No protected items indexed yet" => {
            "Run a scan to confirm what in this folder should be protected.".to_string()
        }
        "Almost fully protected" => format!(
            "{} {} need review to restore full protection.",
            unresolved_item_count,
            pluralize(unresolved_item_count, "item", "items")
        ),
        _ => format!(
            "{} {} in this folder are outside protection and need review.",
            unresolved_item_count,
            pluralize(unresolved_item_count, "item", "items")
        ),
    };

    FolderCoverageReview {
        folder_path: summary.root.path.display().to_string(),
        last_scan_at: summary.root.last_scan.map(|ts| ts.to_rfc3339()),
        coverage_percent,
        state_label,
        summary_text,
        tracked_files: summary.tracked_files,
        unresolved_item_count,
        groups,
    }
}

pub fn build_individual_home_status(input: IndividualHomeStatusInput) -> IndividualHomeStatus {
    let scan_is_stale = match parse_timestamp(input.settings.coverage_last_scan.as_deref()) {
        Some(last_scan) => input.now.signed_duration_since(last_scan).num_hours() > 36,
        None => true,
    };
    let device_review_needed = input.device_counts.pending > 0
        || input.device_counts.stale > 0
        || input.device_counts.unverified > 0;
    let folder_review_needed =
        input.folder_attention.conflicts > 0 || input.folder_attention.recovery_copies > 0;

    let mut attention_count = 0usize;
    if !input.security.mfa_enabled {
        attention_count += 1;
    }
    if !input.security.recovery_backup_ok || !input.security.recovery_auto_backup_ok {
        attention_count += 1;
    }
    if scan_is_stale {
        attention_count += 1;
    }
    if input
        .current_device
        .as_ref()
        .map(|device| device.is_verified)
        .unwrap_or(false)
        == false
    {
        attention_count += 1;
    }
    if device_review_needed {
        attention_count += 1;
    }
    if folder_review_needed {
        attention_count += 1;
    }

    let (
        post_quantum_status,
        post_quantum_primary_text,
        post_quantum_secondary_text,
        post_quantum_explainer_available,
    ) = build_post_quantum_home_snapshot(input.protected_count);

    IndividualHomeStatus {
        protected_count: input.protected_count,
        mounted_count: input.mounted_count,
        attention_count,
        post_quantum_status,
        post_quantum_primary_text,
        post_quantum_secondary_text,
        post_quantum_explainer_available,
        mfa_enabled: input.security.mfa_enabled,
        recovery_backup_ok: input.security.recovery_backup_ok,
        recovery_auto_backup_ok: input.security.recovery_auto_backup_ok,
        last_scan_at: input.settings.coverage_last_scan,
        last_backup_upload_at: input.settings.registry_last_upload,
        current_device: input.current_device,
        device_counts: input.device_counts,
        folder_attention: input.folder_attention,
    }
}

fn build_personal_device_record(
    device_id: String,
    device_name: Option<String>,
    email: Option<String>,
    status: &str,
    added_at: Option<String>,
    last_seen: Option<String>,
    is_current_device: bool,
    is_verified: bool,
) -> PersonalDeviceRecord {
    PersonalDeviceRecord {
        device_id,
        device_name,
        email,
        status: status.to_string(),
        added_at,
        last_seen,
        is_current_device,
        is_verified,
    }
}

pub fn build_personal_devices_overview(
    input: PersonalDevicesOverviewInput,
) -> PersonalDevicesOverview {
    let mut current_device = None;
    let mut trusted_devices = Vec::new();
    let mut setup_devices = Vec::new();
    let mut review_devices = Vec::new();

    let pending_ids = input
        .pending_devices
        .iter()
        .map(|device| device.device_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let stale_ids = input
        .stale_devices
        .iter()
        .map(|device| device.device_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let unverified_ids = input
        .unverified_devices
        .iter()
        .map(|device| device.device_id.as_str())
        .collect::<std::collections::HashSet<_>>();

    let current_device_id = input.current_device_id.as_deref().unwrap_or_default();
    let mut seen_ids = std::collections::HashSet::new();

    for device in input.registered_devices {
        let status = if pending_ids.contains(device.device_id.as_str()) {
            "pending"
        } else if unverified_ids.contains(device.device_id.as_str()) {
            "unverified"
        } else if stale_ids.contains(device.device_id.as_str()) {
            "stale"
        } else {
            "trusted"
        };

        let is_current_device = device.is_current_device || device.device_id == current_device_id;
        let record = build_personal_device_record(
            device.device_id.clone(),
            device.device_name.clone(),
            None,
            status,
            Some(device.created_at.clone()),
            Some(device.last_seen.clone()),
            is_current_device,
            device.is_verified && status != "unverified",
        );
        seen_ids.insert(device.device_id);

        if record.is_current_device {
            current_device = Some(record);
        } else if status == "pending" || status == "unverified" {
            setup_devices.push(record);
        } else if status == "stale" {
            review_devices.push(record);
        } else {
            trusted_devices.push(record);
        }
    }

    for device in input.pending_devices {
        let is_current_device = device.device_id == current_device_id;
        if !seen_ids.insert(device.device_id.clone()) {
            continue;
        }
        let record = build_personal_device_record(
            device.device_id,
            device.device_name,
            Some(device.email),
            "pending",
            device.observed_at.clone(),
            device.observed_at,
            is_current_device,
            false,
        );
        if is_current_device {
            current_device = Some(record);
        } else {
            setup_devices.push(record);
        }
    }

    for device in input.unverified_devices {
        let is_current_device = device.device_id == current_device_id;
        if !seen_ids.insert(device.device_id.clone()) {
            continue;
        }
        let record = build_personal_device_record(
            device.device_id,
            device.device_name,
            Some(device.email),
            "unverified",
            None,
            device.last_seen,
            is_current_device,
            false,
        );
        if is_current_device {
            current_device = Some(record);
        } else {
            setup_devices.push(record);
        }
    }

    for device in input.stale_devices {
        let is_current_device = device.device_id == current_device_id;
        if !seen_ids.insert(device.device_id.clone()) {
            continue;
        }
        let record = build_personal_device_record(
            device.device_id,
            device.device_name,
            Some(device.email),
            "stale",
            None,
            device.last_seen,
            is_current_device,
            true,
        );
        if is_current_device {
            current_device = Some(record);
        } else {
            review_devices.push(record);
        }
    }

    PersonalDevicesOverview {
        current_device,
        trusted_devices,
        setup_devices,
        review_devices,
        rename_supported: input.rename_supported,
        revoke_supported: input.revoke_supported,
    }
}
