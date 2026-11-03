// Verify login, approval, cached keys, and protocol support cannot imply device-management trust, and that setup rows say whether the fingerprint is checked and whether keys are missing.
use super::*;
use hybridcipher_messages::device_actions::DeviceTrustStatus;

fn input(
    approved: bool,
    verified: bool,
    trust: Option<DeviceTrustStatus>,
) -> PersonalDevicesOverviewInput {
    PersonalDevicesOverviewInput {
        current_device_id: Some("current-device".into()),
        registered_devices: vec![RegisteredDeviceRecord {
            fingerprint_verified: verified,
            device_id: "other-device".into(),
            device_name: None,
            created_at: "2026-10-03T10:00:00Z".into(),
            last_seen: "2026-10-03T10:00:00Z".into(),
            is_current_device: false,
            is_approved: approved,
            is_verified: approved && verified,
        }],
        pending_devices: vec![],
        stale_devices: vec![],
        unverified_devices: vec![],
        rename_supported: false,
        revoke_supported: true,
        device_trust: trust,
    }
}

#[test]
fn missing_authoritative_trust_denies_every_management_capability() {
    let overview = build_personal_devices_overview(input(true, true, None));
    assert!(overview.revoke_supported);
    assert!(
        !overview.can_revoke_other_devices
            && !overview.can_approve_devices
            && !overview.can_verify_devices
    );
}

#[test]
fn approval_and_manual_verification_are_independent_setup_steps() {
    let pending = build_personal_devices_overview(input(false, true, None));
    assert_eq!(pending.setup_devices[0].status, "pending");
    let unverified = build_personal_devices_overview(input(true, false, None));
    assert_eq!(unverified.setup_devices[0].status, "unverified");
    assert!(!unverified.setup_devices[0].is_verified);
    assert!(unverified.trusted_devices.is_empty());
}

#[test]
fn capability_projection_uses_explicit_server_permissions() {
    let trust = DeviceTrustStatus {
        device_id: "current-device".into(),
        identity_key_sha256: "ab".repeat(32),
        approved: true,
        fingerprint_verified: true,
        can_revoke_other_devices: true,
        can_approve_devices: true,
        can_verify_devices: true,
        confirmation_required: false,
        blocking_reason: None,
        source: Some("manual_verification".into()),
    };
    let overview = build_personal_devices_overview(input(true, true, Some(trust)));
    assert!(
        overview.can_revoke_other_devices
            && overview.can_approve_devices
            && overview.can_verify_devices
    );
    assert_eq!(overview.trusted_devices.len(), 1);
}

#[test]
fn setup_rows_say_whether_the_fingerprint_is_checked_and_keys_are_missing() {
    // Verified but never approved: giving access can skip the fingerprint step.
    let new_device = build_personal_devices_overview(input(false, true, None));
    assert!(new_device.setup_devices[0].fingerprint_verified);
    assert!(!new_device.setup_devices[0].missing_current_key);

    // Trusted, but a key rotation skipped it in some group.
    let mut repair = input(true, true, None);
    repair.pending_devices = vec![PendingDeviceRecord {
        device_id: "other-device".into(),
        email: "me@example.test".into(),
        device_name: None,
        observed_at: None,
        missing_current_key: true,
    }];
    let repair = build_personal_devices_overview(repair);
    assert_eq!(repair.setup_devices[0].status, "pending");
    assert!(repair.setup_devices[0].missing_current_key);
    assert!(repair.setup_devices[0].fingerprint_verified);
}
