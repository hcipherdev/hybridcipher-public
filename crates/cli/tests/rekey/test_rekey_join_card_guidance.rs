// Tests rekey_problem_guidance() and stale_devices_blocking_rekey() in src/commands/rekey.rs, which decide and explain which devices block a key rotation, including expired join cards and devices not verified on this computer.
use super::*;

#[test]
fn expired_join_cards_get_their_own_fix() {
    let guidance = rekey_problem_guidance(&[JOIN_CARD_EXPIRED_REASON]);
    assert!(guidance.contains("Expired join card: open HybridCipher (or sign in) on that device"));
    assert!(!guidance.contains("publish-joincard"));
    assert!(guidance.contains("--force to skip these devices"));
}

#[test]
fn guidance_lists_only_the_problem_kinds_present() {
    let guidance = rekey_problem_guidance(&["Join card not found", "Pinned key expired"]);
    assert!(guidance.contains("Missing join card"));
    assert!(guidance.contains("Expired pin"));
    assert!(!guidance.contains("Expired join card"));
    assert!(!guidance.contains("Not verified on this computer"));
}

#[test]
fn devices_not_verified_here_are_explained_in_app_terms() {
    let guidance = rekey_problem_guidance(&[NOT_VERIFIED_HERE_REASON]);
    assert!(guidance.contains("Not verified on this computer: compare the device's fingerprint"));
    assert!(guidance.contains("Devices to verify"));
}

#[test]
fn reasons_with_details_still_get_their_fix() {
    let guidance = rekey_problem_guidance(&["Join card expired at 22 Oct 2026 13:00", "Pinned key expired at 1 Oct 2026"]);
    assert!(guidance.contains("Expired join card"));
    assert!(guidance.contains("Expired pin"));
}

fn audit_entry(device_id: &str, stale: bool, reasons: &[&str]) -> diagnostics::DeviceAuditEntry {
    serde_json::from_value(serde_json::json!({
        "user_id": Uuid::nil(),
        "device_id": device_id,
        "device_name": null,
        "last_seen": 0,
        "created_at": 0,
        "invitation_key_present": true,
        "stale": stale,
        "reasons": reasons,
    }))
    .unwrap()
}

#[test]
fn an_expired_join_card_alone_does_not_stop_the_rotation_early() {
    let devices = [
        audit_entry("fresh", false, &[]),
        audit_entry("card-lapsed", true, &["Join card expired on 2026-10-04"]),
        audit_entry("long-absent", true, &["Last seen 41 day(s) ago", "Join card expired on 2026-10-04"]),
        audit_entry("keyless", true, &["Invitation public key missing"]),
    ];
    let blocking = stale_devices_blocking_rekey(&devices);
    assert_eq!(blocking.len(), 2);
    assert!(blocking[0].starts_with("long-absent (user"));
    assert!(blocking[0].contains("Last seen 41 day(s) ago"));
    assert!(blocking[1].starts_with("keyless (user"));
}
