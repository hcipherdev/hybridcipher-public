// Tests the TeamDeviceRoster parsing and team_devices_error() mapping in src/commands/team_devices.rs, used by the Members & devices page.
use super::*;

#[test]
fn roster_parses_server_payload_and_defaults_optional_fields() {
    let roster: TeamDeviceRoster = serde_json::from_value(json!({
        "organization_id": "11111111-1111-1111-1111-111111111111",
        "generated_at": "2026-10-26T10:00:00Z",
        "stale_threshold_days": 30,
        "members": [{
            "user_id": "22222222-2222-2222-2222-222222222222",
            "email": "mia@example.com",
            "role": "member",
            "groups": [{ "id": "33333333-3333-3333-3333-333333333333", "name": "Research" }],
            "devices": [
                { "device_id": "mia-laptop", "device_name": "MacBook", "created_at": "2026-09-01T00:00:00Z",
                  "last_seen": "2026-10-25T00:00:00Z", "status": "missing_key", "approved": true,
                  "fingerprint_verified": true,
                  "missing_key_groups": [{ "id": "33333333-3333-3333-3333-333333333333", "name": "Research" }] },
                { "device_id": "mia-phone", "created_at": "2026-09-01T00:00:00Z",
                  "last_seen": "2026-09-02T00:00:00Z", "status": "stale" }
            ]
        }]
    }))
    .unwrap();
    let devices = &roster.members[0].devices;
    assert_eq!(devices[0].status, "missing_key");
    assert_eq!(devices[0].missing_key_groups[0].name, "Research");
    assert_eq!(devices[1].device_name, None);
    assert!(devices[1].stale_reasons.is_empty());
    assert!(!devices[1].approved);
}

#[test]
fn errors_explain_what_the_admin_can_do() {
    let old_server: CommandResponse<TeamDeviceRoster> = team_devices_error(
        reqwest::StatusCode::NOT_FOUND,
        "",
        "Loading members and devices",
    );
    assert_eq!(
        old_server.error_code.as_deref(),
        Some(TEAM_DEVICES_UNSUPPORTED)
    );

    let untrusted: CommandResponse<TeamDeviceRoster> = team_devices_error(
        reqwest::StatusCode::PRECONDITION_REQUIRED,
        "",
        "Loading members and devices",
    );
    assert_eq!(
        untrusted.error_code.as_deref(),
        Some("device_trust_required")
    );

    // A 404 with a body is a real "not found" (for example a device already removed).
    let gone: CommandResponse<TeamDeviceRevokeResult> = team_devices_error(
        reqwest::StatusCode::NOT_FOUND,
        r#"{"code":"device_not_registered","error":"That device is no longer registered."}"#,
        "Device revocation",
    );
    assert_eq!(gone.error_code, None);
    assert_eq!(
        gone.error.as_deref(),
        Some("That device is no longer registered.")
    );

    let expired: CommandResponse<TeamDeviceRoster> = team_devices_error(
        reqwest::StatusCode::UNAUTHORIZED,
        "",
        "Loading members and devices",
    );
    assert_eq!(
        expired.error.as_deref(),
        Some("Authentication token rejected. Please login again.")
    );
}
