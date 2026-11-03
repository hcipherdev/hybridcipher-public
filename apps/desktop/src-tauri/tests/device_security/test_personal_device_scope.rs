// Tests is_session_owned_device(), own_stale_device_records() and stale_device_summary() in src/commands.rs, which scope device records to their owner.
use super::*;

const OWN_USER: &str = "11111111-1111-1111-1111-111111111111";
const OTHER_USER: &str = "22222222-2222-2222-2222-222222222222";

fn audit_entry(user_id: &str, device_id: &str, stale: bool) -> DeviceHealthEntry {
    DeviceHealthEntry {
        user_id: Uuid::parse_str(user_id).unwrap(),
        device_id: device_id.to_string(),
        device_name: Some("Primary Device".to_string()),
        last_seen: chrono::Utc::now(),
        stale,
        reasons: if stale {
            vec!["Last seen 31 day(s) ago".to_string()]
        } else {
            Vec::new()
        },
        invitation_key_present: true,
    }
}

fn session(user_id: &str, device_id: &str) -> crate::state::UserSession {
    serde_json::from_value(serde_json::json!({
        "email": "me@example.com",
        "device_id": device_id,
        "token": "unused",
        "expires_at": 0,
        "user_id": user_id,
    }))
    .unwrap()
}

#[test]
fn stale_records_exclude_other_members_devices() {
    let audit = vec![
        audit_entry(OWN_USER, "device-own-stale", true),
        audit_entry(OWN_USER, "device-own-fresh", false),
        audit_entry(OTHER_USER, "device-other-stale", true),
    ];

    let records = own_stale_device_records(&audit, OWN_USER, "me@example.com");

    assert_eq!(
        records
            .iter()
            .map(|record| record.device_id.as_str())
            .collect::<Vec<_>>(),
        vec!["device-own-stale"]
    );
    assert_eq!(records[0].email, "me@example.com");
}

#[test]
fn unparseable_session_user_id_keeps_no_group_records() {
    let audit = vec![audit_entry(OWN_USER, "device-own-stale", true)];

    assert!(own_stale_device_records(&audit, "70f3e0a9a9467a87", "me@example.com").is_empty());
    assert!(!is_session_owned_device("", OWN_USER));
}

#[test]
fn ownership_check_matches_only_the_session_account() {
    assert!(is_session_owned_device(OWN_USER, OWN_USER));
    assert!(is_session_owned_device(&format!(" {OWN_USER} "), &OWN_USER.to_uppercase()));
    assert!(!is_session_owned_device(OWN_USER, OTHER_USER));
}

#[test]
fn stale_summary_offers_removal_only_for_the_signed_in_account() {
    let session = session(OWN_USER, "device-current");
    let email_map = HashMap::from([(Uuid::parse_str(OWN_USER).unwrap(), "me@example.com".to_string())]);

    let own = stale_device_summary(audit_entry(OWN_USER, "device-own-stale", true), &email_map, &session);
    assert!(own.owned_by_current_user);
    assert!(!own.is_current_device);
    assert_eq!(own.reasons, vec!["Last seen 31 day(s) ago"]);

    let current = stale_device_summary(audit_entry(OWN_USER, "device-current", true), &email_map, &session);
    assert!(current.is_current_device);

    // Another member missing from the member list must not be shown under the admin's email.
    let other = stale_device_summary(audit_entry(OTHER_USER, "device-other-stale", true), &email_map, &session);
    assert!(!other.owned_by_current_user);
    assert!(!other.is_current_device);
    assert_eq!(other.email, "");
    assert_eq!(other.user_id, OTHER_USER);
}
