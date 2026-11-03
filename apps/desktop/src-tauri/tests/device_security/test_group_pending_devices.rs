// Tests group_pending_device_summaries() in src/commands.rs, which labels every member's devices awaiting a Welcome, including ones a key rotation skipped and whether their owner can give access themselves.
use super::*;

#[test]
fn group_pending_devices_keep_owner_email_and_rotation_flag() {
    let owner = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let payload: Vec<PendingDeviceApiRecord> = serde_json::from_value(serde_json::json!([
        { "user_id": owner, "device_id": "skipped", "device_name": "DESKTOP-5QMKKST",
          "pending_since": 1_760_000_000, "missing_current_key": true,
          "owner_can_self_approve": true },
        { "user_id": "22222222-2222-2222-2222-222222222222", "device_id": "new", "device_name": null,
          "pending_since": 1_760_000_100 },
    ]))
    .unwrap();
    let emails = HashMap::from([(owner, "owner@example.com".to_string())]);

    let summaries = group_pending_device_summaries(payload, &emails);

    assert_eq!(summaries[0].email, "owner@example.com");
    assert!(summaries[0].missing_current_key);
    assert_eq!(summaries[0].device_name.as_deref(), Some("DESKTOP-5QMKKST"));
    // An owner outside the member list stays unnamed rather than borrowing another email.
    assert_eq!(summaries[1].email, "");
    assert!(!summaries[1].missing_current_key);
    // Admins are reminded only when the owner can't give access from a device of their own.
    assert!(summaries[0].owner_can_self_approve);
    assert!(!summaries[1].owner_can_self_approve);
}
