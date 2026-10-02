// Tests the account-protected TOML round trip for Team administration requests in team_requests.rs.
use super::*;

#[test]
fn pending_invitation_survives_session_serialization() {
    let pending = PendingTeamRequest {
        request: TeamAdminRequest {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            kind: "invite_member".into(),
            email: Some("person@example.com".into()),
            invitation_code: Some(format!("HC-INVITE-{}", "A".repeat(48))),
            group_name: None,
            description: None,
            target_id: None,
        },
        created_at: 1_800_000_000,
        status: "pending".into(),
        result_id: None,
        last_error: None,
    };
    let serialized = toml::to_string(&pending).unwrap();
    let restored: PendingTeamRequest = toml::from_str(&serialized).unwrap();
    assert_eq!(restored, pending);
}
