// Tests SessionStore's protected Team request journal across logout and account unlock.
use super::*;
use hybridcipher_client::team_requests::{PendingTeamRequest, TeamAdminRequest};
use uuid::Uuid;

#[test]
fn pending_team_request_survives_logout_and_reunlock() {
    let root = tempfile::tempdir().unwrap();
    let store = SessionStore {
        base_dir: root.path().to_path_buf(),
        global_dir: root.path().join(GLOBAL_DIR),
    };
    fs::create_dir(&store.global_dir).unwrap();
    let email = "owner@example.invalid";
    let server = "https://fixture.example.invalid";
    let account_key = store
        .initialize_account_protection_uncached(email, server, "correct horse")
        .unwrap();
    let state_key = store
        .load_state_key_with_account_key(email, server, &account_key)
        .unwrap();
    let pending = PendingTeamRequest {
        request: TeamAdminRequest {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            kind: "invite_member".into(),
            email: Some("member@example.invalid".into()),
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
    store
        .save_team_requests_with_key(email, server, &[pending.clone()], &state_key)
        .unwrap();
    let journal = store.user_dir(email, server).join(TEAM_REQUESTS_FILE);
    let raw = fs::read_to_string(&journal).unwrap();
    assert!(!raw.contains("member@example.invalid"));
    assert!(!raw.contains("HC-INVITE-"));
    store.delete_session(email, server).unwrap();
    assert!(journal.exists());
    let account_key_again = store
        .initialize_account_protection_uncached(email, server, "correct horse")
        .unwrap();
    let state_key_again = store
        .load_state_key_with_account_key(email, server, &account_key_again)
        .unwrap();
    assert_eq!(*state_key, *state_key_again);
    assert_eq!(
        store
            .load_team_requests_with_key(email, server, &state_key_again)
            .unwrap(),
        vec![pending]
    );
}
