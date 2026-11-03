// Tests delayed Team activation requests reject a changed account or device before any mutation.
use super::check_license_request_context;
use crate::state::UserSession;

fn session() -> UserSession {
    UserSession {
        email: "owner@example.test".into(),
        device_id: "original-device".into(),
        token: "test-token".into(),
        refresh_token: String::new(),
        team_entitlement: None,
        team_revoked: false,
        pending_team_requests: Vec::new(),
        expires_at: 123456,
        user_id: "test-user".into(),
        server_url: Some("https://example.test".into()),
        opaque_export_key: None,
        persistent: true,
    }
}

#[test]
fn requests_remain_bound_to_the_account_and_device_that_opened_activation() {
    let mut current = session();
    let expected_email = "owner@example.test";
    let expected_device = "original-device";
    assert!(
        check_license_request_context(&current, Some(expected_email), Some(expected_device))
            .is_ok()
    );
    current.email = "another@example.test".into();
    assert!(
        check_license_request_context(&current, Some(expected_email), Some(expected_device))
            .is_err()
    );
    current.email = expected_email.into();
    current.device_id = "different-device".into();
    assert!(
        check_license_request_context(&current, Some(expected_email), Some(expected_device))
            .is_err()
    );
}

#[test]
fn token_refresh_preserves_the_same_activation_context() {
    let mut current = session();
    current.token = "refreshed-test-token".into();
    assert!(check_license_request_context(
        &current,
        Some("owner@example.test"),
        Some("original-device")
    )
    .is_ok());
}
