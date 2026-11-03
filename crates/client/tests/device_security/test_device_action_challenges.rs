// Verify device-action signatures cannot authorize a different account, key, body, or scope.
use super::*;
use hybridcipher_messages::device_actions::DeviceAction;
use serde_json::json;

#[test]
fn rejects_changed_account_identity_action_target_body_and_expiry() {
    let identity = Ed25519KeyPair::generate();
    let context = DeviceActionContext {
        server_url: "https://example.test/api/v1",
        token: "test-token",
        user_id: "test-user",
        device_id: "trusted-device",
    };
    let payload = json!({});
    let challenge = DeviceActionChallenge {
        challenge_id: uuid::Uuid::new_v4().to_string(),
        actor_user_id: context.user_id.into(),
        actor_device_id: context.device_id.into(),
        actor_identity_key_sha256: hex::encode(Sha256::digest(identity.public_key_bytes())),
        server_url: "https://example.test".into(),
        action: DeviceAction::Revoke,
        target_device_id: "other-device".into(),
        target_identity_key_sha256: "ab".repeat(32),
        payload_sha256: device_action_payload_sha256(&payload).unwrap(),
        expires_at: 120,
        nonce: "cd".repeat(32),
    };
    let valid = |candidate: &DeviceActionChallenge| {
        validate_device_action_challenge(
            candidate,
            &context,
            &identity.public_key_bytes(),
            DeviceAction::Revoke,
            "other-device",
            None,
            &payload,
            100,
        )
    };
    assert!(valid(&challenge).is_ok());
    let mutations: Vec<Box<dyn Fn(&mut DeviceActionChallenge)>> = vec![
        Box::new(|c| c.actor_user_id = "different-user".into()),
        Box::new(|c| c.actor_device_id = "new-device".into()),
        Box::new(|c| c.actor_identity_key_sha256 = "00".repeat(32)),
        Box::new(|c| c.server_url = "https://attacker.test".into()),
        Box::new(|c| c.action = DeviceAction::ApproveWelcome),
        Box::new(|c| c.target_device_id = "primary-device".into()),
        Box::new(|c| c.payload_sha256 = "00".repeat(32)),
        Box::new(|c| c.expires_at = 100),
        Box::new(|c| c.expires_at = 431),
        Box::new(|c| c.nonce = "00".into()),
        Box::new(|c| c.nonce = "00".repeat(16)),
        Box::new(|c| c.nonce = "00".repeat(33)),
    ];
    for mutate in mutations {
        let mut changed = challenge.clone();
        mutate(&mut changed);
        assert!(valid(&changed).is_err());
    }
    assert!(validate_device_action_challenge(
        &challenge,
        &context,
        &identity.public_key_bytes(),
        DeviceAction::Revoke,
        "other-device",
        Some(&"00".repeat(32)),
        &payload,
        100
    )
    .is_err());
}

#[test]
fn accepts_fresh_recovery_challenge_when_server_clock_is_slightly_ahead() {
    let identity = Ed25519KeyPair::generate();
    let context = DeviceActionContext {
        server_url: "https://example.test",
        token: "test-token",
        user_id: "test-user",
        device_id: "recovery-device",
    };
    let payload = json!({"recovery_session_id": uuid::Uuid::new_v4().to_string()});
    let identity_hash = hex::encode(Sha256::digest(identity.public_key_bytes()));
    let mut challenge = DeviceActionChallenge {
        challenge_id: uuid::Uuid::new_v4().to_string(),
        actor_user_id: context.user_id.into(),
        actor_device_id: context.device_id.into(),
        actor_identity_key_sha256: identity_hash.clone(),
        server_url: context.server_url.into(),
        action: DeviceAction::CompleteSavedCodeRecovery,
        target_device_id: context.device_id.into(),
        target_identity_key_sha256: identity_hash.clone(),
        payload_sha256: device_action_payload_sha256(&payload).unwrap(),
        expires_at: 407,
        nonce: "cd".repeat(32),
    };
    let validate = |candidate: &DeviceActionChallenge| {
        validate_device_action_challenge(
            candidate,
            &context,
            &identity.public_key_bytes(),
            DeviceAction::CompleteSavedCodeRecovery,
            context.device_id,
            Some(&identity_hash),
            &payload,
            100,
        )
    };

    // A server seven seconds ahead issues a five-minute challenge that appears
    // to have 307 seconds remaining on this device.
    assert!(validate(&challenge).is_ok());
    challenge.expires_at = 430;
    assert!(validate(&challenge).is_ok());
    challenge.expires_at = 431;
    assert!(validate(&challenge).unwrap_err().contains("date and time"));
    challenge.expires_at = 100;
    assert!(validate(&challenge).unwrap_err().contains("expired"));

    // Clock tolerance must never permit signing for a different account/key.
    challenge.expires_at = 407;
    challenge.actor_user_id = "other-user".into();
    assert!(validate(&challenge).is_err());
    challenge.actor_user_id = context.user_id.into();
    challenge.target_identity_key_sha256 = "00".repeat(32);
    assert!(validate(&challenge).is_err());
}
