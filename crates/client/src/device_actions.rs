//! Validate and sign one-use, account-scoped device-management challenges.

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use hybridcipher_messages::device_actions::{
    device_action_payload_sha256, DeviceAction, DeviceActionChallenge,
    DeviceActionChallengeRequest, DeviceTrustStatus, DEVICE_CHALLENGE_HEADER,
    DEVICE_SIGNATURE_HEADER,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

// The server issues five-minute challenges. Bound clock differences without
// changing their server-enforced expiry or one-use authorization.
const DEVICE_ACTION_CHALLENGE_LIFETIME_SECONDS: i64 = 300;
const DEVICE_ACTION_CHALLENGE_CLOCK_SKEW_SECONDS: i64 = 30;

/// Authenticated scope expected by the client before it signs a challenge.
pub struct DeviceActionContext<'a> {
    pub server_url: &'a str,
    pub token: &'a str,
    pub user_id: &'a str,
    pub device_id: &'a str,
}

/// A proof is tied to one exact request body and must never be reused.
pub struct DeviceActionProof {
    challenge_id: String,
    signature: String,
}

impl DeviceActionProof {
    pub fn apply(self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
            .header(DEVICE_CHALLENGE_HEADER, self.challenge_id)
            .header(DEVICE_SIGNATURE_HEADER, self.signature)
    }
}

pub fn api_base(server_url: &str) -> String {
    format!(
        "{}/api/v1",
        server_url.trim_end_matches('/').trim_end_matches("/api/v1")
    )
}

/// Emit the complete server DTO shape before hashing an invitation rotation.
pub fn device_invitation_rotation_payload(
    invitation_public: &[u8],
    identity_public: &[u8],
    self_welcome_messages: Value,
) -> Result<Value, String> {
    if !self_welcome_messages.is_array() {
        return Err("Self Welcome messages must be an array.".into());
    }
    Ok(serde_json::json!({
        "invitation_public_key": hex::encode(invitation_public),
        "identity_public_key": hex::encode(identity_public),
        "self_welcome_messages": self_welcome_messages,
    }))
}

/// Reject a response whose identity, operation, body, or lifetime differs from intent.
pub fn validate_device_action_challenge(
    challenge: &DeviceActionChallenge,
    context: &DeviceActionContext<'_>,
    identity_public: &[u8],
    action: DeviceAction,
    target_device_id: &str,
    target_identity_sha256: Option<&str>,
    payload: &Value,
    now: i64,
) -> Result<(), String> {
    let digest = device_action_payload_sha256(payload).map_err(|error| error.to_string())?;
    if challenge.actor_user_id != context.user_id
        || challenge.actor_device_id != context.device_id
        || api_base(&challenge.server_url) != api_base(context.server_url)
        || challenge.actor_identity_key_sha256 != hex::encode(Sha256::digest(identity_public))
        || challenge.action != action
        || challenge.target_device_id != target_device_id
        || challenge.payload_sha256 != digest
        || target_identity_sha256
            .is_some_and(|expected| challenge.target_identity_key_sha256 != expected)
        || uuid::Uuid::parse_str(&challenge.challenge_id).is_err()
        || hex::decode(&challenge.nonce).map_or(true, |nonce| nonce.len() != 32)
        || hex::decode(&challenge.target_identity_key_sha256)
            .map_or(true, |digest| digest.len() != 32)
    {
        return Err(
            "Device authorization challenge does not match this account, device, or action.".into(),
        );
    }
    if challenge.expires_at <= now {
        return Err("Device authorization challenge has expired. Retry the operation.".into());
    }
    if challenge.expires_at
        > now.saturating_add(
            DEVICE_ACTION_CHALLENGE_LIFETIME_SECONDS + DEVICE_ACTION_CHALLENGE_CLOCK_SKEW_SECONDS,
        )
    {
        return Err(
            "Device authorization challenge expiry is too far in the future. Check your device's date and time, then retry."
                .into(),
        );
    }
    Ok(())
}

pub async fn signed_device_action(
    identity: &Ed25519KeyPair,
    context: &DeviceActionContext<'_>,
    action: DeviceAction,
    target_device_id: &str,
    target_identity_sha256: Option<&str>,
    payload: &Value,
) -> Result<DeviceActionProof, String> {
    let challenge = request_action_challenge(
        identity,
        context,
        action,
        target_device_id,
        target_identity_sha256,
        payload,
    )
    .await?;
    let transcript = challenge
        .signing_payload()
        .map_err(|error| error.to_string())?;
    Ok(DeviceActionProof {
        challenge_id: challenge.challenge_id,
        signature: STANDARD.encode(identity.sign(&transcript)),
    })
}

/// Both keys authorize the same checked one-use transcript.
pub async fn signed_recovery_device_action(
    identity: &Ed25519KeyPair,
    recovery_identity: &Ed25519KeyPair,
    context: &DeviceActionContext<'_>,
    action: DeviceAction,
    payload: &Value,
) -> Result<(DeviceActionProof, String), String> {
    let identity_hash = hex::encode(Sha256::digest(identity.public_key_bytes()));
    let challenge = request_action_challenge(
        identity,
        context,
        action,
        context.device_id,
        Some(&identity_hash),
        payload,
    )
    .await?;
    let transcript = challenge
        .signing_payload()
        .map_err(|error| error.to_string())?;
    let recovery_signature = STANDARD.encode(recovery_identity.sign(&transcript));
    Ok((
        DeviceActionProof {
            challenge_id: challenge.challenge_id,
            signature: STANDARD.encode(identity.sign(&transcript)),
        },
        recovery_signature,
    ))
}

async fn request_action_challenge(
    identity: &Ed25519KeyPair,
    context: &DeviceActionContext<'_>,
    action: DeviceAction,
    target_device_id: &str,
    target_identity_sha256: Option<&str>,
    payload: &Value,
) -> Result<DeviceActionChallenge, String> {
    let request = DeviceActionChallengeRequest {
        server_url: context.server_url.to_owned(),
        action,
        target_device_id: target_device_id.to_owned(),
        payload_sha256: device_action_payload_sha256(payload).map_err(|error| error.to_string())?,
    };
    let response = reqwest::Client::new()
        .post(format!(
            "{}/auth/device-actions/challenge",
            api_base(context.server_url)
        ))
        .bearer_auth(context.token)
        .timeout(std::time::Duration::from_secs(15))
        .json(&request)
        .send()
        .await
        .map_err(|error| format!("Device authorization unavailable: {error}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let message = response.text().await.unwrap_or_default();
        return Err(format!(
            "Device authorization rejected ({status}): {message}"
        ));
    }
    let challenge: DeviceActionChallenge = response
        .json()
        .await
        .map_err(|error| format!("Invalid device authorization response: {error}"))?;
    validate_device_action_challenge(
        &challenge,
        context,
        &identity.public_key_bytes(),
        action,
        target_device_id,
        target_identity_sha256,
        payload,
        Utc::now().timestamp(),
    )?;
    Ok(challenge)
}

/// No local login flag or cached role is a substitute for current server trust.
pub async fn fetch_device_trust(
    context: &DeviceActionContext<'_>,
) -> Result<DeviceTrustStatus, String> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/auth/device-trust",
            api_base(context.server_url)
        ))
        .bearer_auth(context.token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|error| format!("Device trust unavailable: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("Device trust unavailable ({})", response.status()));
    }
    let status: DeviceTrustStatus = response
        .json()
        .await
        .map_err(|error| format!("Invalid device trust response: {error}"))?;
    if status.device_id != context.device_id {
        return Err("Device trust response belongs to a different device.".into());
    }
    Ok(status)
}

/// Finish a verified recovery session using the same registered device key.
pub async fn complete_device_trust_recovery(
    identity: &Ed25519KeyPair,
    context: &DeviceActionContext<'_>,
    recovery_session_id: uuid::Uuid,
) -> Result<DeviceTrustStatus, String> {
    let payload = serde_json::json!({"recovery_session_id": recovery_session_id.to_string()});
    let identity_hash = hex::encode(Sha256::digest(identity.public_key_bytes()));
    let proof = signed_device_action(
        identity,
        context,
        DeviceAction::ConfirmRecovery,
        context.device_id,
        Some(&identity_hash),
        &payload,
    )
    .await?;
    let response = proof
        .apply(
            reqwest::Client::new()
                .post(format!(
                    "{}/auth/device-trust/recovery/complete",
                    api_base(context.server_url)
                ))
                .bearer_auth(context.token)
                .json(&payload),
        )
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let message = response.text().await.unwrap_or_default();
        return Err(format!(
            "Device trust confirmation rejected ({status}): {message}"
        ));
    }
    let status: DeviceTrustStatus = response.json().await.map_err(|error| error.to_string())?;
    if status.device_id != context.device_id
        || status.identity_key_sha256 != identity_hash
        || !status.can_revoke_other_devices
    {
        return Err("Device trust confirmation did not establish trust for this identity.".into());
    }
    Ok(status)
}

#[cfg(test)]
#[path = "../tests/device_security/test_device_action_challenges.rs"]
mod tests;
