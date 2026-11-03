//! Account-bound saved-code proof, trusted enrollment, and protected backup writes.
use crate::{
    auth::opaque::{DeviceLoginMetadata, OpaqueAuth},
    device_actions::{
        api_base, signed_device_action, signed_recovery_device_action, DeviceActionContext,
    },
    saved_code_recovery::BackupArtifact,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use hybridcipher_messages::{device_actions::DeviceAction, recovery_credentials::*};
use rand::{rngs::OsRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

async fn response_json(response: reqwest::Response) -> Result<Value, String> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let message = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|body| {
                body["message"]
                    .as_str()
                    .or(body["error"].as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("Recovery request rejected ({status})"));
        return Err(format!("{status}: {message}"));
    }
    response
        .json()
        .await
        .map_err(|_| "Recovery response is invalid".into())
}

pub async fn fetch_recovery_credential(
    context: &DeviceActionContext<'_>,
) -> Result<RecoveryCredentialStatus, String> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/recovery-credential",
            api_base(context.server_url)
        ))
        .bearer_auth(context.token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|_| "Recovery authorization could not reach the server")?;
    serde_json::from_value(response_json(response).await?)
        .map_err(|_| "Recovery credential response is invalid".into())
}

pub fn recovery_signing_identity(
    raw_code: &[u8],
    user_id: &str,
    credential: &RecoveryCredential,
) -> Result<Ed25519KeyPair, String> {
    if raw_code.len() != 32
        || credential.generation == 0
        || Uuid::parse_str(&credential.credential_id).is_err()
    {
        return Err("Recovery credential is invalid".into());
    }
    let salt = STANDARD
        .decode(&credential.salt_b64)
        .map_err(|_| "Recovery salt is invalid")?;
    if salt.len() != 32 {
        return Err("Recovery salt is invalid".into());
    }
    let info = recovery_signing_context(user_id, credential).map_err(|e| e.to_string())?;
    let mut seed = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), raw_code)
        .expand(&info, seed.as_mut())
        .map_err(|_| "Recovery key derivation failed")?;
    Ed25519KeyPair::from_bytes(seed.as_ref()).map_err(|e| e.to_string())
}

pub async fn enroll_recovery_credential(
    identity: &Ed25519KeyPair,
    context: &DeviceActionContext<'_>,
    raw_code: &[u8],
    artifact: &BackupArtifact,
    expected_artifact_version: Option<u32>,
    previous: Option<&RecoveryCredential>,
    recovery_session_id: Option<Uuid>,
) -> Result<RecoveryCredentialStatus, String> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut credential = RecoveryCredential {
        credential_id: Uuid::new_v4().to_string(),
        generation: previous.map_or(Ok(1), |value| {
            value
                .generation
                .checked_add(1)
                .ok_or("Recovery credential generation exhausted")
        })?,
        salt_b64: STANDARD.encode(salt),
        public_key_b64: String::new(),
        recovery_envelope_sha256: recovery_envelope_sha256(
            &serde_json::to_value(artifact).map_err(|e| e.to_string())?,
        )?,
    };
    let signing = recovery_signing_identity(raw_code, context.user_id, &credential)?;
    credential.public_key_b64 = STANDARD.encode(signing.public_key_bytes());
    let body = InstallRecoveryCredentialRequest {
        credential,
        artifact_blob: artifact.to_base64()?,
        expected_artifact_version,
        expected_credential_id: previous.map(|value| value.credential_id.clone()),
        recovery_session_id: recovery_session_id.map(|id| id.to_string()),
    };
    let payload = serde_json::to_value(&body).map_err(|e| e.to_string())?;
    let proof = signed_device_action(
        identity,
        context,
        DeviceAction::ManageRecoveryCredential,
        context.device_id,
        None,
        &payload,
    )
    .await?;
    let response = proof
        .apply(
            reqwest::Client::new()
                .put(format!(
                    "{}/recovery-credential",
                    api_base(context.server_url)
                ))
                .bearer_auth(context.token)
                .json(&body)
                .timeout(std::time::Duration::from_secs(20)),
        )
        .send()
        .await
        .map_err(|_| "Recovery credential installation could not reach the server")?;
    let installed: RecoveryCredentialStatus =
        serde_json::from_value(response_json(response).await?)
            .map_err(|_| "Recovery installation response is invalid")?;
    if installed.credential.as_ref() != Some(&body.credential)
        || installed.artifact_version.is_none()
    {
        return Err("Recovery installation returned a different credential".into());
    }
    Ok(installed)
}

pub async fn authorize_saved_code_recovery(
    identity: &Ed25519KeyPair,
    context: &DeviceActionContext<'_>,
    email: &str,
    password: &str,
    metadata: DeviceLoginMetadata,
    raw_code: &[u8],
    credential: &RecoveryCredential,
    artifact_version: u32,
    artifact_sha256: &str,
) -> Result<CompleteSavedCodeRecoveryResponse, String> {
    let recovery_identity = recovery_signing_identity(raw_code, context.user_id, credential)?;
    if STANDARD.encode(recovery_identity.public_key_bytes()) != credential.public_key_b64 {
        return Err("Recovery code does not match the account's recovery credential".into());
    }
    let opaque = OpaqueAuth::new(context.device_id.to_owned());
    let challenge = opaque
        .saved_code_recovery_start(email, password, context.server_url, metadata, context.token)
        .await
        .map_err(|e| e.to_string())?;
    let finalization = challenge.finalize(password).map_err(|e| e.to_string())?;
    let mut verified = opaque
        .saved_code_recovery_verify(context.server_url, finalization, context.token)
        .await
        .map_err(|e| e.to_string())?;
    let recovery_session_id = verified.recovery_session_id.to_string();
    verified.session_key.zeroize();
    verified.export_key.zeroize();
    let body = CompleteSavedCodeRecoveryRequest {
        recovery_session_id,
        credential_id: credential.credential_id.clone(),
        generation: credential.generation,
        artifact_version,
        artifact_sha256: artifact_sha256.to_owned(),
    };
    let payload = serde_json::to_value(&body).map_err(|e| e.to_string())?;
    let (proof, code_signature) = signed_recovery_device_action(
        identity,
        &recovery_identity,
        context,
        DeviceAction::CompleteSavedCodeRecovery,
        &payload,
    )
    .await?;
    let response = proof
        .apply(
            reqwest::Client::new()
                .post(format!(
                    "{}/auth/saved-code-recovery/complete",
                    api_base(context.server_url)
                ))
                .bearer_auth(context.token)
                .header(RECOVERY_CODE_SIGNATURE_HEADER, code_signature)
                .json(&body)
                .timeout(std::time::Duration::from_secs(20)),
        )
        .send()
        .await
        .map_err(|_| "Recovery completion could not reach the server")?;
    let result: CompleteSavedCodeRecoveryResponse =
        serde_json::from_value(response_json(response).await?)
            .map_err(|_| "Recovery completion response is invalid")?;
    if result.credential_id != credential.credential_id
        || result.generation != credential.generation
        || result.artifact_version != artifact_version
        || result.artifact_sha256 != artifact_sha256
        || result.trust.device_id != context.device_id
        || !result.trust.approved
        || !result.trust.fingerprint_verified
        || result.trust.identity_key_sha256
            != hex::encode(Sha256::digest(identity.public_key_bytes()))
    {
        return Err("Recovery completion belongs to a different device or backup".into());
    }
    Ok(result)
}

pub async fn protected_upload_recovery_artifact(
    identity: &Ed25519KeyPair,
    context: &DeviceActionContext<'_>,
    artifact: &BackupArtifact,
    expected_version: Option<u32>,
    credential_id: Option<&str>,
) -> Result<Value, String> {
    let payload = serde_json::json!({"artifact_blob":artifact.to_base64()?,"expected_version":expected_version,"credential_id":credential_id});
    let proof = signed_device_action(
        identity,
        context,
        DeviceAction::UpdateRecoveryArtifact,
        context.device_id,
        None,
        &payload,
    )
    .await?;
    let response = proof
        .apply(
            reqwest::Client::new()
                .put(format!(
                    "{}/recovery-artifact",
                    api_base(context.server_url)
                ))
                .bearer_auth(context.token)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(20)),
        )
        .send()
        .await
        .map_err(|_| "Recovery backup upload could not reach the server")?;
    response_json(response).await
}

#[cfg(test)]
#[path = "../tests/recovery/test_saved_code_signing.rs"]
mod tests;
