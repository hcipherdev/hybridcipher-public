//! Key-bound device-management challenges and trust capabilities.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Header carrying the one-use challenge identifier.
pub const DEVICE_CHALLENGE_HEADER: &str = "x-device-challenge-id";
/// Header carrying a base64 Ed25519 signature over the challenge transcript.
pub const DEVICE_SIGNATURE_HEADER: &str = "x-device-signature";

/// Sensitive device action authorized by a challenge.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAction {
    /// Remove a registered device.
    Revoke,
    /// Attest that another device's fingerprint was manually checked.
    VerifyFingerprint,
    /// Deliver a Welcome and approve its recipient.
    ApproveWelcome,
    /// Rotate the current device's invitation key.
    RotateInvitation,
    /// Confirm the current device after verified account recovery.
    ConfirmRecovery,
    /// Install or rotate the account's saved-code credential.
    ManageRecoveryCredential,
    /// Complete password plus saved-code recovery for the current device.
    CompleteSavedCodeRecovery,
    /// Update the sealed recovery backup without replacing its pinned credential.
    UpdateRecoveryArtifact,
    /// Repair the account's authoritative Personal workspace identity.
    RepairPersonalWorkspace,
    /// An organization owner or admin removes another member's device.
    AdminRevoke,
}

/// Request for a fresh action challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceActionChallengeRequest {
    /// Exact server URL used by the client, checked before signing.
    pub server_url: String,
    /// Intended mutation.
    pub action: DeviceAction,
    /// Registered target device identifier.
    pub target_device_id: String,
    /// SHA-256 of the canonical mutation body (an empty object for DELETE).
    pub payload_sha256: String,
}

/// One-use, identity-bound transcript; clients must check its context before signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceActionChallenge {
    /// Random challenge identifier.
    pub challenge_id: String,
    /// Authenticated account identifier.
    pub actor_user_id: String,
    /// Authenticated actor device identifier.
    pub actor_device_id: String,
    /// SHA-256 of the actor's registered identity key.
    pub actor_identity_key_sha256: String,
    /// Server URL supplied for this operation.
    pub server_url: String,
    /// Intended mutation.
    pub action: DeviceAction,
    /// Registered target device identifier.
    pub target_device_id: String,
    /// SHA-256 of the target's registered identity key.
    pub target_identity_key_sha256: String,
    /// Canonical mutation-body digest.
    pub payload_sha256: String,
    /// Expiry as Unix seconds.
    pub expires_at: i64,
    /// Cryptographically random nonce, hex encoded.
    pub nonce: String,
}

impl DeviceActionChallenge {
    /// Domain-separated bytes signed by the actor's existing Ed25519 key.
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = b"hybridcipher/device-action/v1\n".to_vec();
        bytes.extend(canonical_json_bytes(&serde_json::to_value(self)?)?);
        Ok(bytes)
    }
}

/// Bytes a registered device signs with its identity key at login, proving it is that
/// device rather than someone who only knows its (non-secret) identifier. The
/// server-chosen `login_id` is random and single-use, so a proof cannot be replayed.
pub fn login_device_proof_payload(login_id: &str, user_id: &str, device_id: &str) -> Vec<u8> {
    let mut bytes = b"hybridcipher/login-device-proof/v1\n".to_vec();
    for part in [login_id, user_id, device_id] {
        bytes.extend((part.len() as u64).to_be_bytes());
        bytes.extend(part.as_bytes());
    }
    bytes
}

/// Current server-authoritative trust for one registered identity key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceTrustStatus {
    /// Registered device identifier.
    pub device_id: String,
    /// SHA-256 of its current registered identity key.
    pub identity_key_sha256: String,
    /// Whether approval exists for this exact key.
    pub approved: bool,
    /// Whether manual verification or an explicit bootstrap exception exists.
    pub fingerprint_verified: bool,
    /// Whether both trust prerequisites permit cross-device management.
    pub can_revoke_other_devices: bool,
    /// Whether the actor can approve devices, subject to account or group authorization.
    pub can_approve_devices: bool,
    /// Whether the actor can attest another device's fingerprint.
    pub can_verify_devices: bool,
    /// Whether an explicit trust confirmation is still required.
    pub confirmation_required: bool,
    /// Human-readable reason management is unavailable.
    pub blocking_reason: Option<String>,
    /// Origin of the last accepted trust evidence.
    pub source: Option<String>,
}

/// Fingerprint manually checked on a distinct trusted device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprintVerificationRequest {
    /// Expected identity fingerprint, hex encoded with optional whitespace.
    pub fingerprint: String,
    /// Optional Team group context for an administrator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
}

/// Canonical JSON: recursively sorted object keys, unchanged arrays and scalars.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys = map.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                let mut result = serde_json::Map::new();
                for key in keys {
                    result.insert(key.clone(), sorted(&map[key]));
                }
                Value::Object(result)
            }
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&sorted(value))
}

/// Digest a mutation body using the shared canonical serialization.
pub fn device_action_payload_sha256(value: &Value) -> Result<String, serde_json::Error> {
    Ok(hex::encode(Sha256::digest(canonical_json_bytes(value)?)))
}
