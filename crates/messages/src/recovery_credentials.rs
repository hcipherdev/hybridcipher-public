//! Account-pinned saved-code credentials and device-bound recovery completion.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::device_actions::{canonical_json_bytes, DeviceTrustStatus};

/// Additional signature over the device-action challenge by the saved-code key.
pub const RECOVERY_CODE_SIGNATURE_HEADER: &str = "x-recovery-code-signature";

/// Public verifier installed by a trusted account root, independent of backup writers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryCredential {
    /// Unique UUID; changing it revokes the previous saved code.
    pub credential_id: String,
    /// Monotonically increasing account credential generation, starting at one.
    pub generation: u64,
    /// Base64 random 32-byte HKDF salt.
    pub salt_b64: String,
    /// Base64 Ed25519 public key derived from the raw saved code.
    pub public_key_b64: String,
    /// Canonical SHA-256 of the backup encryption envelope, excluding entries/version.
    pub recovery_envelope_sha256: String,
}

/// Server-authoritative recovery support and current account credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCredentialStatus {
    /// Pinned credential, or none for a legacy backup requiring one-time enrollment.
    pub credential: Option<RecoveryCredential>,
    /// Current server backup revision, independent of its serialization format.
    pub artifact_version: Option<u32>,
}

/// Signed initial enrollment or explicit credential rotation plus its matching backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRecoveryCredentialRequest {
    /// New public verifier and derivation metadata.
    pub credential: RecoveryCredential,
    /// Base64 serialized sealed backup.
    pub artifact_blob: String,
    /// Required current artifact revision; none means no artifact must exist.
    pub expected_artifact_version: Option<u32>,
    /// Required current credential UUID; none means no credential must exist.
    pub expected_credential_id: Option<String>,
    /// One-use OTP/MFA verified account-recovery authorization for legacy enrollment.
    pub recovery_session_id: Option<String>,
}

/// Exact body bound to both device and saved-code signatures and fresh password proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteSavedCodeRecoveryRequest {
    /// Fresh OPAQUE password-proof session, scoped to this authenticated device.
    pub recovery_session_id: String,
    /// Exact active account credential UUID.
    pub credential_id: String,
    /// Exact active credential generation.
    pub generation: u64,
    /// Exact downloaded artifact revision.
    pub artifact_version: u32,
    /// SHA-256 of the exact decoded downloaded artifact bytes.
    pub artifact_sha256: String,
}

/// Authoritative successful recovery receipt, returned only after both proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteSavedCodeRecoveryResponse {
    /// Trust for the exact registered device key.
    pub trust: DeviceTrustStatus,
    /// Credential used for recovery.
    pub credential_id: String,
    /// Credential generation used for recovery.
    pub generation: u64,
    /// Artifact revision used for recovery.
    pub artifact_version: u32,
    /// Exact artifact snapshot used for recovery.
    pub artifact_sha256: String,
}

/// Stable HKDF info for a raw-code signing seed, never an epoch or writer key.
pub fn recovery_signing_context(
    user_id: &str,
    credential: &RecoveryCredential,
) -> Result<Vec<u8>, serde_json::Error> {
    canonical_json_bytes(&serde_json::json!({
        "purpose": "hybridcipher/saved-code-signing/v1",
        "user_id": user_id,
        "credential_id": credential.credential_id,
        "generation": credential.generation,
    }))
}

/// Commit the five immutable encryption-envelope fields of a legacy-compatible backup.
pub fn recovery_envelope_sha256(artifact: &Value) -> Result<String, String> {
    let mut envelope = serde_json::Map::new();
    for field in [
        "k1_salt_b64",
        "k2_salt_b64",
        "hkdf_salt_b64",
        "k1_wrapped",
        "k2_wrapped",
    ] {
        let value = artifact
            .get(field)
            .ok_or_else(|| format!("Backup envelope is missing {field}"))?;
        envelope.insert(field.to_owned(), value.clone());
    }
    let bytes =
        canonical_json_bytes(&Value::Object(envelope)).map_err(|error| error.to_string())?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
