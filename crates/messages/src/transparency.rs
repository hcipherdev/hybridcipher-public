//! Transparency log structures and verification for HybridCipher
//!
//! This module provides structures and verification logic for maintaining
//! a cryptographically verifiable transparency log of group operations.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use hybridcipher_crypto::signatures::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A single entry in the transparency log that records group operations
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransparencyEntry {
    /// Sequence number in the log (monotonically increasing)
    pub sequence_number: u64,
    /// Timestamp when the entry was created
    pub timestamp: u64,
    /// Hash of the join card or operation being logged
    pub join_card_hash: [u8; 32],
    /// The specific operation being performed
    pub operation: TransparencyOperation,
    /// Cryptographic signature over the entry
    pub signature: Vec<u8>,
}

/// Types of operations that can be logged in the transparency log
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TransparencyOperation {
    /// A new join card was added to the group
    AddJoinCard {
        /// User ID of the joining member
        user_id: String,
        /// Device ID of the joining device
        device_id: String,
        /// Public key fingerprint for verification
        key_fingerprint: String,
    },
    /// A join card was revoked from the group
    RevokeJoinCard {
        /// User ID of the revoked member
        user_id: String,
        /// Device ID of the revoked device
        device_id: String,
        /// Reason for revocation
        reason: RevocationReason,
    },
    /// Directory structure was updated
    DirectoryUpdate {
        /// New Merkle root after the update
        merkle_root: [u8; 32],
        /// Number of files in the update
        file_count: u64,
    },
    /// Epoch key rotation was performed
    EpochKeyRotation {
        /// New epoch number
        epoch_number: u64,
        /// Hash of the new epoch key
        epoch_key_hash: [u8; 32],
    },
    /// Coverage Merkle root published for transparency
    CoverageSnapshot {
        /// Signed coverage Merkle root
        merkle_root: [u8; 32],
        /// Epoch associated with the latest coverage update
        epoch_id: u64,
        /// Total files represented in the coverage log
        file_count: u64,
        /// Identifier for the signing key used to authenticate the root
        signing_key_id: Option<String>,
        /// Verifying key bytes corresponding to the signer
        verifying_key: [u8; 32],
    },
}

/// Reasons why a join card might be revoked
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum RevocationReason {
    /// User requested removal
    UserRequested,
    /// Device was compromised
    DeviceCompromised,
    /// Administrative action
    Administrative,
    /// Key rotation
    KeyRotation,
}

/// Proof that a specific entry is included in the transparency log
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// The entry being proven
    pub entry: TransparencyEntry,
    /// Index of the entry in the log
    pub leaf_index: u64,
    /// Merkle tree proof path
    pub proof_path: Vec<[u8; 32]>,
    /// Size of the log when proof was generated
    pub log_size: u64,
    /// Root hash of the log
    pub log_root: [u8; 32],
}

/// Proof that one log state is consistent with a later log state
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// Size of the older log state
    pub old_size: u64,
    /// Size of the newer log state
    pub new_size: u64,
    /// Root hash of the older log state
    pub old_root: [u8; 32],
    /// Root hash of the newer log state
    pub new_root: [u8; 32],
    /// Merkle tree consistency proof
    pub proof_path: Vec<[u8; 32]>,
}

/// A checkpoint representing the current state of the transparency log
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransparencyCheckpointEntry {
    /// Type of checkpoint entry (e.g. server_fingerprint)
    pub entry_type: String,
    /// SHA-256 hash encoded as hexadecimal
    pub sha256_hex: String,
    /// SHA-256 hash encoded as base64
    pub sha256_base64: String,
    /// Short hash preview (first 16 hex characters)
    pub short_hex: String,
    /// Base64 encoded server public key
    pub public_key_base64: String,
    /// Server metadata
    #[serde(default)]
    pub server: Option<serde_json::Value>,
}

/// A checkpoint representing the current state of the transparency log
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransparencyCheckpoint {
    /// Schema version
    pub version: u32,
    /// Timestamp when the checkpoint was generated (RFC 3339)
    pub generated_at: String,
    /// Canonical log URL advertised by the publisher
    #[serde(default)]
    pub log_url: Option<String>,
    /// Signing key identifier used for this checkpoint
    #[serde(default)]
    pub signing_key_id: Option<String>,
    /// Current size of the transparency log
    pub tree_size: u64,
    /// Root hash of the log (hex encoded)
    pub root_hash: String,
    /// Summary entries included in the checkpoint
    #[serde(default)]
    pub entries: Vec<TransparencyCheckpointEntry>,
    /// Base64 encoded Ed25519 signature over the signing payload
    #[serde(default)]
    pub signature: Option<String>,
}

/// Trusted signing key material for verifying checkpoints
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransparencyTrustedKey {
    /// Identifier that appears in checkpoints
    pub key_id: String,
    /// Base64 encoded Ed25519 verifying key bytes
    pub public_key_base64: String,
}

/// Configuration for transparency log verification
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransparencyConfig {
    /// Whether transparency log verification is enabled
    pub enabled: bool,
    /// URL of the transparency log server
    pub log_server_url: Option<String>,
    /// Timeout for verification requests
    pub verification_timeout_seconds: u64,
    /// Whether to fallback to key pinning if transparency log is unavailable
    pub fallback_to_pinning: bool,
    /// Maximum age of checkpoints to accept (in seconds)
    pub max_checkpoint_age_seconds: u64,
    /// Set of trusted signing keys for checkpoint verification
    #[serde(default)]
    pub trusted_signing_keys: Vec<TransparencyTrustedKey>,
}

impl Default for TransparencyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_server_url: None,
            verification_timeout_seconds: 30,
            fallback_to_pinning: true,
            max_checkpoint_age_seconds: 86400, // 24 hours
            trusted_signing_keys: Vec::new(),
        }
    }
}

#[derive(Serialize)]
struct CheckpointSigningPayload<'a> {
    version: u32,
    generated_at: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_url: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_key_id: &'a Option<String>,
    tree_size: u64,
    root_hash: &'a str,
    entries: &'a [TransparencyCheckpointEntry],
}

impl TransparencyCheckpoint {
    /// Return the signing key identifier, erroring if it is missing.
    pub fn signing_key_id(&self) -> Result<&str, TransparencyError> {
        self.signing_key_id.as_deref().ok_or_else(|| {
            TransparencyError::InvalidCheckpoint("Checkpoint missing signing_key_id".into())
        })
    }

    /// Decode the base64-encoded signature into a `Signature` type.
    pub fn signature(&self) -> Result<Signature, TransparencyError> {
        let signature_b64 = self.signature.as_deref().ok_or_else(|| {
            TransparencyError::InvalidCheckpoint("Checkpoint missing signature".into())
        })?;

        let raw = BASE64
            .decode(signature_b64.trim())
            .map_err(|_| TransparencyError::InvalidSignature)?;

        Signature::from_bytes(&raw).map_err(|_| TransparencyError::InvalidSignature)
    }

    /// Serialize the canonical signing payload used for signature verification.
    pub fn signing_payload(&self) -> Result<Vec<u8>, TransparencyError> {
        let payload = CheckpointSigningPayload {
            version: self.version,
            generated_at: &self.generated_at,
            log_url: &self.log_url,
            signing_key_id: &self.signing_key_id,
            tree_size: self.tree_size,
            root_hash: &self.root_hash,
            entries: &self.entries,
        };

        serde_json::to_vec(&payload).map_err(TransparencyError::Serialization)
    }

    /// Parse the hex-encoded root hash into raw bytes.
    pub fn root_hash_bytes(&self) -> Result<[u8; 32], TransparencyError> {
        let trimmed = self.root_hash.trim();
        let bytes = hex::decode(trimmed).map_err(|e| {
            TransparencyError::InvalidCheckpoint(format!(
                "Checkpoint root hash is not valid hex: {}",
                e
            ))
        })?;

        if bytes.len() != 32 {
            return Err(TransparencyError::InvalidCheckpoint(format!(
                "Checkpoint root hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Ok(root)
    }

    /// Parse the RFC 3339 timestamp into a UTC datetime.
    pub fn generated_at(&self) -> Result<DateTime<Utc>, TransparencyError> {
        let parsed = DateTime::parse_from_rfc3339(&self.generated_at).map_err(|e| {
            TransparencyError::InvalidCheckpoint(format!("Checkpoint timestamp is invalid: {}", e))
        })?;
        Ok(parsed.with_timezone(&Utc))
    }

    /// Verify the Ed25519 signature against the trusted verifying key.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), TransparencyError> {
        let signature = self.signature()?;
        let payload = self.signing_payload()?;

        if verifying_key.verify(&payload, &signature).is_ok() {
            return Ok(());
        }

        // Fallback for legacy payloads that signed only the root hash bytes.
        let root_bytes = self.root_hash_bytes()?;
        verifying_key
            .verify(&root_bytes, &signature)
            .map_err(|_| TransparencyError::InvalidSignature)
    }
}

/// Errors that can occur during transparency log operations
#[derive(Debug, thiserror::Error)]
pub enum TransparencyError {
    /// Failed to serialize transparency data
    #[error("Failed to serialize transparency data: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid inclusion proof
    #[error("Invalid inclusion proof")]
    InvalidInclusionProof,

    /// Invalid consistency proof
    #[error("Invalid consistency proof")]
    InvalidConsistencyProof,

    /// Invalid signature on transparency entry
    #[error("Invalid signature on transparency entry")]
    InvalidSignature,

    /// Transparency entry failed validation
    #[error("Invalid transparency entry: {0}")]
    InvalidEntry(String),

    /// Unknown signing key identifier referenced by checkpoint
    #[error("Unknown transparency signing key: {key_id}")]
    UnknownSigningKey {
        /// Signing key identifier referenced by the checkpoint
        key_id: String,
    },

    /// Checkpoint payload failed validation
    #[error("Invalid transparency checkpoint: {0}")]
    InvalidCheckpoint(String),

    /// Transparency log server unavailable
    #[error("Transparency log server unavailable")]
    ServerUnavailable,

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Checkpoint too old
    #[error("Checkpoint too old: age {age_seconds}s exceeds maximum {max_age_seconds}s")]
    CheckpointTooOld {
        /// Age of checkpoint in seconds
        age_seconds: u64,
        /// Maximum allowed age in seconds
        max_age_seconds: u64,
    },

    /// Verification timeout
    #[error("Verification timeout")]
    Timeout,
}

impl TransparencyEntry {
    /// Calculate the hash of this transparency entry for inclusion proofs
    pub fn hash(&self) -> [u8; 32] {
        let serialized =
            serde_json::to_vec(self).expect("TransparencyEntry should always serialize");

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        hasher.finalize().into()
    }

    /// Create a new transparency entry with the current timestamp
    pub fn new(
        sequence_number: u64,
        join_card_hash: [u8; 32],
        operation: TransparencyOperation,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            sequence_number,
            timestamp: Utc::now().timestamp() as u64,
            join_card_hash,
            operation,
            signature,
        }
    }
}

impl InclusionProof {
    /// Verify that this inclusion proof is valid
    pub fn verify(&self) -> Result<bool, TransparencyError> {
        use sha2::{Digest, Sha256};

        if self.leaf_index >= self.log_size {
            return Ok(false);
        }

        // Merkle tree semantics used by the server are "promote the last node" (CT-style):
        // when a level has an odd number of nodes, the final node is carried up unchanged.
        //
        // Because `proof_path` does not encode "missing sibling" markers, we infer promotion
        // steps from `(leaf_index, log_size)` and only consume a proof element when a sibling
        // exists at that level.
        let mut current_hash = self.entry.hash();
        let mut index = self.leaf_index as usize;
        let mut size = self.log_size as usize;
        let mut proof_iter = self.proof_path.iter();

        while size > 1 {
            let is_last = index == size.saturating_sub(1);
            let odd = (size % 2) == 1;

            if !(is_last && odd) {
                let sibling_hash = proof_iter
                    .next()
                    .ok_or(TransparencyError::InvalidInclusionProof)?;

                let mut hasher = Sha256::new();
                if index % 2 == 0 {
                    // Current node is left child
                    hasher.update(&current_hash);
                    hasher.update(sibling_hash);
                } else {
                    // Current node is right child
                    hasher.update(sibling_hash);
                    hasher.update(&current_hash);
                }
                current_hash = hasher.finalize().into();
            }

            index /= 2;
            size = (size + 1) / 2;
        }

        // Reject proofs with trailing nodes (ambiguous / malformed).
        if proof_iter.next().is_some() {
            return Err(TransparencyError::InvalidInclusionProof);
        }

        Ok(current_hash == self.log_root)
    }
}

impl ConsistencyProof {
    /// Verify that this consistency proof shows the old log is consistent with the new log
    pub fn verify(&self) -> Result<bool, TransparencyError> {
        if self.old_size > self.new_size {
            return Ok(false);
        }

        if self.old_size == self.new_size {
            return Ok(self.old_root == self.new_root && self.proof_path.is_empty());
        }

        if self.old_size == 0 {
            return Ok(self.proof_path.is_empty());
        }

        let mut node = self.old_size - 1;
        let mut last_node = self.new_size - 1;

        while node % 2 == 1 {
            node >>= 1;
            last_node >>= 1;
        }

        let mut index = 0usize;
        let mut old_hash;
        let mut new_hash;

        if node != 0 {
            let sibling = self
                .proof_path
                .get(index)
                .ok_or(TransparencyError::InvalidConsistencyProof)?;
            old_hash = *sibling;
            new_hash = *sibling;
            index += 1;
        } else {
            old_hash = self.old_root;
            new_hash = self.old_root;
        }

        while node != 0 {
            if node % 2 == 1 {
                let sibling = self
                    .proof_path
                    .get(index)
                    .ok_or(TransparencyError::InvalidConsistencyProof)?;
                index += 1;
                old_hash = hash_internal(sibling, &old_hash);
                new_hash = hash_internal(sibling, &new_hash);
            } else if node < last_node {
                let sibling = self
                    .proof_path
                    .get(index)
                    .ok_or(TransparencyError::InvalidConsistencyProof)?;
                index += 1;
                new_hash = hash_internal(&new_hash, sibling);
            }

            node >>= 1;
            last_node >>= 1;
        }

        while last_node != 0 {
            let sibling = self
                .proof_path
                .get(index)
                .ok_or(TransparencyError::InvalidConsistencyProof)?;
            index += 1;
            new_hash = hash_internal(&new_hash, sibling);
            last_node >>= 1;
        }

        if index != self.proof_path.len() {
            return Err(TransparencyError::InvalidConsistencyProof);
        }

        Ok(old_hash == self.old_root && new_hash == self.new_root)
    }
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transparency_entry_creation() {
        let operation = TransparencyOperation::AddJoinCard {
            user_id: "alice".to_string(),
            device_id: "laptop".to_string(),
            key_fingerprint: "abcd1234".to_string(),
        };

        let entry = TransparencyEntry::new(1, [0u8; 32], operation, vec![1, 2, 3, 4]);

        assert_eq!(entry.sequence_number, 1);
        assert_eq!(entry.join_card_hash, [0u8; 32]);
        assert_eq!(entry.signature, vec![1, 2, 3, 4]);
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn test_transparency_entry_hash() {
        let operation = TransparencyOperation::DirectoryUpdate {
            merkle_root: [1u8; 32],
            file_count: 5,
        };

        let entry = TransparencyEntry {
            sequence_number: 42,
            timestamp: 1640995200, // Fixed timestamp for test
            join_card_hash: [2u8; 32],
            operation,
            signature: vec![5, 6, 7, 8],
        };

        let hash1 = entry.hash();
        let hash2 = entry.hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_serialization() {
        let operation = TransparencyOperation::RevokeJoinCard {
            user_id: "bob".to_string(),
            device_id: "phone".to_string(),
            reason: RevocationReason::DeviceCompromised,
        };

        let entry = TransparencyEntry::new(100, [42u8; 32], operation, vec![10, 20, 30]);

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: TransparencyEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_consistency_proof_simple_extension() {
        let leaf_a: [u8; 32] = Sha256::digest(b"a").into();
        let leaf_b: [u8; 32] = Sha256::digest(b"b").into();
        let new_root = hash_internal(&leaf_a, &leaf_b);

        let proof = ConsistencyProof {
            old_size: 1,
            new_size: 2,
            old_root: leaf_a,
            new_root,
            proof_path: vec![leaf_b],
        };

        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_consistency_proof_detects_mismatch() {
        let leaf_a: [u8; 32] = Sha256::digest(b"a").into();
        let leaf_b: [u8; 32] = Sha256::digest(b"b").into();
        let bogus_root: [u8; 32] = Sha256::digest(b"c").into();

        let proof = ConsistencyProof {
            old_size: 1,
            new_size: 2,
            old_root: leaf_a,
            new_root: bogus_root,
            proof_path: vec![leaf_b],
        };

        assert!(!proof.verify().unwrap());
    }

    #[test]
    fn test_transparency_config_default() {
        let config = TransparencyConfig::default();

        assert!(!config.enabled);
        assert!(config.fallback_to_pinning);
        assert_eq!(config.verification_timeout_seconds, 30);
        assert_eq!(config.max_checkpoint_age_seconds, 86400);
        assert!(config.log_server_url.is_none());
        assert!(config.trusted_signing_keys.is_empty());
    }
}
