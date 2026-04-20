//! Transparency log client for HybridCipher
//!
//! This module provides a client for interacting with transparency logs,
//! including verification of inclusion and consistency proofs.

use crate::network::Network;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use hybridcipher_crypto::signatures::VerifyingKey;
use hybridcipher_messages::transparency::{
    ConsistencyProof, InclusionProof, TransparencyCheckpoint, TransparencyConfig,
    TransparencyEntry, TransparencyError, TransparencyOperation, TransparencyTrustedKey,
};
use reqwest::{Client as HttpClient, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

/// Client for interacting with transparency logs
#[derive(Debug, Clone)]
pub struct TransparencyClient<N: Network> {
    /// Network interface for communication
    network: N,
    /// URL of the transparency log server
    log_url: String,
    /// Configuration for transparency verification
    config: TransparencyConfig,
    /// Whether transparency checks should be attempted
    feature_enabled: bool,
    /// Trusted verifying keys indexed by key identifier
    trusted_keys: HashMap<String, VerifyingKey>,
    /// Cached verification state for checkpoints
    state: Arc<Mutex<TransparencyState>>,
    /// HTTP client used to communicate with the transparency service
    http_client: HttpClient,
}

/// Request to get an inclusion proof from the transparency log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofRequest {
    /// Hash of the join card to prove inclusion for
    pub join_card_hash: [u8; 32],
    /// Log size at which to generate the proof
    pub log_size: Option<u64>,
}

/// Request to get a consistency proof between two log states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProofRequest {
    /// Size of the older log state
    pub old_size: u64,
    /// Size of the newer log state
    pub new_size: u64,
}

/// Request to get the latest checkpoint from the transparency log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRequest {
    /// Maximum age of checkpoint to accept (in seconds)
    pub max_age_seconds: Option<u64>,
}

/// Response containing an inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofResponse {
    /// The inclusion proof
    pub proof: InclusionProof,
    /// Timestamp when proof was generated
    pub generated_at: u64,
}

/// Response containing a consistency proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProofResponse {
    /// The consistency proof
    pub proof: ConsistencyProof,
    /// Timestamp when proof was generated
    pub generated_at: u64,
}

/// Response containing the latest checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointResponse {
    /// The current checkpoint
    pub checkpoint: TransparencyCheckpoint,
    /// Server information
    pub server_info: TransparencyServerInfo,
}

/// Information about the transparency log server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyServerInfo {
    /// Server version
    pub version: String,
    /// Server public key for signature verification
    pub public_key: [u8; 32],
    /// Supported protocol versions
    pub supported_versions: Vec<String>,
}

#[derive(Debug, Clone)]
struct VerifiedCheckpoint {
    checkpoint: TransparencyCheckpoint,
    root_hash: [u8; 32],
    signing_key_id: String,
    generated_at: DateTime<Utc>,
    verified_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct TransparencyState {
    last_verified: Option<VerifiedCheckpoint>,
}

impl<N: Network> TransparencyClient<N> {
    /// Create a new transparency client
    pub fn new(network: N, log_url: String, config: TransparencyConfig) -> Self {
        let trusted_keys = build_trusted_key_map(&config.trusted_signing_keys);

        if config.enabled && trusted_keys.is_empty() {
            log::warn!(
                "Transparency verification requested but no trusted signing keys configured; disabling feature"
            );
        }

        let feature_enabled = config.enabled && !trusted_keys.is_empty();

        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(config.verification_timeout_seconds))
            .build()
            .unwrap_or_else(|err| {
                log::warn!(
                    "Failed to build transparency HTTP client ({}); falling back to default client",
                    err
                );
                HttpClient::new()
            });

        Self {
            network,
            log_url: normalize_log_url(log_url),
            config,
            feature_enabled,
            trusted_keys,
            state: Arc::new(Mutex::new(TransparencyState::default())),
            http_client,
        }
    }

    fn validate_entry(&self, entry: &TransparencyEntry) -> Result<(), TransparencyError> {
        if entry.signature.is_empty() || entry.signature.iter().all(|&byte| byte == 0) {
            return Err(TransparencyError::InvalidEntry(
                "transparency entry signature missing or zeroed".into(),
            ));
        }

        match &entry.operation {
            TransparencyOperation::AddJoinCard {
                user_id,
                device_id,
                key_fingerprint,
            } => {
                if user_id.trim().is_empty() || device_id.trim().is_empty() {
                    return Err(TransparencyError::InvalidEntry(
                        "join card entry missing user or device metadata".into(),
                    ));
                }

                if key_fingerprint.trim().is_empty() {
                    return Err(TransparencyError::InvalidEntry(
                        "join card entry missing key fingerprint".into(),
                    ));
                }
            }
            TransparencyOperation::RevokeJoinCard {
                user_id, device_id, ..
            } => {
                if user_id.trim().is_empty() || device_id.trim().is_empty() {
                    return Err(TransparencyError::InvalidEntry(
                        "revoke join card entry missing user or device metadata".into(),
                    ));
                }
            }
            TransparencyOperation::DirectoryUpdate { merkle_root, .. } => {
                if merkle_root.iter().all(|byte| *byte == 0) {
                    return Err(TransparencyError::InvalidEntry(
                        "directory update merkle root is zeroed".into(),
                    ));
                }
            }
            TransparencyOperation::EpochKeyRotation {
                epoch_number: _,
                epoch_key_hash,
            } => {
                if epoch_key_hash.iter().all(|byte| *byte == 0) {
                    return Err(TransparencyError::InvalidEntry(
                        "epoch key rotation hash is zeroed".into(),
                    ));
                }
            }
            TransparencyOperation::CoverageSnapshot {
                signing_key_id,
                verifying_key,
                ..
            } => {
                let key_id = signing_key_id.as_ref().ok_or_else(|| {
                    TransparencyError::InvalidEntry(
                        "coverage snapshot missing signing key identifier".into(),
                    )
                })?;

                if key_id.trim().is_empty() {
                    return Err(TransparencyError::InvalidEntry(
                        "coverage snapshot signing key identifier empty".into(),
                    ));
                }

                if verifying_key.iter().all(|byte| *byte == 0) {
                    return Err(TransparencyError::InvalidEntry(
                        "coverage snapshot verifying key is zeroed".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get an inclusion proof for a specific join card hash
    pub async fn get_inclusion_proof(
        &self,
        join_card_hash: &[u8; 32],
    ) -> Result<InclusionProof, TransparencyError> {
        if !self.is_enabled() {
            return Err(TransparencyError::ServerUnavailable);
        }

        // Always fetch fresh checkpoint to avoid stale server-side cache issues
        let _ = self.fetch_and_store_checkpoint().await?;

        let log_size = {
            let state = self.state.lock().expect("transparency state poisoned");
            state
                .last_verified
                .as_ref()
                .map(|verified| verified.checkpoint.tree_size)
        };

        let request = InclusionProofRequest {
            join_card_hash: *join_card_hash,
            log_size,
        };

        let response = self
            .send_transparency_request("inclusion_proof", &request)
            .await?;

        let proof_response: InclusionProofResponse =
            serde_json::from_slice(&response).map_err(TransparencyError::Serialization)?;

        if proof_response.proof.entry.hash() != *join_card_hash
            && proof_response.proof.entry.join_card_hash != *join_card_hash
        {
            return Err(TransparencyError::InvalidInclusionProof);
        }

        if !proof_response.proof.verify()? {
            return Err(TransparencyError::InvalidInclusionProof);
        }

        if let Err(_err) = self.validate_inclusion_proof(&proof_response.proof) {
            let _ = self.fetch_and_store_checkpoint().await?;
            let log_size = {
                let state = self.state.lock().expect("transparency state poisoned");
                state
                    .last_verified
                    .as_ref()
                    .map(|verified| verified.checkpoint.tree_size)
            };
            let request = InclusionProofRequest {
                join_card_hash: *join_card_hash,
                log_size,
            };

            let response = self
                .send_transparency_request("inclusion_proof", &request)
                .await?;

            let proof_response: InclusionProofResponse =
                serde_json::from_slice(&response).map_err(TransparencyError::Serialization)?;

            if proof_response.proof.entry.hash() != *join_card_hash
                && proof_response.proof.entry.join_card_hash != *join_card_hash
            {
                return Err(TransparencyError::InvalidInclusionProof);
            }

            if !proof_response.proof.verify()? {
                return Err(TransparencyError::InvalidInclusionProof);
            }

            self.validate_inclusion_proof(&proof_response.proof)?;

            return Ok(proof_response.proof);
        }

        Ok(proof_response.proof)
    }

    /// Verify consistency between two log states
    pub async fn verify_consistency(
        &self,
        old_size: u64,
        new_size: u64,
        expected_old_root: &[u8; 32],
        expected_new_root: &[u8; 32],
    ) -> Result<(), TransparencyError> {
        if old_size > new_size {
            return Err(TransparencyError::InvalidConsistencyProof);
        }

        if old_size == new_size {
            return if expected_old_root == expected_new_root {
                Ok(())
            } else {
                Err(TransparencyError::InvalidConsistencyProof)
            };
        }

        if !self.is_enabled() {
            return Ok(());
        }

        let request = ConsistencyProofRequest { old_size, new_size };

        let response = self
            .send_transparency_request("consistency_proof", &request)
            .await?;

        let proof_response: ConsistencyProofResponse =
            serde_json::from_slice(&response).map_err(TransparencyError::Serialization)?;

        let proof = proof_response.proof;

        if proof.old_size != old_size || proof.new_size != new_size {
            return Err(TransparencyError::InvalidConsistencyProof);
        }

        if proof.old_root != *expected_old_root || proof.new_root != *expected_new_root {
            return Err(TransparencyError::InvalidConsistencyProof);
        }

        if !proof.verify()? {
            return Err(TransparencyError::InvalidConsistencyProof);
        }

        Ok(())
    }

    /// Get the latest checkpoint from the transparency log
    pub async fn get_latest_checkpoint(&self) -> Result<TransparencyCheckpoint, TransparencyError> {
        if !self.is_enabled() {
            return Err(TransparencyError::ServerUnavailable);
        }

        self.ensure_verified_state().await?;

        let state = self.state.lock().expect("transparency state poisoned");
        state
            .last_verified
            .as_ref()
            .map(|checkpoint| checkpoint.checkpoint.clone())
            .ok_or(TransparencyError::ServerUnavailable)
    }

    /// Verify that a transparency entry is included in the log
    pub async fn verify_entry_inclusion(
        &self,
        entry: &TransparencyEntry,
    ) -> Result<bool, TransparencyError> {
        if !self.is_enabled() {
            return Ok(true);
        }

        if let Err(err) = self.ensure_verified_state().await {
            if self.should_fallback(&err) {
                log::warn!(
                    "Transparency verification unavailable ({}); falling back to pinned keys",
                    err
                );
                return Ok(true);
            }
            return Err(err);
        }

        let entry_hash = entry.hash();

        match self.get_inclusion_proof(&entry_hash).await {
            Ok(proof) => {
                if proof.entry.hash() != entry_hash {
                    return Ok(false);
                }

                if proof.entry.sequence_number > proof.log_size {
                    return Ok(false);
                }

                proof.verify()
            }
            Err(err) => {
                if self.should_fallback(&err) {
                    log::warn!(
                        "Failed to fetch inclusion proof ({}); falling back to pinned keys",
                        err
                    );
                    Ok(true)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Submit a new entry to the transparency log (for log servers)
    pub async fn submit_entry(&self, entry: &TransparencyEntry) -> Result<u64, TransparencyError> {
        if !self.is_enabled() {
            return Err(TransparencyError::ServerUnavailable);
        }

        self.validate_entry(entry)?;

        let response = self
            .send_transparency_request("submit_entry", entry)
            .await?;

        let sequence_number: u64 =
            serde_json::from_slice(&response).map_err(TransparencyError::Serialization)?;

        Ok(sequence_number)
    }

    /// Send a request to the transparency log server
    async fn send_transparency_request<T: Serialize>(
        &self,
        endpoint: &str,
        request: &T,
    ) -> Result<Vec<u8>, TransparencyError> {
        if let Err(err) = self.network.get_network_status().await {
            log::debug!(
                "Proceeding with transparency request despite network status error: {}",
                err
            );
        }

        let timeout_duration = Duration::from_secs(self.config.verification_timeout_seconds);

        timeout(timeout_duration, async {
            self.send_http_request(endpoint, request).await
        })
        .await
        .map_err(|_| TransparencyError::Timeout)?
    }

    /// Send HTTP request to transparency log server.
    async fn send_http_request<T: Serialize>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<Vec<u8>, TransparencyError> {
        let url = format!(
            "{}/{}",
            self.log_url.trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        );

        let body = serde_json::to_vec(payload).map_err(TransparencyError::Serialization)?;

        let response = self
            .http_client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|err| TransparencyError::Network(err.to_string()))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(TransparencyError::ServerUnavailable);
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "<opaque error>".to_string());
            return Err(TransparencyError::Network(format!(
                "HTTP {}: {}",
                status, error_body
            )));
        }

        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| TransparencyError::Network(err.to_string()))
    }
}

fn build_trusted_key_map(keys: &[TransparencyTrustedKey]) -> HashMap<String, VerifyingKey> {
    let mut map = HashMap::new();

    for key in keys {
        let decoded = match BASE64.decode(key.public_key_base64.trim()) {
            Ok(bytes) => bytes,
            Err(err) => {
                log::warn!(
                    "Failed to decode transparency verifying key '{}' ({}); skipping",
                    key.key_id,
                    err
                );
                continue;
            }
        };

        if decoded.len() != 32 {
            log::warn!(
                "Transparency verifying key '{}' must be 32 bytes (got {})",
                key.key_id,
                decoded.len()
            );
            continue;
        }

        match VerifyingKey::from_bytes(&decoded) {
            Ok(verifying_key) => {
                map.insert(key.key_id.clone(), verifying_key);
            }
            Err(err) => {
                log::warn!(
                    "Transparency verifying key '{}' is invalid: {}",
                    key.key_id,
                    err
                );
            }
        }
    }

    map
}

fn normalize_log_url(log_url: String) -> String {
    let trimmed = log_url.trim().trim_end_matches('/').to_string();
    if trimmed.contains("/checkpoints/") || trimmed.ends_with(".json") {
        if let Some((base, _)) = trimmed.split_once("/checkpoints/") {
            return format!("{}/api/v1/transparency", base.trim_end_matches('/'));
        }
    }
    trimmed
}

impl<N: Network> TransparencyClient<N> {
    pub(crate) fn is_enabled(&self) -> bool {
        self.feature_enabled
    }

    fn checkpoint_is_fresh(&self, checkpoint: &VerifiedCheckpoint) -> bool {
        let max_age = self.config.max_checkpoint_age_seconds;
        if max_age == 0 {
            return true;
        }

        let now = Utc::now();
        let age = now.signed_duration_since(checkpoint.generated_at);
        if age.num_seconds() <= 0 {
            return true;
        }

        if age.num_seconds() as u64 > max_age {
            return false;
        }

        let since_verify = now.signed_duration_since(checkpoint.verified_at);
        if since_verify.num_seconds() > max_age as i64 {
            return false;
        }

        true
    }

    fn validate_inclusion_proof(&self, proof: &InclusionProof) -> Result<(), TransparencyError> {
        if proof.leaf_index >= proof.log_size {
            return Err(TransparencyError::InvalidInclusionProof);
        }

        if proof.entry.sequence_number > proof.log_size {
            return Err(TransparencyError::InvalidInclusionProof);
        }

        let state = self.state.lock().expect("transparency state poisoned");
        let checkpoint = state
            .last_verified
            .as_ref()
            .ok_or(TransparencyError::ServerUnavailable)?;

        if proof.log_root != checkpoint.root_hash {
            return Err(TransparencyError::InvalidInclusionProof);
        }

        if proof.log_size != checkpoint.checkpoint.tree_size {
            return Err(TransparencyError::InvalidInclusionProof);
        }

        Ok(())
    }

    fn should_fallback(&self, error: &TransparencyError) -> bool {
        self.config.fallback_to_pinning
            && matches!(
                error,
                TransparencyError::ServerUnavailable
                    | TransparencyError::Timeout
                    | TransparencyError::Network(_)
            )
    }

    async fn ensure_verified_state(&self) -> Result<(), TransparencyError> {
        if !self.is_enabled() {
            return Err(TransparencyError::ServerUnavailable);
        }

        let needs_refresh = {
            let state = self.state.lock().expect("transparency state poisoned");
            match &state.last_verified {
                Some(checkpoint) => !self.checkpoint_is_fresh(checkpoint),
                None => true,
            }
        };

        if needs_refresh {
            let _ = self.fetch_and_store_checkpoint().await?;
        }

        Ok(())
    }

    async fn fetch_and_store_checkpoint(
        &self,
    ) -> Result<TransparencyCheckpoint, TransparencyError> {
        if !self.is_enabled() {
            return Err(TransparencyError::ServerUnavailable);
        }

        let request = CheckpointRequest {
            max_age_seconds: Some(self.config.max_checkpoint_age_seconds),
        };

        let response = self
            .send_transparency_request("checkpoint", &request)
            .await?;

        let checkpoint_response: CheckpointResponse =
            serde_json::from_slice(&response).map_err(TransparencyError::Serialization)?;

        let checkpoint = checkpoint_response.checkpoint;
        let signing_key_id = checkpoint.signing_key_id()?.to_string();

        let verifying_key = self.trusted_keys.get(&signing_key_id).ok_or_else(|| {
            TransparencyError::UnknownSigningKey {
                key_id: signing_key_id.clone(),
            }
        })?;

        checkpoint.verify_signature(verifying_key)?;
        let root_hash = checkpoint.root_hash_bytes()?;
        let generated_at = checkpoint.generated_at()?;

        if self.config.max_checkpoint_age_seconds > 0 {
            let now = Utc::now();
            let age = now.signed_duration_since(generated_at);
            if age.num_seconds() > self.config.max_checkpoint_age_seconds as i64 {
                return Err(TransparencyError::CheckpointTooOld {
                    age_seconds: age.num_seconds() as u64,
                    max_age_seconds: self.config.max_checkpoint_age_seconds,
                });
            }
        }

        let previous = {
            let state = self.state.lock().expect("transparency state poisoned");
            state.last_verified.clone()
        };

        if let Some(prev) = previous {
            if checkpoint.tree_size < prev.checkpoint.tree_size {
                return Err(TransparencyError::InvalidConsistencyProof);
            } else if checkpoint.tree_size == prev.checkpoint.tree_size {
                if root_hash != prev.root_hash {
                    return Err(TransparencyError::InvalidConsistencyProof);
                }
            } else {
                self.verify_consistency(
                    prev.checkpoint.tree_size,
                    checkpoint.tree_size,
                    &prev.root_hash,
                    &root_hash,
                )
                .await?;
            }

            if prev.signing_key_id != signing_key_id {
                log::info!(
                    "Transparency signing key rotated from {} to {}",
                    prev.signing_key_id,
                    signing_key_id
                );
            }
        }

        let mut state = self.state.lock().expect("transparency state poisoned");
        if let Some(existing) = &state.last_verified {
            if existing.checkpoint.tree_size > checkpoint.tree_size {
                return Ok(existing.checkpoint.clone());
            }

            if existing.checkpoint.tree_size == checkpoint.tree_size
                && existing.root_hash == root_hash
                && self.checkpoint_is_fresh(existing)
            {
                return Ok(existing.checkpoint.clone());
            }
        }

        let verified = VerifiedCheckpoint {
            checkpoint: checkpoint.clone(),
            root_hash,
            signing_key_id,
            generated_at,
            verified_at: Utc::now(),
        };

        state.last_verified = Some(verified);

        Ok(checkpoint)
    }
}

/// Trait for transparency verification operations
#[async_trait]
pub trait TransparencyVerifier: Send + Sync {
    /// Verify that a join card is properly logged in the transparency log
    async fn verify_join_card_logged(
        &self,
        join_card_hash: &[u8; 32],
    ) -> Result<bool, TransparencyError>;

    /// Verify the current state of the transparency log
    async fn verify_log_consistency(&self) -> Result<bool, TransparencyError>;

    /// Get the current checkpoint from the transparency log
    async fn get_checkpoint(&self) -> Result<TransparencyCheckpoint, TransparencyError>;
}

#[async_trait]
impl<N: Network> TransparencyVerifier for TransparencyClient<N> {
    async fn verify_join_card_logged(
        &self,
        join_card_hash: &[u8; 32],
    ) -> Result<bool, TransparencyError> {
        if !self.is_enabled() {
            return Ok(true); // Skip verification if disabled
        }

        if let Err(err) = self.ensure_verified_state().await {
            if self.should_fallback(&err) {
                log::warn!(
                    "Transparency log unavailable ({}); falling back to key pinning",
                    err
                );
                return Ok(true);
            }
            return Err(err);
        }

        match self.get_inclusion_proof(join_card_hash).await {
            Ok(proof) => proof.verify(),
            Err(err) if self.should_fallback(&err) => {
                log::warn!(
                    "Failed to retrieve transparency proof ({}); falling back to key pinning",
                    err
                );
                Ok(true)
            }
            Err(err) => Err(err),
        }
    }

    async fn verify_log_consistency(&self) -> Result<bool, TransparencyError> {
        if !self.is_enabled() {
            return Ok(true);
        }

        match self.ensure_verified_state().await {
            Ok(()) => Ok(true),
            Err(err) if self.should_fallback(&err) => {
                log::warn!(
                    "Transparency verification unavailable ({}); assuming consistency",
                    err
                );
                Ok(true)
            }
            Err(err) => Err(err),
        }
    }

    async fn get_checkpoint(&self) -> Result<TransparencyCheckpoint, TransparencyError> {
        self.get_latest_checkpoint().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::mock::MockNetwork;
    use hybridcipher_messages::transparency::TransparencyOperation;

    #[tokio::test]
    async fn test_transparency_client_creation() {
        let network = MockNetwork::new();
        let config = TransparencyConfig::default();
        let client = TransparencyClient::new(
            network,
            "https://transparency.example.com".to_string(),
            config,
        );

        assert_eq!(client.log_url, "https://transparency.example.com");
        assert!(!client.config.enabled);
    }

    #[tokio::test]
    async fn test_disabled_transparency_verification() {
        let network = MockNetwork::new();
        let mut config = TransparencyConfig::default();
        config.enabled = false;

        let client = TransparencyClient::new(
            network,
            "https://transparency.example.com".to_string(),
            config,
        );

        let join_card_hash = [1u8; 32];
        let result = client.verify_join_card_logged(&join_card_hash).await;

        assert!(result.is_ok());
        assert!(result.unwrap()); // Should pass when disabled
    }

    #[tokio::test]
    async fn test_transparency_entry_verification() {
        let operation = TransparencyOperation::AddJoinCard {
            user_id: "alice".to_string(),
            device_id: "laptop".to_string(),
            key_fingerprint: "abcd1234".to_string(),
        };

        let entry = TransparencyEntry::new(1, [0u8; 32], operation, vec![1, 2, 3, 4]);

        let hash1 = entry.hash();
        let hash2 = entry.hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_consistency_verification_edge_cases() {
        let network = MockNetwork::new();
        let mut config = TransparencyConfig::default();
        config.enabled = false; // Disable to avoid network calls

        let client = TransparencyClient::new(
            network,
            "https://transparency.example.com".to_string(),
            config,
        );

        let old_root = [1u8; 32];
        let new_root = [1u8; 32];

        // Same size with matching roots should be accepted
        let result = client
            .verify_consistency(10, 10, &old_root, &new_root)
            .await;
        assert!(result.is_ok());

        // Old size > new size should be rejected even when disabled
        let result = client
            .verify_consistency(20, 10, &old_root, &new_root)
            .await;
        assert!(matches!(
            result,
            Err(TransparencyError::InvalidConsistencyProof)
        ));
    }
}
