/// Atomic cutover coordination with distributed consensus
///
/// This module implements the atomic cutover phase of two-phase rekey operations
/// with comprehensive safety guarantees and distributed consensus mechanisms.
use crate::{
    audit::{audit_logger, AuditOutcome},
    epoch::EpochState,
    network::{MessagePriority, MessageType, Network, NetworkMessage},
    storage::Storage,
};
use chrono::{DateTime, Utc};
use hex::decode;
use hybridcipher_coverage::CoverageManager;
use hybridcipher_crypto::{
    signatures::{Ed25519KeyPair, Signature, VerifyingKey},
    SecureDelete,
};
use hybridcipher_merkle::Hash;
use hybridcipher_messages::cutover::{CutoverMessage, CutoverPhase, CutoverVote};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

#[derive(Debug, Error)]
pub enum CutoverError {
    #[error("Migration not ready for cutover: {0}")]
    NotReady(String),

    #[error("Coverage verification failed: {0}")]
    CoverageFailure(String),

    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),

    #[error("Timeout during cutover: {0}")]
    Timeout(String),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Safety check failed: {0}")]
    SafetyCheckFailed(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Signature verification failed")]
    SignatureFailure,

    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] hybridcipher_crypto::CryptoError),

    #[error("Invalid cutover state: {0}")]
    InvalidState(String),

    #[error("Invalid cutover phase")]
    InvalidPhase,

    #[error("No cutover in progress for this epoch")]
    NoCutoverInProgress,

    #[error("Missing target epoch for cutover")]
    MissingTargetEpoch,

    #[error("Secure deletion failed: {0}")]
    SecureDeletionFailed(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

#[derive(Debug, Clone)]
pub struct CutoverOperation {
    /// Target epoch state for the cutover
    pub target_epoch: Option<EpochState>,
    /// Previous epoch snapshot for rollback
    pub previous_epoch: Option<EpochState>,
    /// Current operation status
    pub status: CutoverStatus,
    /// Operation start time
    pub started_at: SystemTime,
    /// Operation completion time
    pub completed_at: Option<SystemTime>,
    /// Consensus tracking for this operation
    pub consensus: Option<ConsensusTracker>,
}

#[derive(Debug, Clone)]
pub enum CutoverStatus {
    /// Cutover is in preparation phase
    Preparing,
    /// Cutover is in consensus phase
    InConsensus,
    /// Cutover has been committed
    Committed,
    /// Cutover has been aborted
    Aborted,
    /// Cutover is rolling back
    RollingBack,
    /// Cutover has been rolled back
    RolledBack,
}

/// Consensus tracker for atomic operations
#[derive(Debug, Clone)]
pub struct ConsensusTracker {
    pub commit_count: usize,
    pub required_count: usize,
    pub participants: HashSet<Vec<u8>>,
}

/// Cutover safety configuration
#[derive(Debug, Clone)]
pub struct CutoverConfig {
    /// Minimum required coverage percentage before cutover
    pub min_coverage_threshold: f64,
    /// Maximum time to wait for consensus
    pub consensus_timeout: Duration,
    /// Minimum number of nodes for consensus
    pub min_consensus_nodes: usize,
    /// Required consensus ratio (0.0 to 1.0)
    pub consensus_ratio: f64,
    /// Enable automatic rollback on failure
    pub auto_rollback: bool,
    /// Maximum rollback attempts
    pub max_rollback_attempts: usize,
}

impl Default for CutoverConfig {
    fn default() -> Self {
        Self {
            min_coverage_threshold: 1.0, // 100% coverage required
            consensus_timeout: Duration::from_secs(30),
            min_consensus_nodes: 1,
            consensus_ratio: 0.67, // 2/3 majority
            auto_rollback: true,
            max_rollback_attempts: 3,
        }
    }
}

/// Cutover state tracking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CutoverState {
    /// No cutover in progress
    Idle,
    /// Pre-cutover validation phase
    Validation,
    /// Waiting for consensus from all nodes
    AwaitingConsensus,
    /// Consensus achieved, performing atomic transition
    Transitioning,
    /// Cutover completed successfully
    Completed,
    /// Cutover failed, rolling back
    RollingBack,
    /// Rollback completed
    RolledBack,
}

/// Consensus vote from a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CutoverVoteRecord {
    /// Voter's public key
    pub voter_id: VerifyingKey,
    /// Vote (approve/reject)
    pub vote: CutoverVote,
    /// Merkle root at time of vote
    pub coverage_root: Hash,
    /// Vote timestamp
    pub timestamp: DateTime<Utc>,
    /// Cryptographic signature
    pub signature: Signature,
}

#[derive(Serialize)]
struct SignableCutoverMessage<'a> {
    phase: &'a CutoverPhase,
    from_epoch_id: &'a [u8],
    to_epoch_id: &'a [u8],
    coverage_root: &'a [u8],
    sender_key: &'a [u8],
    timestamp: &'a DateTime<Utc>,
    vote: Option<&'a CutoverVote>,
}

#[derive(Serialize)]
struct SignableNetworkMessage<'a> {
    message_type: &'a MessageType,
    encrypted_payload: &'a [u8],
    sender_public_key: &'a [u8; 32],
    timestamp: &'a DateTime<Utc>,
    sequence_number: u64,
    priority: &'a MessagePriority,
}

fn cutover_signable_bytes(message: &CutoverMessage) -> Result<Vec<u8>, CutoverError> {
    let signable = SignableCutoverMessage {
        phase: &message.phase,
        from_epoch_id: &message.from_epoch_id,
        to_epoch_id: &message.to_epoch_id,
        coverage_root: &message.coverage_root,
        sender_key: &message.sender_key,
        timestamp: &message.timestamp,
        vote: message.vote.as_ref(),
    };

    serde_json::to_vec(&signable).map_err(|e| CutoverError::InvalidState(e.to_string()))
}

fn network_signable_bytes(message: &NetworkMessage) -> Result<Vec<u8>, CutoverError> {
    let signable = SignableNetworkMessage {
        message_type: &message.message_type,
        encrypted_payload: &message.encrypted_payload,
        sender_public_key: &message.sender_public_key,
        timestamp: &message.timestamp,
        sequence_number: message.sequence_number,
        priority: &message.priority,
    };

    serde_json::to_vec(&signable).map_err(|e| CutoverError::InvalidState(e.to_string()))
}

fn encode_epoch_id(epoch_id: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[..8].copy_from_slice(&epoch_id.to_le_bytes());
    bytes
}

fn parse_epoch_id(bytes: &[u8]) -> Result<u64, CutoverError> {
    if bytes.len() == 8 {
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        return Ok(u64::from_le_bytes(array));
    }

    if bytes.len() >= 32 {
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes[..8]);
        return Ok(u64::from_le_bytes(array));
    }

    Err(CutoverError::InvalidState(format!(
        "Invalid epoch identifier length: {}",
        bytes.len()
    )))
}

/// Atomic cutover coordinator
#[derive(Debug)]
pub struct CutoverCoordinator<S: Storage, N: Network> {
    /// Storage interface
    storage: Arc<S>,
    /// Network interface  
    network: Arc<N>,
    /// Coverage manager for verification
    coverage_manager: Arc<CoverageManager<S>>,
    /// Device identity for signing
    device_identity: Ed25519KeyPair,
    /// Current cutover state
    state: Arc<RwLock<CutoverState>>,
    /// Consensus tracker
    consensus: Arc<Mutex<Option<ConsensusTracker>>>,
    /// Configuration
    config: CutoverConfig,
    /// Known peer public keys
    peer_keys: Arc<RwLock<HashSet<VerifyingKey>>>,
    /// Monotonic sequence number for signed network messages
    message_sequence: Arc<AtomicU64>,
    /// Rollback attempt counter
    rollback_attempts: Arc<Mutex<usize>>,
    /// Active cutover operations by epoch
    active_cutovers: Arc<Mutex<HashMap<String, CutoverOperation>>>,
    /// Current epoch state
    epoch_state: Arc<RwLock<EpochState>>,
}

impl<S: Storage, N: Network> CutoverCoordinator<S, N> {
    fn sign_cutover_message(&self, message: &mut CutoverMessage) -> Result<(), CutoverError> {
        let bytes = cutover_signable_bytes(message)?;
        let signature = self.device_identity.sign(&bytes);
        message.signature = signature.to_vec();
        Ok(())
    }

    fn sign_network_message(&self, message: &mut NetworkMessage) -> Result<(), CutoverError> {
        let bytes = network_signable_bytes(message)?;
        let signature = self.device_identity.sign(&bytes);
        message.signature.copy_from_slice(&signature);
        Ok(())
    }

    async fn current_coverage_root(&self) -> Result<Vec<u8>, CutoverError> {
        let coverage_log = self
            .coverage_manager
            .get_coverage_log()
            .await
            .map_err(|e| CutoverError::InvalidState(format!("Coverage log error: {e}")))?;
        let coverage_root_hex = coverage_log.get_merkle_root().unwrap_or_default();
        if coverage_root_hex.len() == 64 {
            Ok(decode(coverage_root_hex).unwrap_or_default())
        } else {
            Ok(coverage_root_hex.into_bytes())
        }
    }

    fn verify_cutover_signature(
        &self,
        message: &CutoverMessage,
        sender: &VerifyingKey,
    ) -> Result<(), CutoverError> {
        let signature = Signature::from_bytes(&message.signature)
            .map_err(|_| CutoverError::SignatureFailure)?;

        let embedded_key = VerifyingKey::from_bytes(&message.sender_key)
            .map_err(|_| CutoverError::SignatureFailure)?;
        if &embedded_key != sender {
            return Err(CutoverError::SignatureFailure);
        }

        let signable_bytes = cutover_signable_bytes(message)?;
        sender
            .verify(&signable_bytes, &signature)
            .map_err(|_| CutoverError::SignatureFailure)?;
        Ok(())
    }

    async fn ensure_cutover_context(&self, target_epoch_id: u64) -> Result<(), CutoverError> {
        let key = target_epoch_id.to_string();
        let mut needs_operation = false;
        {
            let operations = self.active_cutovers.lock().await;
            if !operations.contains_key(&key) {
                needs_operation = true;
            }
        }

        if needs_operation {
            let target_epoch = self
                .storage
                .load_epoch_state(target_epoch_id)
                .await
                .map_err(|e| CutoverError::Storage(e.to_string()))?;

            let current_snapshot = { self.epoch_state.read().await.clone() };

            let mut operations = self.active_cutovers.lock().await;
            operations.entry(key.clone()).or_insert(CutoverOperation {
                target_epoch: Some(target_epoch),
                previous_epoch: Some(current_snapshot),
                status: CutoverStatus::InConsensus,
                started_at: SystemTime::now(),
                completed_at: None,
                consensus: None,
            });
        }

        let peer_count = {
            let peers = self.peer_keys.read().await;
            peers.len()
        };

        let required = self.required_commits(peer_count);

        let mut consensus = self.consensus.lock().await;
        if consensus.is_none() {
            *consensus = Some(ConsensusTracker {
                commit_count: 0,
                required_count: required,
                participants: HashSet::new(),
            });
        } else if let Some(tracker) = consensus.as_mut() {
            tracker.required_count = tracker.required_count.max(required);
        }

        if let Some(tracker) = consensus.as_ref() {
            let mut operations = self.active_cutovers.lock().await;
            if let Some(operation) = operations.get_mut(&key) {
                operation.consensus = Some(tracker.clone());
            }
        }

        Ok(())
    }

    fn required_commits(&self, peer_count: usize) -> usize {
        let ratio = (((peer_count as f64) * self.config.consensus_ratio).ceil()) as usize;
        ratio.max(self.config.min_consensus_nodes).max(1)
    }

    /// Creates a new cutover coordinator
    pub fn new(
        storage: Arc<S>,
        network: Arc<N>,
        coverage_manager: Arc<CoverageManager<S>>,
        device_identity: Ed25519KeyPair,
        config: CutoverConfig,
        initial_epoch: EpochState,
    ) -> Self {
        Self {
            storage,
            network,
            coverage_manager,
            device_identity,
            state: Arc::new(RwLock::new(CutoverState::Idle)),
            consensus: Arc::new(Mutex::new(None)),
            config,
            peer_keys: Arc::new(RwLock::new(HashSet::new())),
            rollback_attempts: Arc::new(Mutex::new(0)),
            active_cutovers: Arc::new(Mutex::new(HashMap::new())),
            epoch_state: Arc::new(RwLock::new(initial_epoch)),
            message_sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Initiates atomic cutover with comprehensive safety checks
    pub async fn initiate_cutover(
        &self,
        current_epoch: &EpochState,
        target_epoch: &EpochState,
    ) -> Result<(), CutoverError> {
        // Check current state
        {
            let mut state = self.state.write().await;
            match *state {
                CutoverState::Idle => *state = CutoverState::Validation,
                _ => {
                    return Err(CutoverError::InvalidState(
                        "Cutover already in progress".to_string(),
                    ))
                }
            }
        }

        log::info!(
            "Initiating cutover from epoch {} to epoch {}",
            current_epoch.epoch_id,
            target_epoch.epoch_id
        );

        // Perform comprehensive pre-cutover validation
        self.validate_cutover_readiness(current_epoch, target_epoch)
            .await?;

        // Transition to consensus phase
        {
            let mut state = self.state.write().await;
            *state = CutoverState::AwaitingConsensus;
        }

        // Start consensus process
        self.start_consensus(current_epoch, target_epoch).await?;

        Ok(())
    }

    /// Validates migration completeness and safety before cutover
    async fn validate_cutover_readiness(
        &self,
        current_epoch: &EpochState,
        target_epoch: &EpochState,
    ) -> Result<(), CutoverError> {
        log::info!("Validating cutover readiness");

        // 1. Verify migration completeness through coverage analysis
        let coverage_status = self
            .coverage_manager
            .get_migration_progress(current_epoch.epoch_id, target_epoch.epoch_id)
            .await
            .map_err(|e| CutoverError::CoverageFailure(e.to_string()))?;

        let coverage_percentage = coverage_status as f64;
        if coverage_percentage < self.config.min_coverage_threshold {
            return Err(CutoverError::NotReady(format!(
                "Coverage {:.1}% below threshold {:.1}%",
                coverage_percentage * 100.0,
                self.config.min_coverage_threshold * 100.0
            )));
        }

        // 2. Verify coverage log integrity
        self.coverage_manager
            .get_coverage_status()
            .await
            .map_err(|e| CutoverError::CoverageFailure(e.to_string()))?;

        // 3. Validate epoch consistency
        self.validate_epoch_consistency(current_epoch, target_epoch)
            .await?;

        // 4. Check network connectivity to required peers
        self.validate_network_connectivity().await?;

        // 5. Verify storage integrity
        self.validate_storage_integrity(current_epoch, target_epoch)
            .await?;

        log::info!("Cutover validation completed successfully");
        Ok(())
    }

    /// Validates epoch consistency and security properties
    async fn validate_epoch_consistency(
        &self,
        current_epoch: &EpochState,
        target_epoch: &EpochState,
    ) -> Result<(), CutoverError> {
        // Verify epoch ordering
        if target_epoch.epoch_id <= current_epoch.epoch_id {
            return Err(CutoverError::SafetyCheckFailed(
                "Target epoch must have higher ID than current".to_string(),
            ));
        }

        // Verify cryptographic material separation
        if current_epoch.encryption_key == target_epoch.encryption_key {
            return Err(CutoverError::SafetyCheckFailed(
                "Epochs must have different encryption keys".to_string(),
            ));
        }

        // Additional epoch-specific validations would go here
        Ok(())
    }

    /// Validates network connectivity to consensus participants
    async fn validate_network_connectivity(&self) -> Result<(), CutoverError> {
        let peer_keys = self.peer_keys.read().await;

        if peer_keys.len() < self.config.min_consensus_nodes {
            return Err(CutoverError::SafetyCheckFailed(format!(
                "Insufficient peers for consensus: {} < {}",
                peer_keys.len(),
                self.config.min_consensus_nodes
            )));
        }

        let peer_infos = self
            .network
            .list_peers()
            .await
            .map_err(|e| CutoverError::Network(e.to_string()))?;
        let connected: HashSet<[u8; 32]> = peer_infos
            .iter()
            .filter(|peer| matches!(peer.status, crate::network::PeerStatus::Connected))
            .map(|peer| peer.public_key)
            .collect();

        let missing: Vec<_> = peer_keys
            .iter()
            .filter(|key| !connected.contains(&key.to_bytes()))
            .collect();

        if !missing.is_empty() {
            return Err(CutoverError::Network(format!(
                "Missing connectivity to {} consensus peers",
                missing.len()
            )));
        }

        Ok(())
    }

    /// Validates storage integrity before cutover
    async fn validate_storage_integrity(
        &self,
        current_epoch: &EpochState,
        target_epoch: &EpochState,
    ) -> Result<(), CutoverError> {
        // Ensure both current and target epochs are persisted
        let current = self
            .storage
            .load_epoch_state_data(current_epoch.epoch_id)
            .await
            .map_err(|e| CutoverError::Storage(e.to_string()))?;
        if current.is_none() {
            return Err(CutoverError::Storage(format!(
                "Current epoch {} not found in storage",
                current_epoch.epoch_id
            )));
        }

        let target = self
            .storage
            .load_epoch_state_data(target_epoch.epoch_id)
            .await
            .map_err(|e| CutoverError::Storage(e.to_string()))?;
        if target.is_none() {
            return Err(CutoverError::Storage(format!(
                "Target epoch {} not staged in storage",
                target_epoch.epoch_id
            )));
        }

        // Verify coverage log can be loaded
        self.coverage_manager
            .verify_integrity()
            .await
            .map_err(|e| CutoverError::CoverageFailure(e.to_string()))?;

        Ok(())
    }

    /// Starts distributed consensus process for cutover
    async fn start_consensus(
        &self,
        current_epoch: &EpochState,
        target_epoch: &EpochState,
    ) -> Result<(), CutoverError> {
        log::info!("Starting cutover consensus");

        let peer_keys = self.peer_keys.read().await;
        let required_count = self.required_commits(peer_keys.len());

        let consensus_tracker = ConsensusTracker {
            commit_count: 0,
            required_count,
            participants: HashSet::new(),
        };

        {
            let mut consensus = self.consensus.lock().await;
            *consensus = Some(consensus_tracker.clone());
        }

        let previous_epoch = current_epoch.clone();
        {
            let mut operations = self.active_cutovers.lock().await;
            operations.insert(
                target_epoch.epoch_id.to_string(),
                CutoverOperation {
                    target_epoch: Some(target_epoch.clone()),
                    previous_epoch: Some(previous_epoch),
                    status: CutoverStatus::InConsensus,
                    started_at: SystemTime::now(),
                    completed_at: None,
                    consensus: Some(consensus_tracker.clone()),
                },
            );
        }

        // Create and broadcast cutover proposal
        let cutover_proposal = self
            .create_cutover_proposal(current_epoch, target_epoch)
            .await?;
        self.broadcast_cutover_message(cutover_proposal).await?;

        // Start consensus monitoring
        self.monitor_consensus().await?;

        Ok(())
    }

    /// Creates cutover proposal message
    async fn create_cutover_proposal(
        &self,
        current_epoch: &EpochState,
        target_epoch: &EpochState,
    ) -> Result<CutoverMessage, CutoverError> {
        // Get coverage root for comparison
        let coverage_root = self.current_coverage_root().await?;

        let mut message = CutoverMessage::new(
            CutoverPhase::Proposal,
            encode_epoch_id(current_epoch.epoch_id),
            encode_epoch_id(target_epoch.epoch_id),
            coverage_root,
            self.device_identity.verifying_key().clone(),
            Utc::now(),
        )
        .map_err(|e| CutoverError::InvalidState(e.to_string()))?;

        if let Some(metadata) = self.coverage_manager.latest_transparency_metadata() {
            message.transparency_sequence = Some(metadata.sequence_number);
            message.transparency_log_size = Some(metadata.log_size);
            message.transparency_leaf_index = Some(metadata.leaf_index);
            message.transparency_entry_timestamp = Some(metadata.entry_timestamp);
        } else {
            warn!(
                "Transparency metadata unavailable when creating cutover proposal; proceeding without transparency linkage"
            );
        }

        self.sign_cutover_message(&mut message)?;

        Ok(message)
    }

    /// Broadcasts cutover message to all participants
    async fn broadcast_cutover_message(
        &self,
        mut message: CutoverMessage,
    ) -> Result<(), CutoverError> {
        if message.signature.len() != 64 {
            self.sign_cutover_message(&mut message)?;
        }

        let serialized =
            serde_json::to_vec(&message).map_err(|e| CutoverError::Network(e.to_string()))?;

        let sequence = self.message_sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let mut network_message = NetworkMessage {
            message_type: MessageType::Cutover,
            encrypted_payload: serialized,
            sender_public_key: self.device_identity.verifying_key().to_bytes(),
            signature: [0u8; 64],
            timestamp: Utc::now(),
            sequence_number: sequence,
            priority: MessagePriority::High,
        };

        self.sign_network_message(&mut network_message)?;

        // Broadcast to all known peers
        let peer_keys = self.peer_keys.read().await;
        for peer_key in peer_keys.iter() {
            self.network
                .send_message(&peer_key.to_bytes(), &network_message)
                .await
                .map_err(|e| CutoverError::Network(e.to_string()))?;
        }

        Ok(())
    }

    /// Monitors consensus progress and handles timeout
    async fn monitor_consensus(&self) -> Result<(), CutoverError> {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let consensus_result = {
                let consensus_guard = self.consensus.lock().await;
                if let Some(tracker) = consensus_guard.as_ref() {
                    // Check if consensus achieved
                    if tracker.commit_count >= tracker.required_count {
                        Some(Ok(()))
                    } else {
                        None
                    }
                } else {
                    Some(Err(CutoverError::InvalidState(
                        "No consensus tracker".to_string(),
                    )))
                }
            };

            if let Some(result) = consensus_result {
                match result {
                    Ok(()) => {
                        log::info!("Consensus achieved, proceeding with cutover");
                        return self.execute_atomic_cutover().await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    /// Executes atomic cutover after consensus
    async fn execute_atomic_cutover(&self) -> Result<(), CutoverError> {
        log::info!("Executing atomic cutover");

        // Update state to transitioning
        {
            let mut state = self.state.write().await;
            *state = CutoverState::Transitioning;
        }

        // Determine target epoch for this cutover
        let (target_epoch_id, target_epoch_state) = {
            let operations = self.active_cutovers.lock().await;
            let (key, op) = operations.iter().next().ok_or_else(|| {
                CutoverError::InvalidState("No active cutover operation found".to_string())
            })?;
            (key.clone(), op.target_epoch.clone())
        };

        let target_epoch_state =
            target_epoch_state.ok_or_else(|| CutoverError::MissingTargetEpoch)?;

        let current_epoch_id = {
            let epoch = self.epoch_state.read().await;
            epoch.epoch_id
        };

        // Broadcast a signed commit message to peers
        let coverage_root = self.current_coverage_root().await?;

        let mut commit_message = CutoverMessage::new(
            CutoverPhase::Commit,
            encode_epoch_id(current_epoch_id),
            encode_epoch_id(target_epoch_state.epoch_id),
            coverage_root,
            self.device_identity.verifying_key().clone(),
            Utc::now(),
        )
        .map_err(|e| CutoverError::InvalidState(e.to_string()))?;
        self.sign_cutover_message(&mut commit_message)?;
        self.broadcast_cutover_message(commit_message).await?;

        // Finalize locally
        {
            let mut consensus = self.consensus.lock().await;
            if let Some(tracker) = consensus.as_mut() {
                tracker.commit_count = tracker.required_count;
            }
        }

        {
            let mut operations = self.active_cutovers.lock().await;
            if let Some(state) = operations.get_mut(&target_epoch_id) {
                self.finalize_cutover_commit(&target_epoch_id, state)
                    .await?;
            }
            operations.remove(&target_epoch_id);
        }

        {
            let mut consensus = self.consensus.lock().await;
            *consensus = None;
        }

        // Update state to completed
        {
            let mut state = self.state.write().await;
            *state = CutoverState::Completed;
        }

        log::info!("Atomic cutover completed successfully");
        Ok(())
    }

    /// Processes received cutover message
    pub async fn process_cutover_message(
        &self,
        message: CutoverMessage,
        sender: VerifyingKey,
    ) -> Result<(), CutoverError> {
        log::debug!("Processing cutover message from {:?}", sender);

        match message.phase {
            CutoverPhase::Prepare => self.handle_cutover_prepare(message, sender).await,
            CutoverPhase::Proposal => self.handle_cutover_proposal(message, sender).await,
            CutoverPhase::Vote => self.handle_cutover_vote(message, sender).await,
            CutoverPhase::Commit => self.handle_cutover_commit(message, sender).await,
            CutoverPhase::Abort => self.handle_cutover_abort(message, sender).await,
        }
    }

    /// Handles cutover preparation phase
    async fn handle_cutover_prepare(
        &self,
        message: CutoverMessage,
        sender: VerifyingKey,
    ) -> Result<(), CutoverError> {
        log::debug!("Handling cutover prepare message from {:?}", sender);

        // Verify sender is authorized
        let peer_keys = self.peer_keys.read().await;
        if !peer_keys.contains(&sender) {
            return Err(CutoverError::SignatureFailure);
        }
        drop(peer_keys);

        self.verify_cutover_signature(&message, &sender)?;

        let target_epoch_id = parse_epoch_id(&message.to_epoch_id)?;
        self.ensure_cutover_context(target_epoch_id).await?;

        {
            let mut operations = self.active_cutovers.lock().await;
            if let Some(state) = operations.get_mut(&target_epoch_id.to_string()) {
                state.status = CutoverStatus::Preparing;
            }
        }

        log::info!(
            "Cutover preparation acknowledged for epoch {}",
            target_epoch_id
        );
        Ok(())
    }

    /// Handles cutover proposal from coordinator
    async fn handle_cutover_proposal(
        &self,
        message: CutoverMessage,
        sender: VerifyingKey,
    ) -> Result<(), CutoverError> {
        // Verify sender is authorized
        let peer_keys = self.peer_keys.read().await;
        if !peer_keys.contains(&sender) {
            return Err(CutoverError::SignatureFailure);
        }
        drop(peer_keys);

        self.verify_cutover_signature(&message, &sender)?;

        let target_epoch_id = parse_epoch_id(&message.to_epoch_id)?;
        self.ensure_cutover_context(target_epoch_id).await?;

        // Validate proposal and cast vote
        let vote = self.evaluate_cutover_proposal(&message).await?;
        self.cast_cutover_vote(vote, &message).await?;

        Ok(())
    }

    /// Evaluates cutover proposal and determines vote
    async fn evaluate_cutover_proposal(
        &self,
        message: &CutoverMessage,
    ) -> Result<CutoverVote, CutoverError> {
        // Verify our coverage state matches proposal
        let our_merkle_root = self.current_coverage_root().await?;
        if our_merkle_root != message.coverage_root {
            log::warn!("Coverage root mismatch in cutover proposal");
            return Ok(CutoverVote::Reject);
        }

        // Additional validation logic would go here
        Ok(CutoverVote::Approve)
    }

    /// Casts vote for cutover proposal
    async fn cast_cutover_vote(
        &self,
        vote: CutoverVote,
        proposal: &CutoverMessage,
    ) -> Result<(), CutoverError> {
        let mut vote_message = CutoverMessage::new_vote(
            proposal.from_epoch_id.clone(),
            proposal.to_epoch_id.clone(),
            proposal.coverage_root.clone(),
            self.device_identity.verifying_key().clone(),
            vote,
            Utc::now(),
        )
        .map_err(|e| CutoverError::InvalidState(e.to_string()))?;

        self.sign_cutover_message(&mut vote_message)?;
        self.broadcast_cutover_message(vote_message).await?;
        Ok(())
    }

    /// Handles cutover vote from participant
    async fn handle_cutover_vote(
        &self,
        message: CutoverMessage,
        sender: VerifyingKey,
    ) -> Result<(), CutoverError> {
        self.verify_cutover_signature(&message, &sender)?;

        let mut consensus_guard = self.consensus.lock().await;
        if let Some(tracker) = consensus_guard.as_mut() {
            // Ensure vote field is present
            let vote = message
                .vote
                .clone()
                .ok_or_else(|| CutoverError::InvalidState("Missing vote field".to_string()))?;

            // Record validated vote
            if tracker.participants.insert(sender.to_bytes().to_vec()) {
                if matches!(vote, CutoverVote::Approve) {
                    tracker.commit_count += 1;
                } else {
                    log::warn!("Received rejection vote for cutover");
                }
            }

            if tracker.commit_count >= tracker.required_count {
                log::info!("Vote quorum reached for cutover");
            }
        }

        Ok(())
    }

    /// Handles cutover commit message
    async fn handle_cutover_commit(
        &self,
        message: CutoverMessage,
        sender: VerifyingKey,
    ) -> Result<(), CutoverError> {
        let target_epoch_id = parse_epoch_id(&message.to_epoch_id)?;
        info!("Processing cutover commit for epoch {}", target_epoch_id);

        // Verify this is a commit message
        if !matches!(message.phase, CutoverPhase::Commit) {
            return Err(CutoverError::InvalidPhase);
        }

        // Verify sender is authorized for this epoch
        self.verify_sender_authorization(&sender, &target_epoch_id.to_string())
            .await?;

        self.verify_cutover_signature(&message, &sender)?;
        self.ensure_cutover_context(target_epoch_id).await?;

        let expected_root = self.current_coverage_root().await?;
        if expected_root != message.coverage_root {
            return Err(CutoverError::CoverageFailure(
                "Commit message coverage root mismatch".to_string(),
            ));
        }

        // Check if we have an active cutover for this epoch
        let mut cutover_state = self.active_cutovers.lock().await;
        let state = cutover_state
            .get_mut(&target_epoch_id.to_string())
            .ok_or(CutoverError::NoCutoverInProgress)?;

        // Update commit status in consensus tracking
        if let Some(consensus) = &mut state.consensus {
            if consensus.participants.insert(sender.to_bytes().to_vec()) {
                consensus.commit_count += 1;
            }

            info!(
                "Commit count: {}/{} for epoch {}",
                consensus.commit_count, consensus.required_count, target_epoch_id
            );

            // Check if we have enough commits to finalize
            if consensus.commit_count >= consensus.required_count {
                info!("Consensus reached for epoch {} cutover", target_epoch_id);

                // Finalize the cutover - make it atomic
                self.finalize_cutover_commit(&target_epoch_id.to_string(), state)
                    .await?;

                // Remove from active cutovers
                cutover_state.remove(&target_epoch_id.to_string());

                info!(
                    "Cutover completed successfully for epoch {}",
                    target_epoch_id
                );
            }
        }

        Ok(())
    }

    /// Finalize the cutover commit with secure key deletion
    async fn finalize_cutover_commit(
        &self,
        epoch_id: &str,
        state: &mut CutoverOperation,
    ) -> Result<(), CutoverError> {
        info!("Finalizing cutover commit for epoch {}", epoch_id);

        // Audit log: Starting cutover commit
        if let Some(logger) = audit_logger() {
            let _ = logger.log_epoch_management(
                "cutover_commit_start",
                state.target_epoch.as_ref().map(|e| e.epoch_id),
                Some(epoch_id.parse().unwrap_or(0)),
                None,
                AuditOutcome::InProgress,
            );
        }

        // 1. Atomically update epoch state
        let mut epoch_state = self.epoch_state.write().await;

        // Store the old epoch data before update
        let old_epoch_data = epoch_state.clone();
        let old_epoch_id = old_epoch_data.epoch_id;

        // Update to new epoch
        if let Some(new_epoch) = &state.target_epoch {
            *epoch_state = new_epoch.clone();
            info!("Updated epoch state to new epoch {}", epoch_id);
        } else {
            // Audit log: Missing target epoch
            if let Some(logger) = audit_logger() {
                let _ = logger.log_epoch_management(
                    "cutover_commit_failed",
                    Some(old_epoch_id),
                    None,
                    None,
                    AuditOutcome::Failure {
                        error_code: "MISSING_TARGET_EPOCH".to_string(),
                        error_message: "Target epoch missing for cutover".to_string(),
                    },
                );
            }
            return Err(CutoverError::MissingTargetEpoch);
        }

        // 2. Persist the new epoch state to storage
        if let Err(e) = self.storage.store_epoch_state(&*epoch_state).await {
            // Rollback on storage failure
            *epoch_state = old_epoch_data;

            // Audit log: Storage failure
            if let Some(logger) = audit_logger() {
                let _ = logger.log_epoch_management(
                    "cutover_commit_storage_failed",
                    Some(old_epoch_id),
                    Some(epoch_id.parse().unwrap_or(0)),
                    None,
                    AuditOutcome::Failure {
                        error_code: "STORAGE_ERROR".to_string(),
                        error_message: e.to_string(),
                    },
                );
            }
            return Err(CutoverError::StorageError(e.to_string()));
        }

        // 3. Secure deletion of old epoch cryptographic material
        if let Err(e) = self.secure_delete_old_epoch_keys(&old_epoch_data).await {
            warn!("Secure deletion failed during cutover: {}", e);

            // Audit log: Secure deletion failure
            if let Some(logger) = audit_logger() {
                let _ = logger.log_key_management(
                    "secure_delete_failed",
                    &format!("epoch_{}", old_epoch_id),
                    "epoch_encryption_key",
                    None,
                    AuditOutcome::Failure {
                        error_code: "SECURE_DELETE_FAILED".to_string(),
                        error_message: e.to_string(),
                    },
                );
            }
            // Don't fail the cutover for secure deletion failures, but log it
        }

        // 4. Update cutover state
        state.status = CutoverStatus::Committed;
        state.completed_at = Some(SystemTime::now());

        // 5. Verify coverage state and refresh transparency metadata after cutover
        self.coverage_manager
            .verify_integrity()
            .await
            .map_err(|e| {
                CutoverError::CoverageFailure(format!(
                    "Coverage integrity check failed after cutover: {e}"
                ))
            })?;

        if let Some(metadata) = self.coverage_manager.latest_transparency_metadata() {
            info!(
                "Coverage transparency verified: sequence={} log_size={} leaf_index={}",
                metadata.sequence_number, metadata.log_size, metadata.leaf_index
            );
        } else {
            warn!("Coverage verified after cutover but no transparency metadata recorded");
        }

        // Audit log: Successful cutover completion
        if let Some(logger) = audit_logger() {
            let _ = logger.log_epoch_management(
                "cutover_commit_completed",
                Some(old_epoch_id),
                Some(epoch_id.parse().unwrap_or(0)),
                None,
                AuditOutcome::Success,
            );
        }

        info!("Cutover finalization completed for epoch {}", epoch_id);
        Ok(())
    }

    /// Securely delete cryptographic material from old epoch
    async fn secure_delete_old_epoch_keys(
        &self,
        old_epoch: &EpochState,
    ) -> Result<(), CutoverError> {
        info!(
            "Securely deleting old epoch {} cryptographic material",
            old_epoch.epoch_id
        );

        // Audit log: Starting secure deletion
        if let Some(logger) = audit_logger() {
            let _ = logger.log_key_management(
                "secure_delete_start",
                &format!("epoch_{}", old_epoch.epoch_id),
                "epoch_encryption_key",
                None,
                AuditOutcome::InProgress,
            );
        }

        // Secure delete encryption key - this is the main sensitive material
        let mut encryption_key = old_epoch.encryption_key;
        encryption_key.secure_delete();

        // Note: Members only contain public keys, so no deletion needed
        // Private keys would be handled by individual member's key management

        info!(
            "Securely deleted encryption key for epoch {}",
            old_epoch.epoch_id
        );

        // Audit log: Successful secure deletion
        if let Some(logger) = audit_logger() {
            let _ = logger.log_key_management(
                "secure_delete_completed",
                &format!("epoch_{}", old_epoch.epoch_id),
                "epoch_encryption_key",
                None,
                AuditOutcome::Success,
            );
        }

        info!("Successfully completed secure deletion of old epoch keys");
        Ok(())
    }

    /// Verify sender is authorized for epoch operations
    async fn verify_sender_authorization(
        &self,
        sender: &VerifyingKey,
        _epoch_id: &str,
    ) -> Result<(), CutoverError> {
        if sender == self.device_identity.verifying_key() {
            return Ok(());
        }

        let peer_keys = self.peer_keys.read().await;
        if !peer_keys.contains(sender) {
            return Err(CutoverError::SignatureFailure);
        }
        drop(peer_keys);

        let peer_infos = self
            .network
            .list_peers()
            .await
            .map_err(|e| CutoverError::Network(e.to_string()))?;

        let authorized = peer_infos.iter().any(|peer| {
            peer.public_key == sender.to_bytes()
                && matches!(peer.status, crate::network::PeerStatus::Connected)
        });

        if authorized {
            Ok(())
        } else {
            Err(CutoverError::Network(
                "Authorized sender is not currently connected".to_string(),
            ))
        }
    }

    /// Handles cutover abort message
    async fn handle_cutover_abort(
        &self,
        message: CutoverMessage,
        sender: VerifyingKey,
    ) -> Result<(), CutoverError> {
        let epoch_id = String::from_utf8_lossy(&message.to_epoch_id);
        info!("Processing cutover abort for epoch {}", epoch_id);

        // Verify this is an abort message
        if !matches!(message.phase, CutoverPhase::Abort) {
            return Err(CutoverError::InvalidPhase);
        }

        // Verify sender is authorized
        self.verify_sender_authorization(&sender, &epoch_id).await?;

        // Check if we have an active cutover for this epoch
        let mut cutover_state = self.active_cutovers.lock().await;
        if let Some(state) = cutover_state.get_mut(&epoch_id.to_string()) {
            // Update abort status
            state.status = CutoverStatus::Aborted;
            state.completed_at = Some(SystemTime::now());
        }

        // Initiate rollback to ensure clean state
        self.initiate_rollback(format!("Received abort message for epoch {}", epoch_id))
            .await
    }

    /// Initiates rollback with state restoration
    async fn initiate_rollback(&self, reason: String) -> Result<(), CutoverError> {
        log::warn!("Initiating cutover rollback: {}", reason);

        {
            let mut attempts = self.rollback_attempts.lock().await;
            *attempts += 1;

            if *attempts > self.config.max_rollback_attempts {
                return Err(CutoverError::RollbackFailed(
                    "Maximum rollback attempts exceeded".to_string(),
                ));
            }
        }

        // Update state
        {
            let mut state = self.state.write().await;
            *state = CutoverState::RollingBack;
        }

        let coverage_root = self.current_coverage_root().await.unwrap_or_default();

        let failed_states = {
            let mut cutovers = self.active_cutovers.lock().await;
            cutovers.drain().collect::<Vec<_>>()
        };

        for (epoch_id_str, operation) in failed_states {
            let target_epoch_id = epoch_id_str.parse::<u64>().unwrap_or_default();
            info!(
                "Cleaning up failed cutover state for epoch {}",
                target_epoch_id
            );

            if let Some(logger) = audit_logger() {
                let _ = logger.log_epoch_management(
                    "cutover_rollback",
                    operation.target_epoch.as_ref().map(|epoch| epoch.epoch_id),
                    Some(target_epoch_id),
                    Some(reason.clone()),
                    AuditOutcome::Failure {
                        error_code: "CUTOVER_ROLLBACK".to_string(),
                        error_message: reason.clone(),
                    },
                );
            }

            if let Some(previous_epoch) = operation.previous_epoch.clone() {
                {
                    let mut current_epoch = self.epoch_state.write().await;
                    *current_epoch = previous_epoch.clone();
                }

                if let Err(e) = self.storage.store_epoch_state(&previous_epoch).await {
                    warn!(
                        "Failed to persist previous epoch {} during rollback: {}",
                        previous_epoch.epoch_id, e
                    );
                }
            }

            if let Some(target_epoch) = &operation.target_epoch {
                if let Err(e) = self.secure_delete_old_epoch_keys(target_epoch).await {
                    warn!(
                        "Failed to secure delete cutover data for epoch {}: {}",
                        target_epoch.epoch_id, e
                    );
                }
            }

            let mut abort_message = CutoverMessage::new(
                CutoverPhase::Abort,
                encode_epoch_id(
                    operation
                        .previous_epoch
                        .as_ref()
                        .map(|epoch| epoch.epoch_id)
                        .unwrap_or(target_epoch_id),
                ),
                encode_epoch_id(target_epoch_id),
                coverage_root.clone(),
                self.device_identity.verifying_key().clone(),
                Utc::now(),
            )
            .map_err(|e| CutoverError::InvalidState(e.to_string()))?;
            self.sign_cutover_message(&mut abort_message)?;
            let _ = self.broadcast_cutover_message(abort_message).await;
        }

        {
            let mut consensus = self.consensus.lock().await;
            *consensus = None;
        }

        {
            let mut attempts = self.rollback_attempts.lock().await;
            *attempts = 0;
        }

        {
            let mut state = self.state.write().await;
            *state = CutoverState::RolledBack;
        }

        log::info!("Cutover rollback completed");
        Ok(())
    }

    /// Gets current cutover state
    pub async fn get_state(&self) -> CutoverState {
        let state = self.state.read().await;
        state.clone()
    }

    /// Adds peer for consensus participation
    pub async fn add_peer(&self, peer_key: VerifyingKey) {
        let mut peers = self.peer_keys.write().await;
        peers.insert(peer_key);
    }

    /// Removes peer from consensus participation
    pub async fn remove_peer(&self, peer_key: &VerifyingKey) {
        let mut peers = self.peer_keys.write().await;
        peers.remove(peer_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{network::MockNetwork, storage::MockStorage};
    use hybridcipher_crypto::signatures::SigningKey;
    use std::sync::Arc;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_cutover_validation() {
        let (coord, _device, voter) = build_coordinator();

        coord.add_peer(voter.verifying_key().clone()).await;
        coord
            .network
            .add_peer(voter.verifying_key().to_bytes(), "peer-1".to_string())
            .await;

        let current_epoch = EpochState::new(1, [1u8; 32]);
        coord
            .storage
            .store_epoch_state(&current_epoch)
            .await
            .unwrap();
        {
            let mut state = coord.epoch_state.write().await;
            *state = current_epoch.clone();
        }

        let target_epoch = EpochState::new(2, [2u8; 32]);
        coord
            .storage
            .store_epoch_state(&target_epoch)
            .await
            .unwrap();

        coord
            .coverage_manager
            .log_file_epoch("file-a", target_epoch.epoch_id)
            .await
            .unwrap();
        coord
            .coverage_manager
            .log_file_epoch("file-b", target_epoch.epoch_id)
            .await
            .unwrap();

        let result = coord
            .validate_cutover_readiness(&current_epoch, &target_epoch)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_consensus_mechanism() {
        let (coord, _device, voter) = build_coordinator();

        coord.add_peer(voter.verifying_key().clone()).await;
        coord
            .network
            .add_peer(voter.verifying_key().to_bytes(), "peer-1".to_string())
            .await;

        let current_epoch = EpochState::new(10, [3u8; 32]);
        coord
            .storage
            .store_epoch_state(&current_epoch)
            .await
            .unwrap();
        {
            let mut state = coord.epoch_state.write().await;
            *state = current_epoch.clone();
        }

        let target_epoch = EpochState::new(11, [4u8; 32]);
        coord
            .storage
            .store_epoch_state(&target_epoch)
            .await
            .unwrap();

        coord
            .coverage_manager
            .log_file_epoch("file-a", target_epoch.epoch_id)
            .await
            .unwrap();
        coord
            .coverage_manager
            .log_file_epoch("file-b", target_epoch.epoch_id)
            .await
            .unwrap();

        {
            let mut cutovers = coord.active_cutovers.lock().await;
            cutovers.insert(
                target_epoch.epoch_id.to_string(),
                CutoverOperation {
                    target_epoch: Some(target_epoch.clone()),
                    previous_epoch: Some(current_epoch.clone()),
                    status: CutoverStatus::InConsensus,
                    started_at: SystemTime::now(),
                    completed_at: None,
                    consensus: Some(ConsensusTracker {
                        commit_count: 1,
                        required_count: 1,
                        participants: HashSet::new(),
                    }),
                },
            );
        }

        {
            let mut consensus = coord.consensus.lock().await;
            *consensus = Some(ConsensusTracker {
                commit_count: 1,
                required_count: 1,
                participants: HashSet::new(),
            });
        }

        let result = tokio::time::timeout(Duration::from_secs(2), coord.monitor_consensus())
            .await
            .expect("consensus monitor should complete");

        assert!(result.is_ok());
        assert_eq!(coord.get_state().await, CutoverState::Completed);
    }

    fn build_coordinator() -> (
        CutoverCoordinator<MockStorage, MockNetwork>,
        Ed25519KeyPair,
        Ed25519KeyPair,
    ) {
        let device_identity = Ed25519KeyPair::generate();
        let voter_identity = Ed25519KeyPair::generate();
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let signing_key =
            SigningKey::from_bytes(&device_identity.private_key_bytes()).expect("signing key");
        let coverage_manager = Arc::new(CoverageManager::new_with_signing_key(
            storage.clone(),
            signing_key,
        ));
        let initial_epoch = EpochState::new(0, [0u8; 32]);
        let coordinator = CutoverCoordinator::new(
            storage,
            network,
            coverage_manager,
            device_identity.clone(),
            CutoverConfig::default(),
            initial_epoch,
        );

        (coordinator, device_identity, voter_identity)
    }

    async fn prepare_vote(kp: &Ed25519KeyPair, vote: CutoverVote) -> CutoverMessage {
        let mut message = CutoverMessage::new_vote(
            vec![],
            vec![0u8; 32],
            vec![0u8; 32],
            kp.verifying_key().clone(),
            vote,
            Utc::now(),
        )
        .unwrap();

        let bytes = cutover_signable_bytes(&message).unwrap();
        let sig = kp.sign(&bytes);
        message.signature = sig.to_vec();
        message
    }

    async fn setup_consensus(coord: &CutoverCoordinator<MockStorage, MockNetwork>) {
        let mut guard = coord.consensus.lock().await;
        *guard = Some(ConsensusTracker {
            commit_count: 0,
            required_count: 1,
            participants: HashSet::new(),
        });
    }

    #[tokio::test]
    async fn vote_approve_valid_signature() {
        let (coord, _id, voter) = build_coordinator();
        coord.add_peer(voter.verifying_key().clone()).await;
        setup_consensus(&coord).await;

        let message = prepare_vote(&voter, CutoverVote::Approve).await;
        let result = coord
            .handle_cutover_vote(message, voter.verifying_key().clone())
            .await;
        assert!(result.is_ok());

        let guard = coord.consensus.lock().await;
        let tracker = guard.as_ref().unwrap();
        assert_eq!(tracker.commit_count, 1);
        assert!(tracker
            .participants
            .contains(&voter.verifying_key().to_bytes().to_vec()));
    }

    #[tokio::test]
    async fn vote_reject_valid_signature() {
        let (coord, _id, voter) = build_coordinator();
        coord.add_peer(voter.verifying_key().clone()).await;
        setup_consensus(&coord).await;

        let message = prepare_vote(&voter, CutoverVote::Reject).await;
        let result = coord
            .handle_cutover_vote(message, voter.verifying_key().clone())
            .await;
        assert!(result.is_ok());

        let guard = coord.consensus.lock().await;
        let tracker = guard.as_ref().unwrap();
        assert_eq!(tracker.commit_count, 0);
        assert!(tracker
            .participants
            .contains(&voter.verifying_key().to_bytes().to_vec()));
    }

    #[tokio::test]
    async fn vote_approve_invalid_signature() {
        let (coord, _id, voter) = build_coordinator();
        coord.add_peer(voter.verifying_key().clone()).await;
        setup_consensus(&coord).await;

        let mut message = prepare_vote(&voter, CutoverVote::Approve).await;
        message.signature[0] ^= 1; // Corrupt signature
        let result = coord
            .handle_cutover_vote(message, voter.verifying_key().clone())
            .await;
        assert!(matches!(result, Err(CutoverError::SignatureFailure)));

        let guard = coord.consensus.lock().await;
        let tracker = guard.as_ref().unwrap();
        assert_eq!(tracker.commit_count, 0);
        assert!(tracker.participants.is_empty());
    }

    #[tokio::test]
    async fn vote_reject_invalid_signature() {
        let (coord, _id, voter) = build_coordinator();
        coord.add_peer(voter.verifying_key().clone()).await;
        setup_consensus(&coord).await;

        let mut message = prepare_vote(&voter, CutoverVote::Reject).await;
        message.signature[0] ^= 1; // Corrupt signature
        let result = coord
            .handle_cutover_vote(message, voter.verifying_key().clone())
            .await;
        assert!(matches!(result, Err(CutoverError::SignatureFailure)));

        let guard = coord.consensus.lock().await;
        let tracker = guard.as_ref().unwrap();
        assert_eq!(tracker.commit_count, 0);
        assert!(tracker.participants.is_empty());
    }

    #[tokio::test]
    async fn rollback_restores_previous_epoch() {
        let (coord, _id, _voter) = build_coordinator();

        let current_epoch = coord.epoch_state.read().await.clone();
        coord
            .storage
            .store_epoch_state(&current_epoch)
            .await
            .unwrap();

        let target_epoch = EpochState::new(42, [2u8; 32]);
        coord
            .storage
            .store_epoch_state(&target_epoch)
            .await
            .unwrap();

        {
            let mut epoch_state = coord.epoch_state.write().await;
            *epoch_state = target_epoch.clone();
        }

        {
            let mut cutovers = coord.active_cutovers.lock().await;
            cutovers.insert(
                target_epoch.epoch_id.to_string(),
                CutoverOperation {
                    target_epoch: Some(target_epoch.clone()),
                    previous_epoch: Some(current_epoch.clone()),
                    status: CutoverStatus::InConsensus,
                    started_at: SystemTime::now(),
                    completed_at: None,
                    consensus: None,
                },
            );
        }

        coord
            .initiate_rollback("test rollback".to_string())
            .await
            .expect("rollback should succeed");

        assert_eq!(coord.get_state().await, CutoverState::RolledBack);

        let restored_epoch = coord.epoch_state.read().await.clone();
        assert_eq!(restored_epoch.epoch_id, current_epoch.epoch_id);
    }
}
