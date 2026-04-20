//! Cutover messages for coordinated two-phase epoch transitions
//!
//! This module implements atomic epoch migration coordination with
//! leader election, consensus mechanisms, and Byzantine fault tolerance.

use crate::error::{MessageError, MessageResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cutover phase states
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CutoverPhase {
    /// Preparation phase - migrating files
    Prepare,
    /// Proposal phase - requesting consensus
    Proposal,
    /// Vote phase - casting consensus votes
    Vote,
    /// Commit phase - finalizing transition
    Commit,
    /// Abort phase - rolling back
    Abort,
}

/// Consensus vote options
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CutoverVote {
    /// Approve the cutover proposal
    Approve,
    /// Reject the cutover proposal
    Reject,
}

/// Consensus state tracking
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConsensusState {
    /// Accepting votes
    Voting,
    /// Consensus achieved
    Achieved,
    /// Consensus failed
    Failed,
    /// Consensus timed out
    TimedOut,
}

/// Unified cutover message for atomic epoch migration coordination
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CutoverMessage {
    /// Current cutover phase
    pub phase: CutoverPhase,
    /// Source epoch identifier
    pub from_epoch_id: Vec<u8>,
    /// Target epoch identifier
    pub to_epoch_id: Vec<u8>,
    /// Coverage Merkle root for verification
    pub coverage_root: Vec<u8>,
    /// Message sender's public key
    pub sender_key: Vec<u8>,
    /// Message timestamp
    pub timestamp: DateTime<Utc>,
    /// Vote (if this is a vote message)
    pub vote: Option<CutoverVote>,
    /// Coordinator signature
    pub signature: Vec<u8>,
    /// Transparency log sequence number for the coverage snapshot.
    #[serde(default)]
    pub transparency_sequence: Option<u64>,
    /// Transparency log size at the time of inclusion.
    #[serde(default)]
    pub transparency_log_size: Option<u64>,
    /// Transparency leaf index for the coverage entry.
    #[serde(default)]
    pub transparency_leaf_index: Option<u64>,
    /// Timestamp recorded in the transparency entry.
    #[serde(default)]
    pub transparency_entry_timestamp: Option<u64>,
}

impl CutoverMessage {
    /// Create new cutover message
    pub fn new(
        phase: CutoverPhase,
        from_epoch_id: Vec<u8>,
        to_epoch_id: Vec<u8>,
        coverage_root: Vec<u8>,
        sender_key: hybridcipher_crypto::signatures::VerifyingKey,
        timestamp: DateTime<Utc>,
    ) -> MessageResult<Self> {
        let message = Self {
            phase,
            from_epoch_id,
            to_epoch_id,
            coverage_root,
            sender_key: sender_key.to_bytes().to_vec(),
            timestamp,
            vote: None,
            signature: vec![0u8; 64], // Will be filled by signing
            transparency_sequence: None,
            transparency_log_size: None,
            transparency_leaf_index: None,
            transparency_entry_timestamp: None,
        };

        message.validate()?;
        Ok(message)
    }

    /// Create vote message
    pub fn new_vote(
        from_epoch_id: Vec<u8>,
        to_epoch_id: Vec<u8>,
        coverage_root: Vec<u8>,
        sender_key: hybridcipher_crypto::signatures::VerifyingKey,
        vote: CutoverVote,
        timestamp: DateTime<Utc>,
    ) -> MessageResult<Self> {
        let message = Self {
            phase: CutoverPhase::Vote,
            from_epoch_id,
            to_epoch_id,
            coverage_root,
            sender_key: sender_key.to_bytes().to_vec(),
            timestamp,
            vote: Some(vote),
            signature: vec![0u8; 64], // Will be filled by signing
            transparency_sequence: None,
            transparency_log_size: None,
            transparency_leaf_index: None,
            transparency_entry_timestamp: None,
        };

        message.validate()?;
        Ok(message)
    }

    /// Validate cutover message
    pub fn validate(&self) -> MessageResult<()> {
        if self.from_epoch_id.len() != 32 && !self.from_epoch_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "from_epoch_id must be 32 bytes or empty".to_string(),
            ));
        }
        if self.to_epoch_id.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "to_epoch_id must be 32 bytes".to_string(),
            ));
        }
        if self.coverage_root.len() != 32 && !self.coverage_root.is_empty() {
            return Err(MessageError::InvalidFormat(
                "coverage_root must be 32 bytes or empty".to_string(),
            ));
        }
        if self.sender_key.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "sender_key must be 32 bytes".to_string(),
            ));
        }
        if self.phase == CutoverPhase::Vote && self.vote.is_none() {
            return Err(MessageError::InvalidFormat(
                "vote phase requires vote field".to_string(),
            ));
        }
        Ok(())
    }
}

/// Cutover coordinator election
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LeaderElection {
    /// Proposed coordinator ID
    pub coordinator_id: String,
    /// Election term number
    pub term: u64,
    /// Votes from participants
    pub votes: HashMap<String, bool>,
    /// Election signature
    pub signature: Vec<u8>,
}

/// Cutover message for atomic epoch migration coordination
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Cutover {
    /// Source epoch identifier
    pub from_epoch_id: Vec<u8>,
    /// Target epoch identifier
    pub to_epoch_id: Vec<u8>,
    /// Current cutover phase
    pub phase: CutoverPhase,
    /// Coordinator for this cutover
    pub coordinator_id: String,
    /// Term number for leader election
    pub term: u64,
    /// Files being migrated in this cutover
    pub affected_files: Vec<Vec<u8>>, // file_ids
    /// Phase timeout (Unix seconds)
    pub timeout: u64,
    /// Participant acknowledgments
    pub acks: HashMap<String, bool>,
    /// Coordinator signature
    pub coordinator_signature: Vec<u8>,
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
}

/// Rollback message for recovery from failed cutover
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CutoverRollback {
    /// Failed cutover source epoch ID
    pub from_epoch_id: Vec<u8>,
    /// Failed cutover target epoch ID
    pub to_epoch_id: Vec<u8>,
    /// Rollback coordinator
    pub coordinator_id: String,
    /// Files to rollback
    pub rollback_files: Vec<Vec<u8>>,
    /// Rollback reason
    pub reason: String,
    /// Recovery state
    pub recovery_state: HashMap<String, Vec<u8>>,
    /// Rollback signature
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

impl Cutover {
    /// Create new cutover message
    pub fn new(
        from_epoch_id: Vec<u8>,
        to_epoch_id: Vec<u8>,
        phase: CutoverPhase,
        coordinator_id: String,
        term: u64,
        affected_files: Vec<Vec<u8>>,
        timeout: u64,
        coordinator_signature: Vec<u8>,
    ) -> MessageResult<Self> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| MessageError::TimestampError("System clock error".to_string()))?
            .as_secs();

        let cutover = Self {
            from_epoch_id,
            to_epoch_id,
            phase,
            coordinator_id,
            term,
            affected_files,
            timeout,
            acks: HashMap::new(),
            coordinator_signature,
            timestamp,
        };

        cutover.validate()?;
        Ok(cutover)
    }

    /// Validate cutover message
    pub fn validate(&self) -> MessageResult<()> {
        if self.coordinator_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "coordinator_id cannot be empty".to_string(),
            ));
        }
        if self.timeout <= self.timestamp {
            return Err(MessageError::InvalidFormat(
                "timeout must be in the future".to_string(),
            ));
        }
        if self.coordinator_signature.len() != 64 {
            return Err(MessageError::InvalidFormat(
                "coordinator_signature must be 64 bytes".to_string(),
            ));
        }
        Ok(())
    }

    /// Check if cutover has timed out
    pub fn is_timed_out(&self, current_time: u64) -> bool {
        current_time > self.timeout
    }

    /// Add participant acknowledgment
    pub fn add_ack(&mut self, participant_id: String, ack: bool) {
        self.acks.insert(participant_id, ack);
    }

    /// Check if all participants have acknowledged
    pub fn all_acked(&self, required_participants: &[String]) -> bool {
        required_participants
            .iter()
            .all(|p| self.acks.get(p).unwrap_or(&false) == &true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hybridcipher_crypto::signatures::Ed25519KeyPair;

    #[test]
    fn test_epoch_id_length_validation() {
        let keypair = Ed25519KeyPair::generate();
        let timestamp = Utc::now();

        // Valid message with 32-byte epoch IDs
        let msg = CutoverMessage::new(
            CutoverPhase::Prepare,
            vec![1u8; 32],
            vec![2u8; 32],
            vec![0u8; 32],
            keypair.verifying_key().clone(),
            timestamp,
        );
        assert!(msg.is_ok());

        // Invalid from_epoch_id length
        let err = CutoverMessage::new(
            CutoverPhase::Prepare,
            vec![1u8; 8],
            vec![2u8; 32],
            vec![0u8; 32],
            keypair.verifying_key().clone(),
            timestamp,
        )
        .unwrap_err();
        assert!(matches!(err, MessageError::InvalidFormat(_)));

        // Invalid to_epoch_id length
        let err = CutoverMessage::new(
            CutoverPhase::Prepare,
            Vec::new(),
            vec![2u8; 8],
            vec![0u8; 32],
            keypair.verifying_key().clone(),
            timestamp,
        )
        .unwrap_err();
        assert!(matches!(err, MessageError::InvalidFormat(_)));
    }
}

impl CutoverRollback {
    /// Create new rollback message
    pub fn new(
        from_epoch_id: Vec<u8>,
        to_epoch_id: Vec<u8>,
        coordinator_id: String,
        rollback_files: Vec<Vec<u8>>,
        reason: String,
        recovery_state: HashMap<String, Vec<u8>>,
        signature: Vec<u8>,
    ) -> MessageResult<Self> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| MessageError::TimestampError("System clock error".to_string()))?
            .as_secs();

        let rollback = Self {
            from_epoch_id,
            to_epoch_id,
            coordinator_id,
            rollback_files,
            reason,
            recovery_state,
            signature,
            timestamp,
        };

        rollback.validate()?;
        Ok(rollback)
    }

    /// Validate rollback message
    pub fn validate(&self) -> MessageResult<()> {
        if self.coordinator_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "coordinator_id cannot be empty".to_string(),
            ));
        }
        if self.reason.is_empty() {
            return Err(MessageError::InvalidFormat(
                "reason cannot be empty".to_string(),
            ));
        }
        if self.signature.len() != 64 {
            return Err(MessageError::InvalidFormat(
                "signature must be 64 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod rollback_tests {
    use super::*;

    #[test]
    fn test_cutover_creation() {
        let cutover = Cutover::new(
            vec![1u8; 32],
            vec![2u8; 32],
            CutoverPhase::Prepare,
            "coordinator1".to_string(),
            1,
            vec![vec![3u8; 32]],
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            vec![0u8; 64],
        )
        .expect("Cutover creation failed");

        assert_eq!(cutover.phase, CutoverPhase::Prepare);
        assert_eq!(cutover.coordinator_id, "coordinator1");
        assert_eq!(cutover.term, 1);
    }

    #[test]
    fn test_cutover_acks() {
        let mut cutover = Cutover::new(
            vec![1u8; 32],
            vec![2u8; 32],
            CutoverPhase::Prepare,
            "coordinator1".to_string(),
            1,
            vec![],
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            vec![0u8; 64],
        )
        .unwrap();

        cutover.add_ack("participant1".to_string(), true);
        cutover.add_ack("participant2".to_string(), true);

        let participants = vec!["participant1".to_string(), "participant2".to_string()];
        assert!(cutover.all_acked(&participants));

        cutover.add_ack("participant3".to_string(), false);
        let participants = vec![
            "participant1".to_string(),
            "participant2".to_string(),
            "participant3".to_string(),
        ];
        assert!(!cutover.all_acked(&participants));
    }

    #[test]
    fn test_rollback_creation() {
        let rollback = CutoverRollback::new(
            vec![1u8; 32],
            vec![2u8; 32],
            "coordinator1".to_string(),
            vec![vec![3u8; 32]],
            "Network partition detected".to_string(),
            HashMap::new(),
            vec![0u8; 64],
        )
        .expect("Rollback creation failed");

        assert_eq!(rollback.coordinator_id, "coordinator1");
        assert_eq!(rollback.reason, "Network partition detected");
    }
}
