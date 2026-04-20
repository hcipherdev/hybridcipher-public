//! GroupUpdate messages for group membership changes and epoch transitions
//!
//! GroupUpdate messages coordinate epoch transitions and membership changes
//! with atomic operations and cryptographic validation.

use crate::error::{MessageError, MessageResult};
use hybridcipher_crypto::signatures::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_cbor;
use std::collections::HashMap;

/// Update actions for group operations
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum UpdateAction {
    /// Initialize new group with founding members
    Initialize {
        /// Founding members of the group
        founding_members: Vec<Member>,
        /// Group configuration parameters
        group_config: GroupConfig,
    },
    /// Start migration to new epoch
    StartMigration {
        /// Target epoch sequence number
        target_epoch: u64,
        /// Reason for migration
        reason: String,
    },
    /// Add new member to group
    AddMember {
        /// New member to add
        member: Member,
        /// Welcome message for new member
        welcome_message: Vec<u8>,
    },
    /// Remove member from group
    RemoveMember {
        /// User ID to remove
        user_id: String,
        /// Device ID to remove
        device_id: String,
        /// Reason for removal
        reason: String,
    },
}

/// Group configuration parameters
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GroupConfig {
    /// Maximum number of members
    pub max_members: u32,
    /// Epoch lifetime in seconds
    pub epoch_lifetime: u64,
    /// Requires unanimous consent for member removal
    pub require_unanimous_removal: bool,
    /// Additional configuration parameters
    pub extensions: HashMap<String, Vec<u8>>,
}

/// A group member with cryptographic keys
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// User identifier (unique across system)
    pub user_id: String,
    /// Device identifier (unique per user)
    pub device_id: String,
    /// Identity public key for signatures (Ed25519 - 32 bytes)
    pub identity_public: Vec<u8>,
    /// Invitation public key for receiving encrypted messages (X25519 - 32 bytes)
    pub invitation_public: Vec<u8>,
    /// Member capabilities and permissions
    pub capabilities: MemberCapabilities,
    /// When this member joined (Unix seconds)
    pub joined_at: u64,
}

/// Member capabilities and permissions
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MemberCapabilities {
    /// Can add new members
    pub can_add_members: bool,
    /// Can remove other members
    pub can_remove_members: bool,
    /// Can initiate epoch transitions
    pub can_initiate_epoch_transitions: bool,
    /// Administrative privileges
    pub is_admin: bool,
}

/// Group roster update message with epoch transition
///
/// Coordinates atomic epoch transitions with membership changes
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GroupUpdate {
    /// Source epoch identifier (previous epoch)
    pub from_epoch_id: Vec<u8>,
    /// Target epoch identifier (new epoch)
    pub to_epoch_id: Vec<u8>,
    /// Epoch sequence numbers
    pub epoch_sequence: (u64, u64), // (from, to)
    /// Update action being performed
    pub action: UpdateAction,
    /// Current group roster after this update
    pub updated_roster: Vec<Member>,
    /// Hash of the group state after update
    pub state_hash: Vec<u8>,
    /// Administrator signature over the update
    pub admin_signature: Vec<u8>,
    /// Per-member encrypted secrets for deriving the new epoch key
    pub per_member_secrets: HashMap<String, Vec<u8>>,
    /// Timestamp of this update (Unix seconds)
    pub timestamp: u64,
}

impl GroupConfig {
    /// Create new group configuration with defaults
    pub fn new() -> Self {
        Self {
            max_members: 100,
            epoch_lifetime: 86400, // 24 hours
            require_unanimous_removal: false,
            extensions: HashMap::new(),
        }
    }

    /// Validate group configuration
    pub fn validate(&self) -> MessageResult<()> {
        if self.max_members == 0 {
            return Err(MessageError::InvalidFormat(
                "max_members must be > 0".to_string(),
            ));
        }
        if self.max_members > 10000 {
            return Err(MessageError::InvalidFormat(
                "max_members must be <= 10000".to_string(),
            ));
        }
        if self.epoch_lifetime == 0 {
            return Err(MessageError::InvalidFormat(
                "epoch_lifetime must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl MemberCapabilities {
    /// Create default member capabilities (non-admin)
    pub fn default() -> Self {
        Self {
            can_add_members: false,
            can_remove_members: false,
            can_initiate_epoch_transitions: false,
            is_admin: false,
        }
    }

    /// Create admin capabilities
    pub fn admin() -> Self {
        Self {
            can_add_members: true,
            can_remove_members: true,
            can_initiate_epoch_transitions: true,
            is_admin: true,
        }
    }
}

impl Member {
    /// Create new member with validation
    pub fn new(
        user_id: String,
        device_id: String,
        identity_public: Vec<u8>,
        invitation_public: Vec<u8>,
        capabilities: MemberCapabilities,
        joined_at: u64,
    ) -> MessageResult<Self> {
        let member = Self {
            user_id,
            device_id,
            identity_public,
            invitation_public,
            capabilities,
            joined_at,
        };
        member.validate()?;
        Ok(member)
    }

    /// Validate member structure
    pub fn validate(&self) -> MessageResult<()> {
        if self.user_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "user_id cannot be empty".to_string(),
            ));
        }
        if self.device_id.is_empty() {
            return Err(MessageError::InvalidFormat(
                "device_id cannot be empty".to_string(),
            ));
        }
        if self.identity_public.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "identity_public must be 32 bytes".to_string(),
            ));
        }
        if self.invitation_public.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "invitation_public must be 32 bytes".to_string(),
            ));
        }
        Ok(())
    }

    /// Get unique member identifier
    pub fn member_id(&self) -> String {
        format!("{}:{}", self.user_id, self.device_id)
    }
}

impl GroupUpdate {
    /// Create new GroupUpdate with validation
    pub fn new(
        from_epoch_id: Vec<u8>,
        to_epoch_id: Vec<u8>,
        epoch_sequence: (u64, u64),
        action: UpdateAction,
        updated_roster: Vec<Member>,
        state_hash: Vec<u8>,
        admin_signature: Vec<u8>,
        per_member_secrets: HashMap<String, Vec<u8>>,
        timestamp: u64,
    ) -> MessageResult<Self> {
        let update = Self {
            from_epoch_id,
            to_epoch_id,
            epoch_sequence,
            action,
            updated_roster,
            state_hash,
            admin_signature,
            per_member_secrets,
            timestamp,
        };
        update.validate()?;
        Ok(update)
    }

    /// Validate GroupUpdate structure
    pub fn validate(&self) -> MessageResult<()> {
        // Validate epoch progression
        if self.epoch_sequence.1 <= self.epoch_sequence.0 {
            return Err(MessageError::InvalidFormat(
                "Target epoch must be greater than source epoch".to_string(),
            ));
        }

        // Validate signatures
        if self.admin_signature.len() != 64 {
            return Err(MessageError::InvalidFormat(
                "admin_signature must be 64 bytes".to_string(),
            ));
        }

        // Validate state hash
        if self.state_hash.len() != 32 {
            return Err(MessageError::InvalidFormat(
                "state_hash must be 32 bytes".to_string(),
            ));
        }

        // Validate roster
        if self.updated_roster.is_empty() {
            return Err(MessageError::InvalidFormat(
                "updated_roster cannot be empty".to_string(),
            ));
        }

        // Validate all members
        for member in &self.updated_roster {
            member.validate()?;
        }

        // Validate action-specific constraints
        self.validate_action()?;

        Ok(())
    }

    /// Validate action-specific constraints
    fn validate_action(&self) -> MessageResult<()> {
        match &self.action {
            UpdateAction::Initialize {
                founding_members,
                group_config,
            } => {
                group_config.validate()?;
                if founding_members.is_empty() {
                    return Err(MessageError::InvalidFormat(
                        "Initialize action requires founding_members".to_string(),
                    ));
                }
                // Founding members should match updated roster
                if founding_members.len() != self.updated_roster.len() {
                    return Err(MessageError::InvalidFormat(
                        "Founding members count must match updated roster".to_string(),
                    ));
                }
            }
            UpdateAction::StartMigration { target_epoch, .. } => {
                if *target_epoch != self.epoch_sequence.1 {
                    return Err(MessageError::InvalidFormat(
                        "Migration target_epoch must match to_epoch".to_string(),
                    ));
                }
            }
            UpdateAction::AddMember { member, .. } => {
                member.validate()?;
                // New member should be in updated roster
                if !self
                    .updated_roster
                    .iter()
                    .any(|m| m.member_id() == member.member_id())
                {
                    return Err(MessageError::InvalidFormat(
                        "Added member must be in updated roster".to_string(),
                    ));
                }
            }
            UpdateAction::RemoveMember {
                user_id, device_id, ..
            } => {
                let member_id = format!("{}:{}", user_id, device_id);
                // Removed member should not be in updated roster
                if self
                    .updated_roster
                    .iter()
                    .any(|m| m.member_id() == member_id)
                {
                    return Err(MessageError::InvalidFormat(
                        "Removed member must not be in updated roster".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Verify administrator signature on this update
    pub fn verify_admin_signature(&self, admin_public_key: &[u8]) -> MessageResult<()> {
        // Parse the admin public key
        let verifying_key = VerifyingKey::from_bytes(admin_public_key)
            .map_err(|e| MessageError::SignatureError(format!("Invalid admin key: {:?}", e)))?;

        // Parse the signature
        let signature = Signature::from_bytes(&self.admin_signature)
            .map_err(|e| MessageError::SignatureError(format!("Invalid signature: {:?}", e)))?;

        // Generate canonical message for signing
        let message = self.canonical_message()?;

        // Verify signature
        verifying_key.verify(&message, &signature).map_err(|e| {
            MessageError::SignatureError(format!("Signature verification failed: {:?}", e))
        })?;

        Ok(())
    }

    /// Generate canonical message for signing (without admin_signature field)
    fn canonical_message(&self) -> MessageResult<Vec<u8>> {
        // Create a temporary structure without signature for canonical encoding
        let signable = SignableGroupUpdate {
            from_epoch_id: &self.from_epoch_id,
            to_epoch_id: &self.to_epoch_id,
            epoch_sequence: self.epoch_sequence,
            action: &self.action,
            updated_roster: &self.updated_roster,
            state_hash: &self.state_hash,
            per_member_secrets: &self.per_member_secrets,
            timestamp: self.timestamp,
        };

        // Use CBOR for canonical encoding
        serde_cbor::to_vec(&signable)
            .map_err(|e| MessageError::SerializationError(format!("CBOR encoding failed: {:?}", e)))
    }

    /// Calculate state hash for group roster
    pub fn calculate_state_hash(roster: &[Member]) -> MessageResult<Vec<u8>> {
        // Sort members by member_id for deterministic hashing
        let mut sorted_roster = roster.to_vec();
        sorted_roster.sort_by(|a, b| a.member_id().cmp(&b.member_id()));

        // Serialize sorted roster
        let roster_bytes = serde_cbor::to_vec(&sorted_roster).map_err(|e| {
            MessageError::SerializationError(format!("Failed to serialize roster: {:?}", e))
        })?;

        // Use SHA-256 for state hash
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"hybridcipher-state-v1:");
        hasher.update(&roster_bytes);
        Ok(hasher.finalize().to_vec())
    }
}

/// Temporary structure for canonical message generation
#[derive(Serialize)]
struct SignableGroupUpdate<'a> {
    from_epoch_id: &'a [u8],
    to_epoch_id: &'a [u8],
    epoch_sequence: (u64, u64),
    action: &'a UpdateAction,
    updated_roster: &'a [Member],
    state_hash: &'a [u8],
    per_member_secrets: &'a HashMap<String, Vec<u8>>,
    timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybridcipher_crypto::signatures::SigningKey;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_member(user_id: &str, device_id: &str, is_admin: bool) -> Member {
        let capabilities = if is_admin {
            MemberCapabilities::admin()
        } else {
            MemberCapabilities::default()
        };

        Member::new(
            user_id.to_string(),
            device_id.to_string(),
            vec![0u8; 32], // Mock identity key
            vec![1u8; 32], // Mock invitation key
            capabilities,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    #[test]
    fn test_member_creation() {
        let member = create_test_member("alice", "laptop", false);
        assert_eq!(member.user_id, "alice");
        assert_eq!(member.device_id, "laptop");
        assert_eq!(member.member_id(), "alice:laptop");
        assert!(!member.capabilities.is_admin);
    }

    #[test]
    fn test_group_config_validation() {
        let mut config = GroupConfig::new();
        assert!(config.validate().is_ok());

        config.max_members = 0;
        assert!(config.validate().is_err());

        config.max_members = 20000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_initialize_action() {
        let alice = create_test_member("alice", "laptop", true);
        let bob = create_test_member("bob", "phone", false);

        let action = UpdateAction::Initialize {
            founding_members: vec![alice.clone(), bob.clone()],
            group_config: GroupConfig::new(),
        };

        let state_hash = GroupUpdate::calculate_state_hash(&[alice.clone(), bob.clone()]).unwrap();

        let update = GroupUpdate::new(
            vec![0u8; 32], // from_epoch_id
            vec![1u8; 32], // to_epoch_id
            (0, 1),        // epoch_sequence
            action,
            vec![alice, bob],
            state_hash,
            vec![0u8; 64], // admin_signature
            HashMap::new(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();

        assert_eq!(update.epoch_sequence, (0, 1));
        assert_eq!(update.updated_roster.len(), 2);
    }

    #[test]
    fn test_add_member_action() {
        let alice = create_test_member("alice", "laptop", true);
        let bob = create_test_member("bob", "phone", false);

        let action = UpdateAction::AddMember {
            member: bob.clone(),
            welcome_message: vec![1, 2, 3],
        };

        let roster = vec![alice, bob];
        let state_hash = GroupUpdate::calculate_state_hash(&roster).unwrap();

        let update = GroupUpdate::new(
            vec![1u8; 32], // from_epoch_id
            vec![2u8; 32], // to_epoch_id
            (1, 2),        // epoch_sequence
            action,
            roster,
            state_hash,
            vec![0u8; 64], // admin_signature
            HashMap::new(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();

        assert!(update.validate().is_ok());
    }

    #[test]
    fn test_state_hash_calculation() {
        let alice = create_test_member("alice", "laptop", true);
        let bob = create_test_member("bob", "phone", false);

        let hash1 = GroupUpdate::calculate_state_hash(&[alice.clone(), bob.clone()]).unwrap();
        let hash2 = GroupUpdate::calculate_state_hash(&[bob, alice]).unwrap(); // Different order

        // Should be the same due to deterministic sorting
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_signature_verification() {
        let mut rng = ChaCha20Rng::from_entropy();
        let signing_key = SigningKey::generate(&mut rng).unwrap();
        let admin_public = signing_key.verifying_key().to_bytes().to_vec();

        let alice = create_test_member("alice", "laptop", true);
        let action = UpdateAction::Initialize {
            founding_members: vec![alice.clone()],
            group_config: GroupConfig::new(),
        };

        let state_hash = GroupUpdate::calculate_state_hash(&[alice.clone()]).unwrap();

        // Create update without signature first
        let mut update = GroupUpdate {
            from_epoch_id: vec![0u8; 32],
            to_epoch_id: vec![1u8; 32],
            epoch_sequence: (0, 1),
            action,
            updated_roster: vec![alice],
            state_hash,
            admin_signature: vec![0u8; 64], // Placeholder
            per_member_secrets: HashMap::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Generate proper signature
        let message = update.canonical_message().unwrap();
        let signature = signing_key.sign(&message).unwrap().to_bytes().to_vec();
        update.admin_signature = signature;

        // Should verify successfully
        assert!(update.verify_admin_signature(&admin_public).is_ok());
    }
}
