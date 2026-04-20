/// Epoch state structures with comprehensive lifecycle management
///
/// Provides data structures for tracking epoch state including cryptographic keys,
/// member rosters, and metadata throughout the epoch lifecycle with extensive
/// validation, querying capabilities, and lifecycle management.
use chrono::{DateTime, Utc};
use hybridcipher_crypto::signatures::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

use crate::epoch_key_source::EpochKeySource;

/// Comprehensive epoch state with cryptographic keys, roster, and metadata
///
/// EpochState tracks all information necessary for epoch operation including:
/// - Cryptographic material for file encryption/decryption
/// - Group member roster with identity verification
/// - Epoch lifecycle status and metadata
/// - Creation timestamps and change tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochState {
    /// Unique epoch identifier
    pub epoch_id: u64,

    /// Epoch-specific encryption key derived from group state
    pub encryption_key: [u8; 32],

    /// Provenance for the epoch key material.
    #[serde(default)]
    pub key_source: EpochKeySource,

    /// Group members participating in this epoch
    pub members: HashMap<Vec<u8>, Member>,

    /// Current epoch lifecycle status
    pub status: EpochStatus,

    /// Epoch creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,

    /// Files currently encrypted under this epoch
    pub file_count: u64,

    /// Epoch metadata for additional information
    pub metadata: EpochMetadata,
}

/// Group member with identity verification and status management
///
/// Member represents a participant in the group with full identity information
/// and status tracking for migration coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// Member's unique identifier (public key)
    pub member_id: Vec<u8>,

    /// Member's Ed25519 public signing key
    pub public_key: Vec<u8>,

    /// Current member status in the group
    pub status: MemberStatus,

    /// Member capabilities and permissions
    pub capabilities: MemberCapabilities,

    /// When this member joined the group
    pub joined_at: DateTime<Utc>,

    /// When member status was last updated
    pub updated_at: DateTime<Utc>,
}

/// Member status supporting Active, PendingMigration, and Removed states
///
/// MemberStatus tracks the current state of a member throughout their
/// lifecycle in the group, especially during migration operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemberStatus {
    /// Member is active and participating normally
    Active,

    /// Member is in the process of migrating to new epoch
    PendingMigration {
        /// Target epoch for migration
        target_epoch: u64,
        /// Migration start timestamp
        started_at: DateTime<Utc>,
    },

    /// Member has been removed from the group
    Removed {
        /// Removal timestamp
        removed_at: DateTime<Utc>,
        /// Reason for removal
        reason: String,
    },
}

/// Member capabilities and permissions within the group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberCapabilities {
    /// Can read files from the group
    pub can_read: bool,

    /// Can write/modify files in the group
    pub can_write: bool,

    /// Can invite new members to the group
    pub can_invite: bool,

    /// Can initiate epoch transitions (rekey operations)
    pub can_rekey: bool,

    /// Can remove other members from the group
    pub can_remove: bool,

    /// Can perform administrative operations
    pub can_admin: bool,
}

/// Epoch lifecycle status tracking
///
/// EpochStatus represents the current phase of an epoch's lifecycle,
/// enabling proper state management during migrations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EpochStatus {
    /// Epoch is being initialized
    Initializing {
        /// Initialization start time
        started_at: DateTime<Utc>,
    },

    /// Epoch is active for normal operations
    Active {
        /// Activation timestamp
        activated_at: DateTime<Utc>,
    },

    /// Epoch is in migration phase (dual-epoch state)
    Migrating {
        /// Target epoch for migration
        target_epoch: u64,
        /// Migration start timestamp
        started_at: DateTime<Utc>,
    },

    /// Epoch is pending cutover to new epoch
    PendingCutover {
        /// Target epoch for cutover
        target_epoch: u64,
        /// Cutover initiation timestamp
        initiated_at: DateTime<Utc>,
    },

    /// Epoch has been deprecated and is read-only
    Deprecated {
        /// Deprecation timestamp
        deprecated_at: DateTime<Utc>,
        /// Successor epoch
        successor_epoch: u64,
    },

    /// Epoch has been securely deleted
    Deleted {
        /// Deletion timestamp
        deleted_at: DateTime<Utc>,
    },
}

/// Epoch lifecycle phases for high-level state categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EpochLifecyclePhase {
    /// Epoch creation and initialization
    Creation,
    /// Normal active operation
    Active,
    /// Migration and transition phases
    Migration,
    /// Deprecation and deletion phases
    Deletion,
}

/// Member capability types for granular permission checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberCapability {
    Read,
    Write,
    Invite,
    Rekey,
    Remove,
    Admin,
}

/// Epoch metadata for additional tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochMetadata {
    /// Human-readable description
    pub description: Option<String>,

    /// Custom tags for organization
    pub tags: HashMap<String, String>,

    /// Version for compatibility tracking
    pub version: u32,

    /// Administrative notes
    pub notes: Vec<String>,
}

impl Default for MemberCapabilities {
    fn default() -> Self {
        Self {
            can_read: true,
            can_write: false,
            can_invite: false,
            can_rekey: false,
            can_remove: false,
            can_admin: false,
        }
    }
}

impl Default for EpochMetadata {
    fn default() -> Self {
        Self {
            description: None,
            tags: HashMap::new(),
            version: 1,
            notes: Vec::new(),
        }
    }
}

impl EpochState {
    /// Create new epoch state with secure defaults
    pub fn new(epoch_id: u64, encryption_key: [u8; 32]) -> Self {
        let now = Utc::now();
        Self {
            epoch_id,
            encryption_key,
            key_source: EpochKeySource::LocalInit,
            members: HashMap::new(),
            status: EpochStatus::Initializing { started_at: now },
            created_at: now,
            updated_at: now,
            file_count: 0,
            metadata: EpochMetadata::default(),
        }
    }

    /// Add member to epoch
    pub fn add_member(&mut self, member: Member) -> Result<(), EpochError> {
        let member_id = member.member_id.clone();
        self.members.insert(member_id, member);
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Remove member from epoch
    pub fn remove_member(&mut self, member_id: &[u8], reason: String) -> Result<(), EpochError> {
        if let Some(member) = self.members.get_mut(member_id) {
            member.status = MemberStatus::Removed {
                removed_at: Utc::now(),
                reason,
            };
            self.updated_at = Utc::now();
            Ok(())
        } else {
            Err(EpochError::MemberNotFound)
        }
    }

    /// Update epoch status
    pub fn update_status(&mut self, status: EpochStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    /// Check if epoch is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, EpochStatus::Active { .. })
    }

    /// Check if epoch is migrating
    pub fn is_migrating(&self) -> bool {
        matches!(self.status, EpochStatus::Migrating { .. })
    }

    /// Get active member count
    pub fn active_member_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.status == MemberStatus::Active)
            .count()
    }

    /// **PHASE 2B COMMIT 30 ENHANCEMENTS** ///

    /// Activate epoch with validation
    pub fn activate(&mut self) -> Result<(), EpochError> {
        match &self.status {
            EpochStatus::Initializing { .. } => {
                if self.members.is_empty() {
                    return Err(EpochError::ValidationFailed(
                        "Cannot activate epoch with no members".to_string(),
                    ));
                }

                self.status = EpochStatus::Active {
                    activated_at: Utc::now(),
                };
                self.updated_at = Utc::now();
                Ok(())
            }
            _ => Err(EpochError::InvalidState(format!(
                "Cannot activate epoch in state: {:?}",
                self.status
            ))),
        }
    }

    /// Start migration to new epoch with validation
    pub fn start_migration(&mut self, target_epoch: u64) -> Result<(), EpochError> {
        match &self.status {
            EpochStatus::Active { .. } => {
                if target_epoch <= self.epoch_id {
                    return Err(EpochError::ValidationFailed(
                        "Target epoch must be greater than current epoch".to_string(),
                    ));
                }

                self.status = EpochStatus::Migrating {
                    target_epoch,
                    started_at: Utc::now(),
                };
                self.updated_at = Utc::now();
                Ok(())
            }
            _ => Err(EpochError::InvalidState(format!(
                "Cannot start migration from state: {:?}",
                self.status
            ))),
        }
    }

    /// Initiate cutover to new epoch
    pub fn initiate_cutover(&mut self, target_epoch: u64) -> Result<(), EpochError> {
        match &self.status {
            EpochStatus::Migrating {
                target_epoch: current_target,
                ..
            } => {
                if target_epoch != *current_target {
                    return Err(EpochError::ValidationFailed(
                        "Cutover target epoch does not match migration target".to_string(),
                    ));
                }

                self.status = EpochStatus::PendingCutover {
                    target_epoch,
                    initiated_at: Utc::now(),
                };
                self.updated_at = Utc::now();
                Ok(())
            }
            _ => Err(EpochError::InvalidState(format!(
                "Cannot initiate cutover from state: {:?}",
                self.status
            ))),
        }
    }

    /// Deprecate epoch (mark as read-only)
    pub fn deprecate(&mut self, successor_epoch: u64) -> Result<(), EpochError> {
        match &self.status {
            EpochStatus::PendingCutover { target_epoch, .. } => {
                if successor_epoch != *target_epoch {
                    return Err(EpochError::ValidationFailed(
                        "Successor epoch does not match cutover target".to_string(),
                    ));
                }

                self.status = EpochStatus::Deprecated {
                    deprecated_at: Utc::now(),
                    successor_epoch,
                };
                self.updated_at = Utc::now();
                Ok(())
            }
            _ => Err(EpochError::InvalidState(format!(
                "Cannot deprecate epoch from state: {:?}",
                self.status
            ))),
        }
    }

    /// Securely delete epoch
    pub fn delete(&mut self) -> Result<(), EpochError> {
        match &self.status {
            EpochStatus::Deprecated { .. } => {
                // Zero out encryption key
                self.encryption_key = [0u8; 32];

                self.status = EpochStatus::Deleted {
                    deleted_at: Utc::now(),
                };
                self.updated_at = Utc::now();
                Ok(())
            }
            _ => Err(EpochError::InvalidState(format!(
                "Cannot delete epoch from state: {:?}",
                self.status
            ))),
        }
    }

    /// Validate epoch state consistency
    pub fn validate(&self) -> Result<(), EpochError> {
        // Check epoch ID is valid
        if self.epoch_id == 0 {
            return Err(EpochError::ValidationFailed(
                "Epoch ID cannot be zero".to_string(),
            ));
        }

        // Check encryption key is not all zeros (unless deleted)
        if !matches!(self.status, EpochStatus::Deleted { .. }) {
            if self.encryption_key == [0u8; 32] {
                return Err(EpochError::ValidationFailed(
                    "Encryption key cannot be all zeros".to_string(),
                ));
            }
        }

        // Validate timestamps
        if self.updated_at < self.created_at {
            return Err(EpochError::ValidationFailed(
                "Updated timestamp cannot be before creation timestamp".to_string(),
            ));
        }

        // Validate member consistency
        for member in self.members.values() {
            member.validate()?;
        }

        // Validate status-specific constraints
        match &self.status {
            EpochStatus::Migrating { target_epoch, .. } => {
                if *target_epoch <= self.epoch_id {
                    return Err(EpochError::ValidationFailed(
                        "Migration target epoch must be greater than current epoch".to_string(),
                    ));
                }
            }
            EpochStatus::PendingCutover { target_epoch, .. } => {
                if *target_epoch <= self.epoch_id {
                    return Err(EpochError::ValidationFailed(
                        "Cutover target epoch must be greater than current epoch".to_string(),
                    ));
                }
            }
            EpochStatus::Deprecated {
                successor_epoch, ..
            } => {
                if *successor_epoch <= self.epoch_id {
                    return Err(EpochError::ValidationFailed(
                        "Successor epoch must be greater than current epoch".to_string(),
                    ));
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Get cryptographic hash of epoch state for integrity verification
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash epoch ID
        hasher.update(self.epoch_id.to_le_bytes());

        // Hash encryption key (unless deleted)
        if !matches!(self.status, EpochStatus::Deleted { .. }) {
            hasher.update(&self.encryption_key);
        }

        // Hash member data
        let mut member_ids: Vec<_> = self.members.keys().collect();
        member_ids.sort();
        for member_id in member_ids {
            if let Some(member) = self.members.get(member_id) {
                hasher.update(member_id);
                hasher.update(&member.public_key);
                hasher.update(&serde_json::to_vec(&member.status).unwrap_or_default());
            }
        }

        // Hash status
        hasher.update(&serde_json::to_vec(&self.status).unwrap_or_default());

        hasher.finalize().into()
    }

    /// Check if epoch can be safely accessed for reading
    pub fn can_read(&self) -> bool {
        match &self.status {
            EpochStatus::Active { .. }
            | EpochStatus::Migrating { .. }
            | EpochStatus::PendingCutover { .. }
            | EpochStatus::Deprecated { .. } => true,
            EpochStatus::Initializing { .. } | EpochStatus::Deleted { .. } => false,
        }
    }

    /// Check if epoch can be safely accessed for writing
    pub fn can_write(&self) -> bool {
        match &self.status {
            EpochStatus::Active { .. } => true,
            _ => false,
        }
    }

    /// Get epoch lifecycle phase
    pub fn lifecycle_phase(&self) -> EpochLifecyclePhase {
        match &self.status {
            EpochStatus::Initializing { .. } => EpochLifecyclePhase::Creation,
            EpochStatus::Active { .. } => EpochLifecyclePhase::Active,
            EpochStatus::Migrating { .. } | EpochStatus::PendingCutover { .. } => {
                EpochLifecyclePhase::Migration
            }
            EpochStatus::Deprecated { .. } | EpochStatus::Deleted { .. } => {
                EpochLifecyclePhase::Deletion
            }
        }
    }

    /// Filter members by status
    pub fn filter_members_by_status(&self, status: MemberStatus) -> Vec<&Member> {
        self.members
            .values()
            .filter(|m| m.status == status)
            .collect()
    }

    /// Get members with specific capabilities
    pub fn get_members_with_capability(&self, capability: MemberCapability) -> Vec<&Member> {
        self.members
            .values()
            .filter(|m| m.has_capability(capability))
            .collect()
    }

    /// Get epoch age in seconds
    pub fn age_seconds(&self) -> i64 {
        (Utc::now() - self.created_at).num_seconds()
    }

    /// Check if epoch is stale (based on configurable threshold)
    pub fn is_stale(&self, threshold_seconds: i64) -> bool {
        self.age_seconds() > threshold_seconds
    }
}

impl Member {
    /// Create new member with secure defaults
    pub fn new(member_id: Vec<u8>, public_key: Vec<u8>, capabilities: MemberCapabilities) -> Self {
        let now = Utc::now();
        Self {
            member_id,
            public_key,
            status: MemberStatus::Active,
            capabilities,
            joined_at: now,
            updated_at: now,
        }
    }

    /// Check if member is active
    pub fn is_active(&self) -> bool {
        self.status == MemberStatus::Active
    }

    /// Update member status
    pub fn update_status(&mut self, status: MemberStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    /// **PHASE 2B COMMIT 30 ENHANCEMENTS** ///

    /// Validate member state consistency
    pub fn validate(&self) -> Result<(), EpochError> {
        // Check member ID is not empty
        if self.member_id.is_empty() {
            return Err(EpochError::ValidationFailed(
                "Member ID cannot be empty".to_string(),
            ));
        }

        // Check public key is not empty
        if self.public_key.is_empty() {
            return Err(EpochError::ValidationFailed(
                "Public key cannot be empty".to_string(),
            ));
        }

        // Validate public key format (should be 32 bytes for Ed25519)
        if self.public_key.len() != 32 {
            return Err(EpochError::ValidationFailed(
                "Public key must be 32 bytes for Ed25519".to_string(),
            ));
        }

        // Validate timestamps
        if self.updated_at < self.joined_at {
            return Err(EpochError::ValidationFailed(
                "Updated timestamp cannot be before join timestamp".to_string(),
            ));
        }

        // Validate status-specific constraints
        match &self.status {
            MemberStatus::PendingMigration {
                target_epoch,
                started_at,
            } => {
                if *target_epoch == 0 {
                    return Err(EpochError::ValidationFailed(
                        "Migration target epoch cannot be zero".to_string(),
                    ));
                }
                if *started_at > Utc::now() {
                    return Err(EpochError::ValidationFailed(
                        "Migration start time cannot be in the future".to_string(),
                    ));
                }
            }
            MemberStatus::Removed { removed_at, reason } => {
                if reason.is_empty() {
                    return Err(EpochError::ValidationFailed(
                        "Removal reason cannot be empty".to_string(),
                    ));
                }
                if *removed_at > Utc::now() {
                    return Err(EpochError::ValidationFailed(
                        "Removal time cannot be in the future".to_string(),
                    ));
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Check if member has specific capability
    pub fn has_capability(&self, capability: MemberCapability) -> bool {
        match capability {
            MemberCapability::Read => self.capabilities.can_read,
            MemberCapability::Write => self.capabilities.can_write,
            MemberCapability::Invite => self.capabilities.can_invite,
            MemberCapability::Rekey => self.capabilities.can_rekey,
            MemberCapability::Remove => self.capabilities.can_remove,
            MemberCapability::Admin => self.capabilities.can_admin,
        }
    }

    /// Start migration for this member
    pub fn start_migration(&mut self, target_epoch: u64) -> Result<(), EpochError> {
        match &self.status {
            MemberStatus::Active => {
                self.status = MemberStatus::PendingMigration {
                    target_epoch,
                    started_at: Utc::now(),
                };
                self.updated_at = Utc::now();
                Ok(())
            }
            _ => Err(EpochError::InvalidState(format!(
                "Cannot start migration from status: {:?}",
                self.status
            ))),
        }
    }

    /// Complete migration for this member
    pub fn complete_migration(&mut self) -> Result<(), EpochError> {
        match &self.status {
            MemberStatus::PendingMigration { .. } => {
                self.status = MemberStatus::Active;
                self.updated_at = Utc::now();
                Ok(())
            }
            _ => Err(EpochError::InvalidState(format!(
                "Cannot complete migration from status: {:?}",
                self.status
            ))),
        }
    }

    /// Remove member from group
    pub fn remove(&mut self, reason: String) -> Result<(), EpochError> {
        if reason.is_empty() {
            return Err(EpochError::ValidationFailed(
                "Removal reason cannot be empty".to_string(),
            ));
        }

        self.status = MemberStatus::Removed {
            removed_at: Utc::now(),
            reason,
        };
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Get member's VerifyingKey for cryptographic operations
    pub fn verifying_key(&self) -> Result<VerifyingKey, EpochError> {
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|e| EpochError::ValidationFailed(format!("Invalid public key: {}", e)))
    }

    /// Compute member hash for integrity verification
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(&self.member_id);
        hasher.update(&self.public_key);
        hasher.update(&serde_json::to_vec(&self.status).unwrap_or_default());
        hasher.update(&serde_json::to_vec(&self.capabilities).unwrap_or_default());

        hasher.finalize().into()
    }

    /// Get member age in seconds
    pub fn age_seconds(&self) -> i64 {
        (Utc::now() - self.joined_at).num_seconds()
    }

    /// Check if member can perform operation on target member
    pub fn can_operate_on(&self, target: &Member, operation: MemberCapability) -> bool {
        // Member must be active and have the required capability
        if !self.is_active() || !self.has_capability(operation) {
            return false;
        }

        // Special rules for certain operations
        match operation {
            MemberCapability::Remove => {
                // Can't remove yourself, and target must not be admin unless you're admin
                self.member_id != target.member_id
                    && (self.has_capability(MemberCapability::Admin)
                        || !target.has_capability(MemberCapability::Admin))
            }
            MemberCapability::Admin => {
                // Only admins can perform admin operations on others
                self.has_capability(MemberCapability::Admin)
            }
            _ => true,
        }
    }
}

/// Comprehensive epoch state querying and filtering utilities
impl EpochState {
    /// Query epochs by lifecycle phase
    pub fn matches_lifecycle_phase(&self, phase: EpochLifecyclePhase) -> bool {
        self.lifecycle_phase() == phase
    }

    /// Query epochs by status
    pub fn matches_status(&self, status: &EpochStatus) -> bool {
        std::mem::discriminant(&self.status) == std::mem::discriminant(status)
    }

    /// Check if epoch is in transition (migrating or pending cutover)
    pub fn is_in_transition(&self) -> bool {
        matches!(
            self.status,
            EpochStatus::Migrating { .. } | EpochStatus::PendingCutover { .. }
        )
    }

    /// Get migration progress (0.0 to 1.0) based on member status
    pub fn migration_progress(&self) -> f64 {
        if !self.is_migrating() {
            return if self.is_active() { 0.0 } else { 1.0 };
        }

        let total_members = self.members.len();
        if total_members == 0 {
            return 1.0;
        }

        let migrated_members = self
            .members
            .values()
            .filter(|m| matches!(m.status, MemberStatus::Active))
            .count();

        migrated_members as f64 / total_members as f64
    }

    /// Get pending migration members
    pub fn get_pending_migration_members(&self) -> Vec<&Member> {
        self.members
            .values()
            .filter(|m| matches!(m.status, MemberStatus::PendingMigration { .. }))
            .collect()
    }

    /// Check if all members have completed migration
    pub fn all_members_migrated(&self) -> bool {
        self.members.values().all(|m| {
            m.status == MemberStatus::Active || matches!(m.status, MemberStatus::Removed { .. })
        })
    }

    /// Get active administrators
    pub fn get_admins(&self) -> Vec<&Member> {
        self.get_members_with_capability(MemberCapability::Admin)
            .into_iter()
            .filter(|m| m.is_active())
            .collect()
    }

    /// Check if member can join this epoch
    pub fn can_member_join(&self, _member_id: &[u8]) -> bool {
        match &self.status {
            EpochStatus::Initializing { .. } | EpochStatus::Active { .. } => true,
            _ => false,
        }
    }

    /// Estimate time to completion for migration
    pub fn estimate_migration_completion(&self) -> Option<DateTime<Utc>> {
        if let EpochStatus::Migrating { started_at, .. } = &self.status {
            let progress = self.migration_progress();
            if progress > 0.0 && progress < 1.0 {
                let elapsed = Utc::now() - *started_at;
                let estimated_total = elapsed.num_seconds() as f64 / progress;
                let remaining = estimated_total - elapsed.num_seconds() as f64;

                return Some(Utc::now() + chrono::Duration::seconds(remaining as i64));
            }
        }
        None
    }

    /// Get epoch summary for reporting
    pub fn summary(&self) -> EpochSummary {
        EpochSummary {
            epoch_id: self.epoch_id,
            status: self.status.clone(),
            lifecycle_phase: self.lifecycle_phase(),
            total_members: self.members.len(),
            active_members: self.active_member_count(),
            pending_migration_members: self.get_pending_migration_members().len(),
            file_count: self.file_count,
            created_at: self.created_at,
            updated_at: self.updated_at,
            age_seconds: self.age_seconds(),
            migration_progress: if self.is_migrating() {
                Some(self.migration_progress())
            } else {
                None
            },
            estimated_completion: self.estimate_migration_completion(),
            can_read: self.can_read(),
            can_write: self.can_write(),
        }
    }
}

/// Epoch summary for efficient reporting and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSummary {
    pub epoch_id: u64,
    pub status: EpochStatus,
    pub lifecycle_phase: EpochLifecyclePhase,
    pub total_members: usize,
    pub active_members: usize,
    pub pending_migration_members: usize,
    pub file_count: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub age_seconds: i64,
    pub migration_progress: Option<f64>,
    pub estimated_completion: Option<DateTime<Utc>>,
    pub can_read: bool,
    pub can_write: bool,
}

/// Multi-epoch query and filtering utilities
pub struct EpochQuery {
    /// Filter by lifecycle phases
    pub phases: Option<HashSet<EpochLifecyclePhase>>,
    /// Filter by minimum age in seconds
    pub min_age_seconds: Option<i64>,
    /// Filter by maximum age in seconds
    pub max_age_seconds: Option<i64>,
    /// Filter by member count range
    pub member_count_range: Option<(usize, usize)>,
    /// Filter by capability requirements
    pub required_capabilities: Option<HashSet<MemberCapability>>,
    /// Filter by read/write access
    pub readable: Option<bool>,
    pub writable: Option<bool>,
}

impl EpochQuery {
    /// Create new empty query
    pub fn new() -> Self {
        Self {
            phases: None,
            min_age_seconds: None,
            max_age_seconds: None,
            member_count_range: None,
            required_capabilities: None,
            readable: None,
            writable: None,
        }
    }

    /// Filter by lifecycle phases
    pub fn with_phases(mut self, phases: HashSet<EpochLifecyclePhase>) -> Self {
        self.phases = Some(phases);
        self
    }

    /// Filter by age range
    pub fn with_age_range(mut self, min_seconds: Option<i64>, max_seconds: Option<i64>) -> Self {
        self.min_age_seconds = min_seconds;
        self.max_age_seconds = max_seconds;
        self
    }

    /// Filter by member count range
    pub fn with_member_count_range(mut self, min: usize, max: usize) -> Self {
        self.member_count_range = Some((min, max));
        self
    }

    /// Filter by access permissions
    pub fn with_access(mut self, readable: Option<bool>, writable: Option<bool>) -> Self {
        self.readable = readable;
        self.writable = writable;
        self
    }

    /// Check if epoch matches this query
    pub fn matches(&self, epoch: &EpochState) -> bool {
        // Check lifecycle phase
        if let Some(phases) = &self.phases {
            if !phases.contains(&epoch.lifecycle_phase()) {
                return false;
            }
        }

        // Check age constraints
        let age = epoch.age_seconds();
        if let Some(min_age) = self.min_age_seconds {
            if age < min_age {
                return false;
            }
        }
        if let Some(max_age) = self.max_age_seconds {
            if age > max_age {
                return false;
            }
        }

        // Check member count
        if let Some((min_count, max_count)) = self.member_count_range {
            let count = epoch.members.len();
            if count < min_count || count > max_count {
                return false;
            }
        }

        // Check access permissions
        if let Some(readable) = self.readable {
            if epoch.can_read() != readable {
                return false;
            }
        }
        if let Some(writable) = self.writable {
            if epoch.can_write() != writable {
                return false;
            }
        }

        true
    }
}

/// Epoch management errors
#[derive(Debug, Error)]
pub enum EpochError {
    #[error("Member not found")]
    MemberNotFound,

    #[error("Invalid epoch state: {0}")]
    InvalidState(String),

    #[error("Epoch access denied: {0}")]
    AccessDenied(String),

    #[error("Epoch validation failed: {0}")]
    ValidationFailed(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Comprehensive epoch state serialization with version compatibility
pub mod serialization {
    use super::*;
    use ciborium;
    use serde_json;

    /// Versioned epoch state wrapper for backward compatibility
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VersionedEpochState {
        /// Serialization format version
        pub version: u32,
        /// Epoch state data
        pub epoch: EpochState,
        /// Serialization timestamp
        pub serialized_at: DateTime<Utc>,
        /// Compatibility metadata
        pub metadata: SerializationMetadata,
    }

    /// Serialization metadata for compatibility tracking
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SerializationMetadata {
        /// Minimum supported version for deserialization
        pub min_supported_version: u32,
        /// Features used in this serialization
        pub features: HashSet<String>,
        /// Checksum for integrity verification
        pub checksum: [u8; 32],
    }

    /// Current serialization format version
    pub const CURRENT_VERSION: u32 = 1;

    /// Minimum supported version for backward compatibility
    pub const MIN_SUPPORTED_VERSION: u32 = 1;

    impl VersionedEpochState {
        /// Create new versioned epoch state
        pub fn new(epoch: EpochState) -> Result<Self, EpochError> {
            let serialized_at = Utc::now();
            let features = Self::detect_features(&epoch);
            let checksum = epoch.compute_hash();

            let metadata = SerializationMetadata {
                min_supported_version: MIN_SUPPORTED_VERSION,
                features,
                checksum,
            };

            Ok(Self {
                version: CURRENT_VERSION,
                epoch,
                serialized_at,
                metadata,
            })
        }

        /// Detect features used in epoch state
        fn detect_features(epoch: &EpochState) -> HashSet<String> {
            let mut features = HashSet::new();

            // Check if epoch uses advanced status types
            match &epoch.status {
                EpochStatus::Migrating { .. } => {
                    features.insert("migration".to_string());
                }
                EpochStatus::PendingCutover { .. } => {
                    features.insert("cutover".to_string());
                }
                EpochStatus::Deprecated { .. } => {
                    features.insert("deprecation".to_string());
                }
                EpochStatus::Deleted { .. } => {
                    features.insert("deletion".to_string());
                }
                _ => {}
            }

            // Check for advanced member features
            for member in epoch.members.values() {
                match &member.status {
                    MemberStatus::PendingMigration { .. } => {
                        features.insert("member_migration".to_string());
                    }
                    MemberStatus::Removed { .. } => {
                        features.insert("member_removal".to_string());
                    }
                    _ => {}
                }

                // Check capabilities
                if member.capabilities.can_admin {
                    features.insert("admin_capabilities".to_string());
                }
            }

            // Check for metadata features
            if !epoch.metadata.tags.is_empty() {
                features.insert("metadata_tags".to_string());
            }
            if !epoch.metadata.notes.is_empty() {
                features.insert("metadata_notes".to_string());
            }

            features
        }

        /// Validate versioned epoch state
        pub fn validate(&self) -> Result<(), EpochError> {
            // Check version compatibility
            if self.version < MIN_SUPPORTED_VERSION {
                return Err(EpochError::Serialization(format!(
                    "Unsupported version: {}",
                    self.version
                )));
            }

            // Validate checksum
            let current_checksum = self.epoch.compute_hash();
            if current_checksum != self.metadata.checksum {
                return Err(EpochError::Serialization(
                    "Checksum mismatch - data may be corrupted".to_string(),
                ));
            }

            // Validate epoch state
            self.epoch.validate()?;

            Ok(())
        }

        /// Serialize to CBOR bytes
        pub fn to_cbor(&self) -> Result<Vec<u8>, EpochError> {
            let mut buffer = Vec::new();
            ciborium::ser::into_writer(self, &mut buffer).map_err(|e| {
                EpochError::Serialization(format!("CBOR serialization failed: {}", e))
            })?;
            Ok(buffer)
        }

        /// Deserialize from CBOR bytes with validation
        pub fn from_cbor(data: &[u8]) -> Result<Self, EpochError> {
            let versioned: Self = ciborium::de::from_reader(data).map_err(|e| {
                EpochError::Serialization(format!("CBOR deserialization failed: {}", e))
            })?;

            versioned.validate()?;
            Ok(versioned)
        }

        /// Serialize to JSON for debugging/export
        pub fn to_json(&self) -> Result<String, EpochError> {
            serde_json::to_string_pretty(self)
                .map_err(|e| EpochError::Serialization(format!("JSON serialization failed: {}", e)))
        }

        /// Deserialize from JSON with validation
        pub fn from_json(json: &str) -> Result<Self, EpochError> {
            let versioned: Self = serde_json::from_str(json).map_err(|e| {
                EpochError::Serialization(format!("JSON deserialization failed: {}", e))
            })?;

            versioned.validate()?;
            Ok(versioned)
        }

        /// Migrate to newer version if needed
        pub fn migrate_if_needed(mut self) -> Result<Self, EpochError> {
            if self.version < CURRENT_VERSION {
                // Perform migration steps here
                // For now, just update version since we only have version 1
                self.version = CURRENT_VERSION;
                self.metadata.min_supported_version = MIN_SUPPORTED_VERSION;
                self.serialized_at = Utc::now();

                // Recalculate features and checksum
                self.metadata.features = Self::detect_features(&self.epoch);
                self.metadata.checksum = self.epoch.compute_hash();
            }
            Ok(self)
        }

        /// Get epoch state (consuming the wrapper)
        pub fn into_epoch(self) -> EpochState {
            self.epoch
        }

        /// Get epoch state reference
        pub fn epoch(&self) -> &EpochState {
            &self.epoch
        }
    }

    impl Default for SerializationMetadata {
        fn default() -> Self {
            Self {
                min_supported_version: MIN_SUPPORTED_VERSION,
                features: HashSet::new(),
                checksum: [0u8; 32],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_state_creation() {
        let epoch_id = 42;
        let key = [1u8; 32];
        let epoch = EpochState::new(epoch_id, key);

        assert_eq!(epoch.epoch_id, epoch_id);
        assert_eq!(epoch.encryption_key, key);
        assert!(epoch.members.is_empty());
        assert!(matches!(epoch.status, EpochStatus::Initializing { .. }));
        assert_eq!(epoch.file_count, 0);
    }

    #[test]
    fn test_member_management() {
        let mut epoch = EpochState::new(1, [0u8; 32]);

        let member = Member::new(vec![1, 2, 3], vec![4, 5, 6], MemberCapabilities::default());

        // Add member
        epoch.add_member(member).unwrap();
        assert_eq!(epoch.active_member_count(), 1);

        // Remove member
        epoch
            .remove_member(&[1, 2, 3], "Test removal".to_string())
            .unwrap();
        assert_eq!(epoch.active_member_count(), 0);
    }

    #[test]
    fn test_epoch_status_transitions() {
        let mut epoch = EpochState::new(1, [0u8; 32]);

        // Initially initializing
        assert!(matches!(epoch.status, EpochStatus::Initializing { .. }));

        // Activate epoch
        epoch.update_status(EpochStatus::Active {
            activated_at: Utc::now(),
        });
        assert!(epoch.is_active());

        // Start migration
        epoch.update_status(EpochStatus::Migrating {
            target_epoch: 2,
            started_at: Utc::now(),
        });
        assert!(epoch.is_migrating());
    }

    #[test]
    fn test_member_capabilities() {
        let caps = MemberCapabilities::default();
        assert!(caps.can_read);
        assert!(!caps.can_write);
        assert!(!caps.can_invite);
        assert!(!caps.can_rekey);
        assert!(!caps.can_remove);
        assert!(!caps.can_admin);
    }

    /// **PHASE 2B COMMIT 30 TEST ENHANCEMENTS** ///

    #[test]
    fn test_epoch_lifecycle_management() {
        let mut epoch = EpochState::new(1, [1u8; 32]);

        // Add a member so we can activate
        let member = Member::new(vec![1], vec![2; 32], MemberCapabilities::default());
        epoch.add_member(member).unwrap();

        // Test activation
        epoch.activate().unwrap();
        assert!(epoch.is_active());
        assert_eq!(epoch.lifecycle_phase(), EpochLifecyclePhase::Active);

        // Test migration start
        epoch.start_migration(2).unwrap();
        assert!(epoch.is_migrating());
        assert_eq!(epoch.lifecycle_phase(), EpochLifecyclePhase::Migration);

        // Test cutover initiation
        epoch.initiate_cutover(2).unwrap();
        assert!(epoch.is_in_transition());

        // Test deprecation
        epoch.deprecate(2).unwrap();
        assert_eq!(epoch.lifecycle_phase(), EpochLifecyclePhase::Deletion);

        // Test deletion
        epoch.delete().unwrap();
        assert_eq!(epoch.encryption_key, [0u8; 32]);
    }

    #[test]
    fn test_epoch_validation() {
        let mut epoch = EpochState::new(0, [0u8; 32]); // Invalid ID and key

        // Should fail validation
        assert!(epoch.validate().is_err());

        // Fix and test again
        epoch.epoch_id = 1;
        epoch.encryption_key = [1u8; 32];
        assert!(epoch.validate().is_ok());
    }

    #[test]
    fn test_member_validation_and_capabilities() {
        let mut member = Member::new(
            vec![1, 2, 3],
            vec![4; 32], // Valid 32-byte key
            MemberCapabilities {
                can_read: true,
                can_admin: true,
                ..Default::default()
            },
        );

        // Should pass validation
        assert!(member.validate().is_ok());

        // Test capabilities
        assert!(member.has_capability(MemberCapability::Read));
        assert!(member.has_capability(MemberCapability::Admin));
        assert!(!member.has_capability(MemberCapability::Write));

        // Test migration
        member.start_migration(2).unwrap();
        assert!(matches!(
            member.status,
            MemberStatus::PendingMigration { .. }
        ));

        member.complete_migration().unwrap();
        assert_eq!(member.status, MemberStatus::Active);
    }

    #[test]
    fn test_epoch_querying() {
        let mut epoch = EpochState::new(1, [1u8; 32]);
        let member1 = Member::new(vec![1], vec![2; 32], MemberCapabilities::default());
        let member2 = Member::new(
            vec![2],
            vec![3; 32],
            MemberCapabilities {
                can_admin: true,
                ..Default::default()
            },
        );

        epoch.add_member(member1).unwrap();
        epoch.add_member(member2).unwrap();
        epoch.activate().unwrap();

        // Test queries
        assert_eq!(epoch.active_member_count(), 2);
        assert_eq!(epoch.get_admins().len(), 1);
        assert!(epoch.can_read());
        assert!(epoch.can_write());

        // Test migration progress
        epoch.start_migration(2).unwrap();
        let progress = epoch.migration_progress();
        assert!(progress >= 0.0 && progress <= 1.0);
    }

    #[test]
    fn test_epoch_query_filtering() {
        let epoch = EpochState::new(1, [1u8; 32]);

        let query = EpochQuery::new()
            .with_phases({
                let mut phases = HashSet::new();
                phases.insert(EpochLifecyclePhase::Creation);
                phases
            })
            .with_access(Some(false), Some(false)); // Not readable/writable

        assert!(query.matches(&epoch));

        let query2 = EpochQuery::new().with_access(Some(true), None); // Must be readable

        assert!(!query2.matches(&epoch)); // Initializing epoch is not readable
    }

    #[test]
    fn test_epoch_hash_computation() {
        let mut epoch1 = EpochState::new(1, [1u8; 32]);
        let mut epoch2 = EpochState::new(1, [1u8; 32]);
        let mut epoch3 = EpochState::new(2, [1u8; 32]);

        let fixed_time = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();

        // Fix all timestamps including the ones inside status
        epoch1.created_at = fixed_time;
        epoch1.updated_at = fixed_time;
        epoch1.status = EpochStatus::Initializing {
            started_at: fixed_time,
        };

        epoch2.created_at = fixed_time;
        epoch2.updated_at = fixed_time;
        epoch2.status = EpochStatus::Initializing {
            started_at: fixed_time,
        };

        epoch3.created_at = fixed_time;
        epoch3.updated_at = fixed_time;
        epoch3.status = EpochStatus::Initializing {
            started_at: fixed_time,
        };

        // Same epochs should have same hash
        assert_eq!(epoch1.compute_hash(), epoch2.compute_hash());

        // Different epochs should have different hashes
        assert_ne!(epoch1.compute_hash(), epoch3.compute_hash());
    }

    #[test]
    fn test_versioned_serialization() {
        use super::serialization::*;

        let epoch = EpochState::new(1, [1u8; 32]);
        let versioned = VersionedEpochState::new(epoch).unwrap();

        // Test CBOR serialization
        let cbor_data = versioned.to_cbor().unwrap();
        let deserialized = VersionedEpochState::from_cbor(&cbor_data).unwrap();
        assert_eq!(deserialized.epoch.epoch_id, 1);

        // Test JSON serialization
        let json_data = versioned.to_json().unwrap();
        let deserialized_json = VersionedEpochState::from_json(&json_data).unwrap();
        assert_eq!(deserialized_json.epoch.epoch_id, 1);

        // Test validation
        assert!(deserialized.validate().is_ok());
    }

    #[test]
    fn test_member_operation_permissions() {
        let admin = Member::new(
            vec![1],
            vec![2; 32],
            MemberCapabilities {
                can_admin: true,
                can_remove: true,
                ..Default::default()
            },
        );

        let regular_member = Member::new(vec![2], vec![3; 32], MemberCapabilities::default());

        // Admin can remove regular member
        assert!(admin.can_operate_on(&regular_member, MemberCapability::Remove));

        // Regular member cannot remove admin
        assert!(!regular_member.can_operate_on(&admin, MemberCapability::Remove));

        // Members cannot remove themselves
        assert!(!admin.can_operate_on(&admin, MemberCapability::Remove));
    }

    #[test]
    fn test_epoch_age_and_staleness() {
        let epoch = EpochState::new(1, [1u8; 32]);

        // Should be very young
        assert!(epoch.age_seconds() >= 0);
        assert!(epoch.age_seconds() < 10); // Should be created within last 10 seconds

        // Should not be stale with reasonable threshold
        assert!(!epoch.is_stale(3600)); // 1 hour threshold
        assert!(!epoch.is_stale(0)); // Newly created epoch should not be stale even with zero threshold

        // Simulate an older epoch and verify staleness detection
        let mut old_epoch = epoch.clone();
        old_epoch.created_at = (old_epoch.created_at - chrono::Duration::hours(2)).into();
        assert!(old_epoch.is_stale(3600));
    }

    #[test]
    fn test_epoch_summary() {
        let mut epoch = EpochState::new(1, [1u8; 32]);
        let member = Member::new(vec![1], vec![2; 32], MemberCapabilities::default());
        epoch.add_member(member).unwrap();
        epoch.activate().unwrap();

        let summary = epoch.summary();
        assert_eq!(summary.epoch_id, 1);
        assert_eq!(summary.total_members, 1);
        assert_eq!(summary.active_members, 1);
        assert_eq!(summary.lifecycle_phase, EpochLifecyclePhase::Active);
        assert!(summary.can_read);
        assert!(summary.can_write);
    }
}
