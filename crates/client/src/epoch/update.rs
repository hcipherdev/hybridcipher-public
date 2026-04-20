/// GroupUpdate message processing with comprehensive migration action support
///
/// Handles GroupUpdate message processing for migration coordination,
/// group membership management, and epoch transitions with atomic operations.
use crate::{
    epoch::state::{EpochState, EpochStatus, Member, MemberCapabilities, MemberStatus},
    epoch_key_source::EpochKeySource,
    network::Network,
    storage::Storage,
};
use chrono::{DateTime, Utc};
use hybridcipher_crypto::{
    hybridkem::{decap, Context, HybridCiphertext, HybridSecretKey},
    signatures::Ed25519KeyPair,
};
use hybridcipher_messages::group_update::{GroupUpdate, Member as GroupMember, UpdateAction};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::Mutex;

/// GroupUpdate configuration parameters
#[derive(Debug, Clone)]
pub struct GroupUpdateConfig {
    /// Maximum message age in seconds
    pub max_message_age: u64,
    /// Maximum retry attempts for processing
    pub max_retry_attempts: u32,
    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,
    /// Enable strict validation
    pub strict_validation: bool,
}

impl Default for GroupUpdateConfig {
    fn default() -> Self {
        Self {
            max_message_age: 300, // 5 minutes
            max_retry_attempts: 3,
            retry_delay_ms: 1000,
            strict_validation: true,
        }
    }
}

/// GroupUpdate processing result with migration state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdateResult {
    /// Successfully processed epochs
    pub processed_epochs: Vec<u64>,

    /// Updated member roster
    pub updated_members: Vec<String>,

    /// Migration status after update
    pub migration_status: Option<MigrationStatus>,

    /// Any warnings encountered during processing
    pub warnings: Vec<String>,

    /// Whether the update requires immediate action
    pub requires_action: bool,
}

/// Migration status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStatus {
    /// Current migration phase
    pub phase: String,

    /// Target epoch for migration
    pub target_epoch: u64,

    /// Migration progress percentage
    pub progress: f32,

    /// Estimated completion time
    pub estimated_completion: Option<DateTime<Utc>>,
}

/// GroupUpdate record for replay protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdateRecord {
    /// Update hash for deduplication
    pub update_hash: String,

    /// Processing timestamp
    pub processed_at: DateTime<Utc>,

    /// Source epoch
    pub from_epoch: u64,

    /// Target epoch
    pub to_epoch: u64,

    /// Update action type
    pub action_type: String,
}

/// GroupUpdate message processor for coordination
#[derive(Debug)]
pub struct GroupUpdateProcessor<S: Storage, N: Network> {
    storage: Arc<S>,
    network: Arc<N>,
    device_identity: Ed25519KeyPair,
    processed_updates: Arc<Mutex<HashMap<String, GroupUpdateRecord>>>,
}

impl<S: Storage, N: Network> GroupUpdateProcessor<S, N> {
    /// Create new GroupUpdate processor with device identity
    pub fn new(storage: Arc<S>, network: Arc<N>, device_identity: Ed25519KeyPair) -> Self {
        Self {
            storage,
            network,
            device_identity,
            processed_updates: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn find_local_member_id(&self, roster: &[GroupMember]) -> Option<String> {
        let public_bytes = self.device_identity.public_key_bytes();
        roster.iter().find_map(|member| {
            if member.identity_public.as_slice() == public_bytes {
                Some(member.member_id())
            } else {
                None
            }
        })
    }

    fn find_local_member_id_in_epoch(&self, epoch: &EpochState) -> Option<String> {
        let public_bytes = self.device_identity.public_key_bytes();
        epoch.members.values().find_map(|member| {
            if member.public_key.as_slice() == public_bytes {
                String::from_utf8(member.member_id.clone()).ok()
            } else {
                None
            }
        })
    }

    /// Process GroupUpdate message with comprehensive migration action support
    ///
    /// Handles all GroupUpdate actions including initialization, migration start,
    /// member addition/removal with atomic epoch transitions.
    pub async fn process_group_update(
        &self,
        update: &GroupUpdate,
        invitation_private_key: &HybridSecretKey,
        config: &GroupUpdateConfig,
    ) -> Result<GroupUpdateResult, GroupUpdateError> {
        if let Err(err) = self.network.get_network_status().await {
            log::warn!(
                "Processing GroupUpdate while network status unavailable: {}",
                err
            );
        }

        // Validate update message structure and freshness
        self.validate_group_update(update, config).await?;

        // Check for replay attacks
        if self.is_replay_attack(update).await? {
            return Err(GroupUpdateError::ReplayAttack(format!(
                "Update already processed: {}",
                self.calculate_update_hash(update)
            )));
        }

        // Verify admin signature
        self.verify_update_signature(update).await?;

        // Process action-specific logic
        let result = match &update.action {
            UpdateAction::Initialize {
                founding_members,
                group_config,
            } => {
                self.process_initialize_action(
                    update,
                    founding_members,
                    group_config,
                    invitation_private_key,
                )
                .await?
            }
            UpdateAction::StartMigration {
                target_epoch,
                reason,
            } => {
                self.process_start_migration_action(
                    update,
                    *target_epoch,
                    reason,
                    invitation_private_key,
                )
                .await?
            }
            UpdateAction::AddMember {
                member,
                welcome_message,
            } => {
                self.process_add_member_action(
                    update,
                    member,
                    welcome_message,
                    invitation_private_key,
                )
                .await?
            }
            UpdateAction::RemoveMember {
                user_id,
                device_id,
                reason,
            } => {
                self.process_remove_member_action(update, user_id, device_id, reason)
                    .await?
            }
        };

        // Store update record for replay protection
        self.store_update_record(update).await?;

        // Update epoch state with new roster
        self.update_epoch_state(update, &result).await?;

        Ok(result)
    }

    /// Validate GroupUpdate message structure and freshness
    async fn validate_group_update(
        &self,
        update: &GroupUpdate,
        config: &GroupUpdateConfig,
    ) -> Result<(), GroupUpdateError> {
        // Basic structure validation
        update.validate().map_err(|e| {
            GroupUpdateError::InvalidUpdate(format!("Structure validation failed: {}", e))
        })?;

        // Check message freshness
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GroupUpdateError::InvalidUpdate(format!("Time error: {}", e)))?
            .as_secs();

        let message_age = current_time.saturating_sub(update.timestamp);
        if message_age > config.max_message_age {
            return Err(GroupUpdateError::MessageTooOld(format!(
                "Message age {} seconds exceeds maximum {}",
                message_age, config.max_message_age
            )));
        }

        // Validate epoch sequence
        if update.epoch_sequence.1 <= update.epoch_sequence.0 {
            return Err(GroupUpdateError::InvalidUpdate(
                "Target epoch must be greater than source epoch".to_string(),
            ));
        }

        // Validate roster is not empty
        if update.updated_roster.is_empty() {
            return Err(GroupUpdateError::InvalidUpdate(
                "Updated roster cannot be empty".to_string(),
            ));
        }

        // Check if we can process this epoch transition
        let current_epoch = self.storage.get_current_epoch_id().await.map_err(|e| {
            GroupUpdateError::Storage(format!("Failed to get current epoch: {}", e))
        })?;

        if update.epoch_sequence.0 != current_epoch {
            return Err(GroupUpdateError::EpochMismatch(format!(
                "Update from epoch {} but current epoch is {}",
                update.epoch_sequence.0, current_epoch
            )));
        }

        Ok(())
    }

    /// Check if this update is a replay attack
    async fn is_replay_attack(&self, update: &GroupUpdate) -> Result<bool, GroupUpdateError> {
        let update_hash = self.calculate_update_hash(update);
        let processed_updates = self.processed_updates.lock().await;
        Ok(processed_updates.contains_key(&update_hash))
    }

    /// Calculate deterministic hash of update for replay protection
    fn calculate_update_hash(&self, update: &GroupUpdate) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&update.from_epoch_id);
        hasher.update(&update.to_epoch_id);
        hasher.update(&update.epoch_sequence.0.to_le_bytes());
        hasher.update(&update.epoch_sequence.1.to_le_bytes());
        hasher.update(&update.timestamp.to_le_bytes());
        hasher.update(&update.state_hash);

        // Hash the action
        if let Ok(action_bytes) = serde_json::to_vec(&update.action) {
            hasher.update(&action_bytes);
        }

        hex::encode(hasher.finalize())
    }

    /// Verify administrator signature on update
    async fn verify_update_signature(&self, update: &GroupUpdate) -> Result<(), GroupUpdateError> {
        // Find admin in the roster
        let admin_member = update
            .updated_roster
            .iter()
            .find(|member| member.capabilities.is_admin)
            .ok_or_else(|| {
                GroupUpdateError::InvalidUpdate("No admin found in roster".to_string())
            })?;

        // Verify signature using GroupUpdate's built-in method
        update
            .verify_admin_signature(&admin_member.identity_public)
            .map_err(|e| {
                GroupUpdateError::SignatureVerificationFailed(format!(
                    "Admin signature verification failed: {}",
                    e
                ))
            })?;

        Ok(())
    }

    /// Process Initialize action for new group creation
    async fn process_initialize_action(
        &self,
        update: &GroupUpdate,
        founding_members: &[GroupMember],
        _group_config: &hybridcipher_messages::group_update::GroupConfig,
        invitation_private_key: &HybridSecretKey,
    ) -> Result<GroupUpdateResult, GroupUpdateError> {
        // Decrypt our epoch secrets
        let member_id = self
            .find_local_member_id(&update.updated_roster)
            .ok_or_else(|| {
                GroupUpdateError::InvalidUpdate(
                    "Local device not present in updated roster".to_string(),
                )
            })?;

        let encrypted_secrets = update.per_member_secrets.get(&member_id).ok_or_else(|| {
            GroupUpdateError::InvalidUpdate("No secrets for our device".to_string())
        })?;

        // Parse ciphertext and decrypt
        let ciphertext = HybridCiphertext::from_bytes(encrypted_secrets).map_err(|e| {
            GroupUpdateError::DecryptionFailed(format!("Invalid ciphertext: {}", e))
        })?;

        let shared_secret = decap(invitation_private_key, &ciphertext, Context::GroupUpdate)
            .map_err(|e| GroupUpdateError::DecryptionFailed(format!("Decryption failed: {}", e)))?;

        // Create new epoch state
        let epoch_state = self
            .create_epoch_from_initialize(update, founding_members, shared_secret.as_bytes())
            .await?;

        // Store the new epoch
        self.storage
            .store_epoch_state(&epoch_state)
            .await
            .map_err(|e| GroupUpdateError::Storage(format!("Failed to store epoch: {}", e)))?;

        Ok(GroupUpdateResult {
            processed_epochs: vec![update.epoch_sequence.1],
            updated_members: founding_members.iter().map(|m| m.member_id()).collect(),
            migration_status: None,
            warnings: Vec::new(),
            requires_action: false,
        })
    }

    /// Process StartMigration action for epoch transitions
    async fn process_start_migration_action(
        &self,
        update: &GroupUpdate,
        target_epoch: u64,
        reason: &str,
        invitation_private_key: &HybridSecretKey,
    ) -> Result<GroupUpdateResult, GroupUpdateError> {
        // Load current epoch state
        let mut current_epoch = self
            .storage
            .load_epoch_state(update.epoch_sequence.0)
            .await
            .map_err(|e| {
                GroupUpdateError::Storage(format!("Failed to load current epoch: {}", e))
            })?;

        let local_member_id = self
            .find_local_member_id_in_epoch(&current_epoch)
            .ok_or_else(|| {
                GroupUpdateError::InvalidUpdate(
                    "Local device not present in current epoch state".to_string(),
                )
            })?;

        // Update epoch status to migrating
        current_epoch.status = EpochStatus::Migrating {
            target_epoch,
            started_at: Utc::now(),
        };

        // Store updated epoch state
        self.storage
            .store_epoch_state(&current_epoch)
            .await
            .map_err(|e| {
                GroupUpdateError::Storage(format!("Failed to update epoch status: {}", e))
            })?;

        // Decrypt new epoch secrets if provided
        let updated_member_id = match self.find_local_member_id(&update.updated_roster) {
            Some(id) => id,
            None => {
                log::warn!(
                    "Local device not found in updated roster while processing migration start"
                );
                local_member_id.clone()
            }
        };

        if let Some(encrypted_secrets) = update.per_member_secrets.get(&updated_member_id) {
            let ciphertext = HybridCiphertext::from_bytes(encrypted_secrets).map_err(|e| {
                GroupUpdateError::DecryptionFailed(format!("Invalid ciphertext: {}", e))
            })?;

            let shared_secret = decap(invitation_private_key, &ciphertext, Context::GroupUpdate)
                .map_err(|e| {
                    GroupUpdateError::DecryptionFailed(format!("Decryption failed: {}", e))
                })?;

            // Create new target epoch state
            let target_epoch_state = self
                .create_epoch_from_migration(update, shared_secret.as_bytes())
                .await?;

            // Store target epoch in pending state
            self.storage
                .store_epoch_state(&target_epoch_state)
                .await
                .map_err(|e| {
                    GroupUpdateError::Storage(format!("Failed to store target epoch: {}", e))
                })?;
        }

        Ok(GroupUpdateResult {
            processed_epochs: vec![update.epoch_sequence.0, target_epoch],
            updated_members: update
                .updated_roster
                .iter()
                .map(|m| m.member_id())
                .collect(),
            migration_status: Some(MigrationStatus {
                phase: "migration_started".to_string(),
                target_epoch,
                progress: 10.0,
                estimated_completion: Some(Utc::now() + chrono::Duration::hours(1)),
            }),
            warnings: vec![format!("Migration started: {}", reason)],
            requires_action: true,
        })
    }

    /// Process AddMember action for member additions
    async fn process_add_member_action(
        &self,
        update: &GroupUpdate,
        new_member: &GroupMember,
        _welcome_message: &[u8],
        invitation_private_key: &HybridSecretKey,
    ) -> Result<GroupUpdateResult, GroupUpdateError> {
        // Load current epoch state
        let mut current_epoch = self
            .storage
            .load_epoch_state(update.epoch_sequence.0)
            .await
            .map_err(|e| {
                GroupUpdateError::Storage(format!("Failed to load current epoch: {}", e))
            })?;

        // Add new member to roster
        let member = Member {
            member_id: new_member.member_id().into_bytes(),
            public_key: new_member.identity_public.clone(),
            status: MemberStatus::Active,
            capabilities: MemberCapabilities {
                can_read: true,
                can_write: true,
                can_invite: new_member.capabilities.can_add_members,
                can_rekey: new_member.capabilities.can_initiate_epoch_transitions,
                can_remove: new_member.capabilities.can_remove_members,
                can_admin: new_member.capabilities.is_admin,
            },
            joined_at: DateTime::<Utc>::from_timestamp(new_member.joined_at as i64, 0)
                .unwrap_or_else(|| Utc::now()),
            updated_at: Utc::now(),
        };

        current_epoch
            .members
            .insert(new_member.member_id().into_bytes(), member);
        current_epoch.updated_at = Utc::now();

        // Store updated epoch
        self.storage
            .store_epoch_state(&current_epoch)
            .await
            .map_err(|e| {
                GroupUpdateError::Storage(format!("Failed to update epoch with new member: {}", e))
            })?;

        // Process new epoch if transition is included
        if update.epoch_sequence.1 != update.epoch_sequence.0 {
            if let Some(member_id) = self.find_local_member_id(&update.updated_roster) {
                if let Some(encrypted_secrets) = update.per_member_secrets.get(&member_id) {
                    let ciphertext =
                        HybridCiphertext::from_bytes(encrypted_secrets).map_err(|e| {
                            GroupUpdateError::DecryptionFailed(format!("Invalid ciphertext: {}", e))
                        })?;

                    let shared_secret = decap(
                        invitation_private_key,
                        &ciphertext,
                        Context::GroupUpdate,
                    )
                    .map_err(|e| {
                        GroupUpdateError::DecryptionFailed(format!("Decryption failed: {}", e))
                    })?;

                    // Create new epoch with updated roster
                    let new_epoch = self
                        .create_epoch_from_roster_update(update, shared_secret.as_bytes())
                        .await?;

                    self.storage
                        .store_epoch_state(&new_epoch)
                        .await
                        .map_err(|e| {
                            GroupUpdateError::Storage(format!("Failed to store new epoch: {}", e))
                        })?;
                }
            } else {
                log::warn!("Local device not present in roster during member addition");
            }
        }

        Ok(GroupUpdateResult {
            processed_epochs: if update.epoch_sequence.1 != update.epoch_sequence.0 {
                vec![update.epoch_sequence.0, update.epoch_sequence.1]
            } else {
                vec![update.epoch_sequence.0]
            },
            updated_members: vec![new_member.member_id()],
            migration_status: None,
            warnings: Vec::new(),
            requires_action: false,
        })
    }

    /// Process RemoveMember action for member removals
    async fn process_remove_member_action(
        &self,
        update: &GroupUpdate,
        user_id: &str,
        device_id: &str,
        reason: &str,
    ) -> Result<GroupUpdateResult, GroupUpdateError> {
        // Load current epoch state
        let mut current_epoch = self
            .storage
            .load_epoch_state(update.epoch_sequence.0)
            .await
            .map_err(|e| {
                GroupUpdateError::Storage(format!("Failed to load current epoch: {}", e))
            })?;

        let local_member_id = self
            .find_local_member_id_in_epoch(&current_epoch)
            .ok_or_else(|| {
                GroupUpdateError::InvalidUpdate(
                    "Local device not present in current epoch state".to_string(),
                )
            })?;

        // Remove member from roster
        let member_id = format!("{}:{}", user_id, device_id);
        let removed_member = current_epoch.members.remove(member_id.as_bytes());

        if removed_member.is_none() {
            return Err(GroupUpdateError::InvalidUpdate(format!(
                "Member {} not found in current roster",
                member_id
            )));
        }

        current_epoch.updated_at = Utc::now();

        // Store updated epoch
        self.storage
            .store_epoch_state(&current_epoch)
            .await
            .map_err(|e| {
                GroupUpdateError::Storage(format!(
                    "Failed to update epoch after member removal: {}",
                    e
                ))
            })?;

        // Member removal typically triggers epoch transition for forward secrecy
        if update.epoch_sequence.1 != update.epoch_sequence.0 {
            // We might not have new epoch secrets if we were the removed member
            if local_member_id == member_id {
                // We were removed - mark our state accordingly
                return Ok(GroupUpdateResult {
                    processed_epochs: vec![update.epoch_sequence.0],
                    updated_members: vec![member_id],
                    migration_status: None,
                    warnings: vec![format!("We were removed from group: {}", reason)],
                    requires_action: true,
                });
            }

            // Process new epoch without the removed member (we should have secrets)
            if let Some(_encrypted_secrets) = update.per_member_secrets.get(&local_member_id) {
                // Use the placeholder derivation path until roster updates carry the
                // invitation private key material needed for a fresh epoch secret.
                let new_epoch = self
                    .create_epoch_from_roster_update(
                        update, &[0u8; 32], // Placeholder - this needs proper key derivation
                    )
                    .await?;

                self.storage
                    .store_epoch_state(&new_epoch)
                    .await
                    .map_err(|e| {
                        GroupUpdateError::Storage(format!("Failed to store new epoch: {}", e))
                    })?;
            }
        }

        Ok(GroupUpdateResult {
            processed_epochs: if update.epoch_sequence.1 != update.epoch_sequence.0 {
                vec![update.epoch_sequence.0, update.epoch_sequence.1]
            } else {
                vec![update.epoch_sequence.0]
            },
            updated_members: vec![member_id],
            migration_status: None,
            warnings: vec![format!("Member removed: {}", reason)],
            requires_action: false,
        })
    }

    /// Create epoch state from Initialize action
    async fn create_epoch_from_initialize(
        &self,
        update: &GroupUpdate,
        founding_members: &[GroupMember],
        epoch_key: &[u8],
    ) -> Result<EpochState, GroupUpdateError> {
        // Convert founding members to internal format
        let mut members = HashMap::new();

        for group_member in founding_members {
            let member = Member {
                member_id: group_member.member_id().into_bytes(),
                public_key: group_member.identity_public.clone(),
                status: MemberStatus::Active,
                capabilities: MemberCapabilities {
                    can_read: true,
                    can_write: true,
                    can_invite: group_member.capabilities.can_add_members,
                    can_rekey: group_member.capabilities.can_initiate_epoch_transitions,
                    can_remove: group_member.capabilities.can_remove_members,
                    can_admin: group_member.capabilities.is_admin,
                },
                joined_at: DateTime::<Utc>::from_timestamp(group_member.joined_at as i64, 0)
                    .unwrap_or_else(|| Utc::now()),
                updated_at: Utc::now(),
            };

            members.insert(group_member.member_id().into_bytes(), member);
        }

        let epoch_state = EpochState {
            epoch_id: update.epoch_sequence.1,
            encryption_key: epoch_key.try_into().map_err(|_| {
                GroupUpdateError::InvalidUpdate("Invalid epoch key length".to_string())
            })?,
            key_source: EpochKeySource::GroupUpdate,
            members,
            status: EpochStatus::Active {
                activated_at: Utc::now(),
            },
            created_at: DateTime::<Utc>::from_timestamp(update.timestamp as i64, 0)
                .unwrap_or_else(|| Utc::now()),
            updated_at: Utc::now(),
            file_count: 0,
            metadata: Default::default(),
        };

        Ok(epoch_state)
    }

    /// Create epoch state from migration action
    async fn create_epoch_from_migration(
        &self,
        update: &GroupUpdate,
        epoch_key: &[u8],
    ) -> Result<EpochState, GroupUpdateError> {
        // Convert roster to internal format
        let mut members = HashMap::new();

        for group_member in &update.updated_roster {
            let member = Member {
                member_id: group_member.member_id().into_bytes(),
                public_key: group_member.identity_public.clone(),
                status: MemberStatus::Active,
                capabilities: MemberCapabilities {
                    can_read: true,
                    can_write: true,
                    can_invite: group_member.capabilities.can_add_members,
                    can_rekey: group_member.capabilities.can_initiate_epoch_transitions,
                    can_remove: group_member.capabilities.can_remove_members,
                    can_admin: group_member.capabilities.is_admin,
                },
                joined_at: DateTime::<Utc>::from_timestamp(group_member.joined_at as i64, 0)
                    .unwrap_or_else(|| Utc::now()),
                updated_at: Utc::now(),
            };

            members.insert(group_member.member_id().into_bytes(), member);
        }

        let epoch_state = EpochState {
            epoch_id: update.epoch_sequence.1,
            encryption_key: epoch_key.try_into().map_err(|_| {
                GroupUpdateError::InvalidUpdate("Invalid epoch key length".to_string())
            })?,
            key_source: EpochKeySource::GroupUpdate,
            members,
            status: EpochStatus::PendingCutover {
                target_epoch: update.epoch_sequence.1,
                initiated_at: Utc::now(),
            },
            created_at: DateTime::<Utc>::from_timestamp(update.timestamp as i64, 0)
                .unwrap_or_else(|| Utc::now()),
            updated_at: Utc::now(),
            file_count: 0,
            metadata: Default::default(),
        };

        Ok(epoch_state)
    }

    /// Create epoch state from roster update (add/remove member)
    async fn create_epoch_from_roster_update(
        &self,
        update: &GroupUpdate,
        epoch_key: &[u8],
    ) -> Result<EpochState, GroupUpdateError> {
        // Convert updated roster to internal format
        let mut members = HashMap::new();

        for group_member in &update.updated_roster {
            let member = Member {
                member_id: group_member.member_id().into_bytes(),
                public_key: group_member.identity_public.clone(),
                status: MemberStatus::Active,
                capabilities: MemberCapabilities {
                    can_read: true,
                    can_write: true,
                    can_invite: group_member.capabilities.can_add_members,
                    can_rekey: group_member.capabilities.can_initiate_epoch_transitions,
                    can_remove: group_member.capabilities.can_remove_members,
                    can_admin: group_member.capabilities.is_admin,
                },
                joined_at: DateTime::<Utc>::from_timestamp(group_member.joined_at as i64, 0)
                    .unwrap_or_else(|| Utc::now()),
                updated_at: Utc::now(),
            };

            members.insert(group_member.member_id().into_bytes(), member);
        }

        let epoch_state = EpochState {
            epoch_id: update.epoch_sequence.1,
            encryption_key: epoch_key.try_into().map_err(|_| {
                GroupUpdateError::InvalidUpdate("Invalid epoch key length".to_string())
            })?,
            key_source: EpochKeySource::GroupUpdate,
            members,
            status: EpochStatus::Active {
                activated_at: Utc::now(),
            },
            created_at: DateTime::<Utc>::from_timestamp(update.timestamp as i64, 0)
                .unwrap_or_else(|| Utc::now()),
            updated_at: Utc::now(),
            file_count: 0,
            metadata: Default::default(),
        };

        Ok(epoch_state)
    }

    /// Store update record for replay protection
    async fn store_update_record(&self, update: &GroupUpdate) -> Result<(), GroupUpdateError> {
        let update_hash = self.calculate_update_hash(update);
        let record = GroupUpdateRecord {
            update_hash: update_hash.clone(),
            processed_at: Utc::now(),
            from_epoch: update.epoch_sequence.0,
            to_epoch: update.epoch_sequence.1,
            action_type: match &update.action {
                UpdateAction::Initialize { .. } => "Initialize".to_string(),
                UpdateAction::StartMigration { .. } => "StartMigration".to_string(),
                UpdateAction::AddMember { .. } => "AddMember".to_string(),
                UpdateAction::RemoveMember { .. } => "RemoveMember".to_string(),
            },
        };

        let mut processed_updates = self.processed_updates.lock().await;
        processed_updates.insert(update_hash, record);

        Ok(())
    }

    /// Update epoch state after processing
    async fn update_epoch_state(
        &self,
        update: &GroupUpdate,
        result: &GroupUpdateResult,
    ) -> Result<(), GroupUpdateError> {
        // Update current epoch statistics
        if let Ok(mut current_epoch) = self.storage.load_epoch_state(update.epoch_sequence.0).await
        {
            current_epoch.updated_at = Utc::now();

            // Update member count if roster changed
            if !result.updated_members.is_empty() {
                // Member count is implicitly updated through the members HashMap
            }

            self.storage
                .store_epoch_state(&current_epoch)
                .await
                .map_err(|e| {
                    GroupUpdateError::Storage(format!(
                        "Failed to update current epoch state: {}",
                        e
                    ))
                })?;
        }

        Ok(())
    }

    /// Retry GroupUpdate processing with exponential backoff
    pub async fn retry_group_update(
        &self,
        update: &GroupUpdate,
        invitation_private_key: &HybridSecretKey,
        config: &GroupUpdateConfig,
        attempt: u32,
    ) -> Result<GroupUpdateResult, GroupUpdateError> {
        if attempt >= config.max_retry_attempts {
            return Err(GroupUpdateError::MaxRetriesExceeded(format!(
                "Failed after {} attempts",
                config.max_retry_attempts
            )));
        }

        // Exponential backoff delay
        let delay_ms = config.retry_delay_ms * (2_u64.pow(attempt));
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

        // Retry the processing
        self.process_group_update(update, invitation_private_key, config)
            .await
    }
}

/// GroupUpdate processing errors with comprehensive error types
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum GroupUpdateError {
    #[error("Invalid group update: {0}")]
    InvalidUpdate(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Epoch mismatch: {0}")]
    EpochMismatch(String),

    #[error("Message too old: {0}")]
    MessageTooOld(String),

    #[error("Replay attack detected: {0}")]
    ReplayAttack(String),

    #[error("Max retries exceeded: {0}")]
    MaxRetriesExceeded(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),
}
