pub mod cutover;
pub mod migration;
/// Epoch management interface providing comprehensive epoch lifecycle operations
///
/// The epoch module manages the lifecycle of cryptographic epochs including:
/// - Epoch creation and initialization with secure key generation
/// - Two-phase migration coordination with dual-epoch state management
/// - Member roster management and status tracking
/// - Epoch validation and consistency checking
/// - Secure epoch cleanup and key deletion
///
/// ## Migration Workflow
///
/// Epochs follow a strict lifecycle during two-phase rekey operations:
/// 1. **Active**: Normal operation with single epoch
/// 2. **Migration**: Dual-epoch state with old epoch readable, new epoch for writes
/// 3. **Cutover**: Atomic transition to new epoch with old epoch cleanup
///
/// ## Security Properties
///
/// - **Forward Secrecy**: Old epoch keys securely deleted after cutover
/// - **Key Isolation**: Epochs maintain cryptographic separation
/// - **Atomic Transitions**: State changes are atomic and consistent
/// - **Recovery**: Migration state persisted for crash recovery
pub mod state;
pub mod update;
pub mod welcome;

pub use cutover::{CutoverConfig, CutoverCoordinator, CutoverError, CutoverState};
pub use migration::{
    MigrationError, MigrationManager, MigrationPhase, MigrationProgress, MigrationStatus,
};
pub use state::{EpochMetadata, EpochState, EpochStatus, Member, MemberCapabilities, MemberStatus};
pub use update::{GroupUpdateError, GroupUpdateProcessor};
pub use welcome::{WelcomeError, WelcomeProcessor, WelcomeResult};

use crate::coverage::{try_build_transparency_handles, TransparencyCoverageHandles};
use crate::network::Network;
use crate::storage::Storage;
use hybridcipher_coverage::CoverageManager;
use hybridcipher_crypto::signatures::{Ed25519KeyPair, SigningKey};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Epoch manager coordinates all epoch-related operations
///
/// Provides a unified interface for epoch lifecycle management including
/// migration coordination, member management, and state persistence.
#[derive(Debug)]
pub struct EpochManager<S: Storage, N: Network> {
    storage: Arc<S>,
    network: Arc<N>,
    migration_manager: Arc<MigrationManager<S, N>>,
    welcome: Arc<Mutex<WelcomeProcessor<S>>>,
    update: Arc<GroupUpdateProcessor<S, N>>,
    current_state: Arc<RwLock<Option<EpochState>>>,
}

impl<S: Storage, N: Network> EpochManager<S, N> {
    /// Create new epoch manager
    pub async fn new(
        storage: Arc<S>,
        network: Arc<N>,
        device_identity: Ed25519KeyPair,
        device_id: String,
    ) -> Result<Self, MigrationError> {
        let signing_key = SigningKey::from_bytes(&device_identity.private_key_bytes())
            .map_err(|e| MigrationError::Storage(format!("Failed to create signing key: {}", e)))?;

        // Create coverage manager with optional transparency publisher
        let mut coverage_manager =
            CoverageManager::new_with_signing_key(storage.clone(), signing_key);
        if let Some(handles) = try_build_transparency_handles(network.clone()) {
            let TransparencyCoverageHandles {
                publisher,
                verifier,
            } = handles;
            coverage_manager = coverage_manager
                .with_publisher(publisher)
                .with_transparency_verifier(verifier);
        }
        let coverage_manager = Arc::new(coverage_manager);

        let migration_manager = Arc::new(MigrationManager::new(
            storage.clone(),
            network.clone(),
            coverage_manager.clone(),
            device_identity.clone(),
        ));
        let welcome = Arc::new(Mutex::new(WelcomeProcessor::new(
            storage.clone(),
            device_identity.clone(),
            device_id.clone(),
        )));
        let update = Arc::new(GroupUpdateProcessor::new(
            storage.clone(),
            network.clone(),
            device_identity.clone(),
        ));

        let epoch_manager = Self {
            storage: storage.clone(),
            network: network.clone(),
            migration_manager,
            welcome,
            update,
            current_state: Arc::new(RwLock::new(None)),
        };

        Ok(epoch_manager)
    }

    /// Get current epoch state
    pub async fn current_epoch(&self) -> Option<EpochState> {
        let state = self.current_state.read().await;
        state.clone()
    }

    #[cfg(test)]
    /// Set the current epoch state (test only)
    pub async fn set_current_epoch(&self, epoch: EpochState) {
        let mut state = self.current_state.write().await;
        *state = Some(epoch);
    }

    /// Starts a migration to a new epoch
    pub async fn start_migration(&self, target_epoch: EpochState) -> Result<(), MigrationError> {
        match self.network.get_network_status().await {
            Ok(status) if !status.is_connected => {
                return Err(MigrationError::Network(
                    "Network unavailable for migration start".to_string(),
                ))
            }
            Ok(_) => {}
            Err(err) => {
                log::warn!("Unable to query network status before migration: {}", err);
            }
        }
        self.migration_manager.start_migration(target_epoch).await
    }

    /// Gets migration progress
    pub async fn migration_progress(&self) -> MigrationProgress {
        self.migration_manager.get_progress().await
    }

    /// Completes the current migration
    pub async fn complete_migration(&self) -> Result<(), MigrationError> {
        let result = self.migration_manager.finalize_migration().await;

        if result.is_ok() {
            // Update our current state after successful migration
            let new_current = self.migration_manager.current_epoch().await;
            let mut state = self.current_state.write().await;
            *state = new_current;
        }

        result
    }

    /// Get epoch key for the specified epoch
    pub async fn get_epoch_key(&self, epoch_id: u64) -> Option<hybridcipher_crypto::AeadKey> {
        // Try to get from current epoch
        if let Some(current) = self.current_epoch().await {
            if current.epoch_id == epoch_id {
                return hybridcipher_crypto::AeadKey::from_bytes(&current.encryption_key).ok();
            }
        }

        // Try to load from storage through migration_manager
        if let Ok(Some(epoch_state)) = self.storage.load_epoch_state_data(epoch_id).await {
            return hybridcipher_crypto::AeadKey::from_bytes(&epoch_state.encrypted_key).ok();
        }

        None
    }

    /// Check whether an epoch key is verified for encryption.
    pub async fn is_epoch_key_verified(&self, epoch_id: u64) -> bool {
        if let Some(current) = self.current_epoch().await {
            if current.epoch_id == epoch_id {
                return current.key_source.is_verified();
            }
        }

        if let Ok(Some(epoch_state)) = self.storage.load_epoch_state_data(epoch_id).await {
            return epoch_state.key_source.is_verified();
        }

        false
    }

    /// Check if migration is currently active
    pub async fn is_migration_active(&self) -> bool {
        self.migration_manager.is_migration_active().await
    }

    /// Get target epoch ID for active migration
    pub async fn get_migration_target_epoch(&self) -> Option<u64> {
        self.migration_manager.get_target_epoch_id().await
    }

    /// Initiates atomic cutover coordination
    pub async fn initiate_cutover(&self) -> Result<(), MigrationError> {
        self.migration_manager.initiate_cutover().await
    }

    /// Processes received cutover message
    pub async fn process_cutover_message(
        &self,
        message: hybridcipher_messages::cutover::CutoverMessage,
        sender: hybridcipher_crypto::signatures::VerifyingKey,
    ) -> Result<(), MigrationError> {
        self.migration_manager
            .process_cutover_message(message, sender)
            .await
    }

    /// Gets cutover coordinator for external operations
    pub fn cutover_coordinator(&self) -> Arc<CutoverCoordinator<S, N>> {
        self.migration_manager.cutover_coordinator()
    }

    /// Process Welcome message
    pub async fn process_welcome(
        &self,
        welcome_data: &[u8],
        invitation_private_key: &hybridcipher_crypto::hybridkem::HybridSecretKey,
    ) -> Result<WelcomeResult, WelcomeError> {
        // Parse the Welcome message using serde
        let welcome: hybridcipher_messages::welcome::Welcome = serde_json::from_slice(welcome_data)
            .map_err(|e| {
                WelcomeError::InvalidMessage(format!("Failed to parse Welcome message: {}", e))
            })?;

        // Create config with defaults
        let config = welcome::WelcomeConfig::default();

        self.welcome
            .lock()
            .await
            .process_welcome(&welcome, invitation_private_key, &config)
            .await
    }

    /// Process GroupUpdate message  
    pub async fn process_group_update(
        &self,
        update_data: &[u8],
        invitation_private_key: &hybridcipher_crypto::HybridSecretKey,
    ) -> Result<(), GroupUpdateError> {
        // Parse the GroupUpdate message from JSON bytes
        let update =
            serde_json::from_slice::<hybridcipher_messages::group_update::GroupUpdate>(update_data)
                .map_err(|e| {
                    GroupUpdateError::InvalidUpdate(format!("Failed to parse GroupUpdate: {}", e))
                })?;

        // Create default configuration
        let config = update::GroupUpdateConfig::default();

        // Process the update and return simplified result
        let _result = self
            .update
            .process_group_update(&update, invitation_private_key, &config)
            .await?;

        // For now, ignore the detailed result and just return success
        Ok(())
    }

    /// Create a placeholder EpochManager for circular dependency resolution
    pub fn new_placeholder() -> Self {
        // This should never be used in practice - only for breaking circular dependencies
        panic!("new_placeholder should not be called - use proper initialization")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MockNetwork;
    use crate::storage::MockStorage;

    #[tokio::test]
    async fn test_epoch_manager_creation() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = Ed25519KeyPair::generate();

        let epoch_manager = EpochManager::new(storage, network, device_identity, "device1".into())
            .await
            .unwrap();

        // Should start with no current epoch
        let current = epoch_manager.current_epoch().await;
        assert!(current.is_none());
    }

    #[tokio::test]
    async fn test_migration_initiation() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = Ed25519KeyPair::generate();

        let epoch_manager = EpochManager::new(storage, network, device_identity, "device1".into())
            .await
            .unwrap();

        // Create a target epoch state
        let target_epoch = EpochState {
            epoch_id: 1,
            status: EpochStatus::Active {
                activated_at: chrono::Utc::now(),
            },
            members: std::collections::HashMap::new(),
            encryption_key: [0u8; 32],
            key_source: crate::epoch_key_source::EpochKeySource::Placeholder,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            file_count: 0,
            metadata: EpochMetadata::default(),
        };

        // Start migration
        let result = epoch_manager.start_migration(target_epoch).await;
        assert!(result.is_ok());

        // Check migration progress
        let progress = epoch_manager.migration_progress().await;
        assert_eq!(progress.phase, MigrationPhase::Prepare);
    }
}
