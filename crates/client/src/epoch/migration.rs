use super::state::EpochStatus;
/// Two-phase migration logic with comprehensive state tracking
///
/// Implements the core two-phase rekey mechanism enabling seamless epoch transitions
/// without downtime while maintaining strong security properties.
use super::{CutoverConfig, CutoverCoordinator, EpochState};
use crate::{network::Network, storage::Storage};
use chrono::{DateTime, Utc};
use hex;
use hybridcipher_coverage::CoverageManager;
use hybridcipher_crypto::{secure_delete::SecureDelete, signatures::Ed25519KeyPair};
use hybridcipher_messages::welcome::EpochSecrets as StoredEpochSecrets;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("Migration already in progress")]
    MigrationInProgress,
    #[error("Invalid migration state")]
    InvalidState,
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Timeout during migration")]
    Timeout,
    #[error("Migration validation failed: {0}")]
    ValidationFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationPhase {
    Prepare,
    Rewrap,
    Sync,
    Cutover,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatus {
    Idle,
    Active(MigrationPhase),
}

#[derive(Debug, Clone)]
pub struct MigrationConfig {
    pub max_duration: chrono::Duration,
    pub batch_size: usize,
    pub progress_interval: chrono::Duration,
    pub auto_rollback: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MigrationMetrics {
    pub migration_start_time: Option<DateTime<Utc>>,
    pub total_migration_time: chrono::Duration,
    pub files_rewrapped: usize,
    pub total_files: usize,
    pub phase_transitions: usize,
    pub completed_migrations: usize,
    pub failed_migrations: usize,
}

#[derive(Debug, Clone)]
pub struct MigrationProgress {
    pub phase: MigrationPhase,
    pub files_rewrapped: usize,
    pub total_files: usize,
    pub completion_percentage: u8,
    pub start_time: Option<DateTime<Utc>>,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            max_duration: chrono::Duration::hours(24),
            batch_size: 100,
            progress_interval: chrono::Duration::minutes(5),
            auto_rollback: true,
        }
    }
}

/// Migration manager coordinates two-phase rekey operations
#[derive(Debug)]
pub struct MigrationManager<S: Storage, N: Network> {
    current_epoch: Arc<RwLock<Option<EpochState>>>,
    next_epoch: Arc<RwLock<Option<EpochState>>>,
    migration_state: Arc<RwLock<MigrationStatus>>,
    storage: Arc<S>,
    network: Arc<N>,
    device_identity: Ed25519KeyPair,
    config: MigrationConfig,
    metrics: Arc<RwLock<MigrationMetrics>>,
    cutover_coordinator: Arc<CutoverCoordinator<S, N>>,
}

impl<S: Storage, N: Network> MigrationManager<S, N> {
    /// Creates a new migration manager
    pub fn new(
        storage: Arc<S>,
        network: Arc<N>,
        coverage_manager: Arc<CoverageManager<S>>,
        device_identity: Ed25519KeyPair,
    ) -> Self {
        let cutover_coordinator = Arc::new(CutoverCoordinator::new(
            storage.clone(),
            network.clone(),
            coverage_manager,
            device_identity.clone(),
            CutoverConfig::default(),
            EpochState::new(0, [0u8; 32]), // Placeholder initial epoch
        ));

        Self {
            current_epoch: Arc::new(RwLock::new(None)),
            next_epoch: Arc::new(RwLock::new(None)),
            migration_state: Arc::new(RwLock::new(MigrationStatus::Idle)),
            storage,
            network,
            device_identity,
            config: MigrationConfig::default(),
            metrics: Arc::new(RwLock::new(MigrationMetrics::default())),
            cutover_coordinator,
        }
    }

    /// Get storage reference for internal use
    pub fn storage(&self) -> &Arc<S> {
        &self.storage
    }

    /// Starts a new migration to the target epoch
    pub async fn start_migration(&self, target_epoch: EpochState) -> Result<(), MigrationError> {
        match self.network.get_network_status().await {
            Ok(status) if !status.is_connected => {
                return Err(MigrationError::Network(
                    "Network connectivity required to start migration".to_string(),
                ))
            }
            Ok(status) => {
                if status.error_rate > 0.5 {
                    log::warn!(
                        "Starting migration while network error rate is {:.2}; monitoring closely",
                        status.error_rate
                    );
                }
            }
            Err(err) => {
                log::warn!(
                    "Unable to determine network status before migration: {}",
                    err
                );
            }
        }

        let mut state = self.migration_state.write().await;

        // Check current migration state
        match *state {
            MigrationStatus::Idle => {}
            _ => return Err(MigrationError::MigrationInProgress),
        }

        let device_fingerprint = hex::encode(&self.device_identity.public_key_bytes()[..8]);
        log::info!(
            "Migration to epoch {} initiated by device {} (batch size {}, auto rollback {}), max duration {:?}",
            target_epoch.epoch_id,
            device_fingerprint,
            self.config.batch_size,
            self.config.auto_rollback,
            self.config.max_duration
        );

        // Set up dual-epoch state
        {
            let mut next = self.next_epoch.write().await;
            *next = Some(target_epoch);
        }

        // Update migration state
        *state = MigrationStatus::Active(MigrationPhase::Prepare);

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.migration_start_time = Some(Utc::now());
            metrics.phase_transitions += 1;
            metrics.total_files = self.config.batch_size;
        }

        log::info!("Migration started to epoch {}", {
            let next = self.next_epoch.read().await;
            next.as_ref().map(|e| e.epoch_id).unwrap_or(0)
        });

        Ok(())
    }

    /// Initiates atomic cutover with comprehensive safety guarantees
    pub async fn initiate_cutover(&self) -> Result<(), MigrationError> {
        let mut state = self.migration_state.write().await;

        match *state {
            MigrationStatus::Active(MigrationPhase::Sync) => {}
            _ => return Err(MigrationError::InvalidState),
        }

        // Get current and target epochs
        let current_epoch = {
            let current = self.current_epoch.read().await;
            current.clone().ok_or(MigrationError::InvalidState)?
        };

        let target_epoch = {
            let next = self.next_epoch.read().await;
            next.clone().ok_or(MigrationError::InvalidState)?
        };

        // Transition to cutover phase
        *state = MigrationStatus::Active(MigrationPhase::Cutover);

        // Initiate distributed cutover coordination
        self.cutover_coordinator
            .initiate_cutover(&current_epoch, &target_epoch)
            .await
            .map_err(|e| MigrationError::ValidationFailed(e.to_string()))?;

        log::info!(
            "Atomic cutover initiated for migration {} -> {}",
            current_epoch.epoch_id,
            target_epoch.epoch_id
        );

        Ok(())
    }

    /// Completes the migration after successful cutover
    pub async fn finalize_migration(&self) -> Result<(), MigrationError> {
        let mut state = self.migration_state.write().await;

        match *state {
            MigrationStatus::Active(MigrationPhase::Cutover) => {}
            _ => return Err(MigrationError::InvalidState),
        }

        // Verify cutover completed successfully
        let cutover_state = self.cutover_coordinator.get_state().await;
        if !matches!(cutover_state, super::cutover::CutoverState::Completed) {
            return Err(MigrationError::ValidationFailed(format!(
                "Cutover not completed: {:?}",
                cutover_state
            )));
        }

        // Perform secure deletion of old epoch keys
        self.secure_delete_old_epoch().await?;

        // Atomic promotion: next epoch becomes current
        {
            let mut current = self.current_epoch.write().await;
            let mut next = self.next_epoch.write().await;

            if let Some(next_epoch) = next.take() {
                *current = Some(next_epoch);
            } else {
                return Err(MigrationError::InvalidState);
            }
        }

        // Complete migration
        *state = MigrationStatus::Idle;

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            if let Some(start) = metrics.migration_start_time {
                metrics.total_migration_time = Utc::now().signed_duration_since(start);
            }
            metrics.completed_migrations += 1;
        }

        log::info!("Migration finalized successfully with atomic cutover");
        Ok(())
    }

    /// Performs secure deletion of old epoch cryptographic material
    async fn secure_delete_old_epoch(&self) -> Result<(), MigrationError> {
        log::info!("Performing secure deletion of old epoch keys");

        let successor_epoch_id = {
            let next_epoch = self.next_epoch.read().await;
            next_epoch.as_ref().map(|epoch| epoch.epoch_id)
        };

        let (epoch_id, sanitized_epoch) = {
            let mut current = self.current_epoch.write().await;

            let epoch = match current.as_mut() {
                Some(epoch) => epoch,
                None => {
                    log::warn!("No current epoch available during secure deletion; skipping");
                    return Ok(());
                }
            };

            let epoch_id = epoch.epoch_id;

            if !matches!(epoch.status, EpochStatus::Deprecated { .. }) {
                if let Some(successor) = successor_epoch_id {
                    if let Err(err) = epoch.deprecate(successor) {
                        log::warn!(
                            "Failed to mark epoch {} as deprecated before deletion: {}",
                            epoch_id,
                            err
                        );
                        epoch.status = EpochStatus::Deprecated {
                            deprecated_at: Utc::now(),
                            successor_epoch: successor,
                        };
                        epoch.updated_at = Utc::now();
                    }
                } else {
                    log::warn!(
                        "No successor epoch ID available when deprecating epoch {}; using fallback",
                        epoch_id
                    );
                    epoch.status = EpochStatus::Deprecated {
                        deprecated_at: Utc::now(),
                        successor_epoch: epoch_id.saturating_add(1),
                    };
                    epoch.updated_at = Utc::now();
                }
            }

            epoch.encryption_key.secure_delete();
            epoch.encryption_key = [0u8; 32];
            epoch.updated_at = Utc::now();

            let snapshot = epoch.clone();

            (epoch_id, snapshot)
        };

        let zeroed_secrets = StoredEpochSecrets {
            epoch_key: vec![0u8; 32],
            signing_key: vec![0u8; 32],
            previous_keys: HashMap::new(),
        };

        if let Err(err) = self
            .storage
            .store_epoch_keys(epoch_id, &zeroed_secrets)
            .await
        {
            log::warn!(
                "Failed to overwrite persisted epoch {} secrets: {}",
                epoch_id,
                err
            );
        }

        self.storage
            .store_epoch_state(&sanitized_epoch)
            .await
            .map_err(|e| MigrationError::Storage(e.to_string()))?;

        match self.storage.load_epoch_state(epoch_id).await {
            Ok(loaded_epoch) => {
                if loaded_epoch.encryption_key.iter().any(|&byte| byte != 0) {
                    return Err(MigrationError::ValidationFailed(format!(
                        "Epoch {} encryption key still present after secure deletion",
                        epoch_id
                    )));
                }
            }
            Err(err) => {
                return Err(MigrationError::Storage(format!(
                    "Failed to reload epoch {} after secure deletion: {}",
                    epoch_id, err
                )));
            }
        }

        log::info!("Securely deleted epoch {} keys", epoch_id);
        Ok(())
    }

    /// Processes received cutover message
    pub async fn process_cutover_message(
        &self,
        message: hybridcipher_messages::cutover::CutoverMessage,
        sender: hybridcipher_crypto::signatures::VerifyingKey,
    ) -> Result<(), MigrationError> {
        self.cutover_coordinator
            .process_cutover_message(message, sender)
            .await
            .map_err(|e| MigrationError::ValidationFailed(e.to_string()))
    }

    /// Gets cutover coordinator for external access
    pub fn cutover_coordinator(&self) -> Arc<CutoverCoordinator<S, N>> {
        self.cutover_coordinator.clone()
    }

    /// Rolls back the migration, discarding next epoch
    pub async fn rollback_migration(&self) -> Result<(), MigrationError> {
        if !self.config.auto_rollback {
            log::warn!("Auto rollback disabled; ignoring rollback request");
            return Ok(());
        }

        let mut state = self.migration_state.write().await;

        match *state {
            MigrationStatus::Active(_) => {}
            _ => return Err(MigrationError::InvalidState),
        }

        // Discard next epoch
        {
            let mut next = self.next_epoch.write().await;
            *next = None;
        }

        // Reset to idle
        *state = MigrationStatus::Idle;

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.failed_migrations += 1;
        }

        log::warn!("Migration rolled back");
        Ok(())
    }

    /// Gets current migration progress
    pub async fn get_progress(&self) -> MigrationProgress {
        let state = self.migration_state.read().await;
        let metrics = self.metrics.read().await;

        MigrationProgress {
            phase: match *state {
                MigrationStatus::Idle => MigrationPhase::Prepare,
                MigrationStatus::Active(phase) => phase,
            },
            files_rewrapped: metrics.files_rewrapped,
            total_files: metrics.total_files,
            completion_percentage: if metrics.total_files > 0 {
                (metrics.files_rewrapped as f64 / metrics.total_files as f64 * 100.0) as u8
            } else {
                0
            },
            start_time: metrics.migration_start_time,
        }
    }

    /// Advances the migration to the next phase
    pub async fn advance_phase(&self) -> Result<(), MigrationError> {
        let mut state = self.migration_state.write().await;

        let new_phase = match *state {
            MigrationStatus::Active(MigrationPhase::Prepare) => MigrationPhase::Rewrap,
            MigrationStatus::Active(MigrationPhase::Rewrap) => MigrationPhase::Sync,
            MigrationStatus::Active(MigrationPhase::Sync) => {
                // Drop the state lock before calling initiate_cutover
                drop(state);
                return self.initiate_cutover().await;
            }
            MigrationStatus::Active(MigrationPhase::Cutover) => {
                // Drop the state lock before calling finalize_migration
                drop(state);
                return self.finalize_migration().await;
            }
            _ => return Err(MigrationError::InvalidState),
        };

        *state = MigrationStatus::Active(new_phase);

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.phase_transitions += 1;
        }

        Ok(())
    }

    /// Gets the current epoch
    pub async fn current_epoch(&self) -> Option<EpochState> {
        let current = self.current_epoch.read().await;
        current.clone()
    }

    /// Gets the next epoch (during migration)
    pub async fn next_epoch(&self) -> Option<EpochState> {
        let next = self.next_epoch.read().await;
        next.clone()
    }

    /// Check if migration is currently active
    pub async fn is_migration_active(&self) -> bool {
        let state = self.migration_state.read().await;
        matches!(*state, MigrationStatus::Active(_))
    }

    /// Get target epoch ID for active migration
    pub async fn get_target_epoch_id(&self) -> Option<u64> {
        let next = self.next_epoch.read().await;
        next.as_ref().map(|epoch| epoch.epoch_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        coverage::CoverageManager, epoch::state::EpochMetadata, network::MockNetwork,
        storage::MockStorage,
    };
    use hybridcipher_crypto::signatures::SigningKey;
    use std::sync::Arc;

    async fn create_test_manager() -> (
        MigrationManager<MockStorage, MockNetwork>,
        Arc<CoverageManager<MockStorage>>,
    ) {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = Ed25519KeyPair::generate();

        let signing_key =
            SigningKey::from_bytes(&device_identity.private_key_bytes()).expect("signing key");
        let coverage_manager = Arc::new(CoverageManager::new_with_signing_key(
            storage.clone(),
            signing_key,
        ));

        let manager =
            MigrationManager::new(storage, network, coverage_manager.clone(), device_identity);
        (manager, coverage_manager)
    }

    #[tokio::test]
    async fn test_migration_lifecycle() {
        let (manager, _) = create_test_manager().await;

        // Initial state should be idle
        let progress = manager.get_progress().await;
        assert_eq!(progress.phase, MigrationPhase::Prepare);

        // Create a target epoch
        let target_epoch = EpochState {
            epoch_id: 2,
            status: EpochStatus::Active {
                activated_at: Utc::now(),
            },
            members: std::collections::HashMap::new(),
            encryption_key: [0u8; 32],
            key_source: crate::epoch_key_source::EpochKeySource::Placeholder,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            file_count: 0,
            metadata: EpochMetadata::default(),
        };

        // Start migration
        let result = manager.start_migration(target_epoch.clone()).await;
        assert!(result.is_ok());

        // Should be able to get next epoch
        let next = manager.next_epoch().await;
        assert!(next.is_some());
        assert_eq!(next.unwrap().epoch_id, 2);

        // Advance through phases (but don't complete due to cutover complexity)
        assert!(manager.advance_phase().await.is_ok()); // Prepare -> Rewrap
        assert!(manager.advance_phase().await.is_ok()); // Rewrap -> Sync
                                                        // Note: Not testing cutover phase due to complexity of mocking consensus
    }

    #[tokio::test]
    async fn test_migration_rollback() {
        let (manager, _) = create_test_manager().await;

        let target_epoch = EpochState {
            epoch_id: 2,
            status: EpochStatus::Active {
                activated_at: Utc::now(),
            },
            members: std::collections::HashMap::new(),
            encryption_key: [0u8; 32],
            key_source: crate::epoch_key_source::EpochKeySource::Placeholder,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            file_count: 0,
            metadata: EpochMetadata::default(),
        };

        // Start migration
        assert!(manager.start_migration(target_epoch).await.is_ok());

        // Rollback migration
        assert!(manager.rollback_migration().await.is_ok());

        // Should be back to idle
        let next = manager.next_epoch().await;
        assert!(next.is_none());
    }

    #[tokio::test]
    async fn secure_delete_zeroizes_epoch_material() {
        let (manager, _) = create_test_manager().await;

        let now = Utc::now();
        let pending_epoch = EpochState {
            epoch_id: 1,
            encryption_key: [0xA5; 32],
            members: std::collections::HashMap::new(),
            status: EpochStatus::PendingCutover {
                target_epoch: 2,
                initiated_at: now,
            },
            key_source: crate::epoch_key_source::EpochKeySource::LocalInit,
            created_at: now,
            updated_at: now,
            file_count: 5,
            metadata: EpochMetadata::default(),
        };

        let successor_epoch = EpochState {
            epoch_id: 2,
            encryption_key: [0x5A; 32],
            members: std::collections::HashMap::new(),
            status: EpochStatus::Active { activated_at: now },
            key_source: crate::epoch_key_source::EpochKeySource::LocalInit,
            created_at: now,
            updated_at: now,
            file_count: 0,
            metadata: EpochMetadata::default(),
        };

        manager
            .storage
            .store_epoch_state(&pending_epoch)
            .await
            .expect("seed epoch state");
        manager
            .storage
            .store_epoch_keys(
                pending_epoch.epoch_id,
                &StoredEpochSecrets {
                    epoch_key: vec![0x11; 32],
                    signing_key: vec![0x22; 32],
                    previous_keys: std::collections::HashMap::new(),
                },
            )
            .await
            .expect("seed epoch secrets");

        *manager.current_epoch.write().await = Some(pending_epoch);
        *manager.next_epoch.write().await = Some(successor_epoch);

        manager
            .secure_delete_old_epoch()
            .await
            .expect("secure deletion succeeds");

        let guard = manager.current_epoch.read().await;
        let sanitized = guard.as_ref().expect("current epoch sanitized");
        assert!(sanitized.encryption_key.iter().all(|byte| *byte == 0u8));

        let persisted = manager
            .storage
            .load_epoch_state(1)
            .await
            .expect("load sanitized epoch");
        assert!(persisted.encryption_key.iter().all(|byte| *byte == 0u8));
    }
}
