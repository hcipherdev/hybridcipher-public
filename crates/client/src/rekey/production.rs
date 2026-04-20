use hybridcipher_coverage::CoverageManager;
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::{Duration, Instant};
use thiserror::Error;

pub type EpochId = u64;

/// Secret material associated with an epoch
#[derive(Debug, Clone)]
pub struct EpochSecret {
    pub hybrid_key: Vec<u8>,
    pub signing_key: Ed25519KeyPair,
}

impl EpochSecret {
    pub fn generate() -> Self {
        let mut hybrid_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut hybrid_key);

        Self {
            hybrid_key,
            signing_key: Ed25519KeyPair::generate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MigrationState {
    Stable,
    MigrationActive {
        new_epoch: EpochId,
        start_time: Instant,
    },
    CutoverPending {
        new_epoch: EpochId,
    },
}

#[derive(Debug, Clone)]
pub struct MigrationProgress {
    pub completion_percentage: f64,
    pub files_rewrapped: usize,
    pub total_files: usize,
    pub elapsed: Duration,
}

impl Default for MigrationProgress {
    fn default() -> Self {
        Self {
            completion_percentage: 0.0,
            files_rewrapped: 0,
            total_files: 0,
            elapsed: Duration::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum RekeyError {
    #[error("migration already in progress")]
    MigrationInProgress,
    #[error("no migration active")]
    NoMigrationActive,
    #[error("cutover already pending")]
    CutoverAlreadyPending,
    #[error("epoch secret missing for epoch {0}")]
    UnknownEpoch(EpochId),
    #[error("operation not permitted in current state: {0}")]
    InvalidState(&'static str),
}

#[derive(Debug, Clone)]
struct MigrationTracking {
    start_time: Instant,
    total_files: usize,
    files_rewrapped: usize,
}

impl MigrationTracking {
    fn new(start_time: Instant, total_files: usize) -> Self {
        Self {
            start_time,
            total_files,
            files_rewrapped: 0,
        }
    }

    fn mark_rewrapped(&mut self) {
        self.files_rewrapped = self.files_rewrapped.saturating_add(1);
        if self.total_files > 0 {
            self.files_rewrapped = self.files_rewrapped.min(self.total_files);
        }
    }

    fn set_total_files(&mut self, total_files: usize) {
        self.total_files = total_files;
        if self.total_files > 0 {
            self.files_rewrapped = self.files_rewrapped.min(self.total_files);
        }
    }

    fn progress(&self) -> MigrationProgress {
        let elapsed = self.start_time.elapsed();
        let completion = if self.total_files == 0 {
            0.0
        } else {
            (self.files_rewrapped as f64 / self.total_files as f64) * 100.0
        };

        MigrationProgress {
            completion_percentage: completion,
            files_rewrapped: self.files_rewrapped,
            total_files: self.total_files,
            elapsed,
        }
    }
}

#[derive(Debug)]
pub struct RekeyManager<S> {
    _storage_marker: PhantomData<S>,
    current_epoch: EpochId,
    migration_state: MigrationState,
    epoch_keys: HashMap<EpochId, EpochSecret>,
    coverage_manager: CoverageManager<S>,
    migration_tracking: Option<MigrationTracking>,
}

impl<S> RekeyManager<S> {
    pub fn new(
        initial_epoch: EpochId,
        initial_secret: EpochSecret,
        coverage_manager: CoverageManager<S>,
    ) -> Self {
        let mut epoch_keys = HashMap::new();
        epoch_keys.insert(initial_epoch, initial_secret);

        Self {
            _storage_marker: PhantomData,
            current_epoch: initial_epoch,
            migration_state: MigrationState::Stable,
            epoch_keys,
            coverage_manager,
            migration_tracking: None,
        }
    }

    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    pub fn migration_state(&self) -> &MigrationState {
        &self.migration_state
    }

    pub fn is_migration_active(&self) -> bool {
        matches!(self.migration_state, MigrationState::MigrationActive { .. })
    }

    pub fn is_cutover_pending(&self) -> bool {
        matches!(self.migration_state, MigrationState::CutoverPending { .. })
    }

    pub fn get_active_epochs(&self) -> Vec<EpochId> {
        match &self.migration_state {
            MigrationState::Stable => vec![self.current_epoch],
            MigrationState::MigrationActive { new_epoch, .. }
            | MigrationState::CutoverPending { new_epoch } => {
                vec![self.current_epoch, *new_epoch]
            }
        }
    }

    pub fn get_epoch_secret(&self, epoch: EpochId) -> Result<&EpochSecret, RekeyError> {
        self.epoch_keys
            .get(&epoch)
            .ok_or(RekeyError::UnknownEpoch(epoch))
    }

    pub fn has_epoch_key(&self, epoch: EpochId) -> bool {
        self.epoch_keys.contains_key(&epoch)
    }

    pub fn initiate_migration(
        &mut self,
        new_epoch: EpochId,
        new_epoch_secret: EpochSecret,
    ) -> Result<(), RekeyError> {
        if !matches!(self.migration_state, MigrationState::Stable) {
            return Err(RekeyError::MigrationInProgress);
        }

        let start_time = Instant::now();
        self.epoch_keys.insert(new_epoch, new_epoch_secret);
        self.migration_state = MigrationState::MigrationActive {
            new_epoch,
            start_time,
        };
        self.migration_tracking = Some(MigrationTracking::new(start_time, 0));
        Ok(())
    }

    pub fn set_expected_total_files(&mut self, total_files: usize) {
        if let Some(tracking) = self.migration_tracking.as_mut() {
            tracking.set_total_files(total_files);
        }
    }

    pub fn promote_cutover(&mut self) -> Result<(), RekeyError> {
        match self.migration_state {
            MigrationState::MigrationActive { new_epoch, .. } => {
                self.migration_state = MigrationState::CutoverPending { new_epoch };
                Ok(())
            }
            MigrationState::CutoverPending { .. } => Err(RekeyError::CutoverAlreadyPending),
            MigrationState::Stable => Err(RekeyError::NoMigrationActive),
        }
    }

    pub fn can_complete_migration(&self) -> Result<bool, RekeyError> {
        match self.migration_state {
            MigrationState::Stable => Ok(false),
            MigrationState::MigrationActive { .. } | MigrationState::CutoverPending { .. } => {
                let Some(tracking) = &self.migration_tracking else {
                    return Ok(false);
                };

                if tracking.total_files == 0 {
                    Ok(true)
                } else {
                    Ok(tracking.files_rewrapped >= tracking.total_files)
                }
            }
        }
    }

    pub fn complete_migration(&mut self) -> Result<EpochId, RekeyError> {
        let target_epoch = match self.migration_state {
            MigrationState::MigrationActive { new_epoch, .. }
            | MigrationState::CutoverPending { new_epoch } => new_epoch,
            MigrationState::Stable => return Err(RekeyError::NoMigrationActive),
        };

        self.current_epoch = target_epoch;
        self.migration_state = MigrationState::Stable;
        self.migration_tracking = None;
        Ok(target_epoch)
    }

    pub fn get_migration_target(&self) -> Option<EpochId> {
        match &self.migration_state {
            MigrationState::MigrationActive { new_epoch, .. }
            | MigrationState::CutoverPending { new_epoch } => Some(*new_epoch),
            MigrationState::Stable => None,
        }
    }

    pub fn should_rewrap_file(&self, file_epoch: EpochId) -> bool {
        matches!(self.migration_state, MigrationState::MigrationActive { .. })
            && file_epoch == self.current_epoch
    }

    pub fn request_file_rewrap(
        &self,
        file_epoch: EpochId,
        _file_id: &str,
    ) -> Result<(), RekeyError> {
        if !self.should_rewrap_file(file_epoch) {
            return Err(RekeyError::InvalidState(
                "file not eligible for rewrap in current state",
            ));
        }
        Ok(())
    }

    pub fn get_rewrap_keys(
        &self,
        file_epoch: EpochId,
    ) -> Result<(&EpochSecret, &EpochSecret), RekeyError> {
        let target_epoch = self
            .get_migration_target()
            .ok_or(RekeyError::NoMigrationActive)?;

        if file_epoch != self.current_epoch {
            return Err(RekeyError::InvalidState(
                "file epoch does not match current epoch",
            ));
        }

        let old_secret = self.get_epoch_secret(self.current_epoch)?;
        let new_secret = self.get_epoch_secret(target_epoch)?;
        Ok((old_secret, new_secret))
    }

    pub fn mark_file_rewrapped(&mut self, file_epoch: EpochId) -> Result<(), RekeyError> {
        if !self.should_rewrap_file(file_epoch) {
            return Err(RekeyError::InvalidState(
                "cannot mark file rewrapped outside active migration",
            ));
        }

        if let Some(tracking) = self.migration_tracking.as_mut() {
            tracking.mark_rewrapped();
        }

        Ok(())
    }

    pub fn get_migration_progress(&self) -> Result<MigrationProgress, RekeyError> {
        let tracking = self
            .migration_tracking
            .as_ref()
            .ok_or(RekeyError::NoMigrationActive)?;
        Ok(tracking.progress())
    }

    pub fn completion_percentage(&self) -> f64 {
        self.migration_tracking
            .as_ref()
            .map(|tracking| tracking.progress().completion_percentage)
            .unwrap_or(0.0)
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.migration_state, MigrationState::Stable)
    }

    pub fn coverage_manager(&self) -> &CoverageManager<S> {
        &self.coverage_manager
    }
}
